"""benchmarks/ant/run.py — xAST Benchmark 一键回归（扫描 → 评分 → 归档）。

用法::

    uv run python benchmarks/ant/run.py                                    # sast-java 默认
    uv run python benchmarks/ant/run.py --lang-dir sast-python3            # python
    uv run python benchmarks/ant/run.py --label fix-container-bridge       # 命名本轮
    uv run python benchmarks/ant/run.py --score-only /tmp/report.json      # 只评分已有报告

说明：
- 基准已克隆在 ``benchmarks/ant-application-security-testing-benchmark/``，
  sast-{java,python2,python3,js,php,go,java-cross-module} 各含 *_T/*_F 用例。
- **``--max-findings`` 必须给高（默认 50000）**：默认每类别 50 会把稠密类别
  （如 command_injection）截断成假 FN（2026-08-27 实测默认 50 → TPR 13.0%，
  无截断 → 72.8%）。这是 run.py 的第一铁律。
- **引擎支持边界**：hyqsast 引擎支持 java/python/javascript（go/php 只有规则
  无 parser），sast-go/sast-php 传参会报错退出，避免用假空结果自欺。
- 结果归档 ``benchmarks/ant/results/<date>-<label>/``（与 OWASP 同约定），
  score.txt 可 diff 对比每轮回归。
"""

from __future__ import annotations

import argparse
import datetime
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANT_BENCH = REPO_ROOT / "benchmarks" / "ant-application-security-testing-benchmark"
RESULTS_DIR = Path(__file__).resolve().parent / "results"

# lang-dir → (语言名, 引擎是否支持)
LANG_MAP = {
    "sast-java": ("java", True),
    "sast-python3": ("python", True),
    "sast-js": ("javascript", True),
    "sast-python2": ("python", True),
    "sast-php": ("php", False),
    "sast-go": ("go", False),
    "sast-java-cross-module": ("java", True),
}

DEFAULT_MAX_FINDINGS = 50000


def scan(lang_dir: str, label: str, max_findings: int, use_cache: bool) -> Path:
    lang, supported = LANG_MAP[lang_dir]
    if not supported:
        sys.exit(
            f"[ant/run] {lang_dir}: hyqsast 引擎暂无 {lang} parser（只有规则），"
            f"不能出真实结果，拒绝空跑。"
        )
    date = datetime.date.today().isoformat()
    out_dir = RESULTS_DIR / f"{date}-{label}"
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / "report.json"
    target = ANT_BENCH / lang_dir

    cmd = [
        sys.executable,
        "-m",
        "hyqsast",
        str(target),
        "--language",
        lang,
        "--max-findings",
        str(max_findings),
        "-o",
        str(report),
    ]
    if not use_cache:
        cmd.append("--no-cache")
    print(f"[ant/run] 扫描 {lang_dir}（{lang}，{max_findings}/类别）...")
    subprocess.run(cmd, check=True, cwd=REPO_ROOT)
    return report


def score_to(report: Path, lang_dir: str, out_dir: Path) -> None:
    import importlib.util

    score_path = Path(__file__).resolve().parent / "score.py"
    spec = importlib.util.spec_from_file_location("ant_score", score_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    s = mod.score(str(report), lang_dir)
    text = mod.render(s, verbose=True)
    (out_dir / "score.txt").write_text(text)
    (out_dir / "score.json").write_text(json.dumps(s, ensure_ascii=False, indent=1))
    print(text)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lang-dir", default="sast-java", choices=sorted(LANG_MAP),
                    help="基准子目录（默认 sast-java）")
    ap.add_argument("--label", default="scan", help="本轮标签（进结果目录名）")
    ap.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS,
                    help="每类别最多 finding 数（铁律：必须给高，否则截断假 FN）")
    ap.add_argument("--cache", action="store_true", help="复用 CPG 缓存（默认 --no-cache 重建）")
    ap.add_argument("--score-only", metavar="REPORT", help="只对已有报告评分并归档，不重扫")
    args = ap.parse_args()

    if args.score_only:
        report = Path(args.score_only)
        if not report.exists():
            sys.exit(f"报告不存在: {report}")
        date = datetime.date.today().isoformat()
        out_dir = RESULTS_DIR / f"{date}-{args.label}"
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(report, out_dir / "report.json")
        score_to(out_dir / "report.json", args.lang_dir, out_dir)
        print(f"\n[ant/run] 归档: {out_dir}")
        return

    report = scan(args.lang_dir, args.label, args.max_findings, use_cache=args.cache)
    score_to(report, args.lang_dir, report.parent)
    print(f"\n[ant/run] 归档: {report.parent}")


if __name__ == "__main__":
    main()
