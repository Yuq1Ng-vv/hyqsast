"""benchmarks/owasp/run.py — OWASP Benchmark 一键回归（克隆 → 扫描 → 评分）。

用法::

    uv run python benchmarks/owasp/run.py                    # 全量扫描 + 评分（默认 --no-cache）
    uv run python benchmarks/owasp/run.py --cache            # 复用 CPG 缓存（仅确定源码没变时）
    uv run python benchmarks/owasp/run.py --score-only /tmp/owasp_report.json  # 只评分已有报告

说明：
- BenchmarkJava 默认浅克隆到 ``/root/benchmarks/owasp-benchmark``（env
  ``OWASP_BENCH_DIR`` 可覆盖），2766 个测试源码不入仓。
- **默认 ``--no-cache``**：这是缺陷平衡铁律的回归入口 —— 改完
  taint_rules.yaml / graph.py / analyzer.py 后重跑必须保证图是新构建的，
  不能吃缓存。确定源码未变、只想快速看结果时才用 ``--cache``。
- ``--max-findings`` 必须给高（默认 50000）：sqli 一类有 504 个测试用例，
  默认每类别 50 会把召回截断成假 FN。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = Path(os.environ.get("OWASP_BENCH_DIR", "/root/benchmarks/owasp-benchmark"))
REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
TESTCODE = "src/main/java/org/owasp/benchmark/testcode"
EXPECTED = "expectedresults-1.2.csv"


def ensure_repo() -> Path:
    if not (BENCH_DIR / TESTCODE).exists():
        print(f"[owasp] 克隆 BenchmarkJava -> {BENCH_DIR}")
        BENCH_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(BENCH_DIR)], check=True)
    else:
        print(f"[owasp] 复用 {BENCH_DIR}")
    return BENCH_DIR


def main() -> None:
    ap = argparse.ArgumentParser(description="OWASP Benchmark 一键回归（扫描 + 评分）")
    ap.add_argument("--report", default="/tmp/owasp_report.json", help="报告输出路径")
    ap.add_argument(
        "--max-findings",
        type=int,
        default=50000,
        help="每类别最多 finding（默认 50000，防截断假 FN）",
    )
    ap.add_argument(
        "--cache",
        action="store_true",
        help="复用 CPG 缓存（默认 --no-cache 保证新鲜）",
    )
    ap.add_argument(
        "--score-only",
        nargs="?",
        const=True,
        metavar="REPORT",
        help="只评分已有报告，不重扫（可带报告路径）",
    )
    args = ap.parse_args()

    bench = ensure_repo()
    expected_csv = bench / EXPECTED

    if args.score_only:
        report_path = args.report if args.score_only is True else args.score_only
        run_score(report_path, expected_csv)
        return

    target = bench / TESTCODE
    # hyqsast 无 __main__，用 venv 里 console script（与 sys.executable 同目录）
    hyqsast_bin = Path(sys.executable).parent / "hyqsast"
    if not hyqsast_bin.exists():
        hyqsast_bin = "hyqsast"  # 回退到 PATH（uv run 通常已注入）
    cache_args = [] if args.cache else ["--no-cache"]
    cmd = [
        str(hyqsast_bin),
        str(target),
        "--language",
        "java",
        "--max-findings",
        str(args.max_findings),
        "-o",
        args.report,
        *cache_args,
    ]
    print(f"[owasp] 扫描 {target} ...")
    subprocess.run(cmd, check=True, cwd=REPO_ROOT)
    run_score(args.report, expected_csv)


def run_score(report_path: str, expected_csv: Path) -> None:
    score_script = Path(__file__).with_name("score.py")
    subprocess.run(
        [sys.executable, str(score_script), report_path, "--expected", str(expected_csv)],
        check=True,
    )


if __name__ == "__main__":
    main()
