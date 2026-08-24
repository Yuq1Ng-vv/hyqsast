"""benchmarks/owasp/chunk_scan.py — OWASP 分块扫描 + 合并（内存有界回归入口）。

2740 文件单进程建图在本机（~1.6GiB RAM）会 OOM——跨文件调用图是内存大头
（见 README「内存注意」）。本脚本把 testcode 文件按名字排序切成 ``--chunks``
个连续块，每块一个子进程跑 hyqsast（内存有界），再合并 findings 评分。OWASP
每个测试用例自包含，跨块边不影响逐用例评分，且与全量扫描 A/B 零差异（已实证，
见 results/2026-08-22-perf-p01-p02）。

用法::

    uv run python benchmarks/owasp/chunk_scan.py                      # 10 块 + 合并 + 评分
    uv run python benchmarks/owasp/chunk_scan.py --chunks 8 --label my-round
    uv run python benchmarks/owasp/chunk_scan.py --scan-only          # 只扫不评分
    uv run python benchmarks/owasp/chunk_scan.py --merge-only <out>   # 只合并已有块报告
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = Path(os.environ.get("OWASP_BENCH_DIR", "/root/benchmarks/owasp-benchmark"))
TESTCODE = BENCH_DIR / "src/main/java/org/owasp/benchmark/testcode"
EXPECTED = BENCH_DIR / "expectedresults-1.2.csv"
RESULTS = REPO_ROOT / "benchmarks/owasp/results"


def _collect_files() -> list[Path]:
    return sorted(p for p in TESTCODE.rglob("*.java") if p.is_file())


def _vm_rss() -> str:
    """当前进程 RSS（读 /proc/self/status，免 psutil 依赖）。"""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return line.split()[1] + "kB"
    except OSError:
        pass
    return "?"


def _link_or_copy(src: Path, dst: Path) -> None:
    """在扫描盒目录里放源码文件：优先 symlink（Linux 快、省空间）。

    Windows 上创建符号链接需要管理员/开发者模式（否则 ``os.symlink`` 抛
    WinError 1314「客户端没有所需的特权」），无权限时退化为复制文件——
    扫描只读文件内容，结果逐字节一致。"""
    try:
        dst.symlink_to(src)
    except OSError:
        shutil.copy2(src, dst)


def scan_chunks(
    files: list[Path],
    out_dir: Path,
    n_chunks: int,
    max_findings: int,
    extra_args: list[str] | None = None,
) -> list[Path]:
    """按 *files* 切成 *n_chunks* 个连续块，每块一个子进程扫描。

    每块在 ``out_dir/parts/part_NNN/`` 下放 symlink 目录（避免复制 2740 个文件），
    报告写到 ``out_dir/parts/report_chunk_NNN.json``。返回各块报告路径。
    """
    parts_dir = out_dir / "parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    size = max(1, (len(files) + n_chunks - 1) // n_chunks)
    reports: list[Path] = []

    hyqsast_bin = Path(sys.executable).parent / "hyqsast"
    if not hyqsast_bin.exists():
        # Windows 下 uv 装的 console script 是 hyqsast.exe
        hyqsast_bin = Path(sys.executable).parent / "hyqsast.exe"
    if not Path(hyqsast_bin).exists():
        hyqsast_bin = "hyqsast"

    for i in range(0, len(files), size):
        chunk = files[i : i + size]
        part_dir = parts_dir / f"part_{i // size:03d}"
        part_dir.mkdir(exist_ok=True)
        for f in chunk:
            link = part_dir / f.name
            if not link.exists():
                _link_or_copy(f, link)
        report = parts_dir / f"report_chunk_{i // size:03d}.json"
        reports.append(report)
        if report.exists():
            print(f"  [chunk {i // size:03d}] {len(chunk)} 文件 -> {report.name}（已存在，跳过）")
            continue
        cmd = [
            str(hyqsast_bin),
            str(part_dir),
            "--language",
            "java",
            "--max-findings",
            str(max_findings),
            "--no-cache",
            *list(extra_args or []),
            "-o",
            str(report),
        ]
        print(f"  [chunk {i // size:03d}] 扫描 {len(chunk)} 文件 ...")
        subprocess.run(cmd, check=True, cwd=REPO_ROOT)
    return reports


def merge(reports: list[Path], out_json: Path) -> dict:
    """把各块报告的 findings / endpoints / blind_spots 合并进单报告。

    分块扫描时跨块边被切掉，但 OWASP 每个测试用例自包含，逐用例评分不受影响。
    summary 计数按块累加；块间不冲突（每块文件集不相交）。
    """
    merged: dict = {"summary": {}, "endpoints": [], "findings": [], "blind_spots": []}
    for rep in reports:
        with open(rep) as fh:
            data = json.load(fh)
        for key in ("summary",):
            for k, v in data.get(key, {}).items():
                if isinstance(v, int):
                    merged["summary"][k] = merged["summary"].get(k, 0) + v
        for key in ("endpoints", "findings", "blind_spots"):
            merged[key].extend(data.get(key, []))
    with open(out_json, "w") as fh:
        json.dump(merged, fh, ensure_ascii=False)
    print(
        f"  合并完成：findings={len(merged['findings'])} endpoints={len(merged['endpoints'])}"
        f" -> {out_json.name}"
    )
    return merged


def scan_per_file(
    files: list[Path],
    out_dir: Path,
    max_findings: int,
    enable_container_bridge: bool = False,
    enable_state_bridge: bool = False,
) -> dict:
    """逐文件独立建图扫描（OWASP 自包含用例的正确口径）。

    OWASP Benchmark 是 2740 个自包含测试用例，不是完整项目：跨文件调用图整体
    建会让 ``thing.doSomething`` 这类撞衫方法全库全连（稠密伪边，findings
    24571→35932）。per-file 模式每个文件单独建图 + 单独跑污点，最后合并——
    单文件间无伪边，逐用例评分口径与 OWASP 官方一致。单个 Python 进程串行，
    每文件小图用完即弃，内存有界（每文件 ~0.2s，2740 文件约 10 分钟）。

    规则加载与 CLI 保持一致：cli.py 会在 cwd 存在 ``rules/`` 目录时自动加载
    （叠加在内置 ``taint_rules.yaml`` 之上）。这里复刻同样的自动发现，否则
    per-file 与 chunk 整体扫描的 sink 标签不一致（如 ``.exec(`` 的 cmdi 模式
    只在 rules/java.yaml，漏加载会让 exec@78 只标 path_traversal 而非
    command_injection）。桥接开关与 ``--enable-container-bridge`` /
    ``--enable-state-bridge`` 透传一致（A/B 用）。
    """
    from hyqsast.api import scan

    # 与 cli.py 相同的 rules/ 自动发现：cwd 下存在则加载（叠加合并）。
    rules_paths: list[str] | None = None
    auto_rules = Path.cwd() / "rules"
    if auto_rules.is_dir():
        rules_paths = [str(auto_rules)]
        print(f"  [per-file] 自动加载额外规则目录: {auto_rules}")

    merged: dict = {"summary": {}, "endpoints": [], "findings": [], "blind_spots": []}
    part_dir = out_dir / "perfile"
    part_dir.mkdir(parents=True, exist_ok=True)
    n_fail = 0
    for i, f in enumerate(files, 1):
        # 每文件一个独立目录（scan 要求目录），symlink 单文件进去避免复制。
        box = part_dir / f"{i:04d}"
        box.mkdir(exist_ok=True)
        link = box / f.name
        if not link.exists():
            _link_or_copy(f, link)
        try:
            r = scan(
                box,
                language="java",
                max_findings_per_category=max_findings,
                use_cache=False,
                include_blind_spots=False,
                rules_paths=rules_paths,
                enable_container_bridge=enable_container_bridge,
                enable_state_bridge=enable_state_bridge,
            )
            d = r.to_dict()
        except Exception as e:  # 单文件失败不影响整体回归
            print(f"  [{i:04d}] {f.name} 失败：{e}")
            n_fail += 1
            continue
        for k, v in d.get("summary", {}).items():
            if isinstance(v, int):
                merged["summary"][k] = merged["summary"].get(k, 0) + v
        for key in ("endpoints", "findings", "blind_spots"):
            merged[key].extend(d.get(key, []))
        if i % 100 == 0:
            rss = _vm_rss()
            print(f"  [{i:04d}/{len(files)}] findings累计={len(merged['findings'])} rss={rss}")
    if n_fail:
        print(f"  [per-file] {n_fail}/{len(files)} 文件失败")
    out_json = out_dir / "owasp-merged.json"
    with open(out_json, "w") as fh:
        json.dump(merged, fh, ensure_ascii=False)
    print(
        f"  [per-file] 完成：findings={len(merged['findings'])}"
        f" endpoints={len(merged['endpoints'])} -> {out_json.name}"
    )
    return merged


def score(report: Path, expected_csv: Path, score_txt: Path | None) -> None:
    score_script = Path(__file__).with_name("score.py")
    proc = subprocess.run(
        [sys.executable, str(score_script), str(report), "--expected", str(expected_csv)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    out = proc.stdout or proc.stderr
    print(out)
    if score_txt is not None:
        score_txt.write_text(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="OWASP 分块扫描 + 合并 + 评分（内存有界）")
    ap.add_argument("--chunks", type=int, default=10, help="分块数（默认 10）")
    ap.add_argument(
        "--per-file",
        action="store_true",
        help="逐文件独立建图扫描（OWASP 自包含用例的正确口径，无跨文件伪边）",
    )
    ap.add_argument(
        "--max-findings",
        type=int,
        default=50000,
        help="每类别最多 finding（防截断假 FN）",
    )
    ap.add_argument("--label", default="owasp-chunked", help="结果归档目录名（results/<label>/）")
    ap.add_argument("--scan-only", action="store_true", help="只分块扫描 + 合并，不评分")
    ap.add_argument("--merge-only", nargs="?", const=True, metavar="OUT", help="只合并已有块报告")
    ap.add_argument(
        "--enable-container-bridge",
        action="store_true",
        help="透传给 hyqsast：开容器写桥接（OWASP 桥接开/关对比用）",
    )
    ap.add_argument(
        "--enable-state-bridge",
        action="store_true",
        help="透传给 hyqsast：开跨函数状态桥接（OWASP 桥接开/关对比用）",
    )
    args = ap.parse_args()

    out_dir = RESULTS / args.label
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.merge_only:
        parts_dir = out_dir / "parts"
        if isinstance(args.merge_only, str):
            out_val = Path(args.merge_only)
        else:
            out_val = out_dir / "owasp-merged.json"
        reports = sorted(parts_dir.glob("report_chunk_*.json")) if parts_dir.exists() else []
        if not reports:
            ap.error(f"{parts_dir} 下没有 report_chunk_*.json")
        merge(reports, out_val)
        return

    if not TESTCODE.exists():
        ap.error(f"找不到 OWASP testcode：{TESTCODE}（先跑 benchmarks/owasp/run.py 克隆）")
    if not EXPECTED.exists():
        ap.error(f"找不到 expectedresults：{EXPECTED}")

    files = _collect_files()
    if args.per_file:
        print(f"[chunk_scan] --per-file：{len(files)} 文件逐目录独立建图 -> {out_dir}")
        merged_json = out_dir / "owasp-merged.json"
        scan_per_file(
            files,
            out_dir,
            args.max_findings,
            enable_container_bridge=args.enable_container_bridge,
            enable_state_bridge=args.enable_state_bridge,
        )
        if not args.scan_only:
            score(merged_json, EXPECTED, out_dir / "score.txt")
            print(f"[chunk_scan] 评分已存档：{out_dir / 'score.txt'}")
        return

    print(f"[chunk_scan] {len(files)} 文件 / {args.chunks} 块 -> {out_dir}")


if __name__ == "__main__":
    main()
