"""benchmarks/taint_explosion_probe.py — 定位污点候选爆炸的来源。

用户 7 万文件 Java 项目扫出 20442 source / 177727 sink / 367 万候选。
本探针加载已构建图（命中缓存），量化让 source→sink 稠密连通的三个来源：
1. DATA_FLOW 边按 confidence（high/medium/low）计数 —— 全连接兜底是否主导
2. 跨文件 call_site 的 callee_files 扇出直方图 + Top 扇出调用 —— 同名函数
   多文件扇出是否是主凶
3. 各节点类型规模（source/sink/call_site/function）

用法::
    uv run python benchmarks/taint_explosion_probe.py <项目路径> <语言>
"""
from __future__ import annotations

import sys
import time
from collections import Counter

from hyqsast.analyzer import Analyzer

CONFIDENCE_KEYS = ("high", "medium", "low")


def main(target: str, language: str) -> None:
    a = Analyzer(target, language=language, use_cache=True)
    t0 = time.monotonic()
    a.graph_builder.add_directory(a.directory, use_cache=a.use_cache, progress=a.progress)
    print(f"建图/加载: {time.monotonic() - t0:.1f}s")
    g = a.graph_builder.graph

    # ── 节点规模 ─────────────────────────────────────────────────────────
    ntypes: Counter[str] = Counter()
    sources = sinks = 0
    for _, d in g.nodes(data=True):
        ntypes[d.get("node_type", "?")] += 1
        if d.get("taint_source"):
            sources += 1
        if d.get("taint_sink"):
            sinks += 1
    print(f"\n节点总数: {g.number_of_nodes():,}")
    for t, n in ntypes.most_common():
        print(f"  {t:<16} {n:,}")
    print(f"  taint_source {sources:,}   taint_sink {sinks:,}")

    # ── DATA_FLOW 边按 confidence ───────────────────────────────────────
    conf: Counter[str] = Counter()
    total_df = 0
    for _, _, ed in g.edges(data=True):
        if ed.get("edge_type") == "DATA_FLOW":
            total_df += 1
            conf[ed.get("confidence", "(无)")] += 1
    print(f"\nDATA_FLOW 边: {total_df:,}")
    for k, n in conf.most_common():
        print(f"  confidence={k:<8} {n:,}  ({100.0 * n / max(1, total_df):.1f}%)")

    # ── 跨文件 call_site 扇出 ────────────────────────────────────────────
    fanout: list[tuple[str, str, int, int]] = []  # (callee, 文件, 行, 目标数)
    n_cross = n_local = 0
    for nid, d in g.nodes(data=True):
        if d.get("node_type") != "call_site":
            continue
        cf = d.get("callee_files")
        if d.get("cross_file"):
            n_cross += 1
            if cf:
                fanout.append((d.get("callee", "?"), d.get("file_path", "?"), d.get("line", 0), len(cf)))
        else:
            n_local += 1
    print(f"\ncall_site: 跨文件 {n_cross:,}  本地 {n_local:,}")
    if fanout:
        fo = sorted(fanout, key=lambda x: -x[3])
        hist: Counter[int] = Counter()
        for _, _, _, n in fanout:
            hist[min(n, 10)] += 1
        print("跨文件扇出直方图（目标文件数，≥10 并到 10+）:")
        for k in sorted(hist):
            bar = "#" * min(hist[k] // max(1, len(fanout) // 40), 40)
            print(f"  {k:>3}: {hist[k]:,}  {bar}")
        print("\nTop 15 扇出调用（callee @ 文件:行 → N 个目标文件）:")
        for callee, fp, line, n in fo[:15]:
            print(f"  {callee:<40} {fp}:{line} → {n}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
