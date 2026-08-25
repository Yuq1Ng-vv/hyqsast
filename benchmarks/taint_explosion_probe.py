"""benchmarks/taint_explosion_probe.py — 定位污点候选爆炸的来源。

用户 7 万文件 Java 项目扫出 20442 source / 177727 sink / 367 万候选（sql 183 万）。
本探针加载已构建图（命中缓存），量化让 source→sink 稠密连通的来源：

1. 节点规模（source / sink / call_site / function）
2. DATA_FLOW 边按 confidence —— 全连接兜底（low）是否主导
3. 跨文件 call_site 扇出直方图 + Top 扇出 —— 同名函数多文件扇出是否主凶
4. sink 按类别计数 + **sink 模式命中直方图** —— 哪个 sink 模式（如裸
   ``.update(``/``.insert(``）贡献了多少 sink，点名通用方法名的误伤占比
5. **可达性采样** —— 抽 ~300 个 source 跑前向 BFS，统计每 source 达 sink 数
   与路径数，外推全项目候选总量（应接近报告里的「候选」截断计数），并报告
   BUG 62 反向预筛跳过了多少 source

用法::
    uv run python benchmarks/taint_explosion_probe.py <项目路径> <语言>
"""
from __future__ import annotations

import random
import sys
import time
from collections import Counter

from hyqsast.analyzer import Analyzer

_BFS_DEPTH = 20
_SAMPLE_SOURCES = 300
_PATTERN_SHOW = 40


def _sink_text(data: dict) -> str:
    """Mirror ``_label_taint_nodes`` 的取文逻辑：assignment 用 source，
    call_site 用 expression。"""
    nt = data.get("node_type", "")
    if nt == "assignment":
        return data.get("source", "")
    if nt == "call_site":
        return data.get("expression", "")
    return ""


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

    # ── sink 类别分布 + 模式命中直方图 ───────────────────────────────────
    cat_count: Counter[str] = Counter()
    pat_count: Counter[str] = Counter()
    loader = a.taint_loader
    rules = loader.rules_for(language)
    # 模式 → 类别（供解读：短模式大多是可跨对象命中的通用方法名）
    pat_to_cat: dict[str, str] = {}
    for cname, cat in rules.categories.items():
        for pat in cat.sinks:
            pat_to_cat.setdefault(pat, cname)

    for _, d in g.nodes(data=True):
        if not d.get("taint_sink"):
            continue
        for c in d["taint_sink"].split(","):
            cat_count[c.strip()] += 1
        text = _sink_text(d)
        if text:
            for pat, cname in pat_to_cat.items():
                if pat in text:
                    pat_count[(pat, cname)] += 1

    print(f"\n[sink] 类别分布（一个 sink 节点可属多类）:")
    for c, n in cat_count.most_common():
        print(f"  {c:<24} {n:,}")
    print(f"\n[sink] 模式命中 Top {_PATTERN_SHOW}（模式 @ 类别 → sink 节点数）:")
    for (pat, cname), n in pat_count.most_common(_PATTERN_SHOW):
        mark = "  ← 短/通用，误伤风险" if len(pat) <= 12 else ""
        print(f"  {n:>8,}  {pat!r:<44} @ {cname}{mark}")

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

    # ── 可达性采样：外推全项目候选总量 ───────────────────────────────────
    source_ids = sorted(n for n, d in g.nodes(data=True) if d.get("taint_source"))
    sink_set = {n for n, d in g.nodes(data=True) if d.get("taint_sink")}
    if not source_ids or not sink_set:
        print("\n[bfs] 无 source 或 sink，跳过采样")
        return

    has_prefilter = hasattr(a, "_sink_reachable")
    reachable: set[str] | None = None
    if has_prefilter:
        reachable = a._sink_reachable(sink_set, _BFS_DEPTH)
    in_r = sum(1 for s in source_ids if reachable is None or s in reachable)
    print(
        f"\n[bfs] BUG62 反向预筛: {in_r:,}/{len(source_ids):,} source 在 R 内"
        f"（{100.0 * in_r / max(1, len(source_ids)):.1f}% 会真正跑 BFS）"
    )

    rng = random.Random(42)
    sample = rng.sample(source_ids, min(_SAMPLE_SOURCES, len(source_ids)))
    n_skipped = n_ran = 0
    total_paths = 0
    sinks_per_src: list[int] = []
    for src in sample:
        if reachable is not None and src not in reachable:
            n_skipped += 1
            continue
        try:
            paths = a._bfs_to_sink(src, sink_set, reachable=reachable)
        except TypeError:  # 旧代码无 reachable 参数
            paths = a._bfs_to_sink(src, sink_set)
        n_ran += 1
        total_paths += len(paths)
        sinks_per_src.append(len({p[0][-1] for p in paths}))

    if n_ran:
        avg_paths = total_paths / n_ran
        avg_sinks = sum(sinks_per_src) / n_ran
        print(
            f"[bfs] 采样 {n_ran} source（跳过预筛 {n_skipped}）: "
            f"平均每 source 达 {avg_sinks:.1f} 个不同 sink、{avg_paths:.1f} 条路径"
        )
        print(f"[bfs] 外推全项目候选 ≈ {avg_paths * len(source_ids):,.0f} "
              f"(平均路径数 × {len(source_ids):,} source)")
        hi = max(sinks_per_src, default=0)
        hist_sinks: Counter[int] = Counter()
        for s in sinks_per_src:
            hist_sinks[min(s, 100)] += 1
        print("每 source 达不同 sink 数分布（≥100 并到 100+）:")
        for k in sorted(hist_sinks):
            bar = "#" * min(hist_sinks[k] // max(1, len(sinks_per_src) // 40), 40)
            print(f"  {k:>4}: {hist_sinks[k]:,}  {bar}")
        print(f"  最大单 source 达 {hi} 个 sink")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
