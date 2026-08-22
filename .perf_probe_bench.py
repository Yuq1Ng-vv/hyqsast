"""性能探针：纯建图插桩计时（无 BFS / 无报告写出，内存最小）。

用法: uv run python .perf_probe_bench.py perf_probes/perfprobe2 [--defuse]
基线（旧代码 O(F×G)）：
  perfprobe2 单文件 500 方法 → add_file 115.5s（rhs 44.3 + vrc 45.2 + def-use 23.8）
  perfprobe4 200 文件 source 密集 → add_directory 69.1s（rhs 20.0 + vrc 18.8
    + cont 8.4 + def-use 6.2）
"""

from __future__ import annotations

import argparse
import time

from hyqsast.cpg.graph import CPGGraphBuilder
from hyqsast.cpg.parser import Parser
from hyqsast.cpg.taint_loader import TaintRuleLoader


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--defuse", action="store_true", help="同时测 build_def_use_chains")
    args = ap.parse_args()

    parser = Parser(languages=["java"])
    loader = TaintRuleLoader()
    builder = CPGGraphBuilder(parser, taint_loader=loader)

    counts: dict[str, int] = {}
    totals: dict[str, float] = {}

    def wrap(name: str) -> None:
        fn = getattr(builder, name)
        counts[name] = 0
        totals[name] = 0.0

        def w(*a, **k):
            t0 = time.monotonic()
            r = fn(*a, **k)
            totals[name] += time.monotonic() - t0
            counts[name] += 1
            return r

        # 关键：必须把 wrapper 真正写回实例属性，否则返回的 w 被丢弃、
        # 计时器从未生效（此前边函数/ add_file 的耗时都归不了因）。
        setattr(builder, name, w)

    wrap("add_file")
    wrap("_add_rhs_to_lhs_edges")
    wrap("_add_varref_to_callsite_edges")
    wrap("_add_container_state_edges")

    if args.defuse:
        df = builder._dataflow
        counts["build_def_use_chains"] = 0
        totals["build_def_use_chains"] = 0.0
        orig_df = df.build_def_use_chains

        def wdf(*a, **k):
            t0 = time.monotonic()
            r = orig_df(*a, **k)
            totals["build_def_use_chains"] += time.monotonic() - t0
            counts["build_def_use_chains"] += 1
            return r

        df.build_def_use_chains = wdf

    t0 = time.monotonic()
    builder.add_directory(args.target, use_cache=False)
    total = time.monotonic() - t0

    print(f"\n=== {args.target} ===")
    print(
        f"add_directory 总耗时 = {total:.1f}s   图节点 = {builder.graph.number_of_nodes()}"
        f"   边 = {builder.graph.number_of_edges()}"
    )
    for name in (
        "_add_rhs_to_lhs_edges",
        "_add_varref_to_callsite_edges",
        "_add_container_state_edges",
        "build_def_use_chains",
        "add_file",
    ):
        if name in counts and counts[name]:
            print(
                f"  {name:34s} × {counts[name]:>5d}  {totals[name]:>8.3f}s"
                f"  ({totals[name] / max(total, 1e-9) * 100:5.1f}%)"
            )


if __name__ == "__main__":
    main()
