"""cli.py — 极简命令行入口（stdlib argparse，无额外依赖）。

用法::

    hyqsast /path/to/project --language java --output report.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hyqsast import scan
from hyqsast.progress import make_progress
from hyqsast.schema import Finding


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hyqsast",
        description="确定性污点分析：输出接口 / 漏洞类型 / 调用链",
    )
    parser.add_argument("directory", help="源码目录")
    parser.add_argument(
        "--language", default=None, help="java / python / javascript（缺省自动探测）"
    )
    parser.add_argument("--framework", default=None, help="框架提取器名（spring / flask ...）")
    parser.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="PATH",
        help="额外规则文件或目录（可多次指定，*.yaml 在内置规则之上追加合并）",
    )
    parser.add_argument("--max-findings", type=int, default=50, help="每类别最多 finding 数")
    parser.add_argument("--output", "-o", default=None, help="JSON 报告输出路径")
    parser.add_argument(
        "--no-canonical",
        action="store_true",
        help="不生成规范版报告（默认与 -o 一并写出 <stem>.canonical.json）",
    )
    parser.add_argument(
        "--no-elements",
        action="store_true",
        help="不生成污点元素清单（默认与 -o 一并写出 <stem>.elements.json，供漏报排查）",
    )
    parser.add_argument(
        "--no-flat",
        action="store_true",
        help="不生成扁平版报告（默认写出 <stem>.flat.json：接口列表 + source/sink 点，供聚合）",
    )
    parser.add_argument(
        "--no-canonical-route",
        action="store_true",
        help="不生成接口精简规范版（默认写出 <stem>.canonical.route.json，endpoint 只留纯接口）",
    )
    parser.add_argument(
        "--no-canonical-agg",
        action="store_true",
        help="不生成聚合规范版（默认写出 <stem>.canonical.agg.json，按 source+sink 聚合调用链）",
    )
    parser.add_argument("--no-blind-spots", action="store_true", help="不输出盲区清单")
    parser.add_argument("--no-cache", action="store_true", help="强制重建 CPG 图，忽略缓存")
    parser.add_argument(
        "--enable-container-bridge",
        action="store_true",
        help="开启容器/Builder 状态写读桥接启发式（默认关；高召回漏报面场景才开）",
    )
    parser.add_argument(
        "--enable-state-bridge",
        action="store_true",
        help="开启跨函数状态桥接启发式（默认关；高召回漏报面场景才开）",
    )
    args = parser.parse_args(argv)

    # 自动发现：cwd 下存在 rules/ 目录则默认加载（--rules 显式指定时优先生效）
    rules_paths = args.rules or None
    if not rules_paths:
        auto = Path.cwd() / "rules"
        if auto.is_dir():
            rules_paths = [str(auto)]
            print(f"自动加载额外规则目录: {auto}（用 --rules 可覆盖）")

    # 控制台进度条：tty+rich → 双进度条；否则纯文本阶段日志（stderr）。
    # 概况统计与扫描各用一个进度实例 —— 概况的条走完后要停掉、打印概况行，
    # 再起扫描的条（rich Live 同流直印会互相覆盖，分开最稳）。
    overview_progress = make_progress()
    overview = _project_overview(args.directory, progress=overview_progress)
    overview_progress.end()
    if overview:
        print(overview)

    # 扫描无论成败都要收尾进度条，放 try/finally。
    progress = make_progress()
    try:
        result = scan(
            directory=args.directory,
            language=args.language,
            framework=args.framework,
            max_findings_per_category=args.max_findings,
            include_blind_spots=not args.no_blind_spots,
            use_cache=not args.no_cache,
            rules_paths=rules_paths,
            enable_container_bridge=args.enable_container_bridge,
            enable_state_bridge=args.enable_state_bridge,
            progress=progress,
        )
    finally:
        progress.end()

    s = result.summary
    print(
        f"文件: {s.files}  函数: {s.functions}  接口: {s.endpoints}  "
        f"finding: {s.findings}  source: {s.sources}  sink: {s.sinks}  "
        f"盲区: {s.blind_spots}"
    )

    # P0-2: 截断可见化 —— 让用户知道某类别还有更多候选被上限吞掉
    if s.truncated_categories:
        detail = ", ".join(f"{k}+{v}" for k, v in sorted(s.truncated_categories.items()))
        print(
            f"⚠  {len(s.truncated_categories)} 个类别达到上限被截断（{detail}）；"
            f"如需完整结果请用 --max-findings 提高（当前 {args.max_findings}）"
        )

    if result.endpoints:
        print("\n── 接口 ──")
        for ep in result.endpoints:
            print(
                f"  {'/'.join(ep.methods) or 'ANY':6s} {ep.route}  "
                f"-> {ep.handler_func}  ({ep.file_path}:{ep.line})"
            )

    if result.findings:
        print("\n── 漏洞 ──")
        for f in result.findings:
            print(_fmt_finding(f))

    if args.output:
        result.to_json(args.output)
        print(f"\n报告已写入: {args.output}")
        output = Path(args.output)
        if not args.no_canonical:
            canonical_path = output.with_name(f"{output.stem}.canonical{output.suffix}")
            result.to_canonical_json(canonical_path)
            print(f"规范版报告已写入: {canonical_path}")
        if not args.no_elements:
            elements_path = output.with_name(f"{output.stem}.elements{output.suffix}")
            result.to_elements_json(elements_path)
            src_n = sum(1 for e in result.taint_elements if e.kind == "source")
            sink_n = sum(1 for e in result.taint_elements if e.kind == "sink")
            print(f"污点元素清单已写入: {elements_path}  (sources: {src_n}  sinks: {sink_n})")
        if not args.no_flat:
            flat_path = output.with_name(f"{output.stem}.flat{output.suffix}")
            result.to_flat_json(flat_path)
            print(f"扁平版报告已写入: {flat_path}  (findings: {len(result.findings)})")
        if not args.no_canonical_route:
            route_path = output.with_name(f"{output.stem}.canonical.route{output.suffix}")
            result.to_canonical_route_json(route_path)
            print(f"接口精简规范版报告已写入: {route_path}")
        if not args.no_canonical_agg:
            agg_path = output.with_name(f"{output.stem}.canonical.agg{output.suffix}")
            result.to_canonical_agg_json(agg_path)
            print(f"聚合规范版报告已写入: {agg_path}")

    return 0


def _fmt_finding(f: Finding) -> str:
    sev = f.severity.upper()
    related = f"  (相关: {','.join(f.related_categories)})" if f.related_categories else ""
    ep = f.endpoint
    if ep.match == "unmatched":
        ep_str = "未关联接口 (unmatched)"
    else:
        ep_str = f"{'/'.join(ep.methods) or 'ANY'} {ep.route} -> {ep.handler_func}  [{ep.match}]"
    return (
        f"  [{sev:8s}] {f.vuln_type}{related}\n"
        f"    endpoint: {ep_str}\n"
        f"    source: {f.source.code.strip()[:60]}  ({f.source.file_path}:{f.source.line})\n"
        f"    sink:   {f.sink.code.strip()[:60]}  ({f.sink.file_path}:{f.sink.line})\n"
        f"    chain:  {len(f.call_chain)} 步"
        + (f"  (sanitized: {','.join(f.sanitizers)})" if f.sanitized else "")
    )


def _project_overview(
    directory: str | Path, progress: object | None = None
) -> str | None:
    """统计源码目录的语言文件数与总行数（扫描前打印概况）。

    只统计受支持语言（java/python/javascript）。逐文件分块读，内存有界
    （内存铁律）。大项目会多一次全量读盘——正是为了让用户先看到规模再决定
    要不要继续，价值大于成本。

    7 万文件级项目这一趟数行可能耗时几十秒：有 progress 时把它作为独立
    「统计概况」阶段走进度条（先 rglob 数文件数 → set_total，再逐文件数行
    step），不让终端在概况统计期间静止、让用户以为没反应。
    """
    from hyqsast.cpg.languages import detect_by_extension

    root = Path(directory)
    # 第一趟：rglob 收集源码清单（轻量 stat，快）。数文件数要 set_total 用。
    file_paths: list[Path] = []
    counts: dict[str, int] = {}
    for entry in root.rglob("*"):
        if not entry.is_file():
            continue
        if any(p.startswith(".") or p == "__pycache__" for p in entry.parts):
            continue
        lang = detect_by_extension(str(entry))
        if not lang:
            continue
        counts[lang] = counts.get(lang, 0) + 1
        file_paths.append(entry)
    if not counts:
        return None
    if progress is not None:
        progress.setup(["统计概况"])
        progress.begin("统计概况", total=len(file_paths))
    # 第二趟：逐文件数行（大项目的主要耗时），带进度。
    total_lines = 0
    for fp in file_paths:
        total_lines += _count_lines_fast(fp)
        if progress is not None:
            progress.step(1)
    langs = " · ".join(f"{k} {v} 个文件" for k, v in sorted(counts.items()))
    return f"项目概况：{langs} · 共 {len(file_paths)} 个源码文件 / {total_lines:,} 行"


def _count_lines_fast(path: Path) -> int:
    """分块数换行符，避免逐行 Python 迭代（大文件更快、内存有界）。"""
    n = 0
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 16):
            n += chunk.count(b"\n")
    return n


if __name__ == "__main__":
    sys.exit(main())
