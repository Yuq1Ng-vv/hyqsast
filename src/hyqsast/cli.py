"""cli.py — 极简命令行入口（stdlib argparse，无额外依赖）。

用法::

    hyqsast /path/to/project --language java --output report.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hyqsast import scan
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
    parser.add_argument("--no-blind-spots", action="store_true", help="不输出盲区清单")
    parser.add_argument("--no-cache", action="store_true", help="强制重建 CPG 图，忽略缓存")
    args = parser.parse_args(argv)

    result = scan(
        directory=args.directory,
        language=args.language,
        framework=args.framework,
        max_findings_per_category=args.max_findings,
        include_blind_spots=not args.no_blind_spots,
        use_cache=not args.no_cache,
        rules_paths=args.rules or None,
    )

    s = result.summary
    print(f"文件: {s.files}  函数: {s.functions}  接口: {s.endpoints}  "
          f"finding: {s.findings}  sink: {s.sinks}  盲区: {s.blind_spots}")

    if result.endpoints:
        print("\n── 接口 ──")
        for ep in result.endpoints:
            print(f"  {'/'.join(ep.methods) or 'ANY':6s} {ep.route}  "
                  f"-> {ep.handler_func}  ({ep.file_path}:{ep.line})")

    if result.findings:
        print("\n── 漏洞 ──")
        for f in result.findings:
            print(_fmt_finding(f))

    if args.output:
        result.to_json(args.output)
        print(f"\n报告已写入: {args.output}")
        if not args.no_canonical:
            output = Path(args.output)
            canonical_path = output.with_name(f"{output.stem}.canonical{output.suffix}")
            result.to_canonical_json(canonical_path)
            print(f"规范版报告已写入: {canonical_path}")

    return 0


def _fmt_finding(f: Finding) -> str:
    sev = f.severity.upper()
    return (
        f"  [{sev:8s}] {f.vuln_type}\n"
        f"    source: {f.source.code.strip()[:60]}  ({f.source.file_path}:{f.source.line})\n"
        f"    sink:   {f.sink.code.strip()[:60]}  ({f.sink.file_path}:{f.sink.line})\n"
        f"    chain:  {len(f.call_chain)} 步"
        + (f"  (sanitized: {','.join(f.sanitizers)})" if f.sanitized else "")
    )


if __name__ == "__main__":
    sys.exit(main())
