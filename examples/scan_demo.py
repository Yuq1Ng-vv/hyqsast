"""scan_demo.py — 最小可用示例。

用法::

    uv run python examples/scan_demo.py /path/to/java/project
"""

from __future__ import annotations

import sys
from pathlib import Path

from hyqsast import scan


def main() -> int:
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    language = sys.argv[2] if len(sys.argv) > 2 else None

    # 自动加载 cwd 下 rules/ 额外规则目录（存在才传，如 examples/rules 模板）
    rules_dir = Path.cwd() / "rules"
    result = scan(
        directory,
        language=language,
        rules_paths=[str(rules_dir)] if rules_dir.is_dir() else None,
    )

    s = result.summary
    print(f"文件={s.files} 函数={s.functions} 接口={s.endpoints} "
          f"finding={s.findings} sink={s.sinks} 盲区={s.blind_spots}")

    print("\n=== 接口 ===")
    for ep in result.endpoints:
        print(f"  {'/'.join(ep.methods) or 'ANY':6s} {ep.route}  -> {ep.handler_func}")

    print("\n=== 漏洞(finding) ===")
    for f in result.findings[:20]:
        print(f"  [{f.severity.upper():8s}] {f.vuln_type}")
        print(f"    src  {f.source.code.strip()[:60]!r} @ {f.source.file_path}:{f.source.line}")
        print(f"    sink {f.sink.code.strip()[:60]!r} @ {f.sink.file_path}:{f.sink.line}")
        for step in f.call_chain:
            print(f"      {step.kind:14s} [{step.edge_type:9s}] {step.function} "
                  f"@{step.file_path}:{step.line}  {step.code.strip()[:50]!r}")

    print("\n=== 规范版(canonical) 前 5 条 ===")
    for c in result.canonical_findings[:5]:
        print(f"  [{c.vuln_type}] {c.vuln_name}")
        if c.endpoint:
            print(f"    endpoint: {c.endpoint}")
        print(f"    chain:    {c.call_chain}")
        print(f"    sink 函数（sink 行标 ▶）:\n{c.sink_function}")

    # 落盘完整报告 + 规范版 JSON 供下游消费
    result.to_json("report.json")
    result.to_canonical_json("report.canonical.json")
    print("\n完整 JSON 已写入 report.json / report.canonical.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
