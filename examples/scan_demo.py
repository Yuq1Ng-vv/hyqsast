"""scan_demo.py — 最小可用示例。

用法::

    uv run python examples/scan_demo.py /path/to/java/project
"""

from __future__ import annotations

import sys

from hyqsast import scan


def main() -> int:
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    language = sys.argv[2] if len(sys.argv) > 2 else None

    result = scan(directory, language=language)

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

    # 落盘一份 JSON 供下游消费
    result.to_json("report.json")
    print("\n完整 JSON 已写入 report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
