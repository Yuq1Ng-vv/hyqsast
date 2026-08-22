"""benchmarks/owasp/compare_findings.py — 两份 owasp 报告逐条 A/B（缺陷平衡铁律验证）。

用法::

    uv run python benchmarks/owasp/compare_findings.py \\
        results/2026-08-21-crypto-pattern/owasp-merged.json \\
        results/2026-08-22-p13-defuse/owasp-merged.json

对每条 finding 生成指纹 ``(vuln_type, basename(src_path), src_line,
basename(sink_path), sink_line)`` 后比较集合。basename 归一化使「分块扫描的
symlink 路径」与「全量扫描的原始路径」可比（score.py 本就按 source 文件
basename 分组）。输出集合对称差；为空即零差异、铁律通过。

内存：两份报告各 ~120MB，进程内逐份加载（加载后立即 del + gc），峰值约单份
报告的内存，1.6GiB 机器安全。
"""

from __future__ import annotations

import argparse
import gc
import json
import os


def _fingerprint(report_path: str) -> tuple[set[str], int]:
    with open(report_path) as fh:
        report = json.load(fh)
    findings = report.get("findings", [])
    fp: set[str] = set()
    for f in findings:
        src = f.get("source", {}) or {}
        sink = f.get("sink", {}) or {}
        fp.add(
            "|".join(
                [
                    str(f.get("vuln_type", "")),
                    os.path.basename(str(src.get("file_path", ""))),
                    str(src.get("line", "")),
                    os.path.basename(str(sink.get("file_path", ""))),
                    str(sink.get("line", "")),
                ]
            )
        )
    return fp, len(findings)


def main() -> None:
    ap = argparse.ArgumentParser(description="OWASP 报告逐条 A/B 指纹比较")
    ap.add_argument("baseline", help="基线报告（旧代码）owasp-merged.json")
    ap.add_argument("candidate", help="候选报告（新代码）owasp-merged.json")
    args = ap.parse_args()

    print(f"[A/B] 加载基线 {os.path.basename(args.baseline)} ...")
    base, base_n = _fingerprint(args.baseline)
    gc.collect()
    print(f"[A/B] 加载候选 {os.path.basename(args.candidate)} ...")
    cand, cand_n = _fingerprint(args.candidate)
    gc.collect()

    only_base = base - cand
    only_cand = cand - base

    print(f"\n基线 findings = {base_n}  候选 findings = {cand_n}")
    print(f"指纹集合：基线 = {len(base)}  候选 = {len(cand)}")
    print(f"对称差：仅基线有 = {len(only_base)}  仅候选有 = {len(only_cand)}")

    if not only_base and not only_cand:
        print("\n✅ 零差异——逐条 A/B 完全一致，缺陷平衡铁律通过。")
        return 0
    print("\n❌ 存在差异：")
    for x in sorted(only_base)[:20]:
        print(f"  [基线有/候选无] {x}")
    for x in sorted(only_cand)[:20]:
        print(f"  [候选有/基线无] {x}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
