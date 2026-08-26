"""benchmarks/dedup_findings.py — 消费侧复核降维：按 source 函数 × sink 函数 × vuln_type 归并。

输入 full 版报告（``hyqsast <项目> -o report.json``，含 ``findings[].source/sink.function``），
输出三类产物，全在消费侧、零引擎改动：

1. **归并复核清单**（``--out-csv``）：每个归并组一行，附代表路径 1 条 + 计数 +
   同组覆盖的 source/sink 行集合 + 严重级，按严重级倒序。
2. **归并明细**（``--out-json``）：每组含全部成员（行号/代码/调用链），可下钻。
3. **分布统计**（stdout / ``--out-stats``）：按 vuln_type / 源函数 / 文件聚合。

归并键 = ``(source.file, source.function, sink.file, sink.function, vuln_type)``：
- **同函数内多条**（同源同 sink 不同行，最常见重复）→ 1 组；
- 同文件同函数名不同来源分支 → 合并（带计数 + 行集合）；
- 不同文件即使同名函数也分开（加 file 维度防跨文件错配）。

``--diagnose`` 输出归并键可靠性报告（function 空值率、源函数分布、组大小直方图），
用于确认归并键在真实项目上的适用性。

用法::

    uv run python benchmarks/dedup_findings.py report.json --out-csv dedup.csv
    uv run python benchmarks/dedup_findings.py report.json --out-csv d.csv --out-json d.json --out-stats stats.txt
    uv run python benchmarks/dedup_findings.py report.json --diagnose
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def _sev_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 4)


def load_findings(report_path: Path) -> list[dict]:
    data = json.loads(report_path.read_text())
    return data.get("findings", [])


def merge_key(f: dict) -> tuple:
    s, k = f["source"], f["sink"]
    return (
        s.get("file_path", ""),
        s.get("function", ""),
        k.get("file_path", ""),
        k.get("function", ""),
        f.get("vuln_type", ""),
    )


def _chain_len(f: dict) -> int:
    return len(f.get("call_chain", []))


def _pick_representative(members: list[dict]) -> dict:
    """代表路径：调用链最长者优先（信息最全），平手取 source 行最小者。"""
    return max(members, key=lambda f: (_chain_len(f), -f["source"].get("line", 0)))


def group_by(items: list[dict]) -> list[dict]:
    """按归并键分组，返回排序后的组列表（每组附代表路径与成员）。"""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in items:
        groups[merge_key(f)].append(f)
    result = []
    for k, members in groups.items():
        sfile, sfunc, kfile, kfunc, vtype = k
        rep = _pick_representative(members)
        sev = rep.get("severity", "")
        result.append(
            {
                "key": k,
                "vuln_type": vtype,
                "severity": sev,
                "count": len(members),
                "source_file": sfile,
                "source_function": sfunc,
                "sink_file": kfile,
                "sink_function": kfunc,
                "source_lines": sorted({f["source"].get("line", 0) for f in members}),
                "sink_lines": sorted({f["sink"].get("line", 0) for f in members}),
                "representative": rep,
                "members": members,
            }
        )
    result.sort(key=lambda g: (_sev_rank(g["severity"]), -g["count"]))
    return result


def _display_lines(lines: list[int]) -> str:
    return ",".join(str(x) for x in lines) if lines else "-"


def write_csv(groups: list[dict], out: Path) -> None:
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "severity",
                "vuln_type",
                "count",
                "source_file",
                "source_function",
                "source_lines",
                "sink_file",
                "sink_function",
                "sink_lines",
                "representative_chain",
            ]
        )
        for g in groups:
            rep = g["representative"]
            chain = " -> ".join(
                f"{s.get('function','')}@{s.get('file_path','').split('/')[-1]}:{s.get('line','')}"
                for s in rep.get("call_chain", [])
            ) or f"{rep['source'].get('function','')} -> {rep['sink'].get('function','')}"
            w.writerow(
                [
                    g["severity"],
                    g["vuln_type"],
                    g["count"],
                    g["source_file"],
                    g["source_function"],
                    _display_lines(g["source_lines"]),
                    g["sink_file"],
                    g["sink_function"],
                    _display_lines(g["sink_lines"]),
                    chain,
                ]
            )


def write_json(groups: list[dict], out: Path) -> None:
    payload = []
    for g in groups:
        payload.append(
            {
                "vuln_type": g["vuln_type"],
                "severity": g["severity"],
                "count": g["count"],
                "source": {
                    "file": g["source_file"],
                    "function": g["source_function"],
                    "lines": g["source_lines"],
                },
                "sink": {
                    "file": g["sink_file"],
                    "function": g["sink_function"],
                    "lines": g["sink_lines"],
                },
                "members": [
                    {
                        "source": f["source"],
                        "sink": f["sink"],
                        "call_chain": f.get("call_chain", []),
                    }
                    for f in g["members"]
                ],
            }
        )
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_stats(groups: list[dict], out: Path | None) -> str:
    total = sum(g["count"] for g in groups)
    lines = []
    lines.append(f"findings: {total}  ->  归并组: {len(groups)}  (压缩比 {total/max(1,len(groups)):.1f}x)")
    lines.append("")
    lines.append("=== 按 vuln_type ===")
    by_vt = Counter((g["vuln_type"], g["severity"]) for g in groups)
    for (vt, sev), n in sorted(by_vt.items(), key=lambda x: (_sev_rank(x[0][1]), -x[1])):
        lines.append(f"  {vt:24s} {sev:9s} {n} 组")
    lines.append("")
    lines.append("=== 按源函数 ===")
    by_sf = Counter(g["source_function"] for g in groups)
    for fn, n in sorted(by_sf.items(), key=lambda x: -x[1]):
        lines.append(f"  {n:4d}  {fn}")
    lines.append("")
    lines.append("=== 按文件 ===")
    by_file = Counter(g["source_file"] for g in groups)
    for fp, n in sorted(by_file.items(), key=lambda x: -x[1]):
        lines.append(f"  {n:4d}  {fp}")
    text = "\n".join(lines)
    if out:
        out.write_text(text + "\n", encoding="utf-8")
    return text


def write_diagnose(items: list[dict], groups: list[dict]) -> str:
    """归并键可靠性报告。"""
    total = len(items)
    sf_empty = sum(1 for f in items if not f["source"].get("function"))
    sk_empty = sum(1 for f in items if not f["sink"].get("function"))
    g_empty = sum(1 for g in groups if not g["source_function"] or not g["sink_function"])
    size_hist = Counter(g["count"] for g in groups)
    multi = sum(1 for g in groups if g["count"] > 1)

    lines = []
    lines.append(f"=== 归并键可靠性诊断 ===")
    lines.append(f"findings={total}  groups={len(groups)}")
    lines.append(f"source.function 空: {sf_empty} ({sf_empty/total*100:.1f}%)")
    lines.append(f"sink.function   空: {sk_empty} ({sk_empty/total*100:.1f}%)")
    lines.append(f"含空函数键的组:   {g_empty}")
    lines.append(f"多成员组: {multi}/{len(groups)} ({multi/max(1,len(groups))*100:.1f}%)")
    lines.append("")
    lines.append("组大小分布（count: 组数）:")
    for size in sorted(size_hist, reverse=True)[:10]:
        lines.append(f"  {size:4d} 成员组: {size_hist[size]}")
    lines.append("")
    lines.append("源函数 top 20:")
    by_sf = Counter(g["source_function"] for g in groups)
    for fn, n in by_sf.most_common(20):
        lines.append(f"  {n:4d}  {fn!r}")
    text = "\n".join(lines)
    print(text)
    return text


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", help="full 版报告路径（hyqsast -o 产出）")
    ap.add_argument("--out-csv", help="归并复核清单 CSV")
    ap.add_argument("--out-json", help="归并明细 JSON（含全部成员/调用链）")
    ap.add_argument("--out-stats", help="分布统计文本")
    ap.add_argument("--diagnose", action="store_true", help="输出归并键可靠性诊断")
    args = ap.parse_args()

    items = load_findings(Path(args.report))
    if not items:
        print("findings 为空", file=sys.stderr)
        return
    groups = group_by(items)

    if args.diagnose:
        write_diagnose(items, groups)
    if args.out_csv:
        write_csv(groups, Path(args.out_csv))
        print(f"归并复核清单 -> {args.out_csv}  ({len(groups)} 组 / {len(items)} 条)")
    if args.out_json:
        write_json(groups, Path(args.out_json))
        print(f"归并明细 -> {args.out_json}")
    if not args.diagnose:
        print(write_stats(groups, Path(args.out_stats) if args.out_stats else None))


if __name__ == "__main__":
    main()
