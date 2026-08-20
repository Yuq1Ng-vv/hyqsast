"""benchmarks/owasp/score.py — 对照 OWASP Benchmark expectedresults 给 hyqsast 报告评分。

用法::

    uv run python benchmarks/owasp/score.py /tmp/owasp_report.json

或让 run.py 自动传入 expectedresults 路径（默认从克隆的 BenchmarkJava 读）。

口径（与 OWASP 官方评分一致：每 (测试, 类别) 一对）：
- 严格(strict)：finding 的 ``vuln_type`` == 期望类别映射的 vtype（含
  ``related_categories``），才算该测试命中。
- 宽松(loose)：vuln_type 为 ``injection_general``（规则兜底类别）也视为命中
  —— 说明流接住了、只是类别不精确，记入 loose 列。
- cross：在某个测试上报告了「与期望类别不一致」的 finding（其它类别，
  仅信息性，不计入该测试的 TP/FP）。

类别映射里标 ``None`` 的是 hyqsast 规则表没有的类别（weakrand / hash /
trustbound / securecookie）—— 这些恒为严格口径 FN，即覆盖缺口。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import defaultdict
from pathlib import Path

# 期望类别 -> hyqsast vuln_type（None = 规则表没有对应类别 → 恒 FN，覆盖缺口）
CAT_MAP = {
    "pathtraver": "path_traversal",
    "sqli": "sql_injection",
    "cmdi": "command_injection",
    "xss": "xss",
    "ldapi": "ldap_injection",
    "xpathi": "xpath_injection",
    "crypto": "crypto_weakness",
    "hash": None,  # 缺 insecure_hash 规则（覆盖缺口，见 README）
    "weakrand": None,  # 缺 weak_randomness 规则
    "trustbound": None,  # 缺 trust_boundary 规则
    "securecookie": None,  # 缺 secure_cookie 规则
}

DEFAULT_EXPECTED = "/root/benchmarks/owasp-benchmark/expectedresults-1.2.csv"


def _load_expected(path: str) -> list[tuple[str, str, bool, str]]:
    rows: list[tuple[str, str, bool, str]] = []
    with open(path) as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or len(row) < 4:
                continue
            test, cat, vuln, cwe = row[0], row[1].strip(), row[2].strip().lower(), row[3]
            rows.append((test, cat, vuln == "true", cwe))
    return rows


def _findings_by_test(report_path: str) -> tuple[dict[str, list[dict]], int]:
    with open(report_path) as fh:
        report = json.load(fh)
    findings = report.get("findings", [])
    by_test: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        src = f.get("source", {})
        test = os.path.splitext(os.path.basename(src.get("file_path", "")))[0]
        if test:
            by_test[test].append(f)
    return by_test, len(findings)


def _hit(f: dict, vtype: str | None) -> bool:
    """严格命中：finding 主类别或 related_categories 等于 vtype。"""
    if vtype is None:
        return False
    return f["vuln_type"] == vtype or vtype in f.get("related_categories", [])


def main() -> None:
    ap = argparse.ArgumentParser(description="给 hyqsast 报告对照 OWASP Benchmark 期望结果评分")
    ap.add_argument("report", help="hyqsast 报告 JSON 路径")
    ap.add_argument("--expected", default=DEFAULT_EXPECTED, help="expectedresults csv 路径")
    args = ap.parse_args()

    if not Path(args.expected).exists():
        ap.error(f"找不到 expectedresults：{args.expected}（先跑 run.py 克隆 BenchmarkJava）")

    expected = _load_expected(args.expected)
    by_test, n_findings = _findings_by_test(args.report)

    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"expected": 0, "TP": 0, "FN": 0, "FP": 0, "TN": 0, "loose": 0, "cross": 0}
    )

    for test, cat, is_vuln, _cwe in expected:
        vtype = CAT_MAP.get(cat)
        s = stats[cat]
        s["expected"] += 1
        flist = by_test.get(test, [])
        if vtype is None:
            # 规则表无此类别：严格必然 FN；报告了 injection_general 记 loose
            s["FN"] += 1
            if is_vuln and any(f["vuln_type"] == "injection_general" for f in flist):
                s["loose"] += 1
            continue
        s["cross"] += len([f for f in flist if f["vuln_type"] != vtype])
        strict_hits = [_hit(f, vtype) for f in flist]
        loose_hits = [_hit(f, vtype) or f["vuln_type"] == "injection_general" for f in flist]
        if is_vuln:
            if any(strict_hits):
                s["TP"] += 1
            else:
                s["FN"] += 1
                if any(loose_hits):
                    s["loose"] += 1
        else:
            if any(strict_hits):
                s["FP"] += 1
            else:
                s["TN"] += 1

    print(
        f"{'category':<13}{'expect':>6}{'TP':>5}{'FN':>5}{'loose':>5}{'FP':>5}{'TN':>5}{'recall%':>8}{'loose%':>8}{'cross':>6}"
    )
    tot: dict[str, int] = defaultdict(int)
    for cat in sorted(stats):
        s = stats[cat]
        exp = s["expected"]
        recall = s["TP"] / exp * 100 if exp else 0
        lrecall = (s["TP"] + s["loose"]) / exp * 100 if exp else 0
        for k in ("expected", "TP", "FN", "loose", "FP", "TN", "cross"):
            tot[k] += s[k]
        print(
            f"{cat:<13}{exp:>6}{s['TP']:>5}{s['FN']:>5}{s['loose']:>5}{s['FP']:>5}{s['TN']:>5}{recall:>8.1f}{lrecall:>8.1f}{s['cross']:>6}"
        )
    print("-" * 66)
    recall = tot["TP"] / tot["expected"] * 100 if tot["expected"] else 0
    lrecall = (tot["TP"] + tot["loose"]) / tot["expected"] * 100 if tot["expected"] else 0
    print(
        f"{'TOTAL':<13}{tot['expected']:>6}{tot['TP']:>5}{tot['FN']:>5}{tot['loose']:>5}{tot['FP']:>5}{tot['TN']:>5}{recall:>8.1f}{lrecall:>8.1f}{tot['cross']:>6}"
    )
    print(f"\nfindings 总数 = {n_findings}，覆盖测试文件 = {len(by_test)}")


if __name__ == "__main__":
    main()
