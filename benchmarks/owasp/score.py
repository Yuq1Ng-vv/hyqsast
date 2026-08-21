"""benchmarks/owasp/score.py — 对照 OWASP Benchmark expectedresults 给 hyqsast 报告评分。

用法::

    uv run python benchmarks/owasp/score.py /tmp/owasp_report.json

或让 run.py 自动传入 expectedresults 路径（默认从克隆的 BenchmarkJava 读）。

口径（与 OWASP 官方一致：每 (测试, 类别) 一对）：
- 严格(strict)：finding 的 ``vuln_type`` == 期望类别映射的 vtype（含
  ``related_categories``），才算该测试命中。
- 宽松(loose)：vuln_type 为 ``injection_general``（规则兜底类别）也视为命中
  —— 说明流接住了、只是类别不精确，记入 loose 列。
- cross：在某个测试上报告了「与期望类别不一致」的 finding（其它类别，
  仅信息性，不计入该测试的 TP/FP）。
- **TPR% = TP/(TP+FN)**（仅脆弱用例的召回率，官方真阳率）、**FPR% =
  FP/(FP+TN)**（安全用例被误报的比例）。vuln 列 = 该类脆弱用例总数。

类别映射见 ``CAT_MAP``：hash/weakrand 是「API 使用本身即漏洞」的 pattern 型，
映射到精确专用类别 ``insecure_hash``/``weak_randomness``；trustbound/securecookie
映射到 ``trust_boundary``/``secure_cookie``。``None`` 兜底保留给将来仍未映射的
类别（规则表缺失 → 严格口径恒 FN）。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import defaultdict
from pathlib import Path

# 期望类别 -> hyqsast vuln_type。
# hash / weakrand 是「危险 API 使用本身」而非污点流（无 source 流入），
# 2026-08-21 起由精确 pattern 专用类别接管：insecure_hash（硬编码弱算法）/
# weak_randomness（java.util.Random、Math.random），不再恒 FN；crypto 仍走
# crypto_weakness（污点流，弱加密 API 由 source 流入时产出）。
# trustbound / securecookie 映射到 trust_boundary / secure_cookie。
# ``None`` 兜底保留给将来仍未映射的类别（规则表缺失 → 严格口径恒 FN）。
CAT_MAP = {
    "pathtraver": "path_traversal",
    "sqli": "sql_injection",
    "cmdi": "command_injection",
    "xss": "xss",
    "ldapi": "ldap_injection",
    "xpathi": "xpath_injection",
    "crypto": "crypto_weakness",
    "hash": "insecure_hash",
    "weakrand": "weak_randomness",
    "trustbound": "trust_boundary",
    "securecookie": "secure_cookie",
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

    # 官方 OWASP 口径：TPR = TP/(TP+FN)（仅脆弱用例），FPR = FP/(FP+TN)
    # （仅安全用例）。旧版 recall% 曾用 TP/全部用例，会被大量 safe 用例稀释，
    # 与官方口径不符，改为 TPR%/FPR% 双列。
    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "expected": 0, "vuln": 0, "TP": 0, "FN": 0, "FP": 0, "TN": 0,
            "loose": 0, "cross": 0,
        }
    )

    for test, cat, is_vuln, _cwe in expected:
        vtype = CAT_MAP.get(cat)
        s = stats[cat]
        s["expected"] += 1
        s["vuln"] += 1 if is_vuln else 0
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
        f"{'category':<13}{'expect':>6}{'vuln':>5}{'TP':>5}{'FN':>5}{'FP':>5}{'TN':>5}{'TPR%':>7}{'FPR%':>7}{'loose':>5}{'cross':>6}"
    )
    tot: dict[str, int] = defaultdict(int)
    for cat in sorted(stats):
        s = stats[cat]
        exp_vuln = s["TP"] + s["FN"]
        exp_safe = s["FP"] + s["TN"]
        tpr = s["TP"] / exp_vuln * 100 if exp_vuln else 0
        fpr = s["FP"] / exp_safe * 100 if exp_safe else 0
        for k in ("expected", "vuln", "TP", "FN", "FP", "TN", "loose", "cross"):
            tot[k] += s[k]
        print(
            f"{cat:<13}{s['expected']:>6}{s['vuln']:>5}{s['TP']:>5}{s['FN']:>5}{s['FP']:>5}{s['TN']:>5}{tpr:>7.1f}{fpr:>7.1f}{s['loose']:>5}{s['cross']:>6}"
        )
    print("-" * 70)
    tpr = tot["TP"] / (tot["TP"] + tot["FN"]) * 100 if (tot["TP"] + tot["FN"]) else 0
    fpr = tot["FP"] / (tot["FP"] + tot["TN"]) * 100 if (tot["FP"] + tot["TN"]) else 0
    print(
        f"{'TOTAL':<13}{tot['expected']:>6}{tot['vuln']:>5}{tot['TP']:>5}{tot['FN']:>5}{tot['FP']:>5}{tot['TN']:>5}{tpr:>7.1f}{fpr:>7.1f}{tot['loose']:>5}{tot['cross']:>6}"
    )
    print(f"\nfindings 总数 = {n_findings}，覆盖测试文件 = {len(by_test)}")


if __name__ == "__main__":
    main()
