"""benchmarks/owasp/extract_hits.py — 从单份 merged 报告输出「每测试文件→检出类别集合」。

内存铁律：74MB 级 merged JSON 一次只 load 一份。本脚本只吃一个路径参数，
输出到 stdout（重定向到 /tmp/*.txt），再 comm/diff 对比两轮回归的命中差异。
"""
from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict

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
# 宽松口径同样视为命中（与 score.py loose 一致）
LOOSE = {"injection_general"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--hits-only", action="store_true", help="只输出有检出的测试")
    args = ap.parse_args()

    with open(args.report) as fh:
        report = json.load(fh)
    findings = report.get("findings", [])

    # test -> set of strict 命中类别
    strict_hits: dict[str, set[str]] = defaultdict(set)
    # test -> set of 额外 loose 命中（injection_general 兜底）
    loose_hits: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        src = f.get("source", {})
        test = os.path.splitext(os.path.basename(src.get("file_path", "")))[0]
        if not test:
            continue
        vt = f.get("vuln_type", "")
        cats = set(vt.split(","))
        related = set(f.get("related_categories", []) or [])
        all_cats = cats | related
        if any(c in CAT_MAP.values() for c in all_cats):
            strict_hits[test].update(all_cats)
        if any(c in LOOSE for c in all_cats):
            loose_hits[test].add("loose_general")

    for test in sorted(set(strict_hits) | set(loose_hits)):
        cats = sorted(strict_hits.get(test, ())) + sorted(loose_hits.get(test, ()))
        print(f"{test}:{','.join(cats)}")


if __name__ == "__main__":
    main()
