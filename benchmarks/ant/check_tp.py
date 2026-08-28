"""benchmarks/ant/check_tp.py — 核查 sast-java 报告里 TP 是否有假 TP。

评分口径「source 或 sink file_path 落用例文件即算命中」下，TP 可能被
**跨用例污染**或**假路径**撑起来。本脚本对每个 TP 用例做真伪核查：

1. **跨用例污染**：source 在 X 用例、sink 在 Y 用例（两个不同 _T/_F 文件）——
   BUG 64 后应为 0。
2. **链条跳过用例文件中间步骤**：finding 链条从 source 直接跳到 helper/别的
   文件、中间没有用例文件自身的调用/赋值步骤 → 假路径。
3. **helper 调用实参不含污点变量**：sink 在 helper（CmdUtil/HttpUtil/JDBCUtil/
   SSRFShowManageImpl 等），但用例文件里调用该 helper 的那行代码实参不含 source
   变量（需人工区分「变量改名/派生」与「真常量」）。
4. **sink 实参变量在链条中从未出现**：``exec(X)`` 的 X 在链条任何步骤代码里都
   找不到 → 假连接。
5. **多 vuln_type 命中**：一个用例通常只对应一个真实漏洞类别，多类别命中时
   逐一人工复核（如 infix 表达式污染会误标 ``HttpUtil.doGet("常量")`` 为 ssrf）。

用法::

    uv run python benchmarks/ant/check_tp.py [report.json]

默认读 ``results/<最新>/report.json``。只读不改，不触发扫描（内存友好）。

2026-08-28 结论（results/2026-08-28-bug64）：
- 173 个 TP 用例全部为真（每例至少 1 条 finding 的链条真实连通用例的实际漏洞），
  无假 TP。跨用例污染 0、跳步链 0、sink 实参缺变量 0。
- finding 层仍有 28 条假/弱 FP 噪声（不影响 TP 计数）：4 条 ssrf 命中 cmdi 用例的
  ``HttpUtil.doGet("www.test.com")`` 常量实参（infix 表达式污染外溢）；24 条
  info_disclosure 命中 SSRF facade 用例的 ``println/printStackTrace(HTTP响应体)``。

2026-08-28 更新（results/2026-08-28-bug65，BUG 65）：
- 常量实参 ssrf 假阳性已修（``_add_cross_function_edges`` 只桥「名字出现在本调用
  实参里」的 var_ref，commit 见 git log）。sast-java 上 8 条该型 finding 全部移除
  （4 个 infix 用例 × 2 个 HttpUtil sink 行），TP/FN/FP/TN 逐项不变，vfa/flask-xss/
  vampi/demo-java 零丢失。
- 剩余 finding 层噪声：24 条 info_disclosure（SSRF facade 用例打印 HTTP 响应体，
  ``println/printStackTrace`` 宽 sink 误标，未修）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ANT = Path(__file__).resolve().parents[1] / "ant-application-security-testing-benchmark"
_REAL_RE = re.compile(r"// real case\s*=\s*(true|false)")


def load_ground_truth(lang_dir: str = "sast-java") -> tuple[set[str], set[str], dict[str, bool]]:
    """返回 (真用例集, 安全用例集, {绝对路径: bool})。"""
    gt: dict[str, bool] = {}
    base = ANT / lang_dir
    for p in list(base.rglob("*_T.java")) + list(base.rglob("*_F.java")):
        m = _REAL_RE.search(p.read_text(errors="ignore"))
        if m:
            gt[str(p)] = m.group(1) == "true"
    true_cases = {p for p, t in gt.items() if t}
    false_cases = {p for p, t in gt.items() if not t}
    return true_cases, false_cases, gt


def case_of(path: str, all_cases: set[str]) -> str | None:
    for c in all_cases:
        if path.endswith(c):
            return c
    return None


def check(report_path: Path) -> None:
    true_cases, false_cases, gt = load_ground_truth()
    all_cases = set(gt)
    r = json.loads(report_path.read_text())
    findings = r["findings"]

    # ── 1. 跨用例污染 ──
    cross = []
    for f in findings:
        sc = case_of(f["source"]["file_path"], all_cases)
        kc = case_of(f["sink"]["file_path"], all_cases)
        if sc and kc and sc != kc:
            cross.append((sc, kc, f["vuln_type"]))
    print(f"[1] 跨用例污染（X 用例 source -> Y 用例 sink）: {len(cross)}")

    # ── 2/4. 链完整性 + sink 实参溯源 ──
    tp_hits: dict[str, list] = defaultdict(list)
    no_midstep, no_sink_var = [], []
    for f in findings:
        sc = case_of(f["source"]["file_path"], all_cases)
        kc = case_of(f["sink"]["file_path"], all_cases)
        c = sc if sc in true_cases else (kc if kc in true_cases else None)
        if not c:
            continue
        tp_hits[c].append(f)
        chain = f.get("call_chain", [])
        if not chain:
            continue
        cfile = f["source"]["file_path"] if sc == c else f["sink"]["file_path"]
        src_ln = f["source"]["line"]
        mid = [s for s in chain if s["file_path"] == cfile and s["line"] != src_ln]
        if not mid and len(chain) > 1:
            no_midstep.append((Path(c).name, f["vuln_type"]))
        # sink 实参变量溯源
        m = re.search(r"exec\(([^)]*)\)", f["sink"].get("code", ""))
        if m:
            arg_vars = set(re.findall(r"[A-Za-z_$][\w$]*", m.group(1))) - {"Runtime"}
            all_code = " ".join(s.get("code", "") for s in chain)
            missing = [v for v in arg_vars if v not in all_code]
            if missing:
                no_sink_var.append((Path(c).name, f["vuln_type"], missing))
    print(f"[2] 链条无用例文件中间步骤的 finding: {len(no_midstep)}")
    for n in no_midstep:
        print(f"      {n[0]} {n[1]}")
    print(f"[3] sink 实参变量链条中未出现的 finding: {len(no_sink_var)}")
    for n in no_sink_var:
        print(f"      {n[0]} {n[1]} 缺失={n[2]}")

    # ── 5. 多 vuln_type 用例（需人工复核）──
    multi = []
    for c, fs in sorted(tp_hits.items()):
        vts = {f["vuln_type"] for f in fs}
        if len(vts) > 1:
            multi.append((Path(c).name, sorted(vts)))
    print(f"[4] 多 vuln_type 命中的 TP 用例（人工复核）: {len(multi)}")
    for cname, vts in multi:
        print(f"      {cname}: {', '.join(vts)}")

    print(f"\nTP 用例总数 = {len(tp_hits)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="核查 ant sast-java 报告 TP 真伪")
    ap.add_argument(
        "report", nargs="?", default=None, help="report.json 路径（默认取 results/ 最新归档）"
    )
    args = ap.parse_args()
    if args.report:
        check(Path(args.report))
    else:
        results = sorted((Path(__file__).parent / "results").glob("*"))
        check(results[-1] / "report.json")


if __name__ == "__main__":
    sys.exit(main())
