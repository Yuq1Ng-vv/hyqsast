"""benchmarks/ant/score.py — 对照 xAST Benchmark 给 hyqsast 报告评分。

用法::

    uv run python benchmarks/ant/score.py /tmp/sast-java-full.json [--lang-dir sast-java]

ground truth 取 ``--lang-dir`` 下全部 ``*_T.java``（真漏洞）与 ``*_F.java``
（安全样本）的头部注释 ``// real case = true/false``（与文件名后缀 100% 一致，
见 doc/sast-java-engine-evaluation.md 评价体系）；评估维度取头部注释
``// evaluation item``（xAST「体检报告」口径，完整度/准确度两级分类）。

口径：
- 命中(hit)：某 finding 的 ``source.file_path`` 或 ``sink.file_path`` 落在某
  用例文件内，算该用例被检测到（与 OWASP score.py 同思路：源或汇命中即算）。
- TP = 真漏洞用例被命中；FN = 真漏洞用例未被命中；FP = 安全样本被命中；
  TN = 安全样本未被命中。
- TPR% = TP/(TP+FN)（脆弱用例召回率）、FPR% = FP/(FP+TN)（安全样本误报率）。

**注意**：扫描时 ``--max-findings`` 必须给高（run.py 默认 50000）。默认每类别
50 会把稠密类别（如 sast-java command_injection）截断成 83% 假漏报
（2026-08-27 实测：默认 50 → TPR 13.0%；无截断 → TPR 72.8%）。
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANT_DIR = REPO_ROOT / "benchmarks" / "ant-application-security-testing-benchmark"

_REAL_RE = re.compile(r"// real case\s*=\s*(true|false)")
_ITEM_RE = re.compile(r"// evaluation item\s*=\s*(.+)")


def load_ground_truth(lang_dir: str) -> dict[str, bool]:
    """返回 {用例文件绝对路径: 是否为真漏洞}（来自 real case 头注释）。"""
    base = ANT_DIR / lang_dir
    if not base.is_dir():
        raise SystemExit(f"基准目录不存在: {base}（--lang-dir 可选 sast-java 等）")
    out: dict[str, bool] = {}
    for p in list(base.rglob("*_T.java")) + list(base.rglob("*_F.java")):
        txt = p.read_text(errors="ignore")
        m = _REAL_RE.search(txt)
        if m is None:
            raise SystemExit(f"用例缺 real case 头: {p}")
        out[str(p)] = m.group(1) == "true"
    return out


def load_items(lang_dir: str) -> dict[str, str]:
    """返回 {用例文件绝对路径: evaluation item}，供维度细分。"""
    base = ANT_DIR / lang_dir
    out: dict[str, str] = {}
    for p in list(base.rglob("*_T.java")) + list(base.rglob("*_F.java")):
        txt = p.read_text(errors="ignore")
        m = _ITEM_RE.search(txt)
        if m:
            out[str(p)] = m.group(1).strip()
    return out


def score(report_path: str, lang_dir: str) -> dict:
    """对 hyqsast 报告评分，返回指标 + 逐维度表 + FN/FP 清单。"""
    rep = json.load(open(report_path))
    findings = rep.get("findings", [])
    gt = load_ground_truth(lang_dir)
    items = load_items(lang_dir)

    hit_count: Counter[str] = Counter()
    for f in findings:
        for key in ("source", "sink"):
            fp = f[key].get("file_path", "")
            if fp in gt:
                hit_count[fp] += 1
                break

    # 总体四格
    n_t = sum(gt.values())
    n_f = len(gt) - n_t
    tp = fn = fp = tn = 0
    tp_files: list[str] = []
    fn_files: list[str] = []
    fp_files: list[str] = []
    for path, is_t in gt.items():
        n = hit_count.get(path, 0)
        if is_t:
            if n:
                tp += 1
                tp_files.append(path)
            else:
                fn += 1
                fn_files.append(path)
        else:
            if n:
                fp += 1
                fp_files.append(path)
            else:
                tn += 1

    # 逐维度表（evaluation item 分组）
    per_dim: dict[str, dict[str, int]] = defaultdict(lambda: {"TP": 0, "FN": 0, "FP": 0, "TN": 0})
    for path, is_t in gt.items():
        dim = items.get(path, "（无 evaluation item）")
        cell = per_dim[dim]
        n = hit_count.get(path, 0)
        if is_t:
            if n:
                cell["TP"] += 1
            else:
                cell["FN"] += 1
        else:
            if n:
                cell["FP"] += 1
            else:
                cell["TN"] += 1

    return {
        "report": report_path,
        "lang_dir": lang_dir,
        "cases": {"total": len(gt), "true": n_t, "false": n_f},
        "findings_total": len(findings),
        "confusion": {"TP": tp, "FN": fn, "FP": fp, "TN": tn},
        "tpr": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "per_dim": dict(per_dim),
        "fn_files": sorted(fn_files),
        "fp_files": sorted(fp_files),
    }


def render(s: dict, verbose: bool = False) -> str:
    c = s["confusion"]
    lines = [
        f"=== xAST Benchmark 评分: {s['lang_dir']} ===",
        f"报告: {s['report']}",
        f"用例 {s['cases']['total']}（真漏洞 {s['cases']['true']} / 安全 {s['cases']['false']}）"
        f"  findings 共 {s['findings_total']}",
        f"TP={c['TP']}  FN={c['FN']}  FP={c['FP']}  TN={c['TN']}",
        f"召回率 TPR = {s['tpr']*100:.1f}%  ({c['TP']}/{c['TP']+c['FN']})"
        f"    误报率 FPR = {s['fpr']*100:.1f}%  ({c['FP']}/{c['FP']+c['TN']})",
        "",
        "=== 逐维度（evaluation item）===",
    ]
    rows = sorted(s["per_dim"].items(), key=lambda kv: -(kv[1]["FN"] + kv[1]["FP"]))
    for dim, v in rows:
        subtotal = v["TP"] + v["FN"] + v["FP"] + v["TN"]
        tpr = v["TP"] / (v["TP"] + v["FN"]) if v["TP"] + v["FN"] else 0.0
        fpr = v["FP"] / (v["FP"] + v["TN"]) if v["FP"] + v["TN"] else 0.0
        flag = ""
        if v["FN"]:
            flag += " ↑FN"
        if v["FP"]:
            flag += " ↑FP"
        lines.append(
            f"  {dim:52s} T={v['TP']:2d} FN={v['FN']:2d} FP={v['FP']:2d} TN={v['TN']:2d}"
            f"  TPR={tpr*100:5.1f}% FPR={fpr*100:5.1f}%  ({subtotal} 样例){flag}"
        )
    if verbose:
        lines.append("")
        lines.append(f"=== FN 清单（真漏洞漏报 {len(s['fn_files'])}）===")
        for p in s["fn_files"]:
            lines.append("  " + p.replace(str(ANT_DIR) + "/", ""))
        lines.append("")
        lines.append(f"=== FP 清单（安全样本误报 {len(s['fp_files'])}）===")
        for p in s["fp_files"]:
            lines.append("  " + p.replace(str(ANT_DIR) + "/", ""))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report", help="hyqsast 扫描报告 JSON 路径")
    ap.add_argument("--lang-dir", default="sast-java", help="基准子目录（默认 sast-java）")
    ap.add_argument("--verbose", "-v", action="store_true", help="追加 FN/FP 文件清单")
    args = ap.parse_args()
    s = score(args.report, args.lang_dir)
    print(render(s, verbose=args.verbose))


if __name__ == "__main__":
    main()
