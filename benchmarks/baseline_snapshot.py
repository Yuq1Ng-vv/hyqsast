"""benchmarks/baseline_snapshot.py — 五基准 A/B 快照/比对工具。

用法::

    # 快照 BEFORE（改动前）
    uv run python benchmarks/baseline_snapshot.py snapshot /tmp/baseline_before

    # 改动后再快照 AFTER，并与 BEFORE 比对（A/B 零丢失检查）
    uv run python benchmarks/baseline_snapshot.py compare /tmp/baseline_before /tmp/baseline_after

快照内容：每个基准项目的 canonical finding 键集合
``(vuln_type, source.file:line, sink.file:line)``，存为 ``{proj}.keys.txt``
（BEFORE 的每一条键必须在 AFTER 里出现，才叫「原有命中一条不少」）。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path("/root/hyqhuman")

# (项目名, 路径, 语言)
BASELINES = [
    ("vfa", "examples/Real-Vuln-Benchmark/repos/realvuln-vulnerable-flask-app", "python"),
    ("flask-xss", "examples/Real-Vuln-Benchmark/repos/realvuln-flask-xss", "python"),
    ("vampi", "examples/Real-Vuln-Benchmark/repos/realvuln-vampi", "python"),
    ("demo-java", "examples/demo-java", "java"),
    ("probe-python", "/tmp/bridge_sample", "python"),
    ("probe-java", "/tmp/rules_probe", "java"),
]


def _scan(proj: str, path: str, language: str, out_dir: Path) -> list[str]:
    report = out_dir / f"{proj}.json"
    cmd = [
        "uv",
        "run",
        "hyqsast",
        str(ROOT / path if not path.startswith("/") else path),
        "--language",
        language,
        "-o",
        str(report),
        "--no-canonical",
        "--no-elements",
    ]
    if language == "python":
        cmd += ["--no-cache"]  # 探针等小项目避免 stale 缓存
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(f"[{proj}] 扫描失败 rc={r.returncode}: {r.stderr[-500:]}")
        return []
    data = json.loads(report.read_text())
    keys = sorted(
        {
            f"{f['vuln_type']}|{f['source']['file_path']}:{f['source']['line']}|{f['sink']['file_path']}:{f['sink']['line']}"
            for f in data.get("findings", [])
        }
    )
    return keys


def snapshot(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for proj, path, lang in BASELINES:
        keys = _scan(proj, path, lang, out_dir)
        (out_dir / f"{proj}.keys.txt").write_text("\n".join(keys) + ("\n" if keys else ""))
        print(f"[{proj}] {len(keys)} findings -> {out_dir}/{proj}.keys.txt")


def compare(before: Path, after: Path) -> bool:
    ok = True
    for proj, _, _ in BASELINES:
        b = set((before / f"{proj}.keys.txt").read_text().splitlines())
        a = set((after / f"{proj}.keys.txt").read_text().splitlines())
        lost = b - a
        gained = a - b
        status = "OK" if not lost else "LOST"
        if lost:
            ok = False
        print(
            f"[{proj}] BEFORE={len(b)} AFTER={len(a)} 丢失={len(lost)} 新增={len(gained)}  {status}"
        )
        for k in sorted(lost):
            print(f"    -LOST {k}")
        for k in sorted(gained):
            print(f"    +NEW  {k}")
    return ok


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "snapshot":
        snapshot(Path(sys.argv[2]))
    elif mode == "compare":
        sys.exit(0 if compare(Path(sys.argv[2]), Path(sys.argv[3])) else 1)
    else:
        raise SystemExit(f"unknown mode {mode}")
