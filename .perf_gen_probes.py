"""按 docs/性能分析-大项目卡死.md 记录的形状重建性能探针。

- perfprobe2: 单文件 500 方法（原 4007 行），每方法 1 source 参数 + 若干赋值
- perfprobe4: 200 文件 × 8 方法（原 29200 行），每方法 4 source 参数、1/8 方法带 sink

形状决定 O(F×G) 是否复现；精确行数不影响建图二次方形态。
输出到 perf_probes/（仓库根，gitignore，不随 /tmp 清理）。
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent / "perf_probes"


def gen_probe2() -> None:
    d = ROOT / "perfprobe2" / "com" / "example"
    d.mkdir(parents=True, exist_ok=True)
    lines = ["package com.example;", "import javax.servlet.http.*;", "public class PerfProbe {"]
    for i in range(500):
        lines.append(f"    public String m{i:04d}(HttpServletRequest req) {{")
        lines.append(f'        String p = req.getParameter("p{i:04d}");')
        lines.append(f'        String s = p + "-x";')
        lines.append(f'        String t = s + "-y";')
        lines.append(f"        String u = t.toLowerCase();")
        lines.append(f"        return u;")
        lines.append("    }")
    lines.append("}")
    (d / "PerfProbe.java").write_text("\n".join(lines))
    print(f"perfprobe2: {len(lines)} 行 / 500 方法 -> {d / 'PerfProbe.java'}")


def gen_probe4() -> None:
    d = ROOT / "perfprobe4" / "com" / "app"
    d.mkdir(parents=True, exist_ok=True)
    for f in range(200):
        lines = ["package com.app;", "import javax.servlet.http.*;", f"public class C{f:03d} {{"]
        for m in range(8):
            i = f * 8 + m
            lines.append(f"    public void m{i:04d}(HttpServletRequest req) {{")
            # 4 source 参数（模拟 source 密集）
            for k in range(4):
                lines.append(f'        String a{k} = req.getParameter("p{i:04d}_{k}");')
            lines.append(f"        String c = a0 + a1;")
            lines.append(f"        String b = a2 + a3;")
            # 1/8 方法带一个 sink（保持 source→sink 链存在，与实验 2 一致）
            if i % 8 == 0:
                lines.append(f"        out.println(b);")
            lines.append("    }")
        lines.append("}")
        (d / f"C{f:03d}.java").write_text("\n".join(lines))
    print(f"perfprobe4: 200 文件 × 8 方法 (source 密集, 1/8 带 sink) -> {d}")


if __name__ == "__main__":
    gen_probe2()
    gen_probe4()
