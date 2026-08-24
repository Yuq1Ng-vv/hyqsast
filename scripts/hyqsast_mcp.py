"""scripts/hyqsast_mcp.py — MCP 服务器启动器（离线/vendor 兼容）。

断网机器上无需 uv/venv/pip，只要系统有 python 3.12 + 预先构建的 vendor/
（scripts/build_vendor.py 生成，与本仓库一起拷过来）：

    python3 scripts/hyqsast_mcp.py

即启动 MCP server（默认 stdio 传输，客户端把它当子进程拉起，不开端口）。
在 Claude Code 里注册：``claude mcp add hyqsast -- python3 scripts/hyqsast_mcp.py``

原理与 scripts/hyqsast.py 一致：把 vendor/common + vendor/<平台> + src 挂进
PYTHONPATH，再以 ``python -m hyqsast_mcp`` 重执行。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PLAT_MAP = {"linux": "linux-x86_64", "win32": "win-amd64", "darwin": "macos-arm64"}

plat = PLAT_MAP.get(sys.platform)
if plat is None:
    sys.exit(f"[hyqsast] 不支持的平台：{sys.platform}（可用：{list(PLAT_MAP)}）")

vend = REPO / "vendor" / plat
if not vend.is_dir():
    sys.exit(
        f"[hyqsast] 缺 vendor/{plat} 依赖目录。联网机上先跑 "
        f"`uv run python scripts/build_vendor.py --platform <平台>` 构建，"
        f"然后把整个仓库（含 vendor/）一起拷到本机。"
    )

extra = [str(REPO / "vendor" / "common"), str(vend), str(REPO / "src")]
os.environ["PYTHONPATH"] = os.pathsep.join(
    extra + ([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])
)

# 重执行为 python -m hyqsast_mcp，启动 MCP server（stdio）。
os.execv(sys.executable, [sys.executable, "-m", "hyqsast_mcp", *sys.argv[1:]])
