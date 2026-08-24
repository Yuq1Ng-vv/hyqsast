"""scripts/hyqsast.py — 离线启动器：自动挂 vendor/ 依赖 + src，然后跑 hyqsast CLI。

断网机器上无需 uv / venv / pip，只要系统有 python 3.12（>=3.12，见下）就能跑整个
项目扫描——等价于联网机上的 ``uv run hyqsast ...``：

    python3 scripts/hyqsast.py /path/to/project --language java -o report.json
    python3 scripts/hyqsast.py examples/demo-java --language java

原理：把 vendor/common + vendor/<平台>（构建产物，见 scripts/build_vendor.py）
和 src/ 挂进 PYTHONPATH，再以 ``python -m hyqsast`` 重执行。

注意：vendor 是给特定 python 小版本构建的（tree-sitter 核心是 cp312 专用 .so）。
目标机 python 小版本要和构建时一致（默认 3.12；3.13 需 ``--python-version 3.13``
重新 build_vendor）。
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

# 重执行为 python -m hyqsast，把 CLI 参数原样带过去。
os.execv(sys.executable, [sys.executable, "-m", "hyqsast", *sys.argv[1:]])
