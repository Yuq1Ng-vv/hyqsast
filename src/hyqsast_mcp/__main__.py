"""hyqsast_mcp — ``python -m hyqsast_mcp`` 入口（配合 scripts/hyqsast_mcp.py 启动器）。"""

from __future__ import annotations

import sys

from hyqsast_mcp.server import main

sys.exit(main())
