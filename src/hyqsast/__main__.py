"""__main__.py — 支持 ``python -m hyqsast`` 直接跑 CLI（离线无 venv 时用）。

正常 ``uv run hyqsast`` 走 pyproject 的 console script；离线机器没有 venv 时，
配合 ``vendor/`` 依赖目录 + ``PYTHONPATH`` 用系统 python 3.12 跑：

    PYTHONPATH=vendor/common:vendor/linux-x86_64:src python3 -m hyqsast ...
"""

import sys

from hyqsast.cli import main

if __name__ == "__main__":
    sys.exit(main())
