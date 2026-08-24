"""scripts/build_vendor.py — 联网机上为「离线执行」预构建 vendor/ 依赖目录。

断网机器没法跑 ``uv sync``，但 hyqsast 的 6 个依赖总共 ~20MB（其中只有
tree-sitter 及语言包是编译型，其余纯 Python）。本脚本用 ``uv pip download``
按目标平台拉 wheel、解包成 site-packages 布局，离线机器只需有 python 3.12：

    PYTHONPATH=vendor/common:vendor/<平台目录>:src python3 -m hyqsast ...

用法::

    uv run python scripts/build_vendor.py                 # 当前平台（linux）
    uv run python scripts/build_vendor.py --platform win   # 交叉构建 Windows
    uv run python scripts/build_vendor.py --all            # linux + win + mac

布局：纯 Python wheel（``py3-none-any``，networkx）解到 ``vendor/common/``
共享；编译型（tree-sitter 各语言 + PyYAML）按平台分目录。
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR = REPO_ROOT / "vendor"

# 编译型依赖（按平台分目录装）；纯 Python 依赖（networkx，py3-none-any）装 common/ 共享。
NATIVE_PACKAGES = [
    "tree-sitter",
    "tree-sitter-python",
    "tree-sitter-java",
    "tree-sitter-javascript",
    "pyyaml",
]
PURE_PACKAGES = ["networkx"]

# 平台别名 -> (vendor 子目录, uv --python-platform 标签)
PLATFORMS: dict[str, tuple[str, str]] = {
    "linux": ("linux-x86_64", "x86_64-unknown-linux-gnu"),
    "win": ("win-amd64", "x86_64-pc-windows-msvc"),
    "mac": ("macos-arm64", "aarch64-apple-darwin"),
}


def build(plat_key: str, python_version: str) -> None:
    subdir, uv_platform = PLATFORMS[plat_key]
    dest = VENDOR / subdir
    common = VENDOR / "common"
    dest.mkdir(parents=True, exist_ok=True)
    common.mkdir(parents=True, exist_ok=True)

    # uv pip install --target 直接把 wheel 解成 site-packages 布局（自动带依赖）；
    # --python-platform/--python-version 交叉解析目标平台 wheel，--only-binary 防源码构建。
    def install(target: Path, packages: list[str]) -> None:
        subprocess.run(
            [
                "uv", "pip", "install",
                "--target", str(target),
                *packages,
                "--python-version", python_version,
                "--python-platform", uv_platform,
                "--only-binary", ":all:",
            ],
            check=True,
        )

    print(f"[vendor] 安装 {subdir}（{uv_platform}，py{python_version}）编译型依赖 ...")
    install(dest, NATIVE_PACKAGES)
    # 纯 Python 依赖跨平台同一 wheel，只装一次到 common/ 共享。
    if not any(common.iterdir()):
        print("[vendor] 安装纯 Python 依赖到 common/（跨平台共享）...")
        install(common, PURE_PACKAGES)


def total_size() -> int:
    if not VENDOR.is_dir():
        return 0
    return sum(f.stat().st_size for f in VENDOR.rglob("*") if f.is_file())


def main() -> None:
    ap = argparse.ArgumentParser(description="离线 vendor 依赖目录构建")
    ap.add_argument(
        "--platform",
        choices=list(PLATFORMS) + ["all"],
        default=None,
        help="目标平台；缺省为当前平台，all = linux + win + mac",
    )
    ap.add_argument("--python-version", default="3.12", help="目标 python 版本（默认 3.12）")
    args = ap.parse_args()

    keys = list(PLATFORMS) if args.platform in (None, "all") else [args.platform]
    for k in keys:
        build(k, args.python_version)
    print(f"[vendor] 完成，vendor 总体积约 {total_size() / 1024 / 1024:.1f}MB")
    py_path = f"{VENDOR / 'common'}:{VENDOR / keys[0]}:{REPO_ROOT / 'src'}"
    print(f"[vendor] 离线用法：export PYTHONPATH={py_path}")
    print("[vendor] 然后 python3 -m hyqsast / chunk_scan.py --per-file 即可")


if __name__ == "__main__":
    main()
