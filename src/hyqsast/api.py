"""api.py — 模块公开门面。

一句话用法::

    from hyqsast import scan
    result = scan("/path/to/project", language="java")
    result.to_json("report.json")
"""

from __future__ import annotations

from pathlib import Path

from hyqsast.analyzer import Analyzer
from hyqsast.schema import ScanResult

__all__ = ["scan"]


def scan(
    directory: str | Path,
    language: str | None = None,
    framework: str | list[str] | None = None,
    max_findings_per_category: int = 50,
    include_blind_spots: bool = True,
    use_cache: bool = True,
    severity_overrides: dict[str, str] | None = None,
) -> ScanResult:
    """扫描一个源码目录，返回接口 / 漏洞类型 / 调用链的结构化结果。

    Args:
        directory: 源码目录。
        language: ``"java"`` / ``"python"`` / ``"javascript"``；缺省自动探测。
        framework: 框架提取器名（``"spring"`` / ``"flask"`` ...），缺省按语言默认。
        max_findings_per_category: 每个漏洞类别最多产出多少条 finding。
        include_blind_spots: 是否附带「无已知污点源的接口」盲区清单。
        use_cache: 是否复用 CPG 图缓存（``~/.cache/hyqsast/cpg/``）。
        severity_overrides: 覆盖默认的 vuln_type → severity 映射。

    Returns:
        :class:`ScanResult`，可用 ``.to_json(path)`` 落盘。
    """
    return Analyzer(
        directory=directory,
        language=language,
        framework=framework,
        max_findings_per_category=max_findings_per_category,
        include_blind_spots=include_blind_spots,
        use_cache=use_cache,
        severity_overrides=severity_overrides,
    ).run()
