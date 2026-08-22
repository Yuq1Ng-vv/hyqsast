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
    rules_paths: str | Path | list[str | Path] | None = None,
    *,
    enable_container_bridge: bool = False,
    enable_state_bridge: bool = False,
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
        rules_paths: 额外规则文件（或目录，自动 glob ``*.yaml``）。在内置
            ``taint_rules.yaml`` 之上按 ``(语言, 区块, 类别)`` 追加去重合并。
        enable_container_bridge: 开启「容器/Builder 状态写读桥接」启发式
            （默认关）。这是过近似：``sb.append(t); s = sb.toString()`` 这类
            链它才有边。默认关会牺牲该类别漏报面（A 类）的部分召回，见
            OWASP 开/关回归对比。
        enable_state_bridge: 开启「跨函数状态桥接」启发式（默认关）。默认关
            会牺牲漏报面 J 类（模块全局/静态/实例字段跨函数写读）的召回。

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
        rules_paths=rules_paths,
        enable_container_bridge=enable_container_bridge,
        enable_state_bridge=enable_state_bridge,
    ).run()
