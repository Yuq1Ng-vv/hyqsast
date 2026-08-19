"""hyqsast — 独立确定性污点分析模块。

输入一个源码目录 + 语言/框架配置，输出接口（Endpoint）、漏洞类型（vuln_type）
与调用链（source → sink 的跨函数传播路径）。全部零 LLM。

用法::

    from hyqsast import scan
    result = scan("/path/to/java/project", language="java")
    result.to_json("report.json")
"""

from hyqsast.api import scan
from hyqsast.schema import (
    CanonicalFinding,
    ChainStep,
    Endpoint,
    Finding,
    NodeRef,
    ScanResult,
    ScanSummary,
    TaintElement,
    vuln_display_name,
)

__version__ = "0.1.0"

__all__ = [
    "scan",
    "CanonicalFinding",
    "ChainStep",
    "Endpoint",
    "Finding",
    "NodeRef",
    "ScanResult",
    "ScanSummary",
    "TaintElement",
    "vuln_display_name",
    "__version__",
]
