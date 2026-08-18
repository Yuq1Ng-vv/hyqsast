"""schema.py — 扫描结果的数据模型。

所有类型均为纯 dataclass，可直接 JSON 序列化（通过 :meth:`ScanResult.to_json`），
也可被下游（报告生成器、LLM 验证器、CI 门禁）直接消费。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ─── 漏洞类型 → 严重级别默认映射 ───────────────────────────────────────────
#
# 来自 cpg/taint_rules.yaml 的类别名（Java 共 20 类）。调用方可通过
# ``scan(..., severity_overrides={...})`` 覆盖，或直接改此表。

SEVERITY_MAP: dict[str, str] = {
    # 远程代码执行 / 任意代码执行 / 反序列化 → critical
    "code_injection": "critical",
    "command_injection": "critical",
    "deserialization": "critical",
    "jndi_injection": "critical",
    "ssti": "critical",
    "sql_injection": "critical",
    "xpath_injection": "critical",
    "xxe": "critical",
    "ldap_injection": "critical",
    # 高危：服务端请求伪造 / 路径穿越 / 认证绕过 / 头注入 / 格式化串
    "ssrf": "high",
    "path_traversal": "high",
    "auth_bypass": "high",
    "header_injection": "high",
    "format_string": "high",
    # 中危
    "xss": "medium",
    "open_redirect": "medium",
    "crypto_weakness": "medium",
    "log_injection": "medium",
    "info_disclosure": "medium",
    # 兜底：通用注入类别
    "injection_general": "medium",
}


def severity_for(vuln_type: str) -> str:
    """返回某个漏洞类别的默认严重级别，未知类别回退 ``medium``。"""
    return SEVERITY_MAP.get(vuln_type, "medium")


# ─── 接口 ──────────────────────────────────────────────────────────────────


@dataclass
class RouteParam:
    """HTTP 接口的一个参数。"""

    name: str
    source: str = "query"  # path / query / body / header / cookie / form
    type_hint: str = ""
    required: bool = True


@dataclass
class Endpoint:
    """源码中发现的一个 HTTP 接口。"""

    route: str  # "/api/users/{id}"
    methods: list[str] = field(default_factory=list)  # ["GET", "POST"]
    handler_func: str = ""
    file_path: str = ""
    line: int = 0
    params: list[RouteParam] = field(default_factory=list)
    auth_required: bool = False
    auth_decorators: list[str] = field(default_factory=list)
    framework: str = ""  # spring / flask / express / ...
    source_lines: list[str] = field(default_factory=list)


# ─── 污点 / 调用链 / 漏洞 ───────────────────────────────────────────────────


@dataclass
class NodeRef:
    """污点源或污点汇的位置快照。"""

    file_path: str = ""
    line: int = 0
    function: str = ""
    code: str = ""
    category: str = ""


@dataclass
class ChainStep:
    """调用链上的一步。"""

    file_path: str = ""
    line: int = 0
    function: str = ""
    code: str = ""
    kind: str = ""  # parameter / assignment / variable_ref / call_site / sink
    edge_type: str = ""  # DATA_FLOW / CALLS


@dataclass
class Finding:
    """一条污点漏洞（source → sink 的完整传播路径）。"""

    id: str
    vuln_type: str  # sql_injection / xss / ssrf / path_traversal / ...
    severity: str
    source: NodeRef
    sink: NodeRef
    call_chain: list[ChainStep] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    sanitized: bool = False


@dataclass
class BlindSpot:
    """扫描盲区条目 —— 让使用者知道「没覆盖到什么」。"""

    kind: str = ""  # endpoint_no_source / uncovered_sink
    location: str = ""
    reason: str = ""
    recommendation: str = ""


# ─── 汇总与顶层结果 ────────────────────────────────────────────────────────


@dataclass
class ScanSummary:
    """扫描概况计数。"""

    files: int = 0
    functions: int = 0
    endpoints: int = 0
    findings: int = 0
    sinks: int = 0
    blind_spots: int = 0


@dataclass
class ScanResult:
    """``scan()`` 的顶层返回结构。"""

    summary: ScanSummary = field(default_factory=ScanSummary)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    blind_spots: list[BlindSpot] = field(default_factory=list)

    def to_dict(self) -> dict:
        """递归转为纯 dict（JSON 可直接序列化）。"""
        return asdict(self)

    def to_json(self, path: str | Path | None = None, *, indent: int = 2) -> str:
        """序列化为 JSON 字符串；若给定 ``path`` 则同时落盘。"""
        text = json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
        if path is not None:
            Path(path).write_text(text, encoding="utf-8")
        return text
