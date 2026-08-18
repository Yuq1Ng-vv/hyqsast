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
    "nosql_injection": "critical",
    # 高危：服务端请求伪造 / 路径穿越 / 认证绕过 / 头注入 / 格式化串
    "ssrf": "high",
    "cleartext_transmission": "high",
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
    "hardcoded_secret": "medium",
    # 兜底：通用注入类别
    "injection_general": "medium",
}


def severity_for(vuln_type: str) -> str:
    """返回某个漏洞类别的默认严重级别，未知类别回退 ``medium``。"""
    return SEVERITY_MAP.get(vuln_type, "medium")


# 漏洞类别 → 中文显示名（规范版报告的 ``vuln_name`` 用）
VULN_DISPLAY_NAMES: dict[str, str] = {
    "code_injection": "代码注入",
    "command_injection": "命令注入",
    "deserialization": "反序列化",
    "jndi_injection": "JNDI 注入",
    "ssti": "服务端模板注入(SSTI)",
    "sql_injection": "SQL 注入",
    "xpath_injection": "XPath 注入",
    "xxe": "XML 外部实体注入(XXE)",
    "ldap_injection": "LDAP 注入",
    "nosql_injection": "NoSQL 注入",
    "ssrf": "SSRF 服务端请求伪造",
    "cleartext_transmission": "明文传输敏感数据",
    "path_traversal": "路径穿越",
    "auth_bypass": "认证绕过",
    "header_injection": "响应头注入",
    "format_string": "格式化字符串漏洞",
    "xss": "跨站脚本(XSS)",
    "open_redirect": "开放重定向",
    "crypto_weakness": "弱加密",
    "log_injection": "日志注入",
    "info_disclosure": "信息泄露",
    "hardcoded_secret": "硬编码密钥",
    "injection_general": "通用注入",
}


def vuln_display_name(vuln_type: str) -> str:
    """返回某个漏洞类别的中文显示名，未知类别回退原类别名。"""
    return VULN_DISPLAY_NAMES.get(vuln_type, vuln_type)


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
    # P1-5: 相同 (source, sink) 的多类别候选被聚合后，其余类别收在这里。
    # 主 vuln_type 取严重级别最高、sink 模式最具体者。
    related_categories: list[str] = field(default_factory=list)


@dataclass
class BlindSpot:
    """扫描盲区条目 —— 让使用者知道「没覆盖到什么」。"""

    kind: str = ""  # endpoint_no_source / uncovered_sink
    location: str = ""
    reason: str = ""
    recommendation: str = ""


@dataclass
class CanonicalFinding:
    """规范版报告条目 —— 人工复核优先看这份。

    - ``vuln_name``: 中文漏洞名 + 漏洞所在文件位置
    - ``endpoint``: 漏洞所在的 HTTP 接口（方法 + 路由 + 文件位置）
    - ``sink_function``: sink 点所在函数完整源码（带行号，sink 行标 ``▶``）
    - ``call_chain``: 函数级真实调用链 ``x -> y -> z -> sink``（每个 hop 带 file:line）
    """

    id: str = ""
    vuln_type: str = ""
    vuln_name: str = ""
    endpoint: str = ""
    sink_function: str = ""
    call_chain: str = ""


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
    # P0-2: 每个漏洞类别因 max_findings_per_category 被截断的候选数。
    # 值是保守下限——外层 BFS 提前终止时未扫描到的部分不计入。
    truncated_categories: dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    """``scan()`` 的顶层返回结构。"""

    summary: ScanSummary = field(default_factory=ScanSummary)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    blind_spots: list[BlindSpot] = field(default_factory=list)
    canonical_findings: list[CanonicalFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        """递归转为纯 dict（JSON 可直接序列化）。

        规范版报告独立成文件（``to_canonical_json``），不进原报告结构，
        保持既有输出字段不变。
        """
        d = asdict(self)
        d.pop("canonical_findings", None)
        return d

    def to_json(self, path: str | Path | None = None, *, indent: int = 2) -> str:
        """序列化为 JSON 字符串；若给定 ``path`` 则同时落盘。"""
        text = json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
        if path is not None:
            Path(path).write_text(text, encoding="utf-8")
        return text

    def to_canonical_json(self, path: str | Path | None = None, *, indent: int = 2) -> str:
        """序列化规范版报告（``list[CanonicalFinding]``）；给定 ``path`` 则落盘。"""
        text = json.dumps(
            [asdict(c) for c in self.canonical_findings],
            ensure_ascii=False,
            indent=indent,
        )
        if path is not None:
            Path(path).write_text(text, encoding="utf-8")
        return text
