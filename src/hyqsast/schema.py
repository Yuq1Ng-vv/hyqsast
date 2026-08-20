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
class EndpointMatch:
    """Finding → 接口的对应关系。

    ``match`` 取值（供 LLM 下游区分可靠关联与兜底/缺失）：
    - ``exact``：finding 的 source 所在 (文件, 函数) 与某接口的
      (file_path, handler_func) 完全一致；
    - ``same_file``：同文件内有接口但 handler 名对不上 —— 取同文件
      第一个接口（相关但不完全确定）；
    - ``unmatched``：source 所在文件里没有任何已识别接口。
    """

    match: str = "unmatched"  # exact / same_file / unmatched
    route: str = ""
    methods: list[str] = field(default_factory=list)
    handler_func: str = ""
    file_path: str = ""
    line: int = 0
    framework: str = ""
    params: list[RouteParam] = field(default_factory=list)


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
    # P1-6: 与 HTTP 接口的关联（exact / same_file / unmatched），供 LLM
    # 下游把漏洞直接对应到具体路由，无需自己 join endpoints 表。
    endpoint: EndpointMatch = field(default_factory=EndpointMatch)


@dataclass
class TaintElement:
    """规则引擎识别出的一个 source / sink 点（报告副产品，供漏报排查）。

    与 finding 正交：每个被打上 taint_source / taint_sink 标签的图节点都
    记一条（多类别节点逐类别展开）。排查漏报时用 ``covered`` 一眼筛出
    「sink 规则命中了、却没有 finding 接住它」的裸 sink。
    """

    kind: str  # "source" / "sink"
    category: str  # 命中的漏洞类别
    file_path: str = ""
    line: int = 0
    function: str = ""
    code: str = ""
    node_type: str = ""  # assignment / call_site / parameter
    patterns: list[str] = field(default_factory=list)  # 命中的具体规则模式（可空）
    covered: bool = False  # 该 (file, line) 是否出现在某条 finding 的 source/sink


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
    # 规则引擎识别到的 source/sink 点清单（漏报排查用），独立成文件，
    # 不进主报告（``to_elements_json``）。
    taint_elements: list[TaintElement] = field(default_factory=list)

    def to_dict(self) -> dict:
        """递归转为纯 dict（JSON 可直接序列化）。

        规范版报告（``to_canonical_json``）与污点元素清单
        （``to_elements_json``）都独立成文件，不进原报告结构，
        保持既有输出字段不变。
        """
        d = asdict(self)
        d.pop("canonical_findings", None)
        d.pop("taint_elements", None)
        return d

    def to_json(self, path: str | Path | None = None, *, indent: int = 2) -> str:
        """序列化为 JSON 字符串；若给定 ``path`` 则同时落盘。"""
        text = json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
        if path is not None:
            Path(path).write_text(text, encoding="utf-8")
        return text

    def to_elements_json(self, path: str | Path | None = None, *, indent: int = 2) -> str:
        """序列化污点元素清单（``list[TaintElement]``）；给定 ``path`` 则落盘。

        供漏报排查：列出本次扫描识别到的全部 source/sink 点、命中规则及
        ``covered`` 标记。
        """
        text = json.dumps(
            [asdict(e) for e in self.taint_elements],
            ensure_ascii=False,
            indent=indent,
        )
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
