"""analyzer.py — 编排：建图 → 提取接口 → 跑污点 → 汇总成 ScanResult。

这是整个模块的核心，把 cpg 子包里已经打磨好的确定性能力串起来：
- :class:`CPGGraphBuilder` 建图 + 打污点标签
- :class:`CPGQuery.find_path` 跑 source → sink 的跨函数 BFS（即调用链）
- 框架提取器（spring / flask / express ...）枚举 HTTP 接口
- :class:`SourceCompletenessChecker` 产出盲区

全部零 LLM。
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from pathlib import Path

from hyqsast.cpg.frameworks import available_frameworks, get_extractor
from hyqsast.cpg.graph import EDGE_CALLS, EDGE_DATA_FLOW, NODE_FUNCTION, CPGGraphBuilder
from hyqsast.cpg.languages import detect_by_extension
from hyqsast.cpg.parser import Parser
from hyqsast.cpg.taint_loader import TaintRuleLoader
from hyqsast.schema import (
    BlindSpot,
    ChainStep,
    Endpoint,
    Finding,
    NodeRef,
    RouteParam,
    ScanResult,
    ScanSummary,
    severity_for,
)

logger = logging.getLogger(__name__)

# 语言 → 默认尝试的框架提取器（也可通过 scan(framework=...) 显式指定）
_LANGUAGE_FRAMEWORKS: dict[str, list[str]] = {
    "python": ["flask", "django", "fastapi"],
    "javascript": ["express"],
    "java": ["spring"],
}

# 单次扫描每个漏洞类别最多产出的 finding 数（防止大型项目输出爆炸）
_DEFAULT_MAX_FINDINGS_PER_CATEGORY = 50


class Analyzer:
    """目录级确定性污点分析。"""

    def __init__(
        self,
        directory: str | Path,
        language: str | None = None,
        framework: str | list[str] | None = None,
        max_findings_per_category: int = _DEFAULT_MAX_FINDINGS_PER_CATEGORY,
        include_blind_spots: bool = True,
        use_cache: bool = True,
        severity_overrides: dict[str, str] | None = None,
    ) -> None:
        self.directory = Path(directory).resolve()
        if not self.directory.is_dir():
            raise NotADirectoryError(f"目录不存在或不可读: {self.directory}")

        self.language = language or self._detect_language()
        self.frameworks = self._resolve_frameworks(framework)
        self.max_findings_per_category = max_findings_per_category
        self.include_blind_spots = include_blind_spots
        self.use_cache = use_cache
        self.severity_overrides = severity_overrides or {}

        self.parser = Parser(languages=[self.language])
        self.taint_loader = TaintRuleLoader()
        self.graph_builder = CPGGraphBuilder(self.parser, taint_loader=self.taint_loader)

    # ── 入口 ────────────────────────────────────────────────────────────

    def run(self) -> ScanResult:
        """执行完整扫描，返回结构化结果。"""
        self.graph_builder.add_directory(self.directory, use_cache=self.use_cache)

        endpoints = self._extract_endpoints()
        findings = self._build_findings()
        blind_spots = self._build_blind_spots(endpoints) if self.include_blind_spots else []

        return ScanResult(
            summary=self._summarize(endpoints, findings, blind_spots),
            endpoints=endpoints,
            findings=findings,
            blind_spots=blind_spots,
        )

    # ── 接口提取 ────────────────────────────────────────────────────────

    def _extract_endpoints(self) -> list[Endpoint]:
        """用框架提取器枚举 HTTP 接口。"""
        files = self._source_files()
        result: list[Endpoint] = []

        for fw_name in self.frameworks:
            extractor = get_extractor(fw_name, self.parser)
            for file_path in files:
                try:
                    if extractor.detect(file_path):
                        for ep in extractor.extract_routes(file_path):
                            result.append(self._to_endpoint(ep))
                except (OSError, ValueError):
                    continue

        result.sort(key=lambda e: (e.file_path, e.line))
        return result

    @staticmethod
    def _to_endpoint(ep: object) -> Endpoint:
        """把框架提取器的 HttpEndpoint 转成 schema.Endpoint。"""
        params = [
            RouteParam(
                name=p.name,
                source=p.source,
                type_hint=p.type_hint,
                required=p.required,
            )
            for p in getattr(ep, "params", [])
        ]
        return Endpoint(
            route=getattr(ep, "route", ""),
            methods=list(getattr(ep, "methods", [])),
            handler_func=getattr(ep, "handler_func", ""),
            file_path=getattr(ep, "file_path", ""),
            line=getattr(ep, "line", 0),
            params=params,
            auth_required=getattr(ep, "auth_required", False),
            auth_decorators=list(getattr(ep, "auth_decorators", [])),
            framework=getattr(ep, "framework", ""),
            source_lines=list(getattr(ep, "source_lines", [])),
        )

    # ── 污点 / 调用链 ────────────────────────────────────────────────────

    def _build_findings(self) -> list[Finding]:
        """枚举污点路径：源侧不限类别，漏洞类型由 sink 决定。

        对齐 Session 1.45 的参数标记语义：
        - 源节点（``taint_source``）只表示「有用户输入」，其类别可能是
          ``injection_general``（如 ``@RequestParam`` 的保守标记）；
        - 精确漏洞类型由 sink 决定（``jdbcTemplate.query`` → ``sql_injection``）。

        因此从任意源做前向 BFS，命中 sink 后用 sink 类别作为 vuln_type。
        """
        graph = self.graph_builder.graph
        source_ids = sorted(n for n, d in graph.nodes(data=True) if d.get("taint_source"))
        sink_set = {n for n, d in graph.nodes(data=True) if d.get("taint_sink")}
        if not source_ids or not sink_set:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        per_category: dict[str, int] = defaultdict(int)

        for src in source_ids:
            if per_category and all(
                c >= self.max_findings_per_category for c in per_category.values()
            ):
                break
            for node_ids, edge_types in self._bfs_to_sink(src, sink_set):
                for cat in self._sink_categories(node_ids[-1]):
                    if per_category.get(cat, 0) >= self.max_findings_per_category:
                        continue
                    finding = self._ids_to_finding(node_ids, edge_types, cat)
                    if finding is None:
                        continue
                    key = (
                        cat,
                        finding.source.file_path,
                        finding.source.line,
                        finding.sink.file_path,
                        finding.sink.line,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    per_category[cat] += 1
                    findings.append(finding)

        findings.sort(key=lambda f: (f.vuln_type, f.sink.file_path, f.sink.line))
        return findings

    def _bfs_to_sink(
        self,
        src: str,
        sink_set: set[str],
        max_depth: int = 20,
        max_paths: int = 5,
    ) -> list[tuple[list[str], list[str]]]:
        """从 *src* 沿 DATA_FLOW/CALLS 前向 BFS 到任一 sink。

        Returns: ``(节点 id 列表, 边类型列表)`` 的列表（最多 ``max_paths`` 条）。
        """
        graph = self.graph_builder.graph
        results: list[tuple[list[str], list[str]]] = []
        visited: set[str] = {src}
        queue: deque[tuple[str, list[str], list[str]]] = deque([(src, [src], [])])

        while queue and len(results) < max_paths:
            cur, node_path, edge_path = queue.popleft()
            if len(node_path) > max_depth:
                continue

            if cur in sink_set and cur != src:
                results.append((node_path, edge_path))
                continue

            for succ in graph.successors(cur):
                if succ in visited:
                    continue
                etype = self._edge_type(cur, succ)
                if etype is None:
                    continue
                visited.add(succ)
                queue.append((succ, [*node_path, succ], [*edge_path, etype]))

        return results

    def _edge_type(self, u: str, v: str) -> str | None:
        """若 u→v 存在 DATA_FLOW/CALLS 边，返回其类型，否则 None。"""
        edge_data = self.graph_builder.graph.get_edge_data(u, v)
        if not edge_data:
            return None
        for ed in edge_data.values():
            if ed.get("edge_type") in (EDGE_DATA_FLOW, EDGE_CALLS):
                return ed.get("edge_type")
        return None

    def _ids_to_finding(
        self,
        node_ids: list[str],
        edge_types: list[str],
        cat: str,
    ) -> Finding | None:
        """从节点 id 列表构建 Finding。"""
        if len(node_ids) < 2:
            return None

        source = self._node_ref_from_id(node_ids[0], "source")
        sink = self._node_ref_from_id(node_ids[-1], "sink")
        sink.category = cat

        chain: list[ChainStep] = []
        for i, nid in enumerate(node_ids):
            data = self._node_data(nid)
            edge = edge_types[i] if i < len(edge_types) else ""
            chain.append(
                ChainStep(
                    file_path=data.get("file_path") or _file_of(data.get("location", "")),
                    line=data.get("line") or data.get("start_line")
                    or _line_of(data.get("location", "")),
                    function=data.get("enclosing_function") or data.get("name") or "",
                    code=data.get("source") or data.get("expression") or "",
                    kind=data.get("node_type", ""),
                    edge_type=edge,
                )
            )

        sanitizers = self._sanitizers_on_path(node_ids, cat)
        severity = self.severity_overrides.get(cat) or severity_for(cat)

        return Finding(
            id=f"{cat}-{source.file_path}:{source.line}->{sink.file_path}:{sink.line}",
            vuln_type=cat,
            severity=severity,
            source=source,
            sink=sink,
            call_chain=chain,
            sanitizers=sanitizers,
            sanitized=bool(sanitizers),
        )

    def _node_ref_from_id(self, node_id: str, role: str) -> NodeRef:
        """从图节点 id 构建 NodeRef。"""
        data = self._node_data(node_id)
        return NodeRef(
            file_path=data.get("file_path") or _file_of(data.get("location", "")),
            line=data.get("line") or data.get("start_line")
            or _line_of(data.get("location", "")),
            function=data.get("enclosing_function") or data.get("name") or "",
            code=data.get("source") or data.get("expression") or "",
            category=data.get(f"taint_{role}") or "",
        )

    def _sink_categories(self, node_id: str) -> list[str]:
        """返回 sink 节点的所有类别（按逗号拆分）。

        ``injection_general`` 是兜底类别；当它和某个具体类别（如 ``xxe``）
        同时出现时，丢弃 ``injection_general`` 以避免同一路径产出重复 finding。
        """
        label = self._node_data(node_id).get("taint_sink", "") or ""
        cats = [c.strip() for c in label.split(",") if c.strip()]
        specific = [c for c in cats if c != "injection_general"]
        return specific or cats

    def _sanitizers_on_path(self, node_ids: list[str], cat: str) -> list[str]:
        """沿路径匹配该漏洞类别的 sanitizer 模式。"""
        rules = self.taint_loader.rules_for(self.language)
        category = rules.categories.get(cat)
        patterns = [p.lower() for p in (category.sanitizers if category else [])]
        found: list[str] = []
        for nid in node_ids:
            text = (self._node_data(nid).get("source") or "").lower()
            for pat in patterns:
                if pat and pat in text and pat not in found:
                    found.append(pat)
        return found

    def _node_data(self, node_id: str) -> dict:
        """从图中取回节点的完整属性。"""
        return self.graph_builder.graph.nodes.get(node_id, {})

    # ── 盲区 ────────────────────────────────────────────────────────────

    def _build_blind_spots(self, endpoints: list[Endpoint]) -> list[BlindSpot]:
        """枚举没有已知污点源的接口（IDOR / 业务逻辑复核候选）。"""
        from hyqsast.cpg.discovery import SourceCompletenessChecker

        checker = SourceCompletenessChecker(self.graph_builder.graph, self.taint_loader)
        checker.set_endpoints([self._to_endpoint_for_checker(ep) for ep in endpoints])

        spots: list[BlindSpot] = []
        for exposed in checker.find_exposed_no_source():
            spots.append(
                BlindSpot(
                    kind="endpoint_no_source",
                    location=f"{exposed.file_path}:{exposed.line}",
                    reason=f"接口 {exposed.endpoint} 的处理器无已知污点源",
                    recommendation="人工复核 IDOR / 业务逻辑漏洞",
                )
            )
        return spots

    @staticmethod
    def _to_endpoint_for_checker(ep: Endpoint) -> object:
        """schema.Endpoint → 兼容 checker 期望的鸭子类型对象。"""
        from types import SimpleNamespace

        return SimpleNamespace(
            handler_func=ep.handler_func,
            route=ep.route,
            file_path=ep.file_path,
            line=ep.line,
            methods=ep.methods,
        )

    # ── 汇总 ────────────────────────────────────────────────────────────

    def _summarize(
        self,
        endpoints: list[Endpoint],
        findings: list[Finding],
        blind_spots: list[BlindSpot],
    ) -> ScanSummary:
        graph = self.graph_builder.graph
        functions = sum(1 for _, d in graph.nodes(data=True) if d.get("node_type") == NODE_FUNCTION)
        sinks = sum(
            1 for _, d in graph.nodes(data=True) if d.get("taint_sink")
        )
        return ScanSummary(
            files=len(self._source_files()),
            functions=functions,
            endpoints=len(endpoints),
            findings=len(findings),
            sinks=sinks,
            blind_spots=len(blind_spots),
        )

    # ── 内部工具 ────────────────────────────────────────────────────────

    def _source_files(self) -> list[str]:
        """返回目录下、匹配目标语言的所有源码文件（绝对路径）。"""
        files: list[str] = []
        for entry in sorted(self.directory.rglob("*")):
            if not entry.is_file():
                continue
            if any(p.startswith(".") or p == "__pycache__" for p in entry.parts):
                continue
            if detect_by_extension(str(entry)) == self.language:
                files.append(str(entry))
        return files

    def _detect_language(self) -> str:
        """按扩展名统计，取出现最多的受支持语言。"""
        from collections import Counter

        counter: Counter[str] = Counter()
        for entry in self.directory.rglob("*"):
            if not entry.is_file():
                continue
            lang = detect_by_extension(str(entry))
            if lang:
                counter[lang] += 1
        if not counter:
            raise ValueError(f"目录 {self.directory} 中未发现受支持语言的源码文件")
        return counter.most_common(1)[0][0]

    def _resolve_frameworks(self, framework: str | list[str] | None) -> list[str]:
        """解析 framework 参数，缺省用语言默认映射。"""
        if framework is None:
            return list(_LANGUAGE_FRAMEWORKS.get(self.language, []))
        names = [framework] if isinstance(framework, str) else list(framework)
        available = set(available_frameworks())
        unknown = [n for n in names if n not in available]
        if unknown:
            raise ValueError(f"未知框架: {unknown}。可用: {sorted(available)}")
        return names


# ─── 位置字符串解析工具 ────────────────────────────────────────────────────


def _file_of(location: str) -> str:
    if not location:
        return ""
    return location.rsplit(":", 1)[0]


def _line_of(location: str) -> int:
    if not location:
        return 0
    try:
        return int(location.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return 0
