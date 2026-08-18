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
import re
from collections import defaultdict, deque
from pathlib import Path

from hyqsast.cpg.frameworks import available_frameworks, get_extractor
from hyqsast.cpg.graph import (
    EDGE_CALLS,
    EDGE_DATA_FLOW,
    NODE_ASSIGNMENT,
    NODE_CALL_SITE,
    NODE_FUNCTION,
    CPGGraphBuilder,
)
from hyqsast.cpg.languages import detect_by_extension
from hyqsast.cpg.parser import Parser
from hyqsast.cpg.taint_loader import TaintRuleLoader
from hyqsast.schema import (
    BlindSpot,
    CanonicalFinding,
    ChainStep,
    Endpoint,
    Finding,
    NodeRef,
    RouteParam,
    ScanResult,
    ScanSummary,
    severity_for,
    vuln_display_name,
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

# P1-4: 「字符串模板」型注入 sink —— 危险载荷（SQL/命令/表达式串）只可能
# 出现在第一个参数，其余参数位是绑定/参数（如 ``query(sql, params)``），
# 污点流到这些位置不算语句注入，做位置门控。其余类别（xss/ssrf/nosql/
# ldap/...）载荷位置不固定，不做门控。
_SINK_STR_TEMPLATE_CATS: frozenset[str] = frozenset(
    {
        "sql_injection",
        "command_injection",
        "code_injection",
        "xpath_injection",
        "ssti",
    }
)


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
        rules_paths: str | Path | list[str | Path] | None = None,
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
        # rules_paths=None 时用内置 taint_rules.yaml；传入文件/目录则在
        # 内置规则之上追加合并（见 TaintRuleLoader 的 merge 语义）
        self.taint_loader = TaintRuleLoader(rules_paths=rules_paths)
        self.graph_builder = CPGGraphBuilder(self.parser, taint_loader=self.taint_loader)
        # 报告层读源码的按文件缓存（兜底 code / 提取整函数源码）
        self._src = _SourceCache()
        # P0-2: 被 max_findings_per_category 截断的类别计数（_build_findings 填充）
        self._truncated_categories: dict[str, int] = {}

    # ── 入口 ────────────────────────────────────────────────────────────

    def run(self) -> ScanResult:
        """执行完整扫描，返回结构化结果。"""
        self.graph_builder.add_directory(self.directory, use_cache=self.use_cache)

        endpoints = self._extract_endpoints()
        findings = self._build_findings()
        blind_spots = self._build_blind_spots(endpoints) if self.include_blind_spots else []
        canonical = self._build_canonical_findings(findings, endpoints)

        return ScanResult(
            summary=self._summarize(endpoints, findings, blind_spots),
            endpoints=endpoints,
            findings=findings,
            blind_spots=blind_spots,
            canonical_findings=canonical,
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
        # P0-2: 记录每个类别因上限被跳过的候选数（供截断可见化）
        skipped: dict[str, int] = defaultdict(int)

        for src in source_ids:
            if per_category and all(
                c >= self.max_findings_per_category for c in per_category.values()
            ):
                break
            for node_ids, edge_types in self._bfs_to_sink(src, sink_set):
                for cat in self._sink_categories(node_ids[-1]):
                    if per_category.get(cat, 0) >= self.max_findings_per_category:
                        skipped[cat] += 1
                        continue
                    # P1-4: 字符串模板型注入的位置门控 —— 污点在参数绑定位
                    # （如 ``query(sql, tainted_params)`` 的第二个实参）不算
                    # 语句注入命中；确定不了位置时放行，保持高召回。
                    if cat in _SINK_STR_TEMPLATE_CATS:
                        taint_pos = self._tainted_arg_position(node_ids)
                        if taint_pos is not None and taint_pos >= 1:
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

        # P0-2: 把截断计数暴露给汇总层；0 的类别不保留
        self._truncated_categories = {k: v for k, v in skipped.items() if v > 0}

        # P1-5: 相同 (src,sink) 的多类别候选合并为一条主 finding
        return self._aggregate_multi_category(findings)

    def _aggregate_multi_category(self, findings: list[Finding]) -> list[Finding]:
        """P1-5: 把相同 (source, sink) 的多类别 finding 合并为一条主 finding。

        同一 source → 同一 sink 的路径往往同时命中多个类别（如
        ``jdbc.queryForObject(sql, ...)`` 同时匹配 sql_injection 和
        code_injection），旧实现产出多条同位置 finding 造成噪音。合并规则：

        - 主类别取严重级别最高者；
        - 同级用「该类别在该 sink 表达式上最长匹配的模式长度」裁定 ——
          更长模式更具体（``.queryForObject(`` > ``.query(``），
          ``sql_injection`` 因而胜出 ``code_injection``；
        - 其余类别按严重级别降序收进 ``related_categories``。
        """
        if not findings:
            return []
        groups: dict[tuple[str, int, str, int], list[Finding]] = defaultdict(list)
        for f in findings:
            key = (f.source.file_path, f.source.line, f.sink.file_path, f.sink.line)
            groups[key].append(f)

        out: list[Finding] = []
        for group in groups.values():
            if len(group) == 1:
                out.append(group[0])
                continue
            ranked = sorted(
                group,
                key=lambda f: (
                    -_severity_rank(f.severity),
                    -self._sink_specificity(f.sink),
                    f.vuln_type,
                ),
            )
            main = ranked[0]
            main.related_categories = [f.vuln_type for f in ranked[1:]]
            out.append(main)
        out.sort(key=lambda f: (f.vuln_type, f.sink.file_path, f.sink.line))
        return out

    def _sink_specificity(self, sink: NodeRef) -> int:
        """返回 sink 类别中在该 sink 表达式上最长匹配模式的长度（更具体→更大）。

        BUG 39: 匹配前模式也要小写 —— 文本已 ``lower()`` 而模式仍是原样时，
        ``Object(`` 永远匹配不上 ``queryforobject(``，导致 sql_injection
        （``.queryForObject(``）反而输给 code_injection（``Object(``）。
        """
        rules = self.taint_loader.rules_for(self.language)
        category = rules.categories.get(sink.category)
        if not category:
            return 0
        text = (sink.code or "").lower()
        best = 0
        for pat in category.sinks:
            pat_l = pat.lower()
            if pat_l and pat_l in text:
                best = max(best, len(pat))
        return best

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
            file_path, line, function, code = self._node_fields(data)
            # BUG 35: 链尾 sink 步没有出边（edge_types 比 node_ids 少一个），
            # edge_type 取「进入 sink」的那条边，避免报告里出现空值。
            edge = edge_types[i] if i < len(edge_types) else (edge_types[-1] if edge_types else "")
            chain.append(
                ChainStep(
                    file_path=file_path,
                    line=line,
                    function=function,
                    code=code,
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
        file_path, line, function, code = self._node_fields(data)
        return NodeRef(
            file_path=file_path,
            line=line,
            function=function,
            code=code,
            category=data.get(f"taint_{role}") or "",
        )

    def _node_fields(self, data: dict) -> tuple[str, int, str, str]:
        """从节点属性取 ``(file_path, line, function, code)``，带空值兜底。

        BUG 34: parameter / variable_ref 节点不存源码文本，``code`` 从文件
        行读回兜底；call_site 节点虽已补 ``enclosing_function``，但对旧缓存
        仍可能缺失，故 ``function`` 继续兜底 ``caller``/``callee``。
        """
        file_path = data.get("file_path") or _file_of(data.get("location", ""))
        line = data.get("line") or data.get("start_line") or _line_of(data.get("location", ""))
        function = (
            data.get("enclosing_function")
            or data.get("name")
            or data.get("caller")
            or data.get("callee")
            or ""
        )
        code = data.get("source") or data.get("expression") or ""
        if not code and file_path and line:
            code = self._src.line(file_path, line)
        return file_path, line, function, code

    # ── 规范版报告 ───────────────────────────────────────────────────────

    def _build_canonical_findings(
        self,
        findings: list[Finding],
        endpoints: list[Endpoint],
    ) -> list[CanonicalFinding]:
        """构建规范版报告：sink 函数完整源码 + 函数级真实调用链 + 接口信息。

        与正常报告一一对应，但更面向人工复核：调用链折叠成函数级
        ``x -> y -> z -> sink``，sink 函数整段贴出并标出 sink 行。
        """
        return [
            CanonicalFinding(
                id=f.id,
                vuln_type=f.vuln_type,
                vuln_name=(f"{vuln_display_name(f.vuln_type)} @ {f.sink.file_path}:{f.sink.line}"),
                endpoint=self._endpoint_for_finding(f, endpoints),
                sink_function=self._sink_function_block(f),
                call_chain=self._render_chain(f),
            )
            for f in findings
        ]

    @staticmethod
    def _endpoint_for_finding(f: Finding, endpoints: list[Endpoint]) -> str:
        """找漏洞所在接口：优先 ``(文件, handler)`` 精确匹配，退回同文件第一个。"""
        src = f.source
        exact = [
            ep
            for ep in endpoints
            if ep.file_path == src.file_path and ep.handler_func == src.function
        ]
        candidates = exact or [ep for ep in endpoints if ep.file_path == src.file_path]
        if not candidates:
            return ""
        ep = candidates[0]
        methods = "/".join(ep.methods) or "ANY"
        return f"{methods} {ep.route} @ {ep.file_path}:{ep.line} ({ep.handler_func})"

    def _sink_function_block(self, f: Finding, margin: int = 5) -> str:
        """返回 sink 点所在函数的完整源码：带行号，sink 行标 ``▶`` 并尾注类别。

        在图中找 ``file_path`` 相同且包含 sink 行的函数节点（取范围最小者）；
        找不到时退化为 sink 行 ±*margin* 行的窗口。
        """
        sink = f.sink
        best: tuple[int, int] | None = None
        for _, data in self.graph_builder.graph.nodes(data=True):
            if data.get("node_type") != NODE_FUNCTION:
                continue
            if data.get("file_path") != sink.file_path:
                continue
            start = data.get("start_line") or 0
            end = data.get("end_line") or 0
            if start and end and start <= sink.line <= end:
                if best is None or (end - start) < (best[1] - best[0]):
                    best = (start, end)
        if best is None:
            start, end = max(1, sink.line - margin), sink.line + margin
        else:
            start, end = best

        lines = self._src.slice(sink.file_path, start, end)
        width = len(str(end))
        out: list[str] = []
        for n, text in enumerate(lines, start=start):
            flag = "▶" if n == sink.line else " "
            # rstrip：源码行尾若有空白，紧贴代码放 sink 标注更整洁
            suffix = f"  // ← SINK: {f.vuln_type}" if n == sink.line else ""
            out.append(f"{flag} {n:>{width}} | {text.rstrip()}{suffix}")
        return "\n".join(out)

    def _render_chain(self, f: Finding) -> str:
        """把 finding 的节点路径折叠成函数级真实链 ``x -> y -> z -> sink``。

        每个 hop 取「所在函数（call_site 取被调用的 callee）」+ 相对扫描目录的
        ``file:line``；同一函数内的连续步骤折叠为一步。
        """
        # (file, line) → callee：call_site 步骤折叠成「被调用的函数」hop
        callee_at: dict[tuple[str, int], str] = {}
        for _, data in self.graph_builder.graph.nodes(data=True):
            if data.get("node_type") == NODE_CALL_SITE and data.get("callee") and data.get("line"):
                callee_at[(data.get("file_path", ""), data.get("line"))] = data["callee"]

        hops: list[tuple[str, str]] = []  # (函数名, 相对路径:行号)
        total = len(f.call_chain)
        for idx, step in enumerate(f.call_chain):
            if step.kind == "call_site":
                label = callee_at.get((step.file_path, step.line)) or step.function
                # BUG 36: 方法链 sink（如 ``this.getClass().getMethod(...)``）
                # 的 callee 只取到链首 ``getClass``，从表达式提链尾真 sink。
                if idx == total - 1 and step.code:
                    label = _last_call_name(step.code) or label
            else:
                label = step.function
            if not label:
                continue
            loc = f"{self._rel_path(step.file_path)}:{step.line}"
            if hops and hops[-1][0] == label:
                continue  # 同一函数内折叠
            hops.append((label, loc))

        if not hops:
            return ""
        parts = [f"{label} @ {loc}" for label, loc in hops]
        parts[-1] += "  ← SINK"
        return " -> ".join(parts)

    def _rel_path(self, path: str) -> str:
        """返回相对扫描目录的路径；文件在目录外时退化为 basename。"""
        try:
            return str(Path(path).resolve().relative_to(self.directory.resolve()))
        except (ValueError, OSError):
            return Path(path).name

    def _sink_categories(self, node_id: str) -> list[str]:
        """返回 sink 节点的所有类别（按逗号拆分）。

        ``injection_general`` 是兜底类别；当它和某个具体类别（如 ``xxe``）
        同时出现时，丢弃 ``injection_general`` 以避免同一路径产出重复 finding。
        """
        label = self._node_data(node_id).get("taint_sink", "") or ""
        cats = [c.strip() for c in label.split(",") if c.strip()]
        specific = [c for c in cats if c != "injection_general"]
        return specific or cats

    def _tainted_arg_position(self, node_ids: list[str]) -> int | None:
        """返回污点变量在 sink 调用实参中的下标（0-based）；无法确定返回 None。

        sink 必须是带 ``call_args`` 的 ``NODE_CALL_SITE``；污点载体取路径上
        进入 sink 的上一节点（通常是 ``variable_ref``）的 ``var_name``，再在
        实参表达式里做精确/属性后缀匹配。确定不了（sink 是 assignment、实参是
        复杂表达式、或经 CALLS 进入）时返回 ``None``，调用方放行。
        """
        if len(node_ids) < 2:
            return None
        sink = self._node_data(node_ids[-1])
        if sink.get("node_type") != NODE_CALL_SITE:
            return None
        args = [a.strip() for a in (sink.get("call_args") or [])]
        if not args:
            return None
        prev = self._node_data(node_ids[-2])
        prev_var = (prev.get("var_name") or "").strip()
        if not prev_var:
            return None
        for i, arg in enumerate(args):
            # 实参就是该变量（``query(sql)``），或实参是 ``obj.var`` 属性访问
            if arg == prev_var or arg.endswith("." + prev_var):
                return i
        return None

    def _sanitizers_on_path(self, node_ids: list[str], cat: str) -> list[str]:
        """沿路径匹配该漏洞类别的 sanitizer 模式（def-use 级）。

        BUG 38 (P0-1): 旧实现检查路径上所有节点，而 ``NODE_FUNCTION`` 的
        ``source`` 是整段函数体（截断 200 字符）—— 函数体内任意位置出现
        sanitizer 子串（如 ``html.escape(``）都会把整条路径误判为「已净化」，
        真实漏洞被成批吞掉。修复后的语义：

        - 只检查**语句级**节点（``CALL_SITE`` / ``ASSIGNMENT``），跳过
          function / parameter / variable_ref；
        - ``CALL_SITE`` 在能拿到「流入本调用的污点变量」和实参列表时，
          要求污点变量确实是实参之一（净化发生在污点真正流经处）；信息
          不完整时退回按表达式子串匹配，保持高召回。
        """
        rules = self.taint_loader.rules_for(self.language)
        category = rules.categories.get(cat)
        patterns = [p.lower() for p in (category.sanitizers if category else [])]
        if not patterns:
            return []
        found: list[str] = []
        prev: dict = {}
        for nid in node_ids:
            data = self._node_data(nid)
            ntype = data.get("node_type")
            if ntype == NODE_FUNCTION:
                prev = {}  # 函数节点不绑定「某个具体污点变量」
                continue
            text = ""
            if ntype == NODE_CALL_SITE:
                text = (data.get("expression") or "").lower()
                # def-use 级门控：已知污点变量且已知实参时，污点必须真在实参里
                prev_var = prev.get("var_name")
                args = [a.lower() for a in (data.get("call_args") or [])]
                if prev_var and args and prev_var not in args:
                    prev = data
                    continue
            elif ntype == NODE_ASSIGNMENT:
                text = (data.get("source") or "").lower()
            else:
                prev = data
                continue
            for pat in patterns:
                if pat and pat in text and pat not in found:
                    found.append(pat)
            prev = data
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
        sinks = sum(1 for _, d in graph.nodes(data=True) if d.get("taint_sink"))
        return ScanSummary(
            files=len(self._source_files()),
            functions=functions,
            endpoints=len(endpoints),
            findings=len(findings),
            sinks=sinks,
            blind_spots=len(blind_spots),
            truncated_categories=dict(self._truncated_categories),
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


def _severity_rank(severity: str) -> int:
    """严重级别 → 数值（越大越严重），用于多类别聚合时选主类别。"""
    return {"critical": 3, "high": 2, "medium": 1}.get(severity, 0)


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


def _last_call_name(expr: str) -> str:
    """从调用表达式取「链中最后一个被调用的方法名」。

    处理 ``this.getClass().getMethod(...)`` 这类方法链：callgraph 的 callee
    只取到链首 ``getClass``，而真正的 sink 是链尾 ``getMethod``。
    """
    m = re.findall(r"(?:\.|^)\s*([A-Za-z_$][\w$]*)\s*\(", expr)
    return m[-1] if m else ""


class _SourceCache:
    """按文件缓存全部行文本，供报告层兜底 ``code`` / 提取整函数源码。

    图节点只存精简属性（``source`` 截断、``variable_ref`` 无源码文本），
    报告层需要真实代码时按文件读一次并缓存，避免逐行重复 I/O。
    """

    def __init__(self) -> None:
        self._lines: dict[str, list[str]] = {}

    def _load(self, path: str) -> list[str]:
        cached = self._lines.get(path)
        if cached is None:
            try:
                cached = Path(path).read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                cached = []
            self._lines[path] = cached
        return cached

    def line(self, path: str, n: int) -> str:
        """返回第 *n* 行文本（去首尾空白）；行号越界返回空串。"""
        lines = self._load(path)
        if 1 <= n <= len(lines):
            return lines[n - 1].strip()
        return ""

    def slice(self, path: str, start: int, end: int) -> list[str]:
        """返回 ``[start, end]`` 闭区间的行文本列表（保留原缩进，越界自动截断）。"""
        lines = self._load(path)
        start = max(1, start)
        end = min(len(lines), end)
        if start > end:
            return []
        return lines[start - 1 : end]
