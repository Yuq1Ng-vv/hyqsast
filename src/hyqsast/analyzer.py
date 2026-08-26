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
from hyqsast.progress import PHASES, Progress
from hyqsast.schema import (
    BlindSpot,
    CanonicalFinding,
    ChainStep,
    Endpoint,
    EndpointMatch,
    Finding,
    NodeRef,
    RouteParam,
    ScanResult,
    ScanSummary,
    TaintElement,
    severity_for,
    vuln_display_name,
)

logger = logging.getLogger(__name__)

# 语言 → 默认尝试的框架提取器（也可通过 scan(framework=...) 显式指定）
_LANGUAGE_FRAMEWORKS: dict[str, list[str]] = {
    "python": ["flask", "django", "fastapi", "connexion"],
    "javascript": ["express"],
    "java": ["spring", "jaxrs"],  # N2: jaxrs 提取器接通，JAX-RS 应用不再接口全漏
}


def default_frameworks_for(language: str) -> list[str]:
    """返回某语言默认尝试的框架提取器候选（供 discover / MCP 层使用）。"""
    return list(_LANGUAGE_FRAMEWORKS.get(language, []))


# 单次扫描每个漏洞类别最多产出的 finding 数（防止大型项目输出爆炸）
_DEFAULT_MAX_FINDINGS_PER_CATEGORY = 50

# BUG 62: 前向 BFS 深度上限（与 _bfs_to_sink 默认 max_depth 保持一致）。sink
# 反向可达预筛（_sink_reachable）按同一深度反向扩张，保证预筛集是超集。
_BFS_MAX_DEPTH = 20

# P1-4: 「字符串模板」型注入 sink —— 危险载荷（SQL/命令/表达式串）只可能
# 出现在第一个参数，其余参数位是绑定/参数（如 ``query(sql, params)``），
# 污点流到这些位置不算语句注入，做位置门控。其余类别（xss/ssrf/nosql/
# ldap/...）载荷位置不固定，不做门控。
_SINK_STR_TEMPLATE_CATS: frozenset[str] = frozenset(
    {
        "sql_injection",
        # 门控前提「命令串只出现在第一个实参」对 ``Runtime.exec(args, envp)``
        # 不成立：envp（第 2 实参）在 OWASP cmdi 语义里是真实攻击面（37 个
        # cmdi FN 全经 envp 位置进 sink）。命令执行类 sink 的任一实参携带
        # taint 都算命中，故不做位置门控（见 docs/OWASP漏报清单.md §3）。
        "code_injection",
        "xpath_injection",
        "ssti",
    }
)

# pattern 型类别 → 同类 taint 型类别（评分侧算同一漏洞类别）。weak_crypto 与
# crypto_weakness 是同一弱加密漏洞的两种接法：crypto_weakness 是 taint 型
# （source 流入弱加密 API 才报），weak_crypto 是 pattern 型（硬编码弱算法字面量，
# BFS 够不到）。节点已被 taint 型同类报过时，pattern 型让位避免重复 finding
# （见 _pattern_findings 的 covered 去重）；评分侧靠 Finding.related_categories
# 让 score.py 把 weak_crypto 也算 crypto 命中。
# F7（对抗审查）: insecure_hash / weak_randomness 与 crypto_weakness 是同一
# 「弱哈希 / 弱随机 API 使用」的两种接法——`MessageDigest.getInstance("MD5"` 同时列在
# crypto_weakness（taint 型）与 insecure_hash（pattern 型）sinks，`new Random(` 同时
# 列在 crypto_weakness 与 weak_randomness。同节点被 taint 型报过时 pattern 型让位
# （去重）；被让位的类别并进该 taint finding 的 related_categories，保住 score.py
# 的 1:1 类别映射（hash→insecure_hash / weakrand→weak_randomness）不因去重丢命中。
_PATTERN_ALIAS_CATEGORIES: dict[str, tuple[str, ...]] = {
    "weak_crypto": ("crypto_weakness",),
    "insecure_hash": ("crypto_weakness",),
    "weak_randomness": ("crypto_weakness",),
}


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
        *,
        vuln_types: list[str] | None = None,
        enable_container_bridge: bool = False,
        enable_state_bridge: bool = False,
        progress: Progress | None = None,
    ) -> None:
        # 进度上报（默认 no-op；CLI 传 rich 渲染器，MCP 等 stdout 承载协议不传）
        self.progress = progress or Progress()
        self.directory = Path(directory).resolve()
        if not self.directory.is_dir():
            raise NotADirectoryError(f"目录不存在或不可读: {self.directory}")

        self.language = language or self._detect_language()
        self.frameworks = self._resolve_frameworks(framework)
        self.max_findings_per_category = max_findings_per_category
        self.include_blind_spots = include_blind_spots
        self.use_cache = use_cache
        self.severity_overrides = severity_overrides or {}
        # BUG 55: 两个过近似桥接默认关（真项目 800k finding 主凶）；高召回
        # 场景显式开启。见 CPGGraphBuilder.__init__ 注释与 OWASP 回归对比。
        self.enable_container_bridge = enable_container_bridge
        self.enable_state_bridge = enable_state_bridge
        # --vuln-types 定向扫描：只产指定 sink 类别的 finding（None = 全扫）。
        # 只在规则加载层收窄 sinks，source 与 sanitizer 全保留（见 taint_loader
        # _apply_sink_allowlist 注释）——BFS 从所有 source 出发、sanitizer
        # 跨类别共享，过滤 source/sanitizer 会漏报/误伤。
        self.vuln_types = list(vuln_types) if vuln_types else None
        # T2（对抗审查）: _source_files 结果缓存（directory/language init 后不变，
        # _extract_endpoints 与 _summarize 各调一次全目录 rglob，70k 文件浪费）。
        self._source_files_cache: list[str] | None = None

        self.parser = Parser(languages=[self.language])
        # rules_paths=None 时用内置 taint_rules.yaml；传入文件/目录则在
        # 内置规则之上追加合并（见 TaintRuleLoader 的 merge 语义）
        self.taint_loader = TaintRuleLoader(
            rules_paths=rules_paths,
            sink_categories_allowlist=set(vuln_types) if vuln_types else None,
        )
        # --vuln-types 类别名校验：用 loader 过滤前快照的全量 sink 类别
        # （含 rules/ 额外规则），而非 SEVERITY_MAP——YAML 才是单一事实源，
        # 能捕获 --rules 自定义类别。抛 ValueError 与 _resolve_frameworks
        # 对未知框架的约定一致。
        if vuln_types:
            known = self.taint_loader.known_sink_categories(self.language)
            unknown = sorted({t for t in vuln_types if t not in known})
            if unknown:
                raise ValueError(
                    f"未知漏洞类别: {unknown}（语言 {self.language} 可用: {sorted(known)}）"
                )
        self.graph_builder = CPGGraphBuilder(
            self.parser,
            taint_loader=self.taint_loader,
            enable_container_bridge=enable_container_bridge,
            enable_state_bridge=enable_state_bridge,
        )
        # 报告层读源码的按文件缓存（兜底 code / 提取整函数源码）
        self._src = _SourceCache()
        # P0-2: 被 max_findings_per_category 截断的类别计数（_build_findings 填充）
        self._truncated_categories: dict[str, int] = {}
        # BUG 62: _callee_at_map 的惰性缓存（汇总阶段 _render_chain 复用）
        self._callee_at: dict[tuple[str, int], str] | None = None

    # ── 入口 ────────────────────────────────────────────────────────────

    def run(self) -> ScanResult:
        """执行完整扫描，返回结构化结果。"""
        # 进度上报：只在阶段边界与长循环里上报，渲染细节见 progress.py
        prog = self.progress
        prog.setup(list(PHASES))

        prog.begin("建图")
        self.graph_builder.add_directory(self.directory, use_cache=self.use_cache, progress=prog)

        prog.begin("接口提取")
        endpoints = self._extract_endpoints()
        prog.stage("注入路由参数 source")
        self._inject_route_param_sources(endpoints)

        prog.begin("污点传播")
        findings = self._build_findings()
        prog.stage("关联接口")
        self._link_findings(findings, endpoints)

        # 汇总四个子阶段，慢的按工作单元粒度 set_total+step（与建图一致）：
        # 规范版报告/污点元素清单都是长循环，零 step 会卡在上一子阶段的 % 且
        # ETA 因无速度样本显示 -:--:--。盲区清单、汇总计数各单步。
        prog.begin("汇总")
        prog.stage("盲区清单")
        blind_spots = self._build_blind_spots(endpoints) if self.include_blind_spots else []
        prog.set_total(1)
        prog.step(1)
        prog.stage("规范版报告")
        canonical = self._build_canonical_findings(findings, progress=prog)
        prog.stage("污点元素清单")
        taint_elements = self._collect_taint_elements(findings, progress=prog)
        prog.stage("汇总计数")
        summary = self._summarize(endpoints, findings, blind_spots)
        prog.set_total(1)
        prog.step(1)
        prog.end()

        return ScanResult(
            summary=summary,
            endpoints=endpoints,
            findings=findings,
            blind_spots=blind_spots,
            canonical_findings=canonical,
            taint_elements=taint_elements,
        )

    # ── 接口提取 ────────────────────────────────────────────────────────

    def _extract_endpoints(self) -> list[Endpoint]:
        """用框架提取器枚举 HTTP 接口。"""
        files = self._source_files()
        result: list[Endpoint] = []
        prog = self.progress
        prog.stage("提取接口")
        prog.set_total(len(files) * len(self.frameworks))

        for fw_name in self.frameworks:
            extractor = get_extractor(fw_name, self.parser)
            for file_path in files:
                try:
                    if extractor.detect(file_path):
                        for ep in extractor.extract_routes(file_path):
                            result.append(self._to_endpoint(ep))
                except (OSError, ValueError):
                    pass
                prog.step(1)

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

    def _inject_route_param_sources(self, endpoints: list[Endpoint]) -> None:
        """把接口 handler 的声明参数标记为 source。

        建图（step 1）时 Python 函数参数从不被标 source；接口提取（step 2）
        拿到 handler + 参数名后补标（``mark_params_as_sources``），BFS
        （step 3）才能从路由参数一路溯源到 sink。Connexion / OpenAPI-First
        应用的路由参数只存在于 openapi yaml，这是它们唯一的污点入口。
        """
        specs = [
            (e.file_path, e.handler_func, [p.name for p in e.params])
            for e in endpoints
            if e.handler_func
        ]
        self.graph_builder.mark_params_as_sources(specs)

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
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        per_category: dict[str, int] = defaultdict(int)
        # P0-2: 记录每个类别因上限被跳过的候选数（供截断可见化）
        skipped: dict[str, int] = defaultdict(int)
        prog = self.progress

        if source_ids and sink_set:
            prog.stage("源点前向 BFS")
            # BUG 62: sink 反向可达预筛 —— 一次反向 BFS 算出 R =「_BFS_MAX_DEPTH
            # 跳内能到任一 sink」的节点集。源点 ∉ R ⇒ 前向 BFS 必然 0 条路径
            # （够不到任何 sink），整源跳过；R 同时传进 _bfs_to_sink 剪枝后继。
            # 语义恒等：被跳过的源点本就会产出空结果；剪掉的节点不在任何合法
            # src→sink 路径上，跳过/剪枝不改变任何 finding（见 _sink_reachable）。
            reachable = self._sink_reachable(sink_set, _BFS_MAX_DEPTH)
            # N3: 早退条件必须覆盖「图里存在 sink 的全部类别」。原来只查
            # per_category 里已见的类别：source 排序导致某类别先饱和时提前
            # break，排在后面的类别（还没轮到它的 source）被整类饿死（FN）。
            # 换成 sink 类别全集后，未产出类别 get()=0 < cap → 不会提前 break；
            # 已饱和类别仍能触发早退（预算保护不丢）。
            target_categories = {cat for n in sink_set for cat in self._sink_categories(n)}
            prog.set_total(len(source_ids))
            for src in source_ids:
                prog.step(1)
                if src not in reachable:
                    continue
                if per_category and all(
                    per_category.get(c, 0) >= self.max_findings_per_category
                    for c in target_categories
                ):
                    break
                for node_ids, edge_types in self._bfs_to_sink(src, sink_set, reachable=reachable):
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
                        # 精去重：同一 (类别, 源位置, sink 位置) 只报一条。
                        # 不同 source → 同一 sink 的真实调用链保留（BUG 53 已
                        # 保证这些链是真边，不该被砍）。
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

        # P1-5: 相同 (src,sink) 的多类别候选合并为一条主 finding
        prog.stage("聚合多类别")
        findings = self._aggregate_multi_category(findings)

        # 非污点流 pattern 型漏洞（taint_rules.yaml 的 ``pattern_sinks`` 标记，
        # 如 crypto_weakness / secure_cookie）：sink 节点没有 source 流入，BFS
        # 永远够不到；类别本身代表危险 API 使用，对每个被标上该类别的节点
        # 无条件产出 finding（source==sink==该节点）。放在聚合之后追加，避免
        # 与 BFS finding 的 (src,sink) 位置碰撞被误合并。
        # BUG 49: pattern 型追加前的「同类 taint 已报过」位置去重。把 taint 型
        # finding 的 (sink 文件, sink 行, 类别[含 related_categories 别名]) 记成
        # covered 集，pattern 型发现里同一位置命中同类别的节点就跳过（如某测试
        # 的 Cipher.getInstance("DES…") 已由 taint 型 crypto_weakness 报过，就不
        # 再补一条 weak_crypto，避免 ~217 个已命中测试各多一条重复）。
        prog.stage("pattern 型漏洞")
        covered: set[tuple[str, int, str]] = set()
        # F7: (sink 文件, sink 行) → taint finding 列表，供 _pattern_findings 去重时
        # 把被让位的 pattern 类别并进对应 taint finding 的 related_categories。
        findings_by_pos: dict[tuple[str, int], list[Finding]] = {}
        for f in findings:
            if f.sink and f.sink.file_path and f.sink.line:
                pos = (f.sink.file_path, f.sink.line)
                covered.add((pos[0], pos[1], f.vuln_type))
                for rc in f.related_categories:
                    covered.add((pos[0], pos[1], rc))
                findings_by_pos.setdefault(pos, []).append(f)
        pattern_findings, pattern_skipped = self._pattern_findings(covered, findings_by_pos)
        if pattern_skipped:
            self._truncated_categories = dict(pattern_skipped)
        findings.extend(pattern_findings)

        # P0-2: 把截断计数暴露给汇总层；0 的类别不保留
        if skipped:
            for cat, n in skipped.items():
                self._truncated_categories[cat] = self._truncated_categories.get(cat, 0) + n
        self._truncated_categories = {k: v for k, v in self._truncated_categories.items() if v > 0}
        return findings

    def _pattern_findings(
        self,
        covered: set[tuple[str, int, str]] | None = None,
        findings_by_pos: dict[tuple[str, int], list[Finding]] | None = None,
    ) -> tuple[list[Finding], dict[str, int]]:
        """非污点流 pattern 型漏洞的 finding + 截断计数。

        这类类别（``taint_rules.yaml`` 的 ``pattern_sinks`` 标记）的 sink 节点
        没有 source 流入，前向 BFS 永远够不到 —— 但它们代表「危险 API 使用
        本身」（弱随机数 / 弱哈希 / cookie 未加 secure 等），与是否有用户
        输入流入无关。规则：对被标上该类别的每个节点无条件产出 finding，
        ``source==sink==该节点``（调用链单步，edge_type=PATTERN），召回优先。

        放在 :meth:`_aggregate_multi_category` 之后追加，避免 pattern finding
        的 (src,sink) 位置与 BFS finding 的 sink 位置碰撞被误合并。

        ``covered``：已有 taint 型 finding 的 (文件, 行, 类别[含别名]) 集合
        （见 :meth:`_build_findings` 的 BUG 49 注记）。节点命中 pattern 型类别
        但同位置已被其 taint 型同类（``_PATTERN_ALIAS_CATEGORIES``）报过时，
        跳过，避免同一漏洞重复报（如 weak_crypto 让位 crypto_weakness）。
        """
        pattern_cats = self.taint_loader.pattern_categories(self.language)
        if not pattern_cats:
            return [], {}
        graph = self.graph_builder.graph
        out: list[Finding] = []
        per_category: dict[str, int] = defaultdict(int)
        skipped: dict[str, int] = defaultdict(int)
        for nid in sorted(graph.nodes):
            data = graph.nodes[nid]
            sink_cats = (data.get("taint_sink") or "").split(",")
            hits = [c for c in sink_cats if c in pattern_cats]
            if not hits:
                continue
            # 位置去重：仅当有 covered 集（taint 型已产出）且节点位置可定位时评估。
            node_file: str | None = None
            node_line: int | None = None
            if covered:
                node_file, node_line = self._node_fields(data)[:2]
            for cat in hits:
                if per_category[cat] >= self.max_findings_per_category:
                    skipped[cat] += 1
                    continue
                if covered and node_file and node_line:
                    if any(
                        (node_file, node_line, alias) in covered
                        for alias in _PATTERN_ALIAS_CATEGORIES.get(cat, ())
                    ):
                        # F7: 被让位的 pattern 类别并进同位置 taint finding 的
                        # related_categories —— score.py 类别映射 1:1（hash→
                        # insecure_hash / weakrand→weak_randomness），只去重不折算
                        # 会让该测试从 hash/weakrand 类消失（TPR 掉）。取同位置
                        # vuln_type==别名的 taint finding，把 cat 追加进去。
                        taint_f = None
                        if findings_by_pos:
                            taint_f = next(
                                (
                                    f
                                    for f in findings_by_pos.get((node_file, node_line), [])
                                    if f.vuln_type in _PATTERN_ALIAS_CATEGORIES.get(cat, ())
                                ),
                                None,
                            )
                        if taint_f is not None and cat not in taint_f.related_categories:
                            taint_f.related_categories.append(cat)
                        continue
                finding = self._pattern_node_to_finding(nid, cat)
                if finding is None:
                    continue
                per_category[cat] += 1
                out.append(finding)
        out.sort(key=lambda f: (f.vuln_type, f.sink.file_path, f.sink.line))
        return out, skipped

    def _pattern_node_to_finding(self, node_id: str, cat: str) -> Finding | None:
        """从被标上 pattern 型类别的图节点构建 Finding（source==sink==节点）。"""
        data = self._node_data(node_id)
        if not data:
            return None
        file_path, line, function, code = self._node_fields(data)
        if not (file_path and line):
            return None
        ref = NodeRef(
            file_path=file_path,
            line=line,
            function=function,
            code=code,
            category=cat,
        )
        severity = self.severity_overrides.get(cat) or severity_for(cat)
        # BUG 49: pattern 型类别（weak_crypto）带上同类 taint 型类别
        # （crypto_weakness）作 related_categories，使 score.py 的类别命中判断
        # 把两者都算同一类别；同时供 _pattern_findings 的 covered 去重互认。
        aliases = list(_PATTERN_ALIAS_CATEGORIES.get(cat, ()))
        return Finding(
            id=f"{cat}-{file_path}:{line}",
            vuln_type=cat,
            severity=severity,
            related_categories=aliases,
            source=ref,
            sink=ref,
            call_chain=[
                ChainStep(
                    file_path=file_path,
                    line=line,
                    function=function,
                    code=code,
                    kind=data.get("node_type", ""),
                    edge_type="PATTERN",
                )
            ],
        )

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
        reachable: set[str] | None = None,
    ) -> list[tuple[list[str], list[str]]]:
        """从 *src* 沿 DATA_FLOW/CALLS 前向 BFS 到任一 sink。

        Returns: ``(节点 id 列表, 边类型列表)`` 的列表（每 sink 最多 ``max_paths`` 条）。
        """
        graph = self.graph_builder.graph
        results: list[tuple[list[str], list[str]]] = []
        visited: set[str] = {src}
        # BUG 47: 预算按 sink 独立计，而不是全 BFS 共享。旧的 ``while len(results)
        # < max_paths`` 让先到达的 5 个 sink 吃光全局预算——加边引入新 sink
        # （如多行实参桥接新连通的一个 println sink）会把原有 sink 的记录名额
        # 挤掉，表现为「加边反而丢 finding」（非单调）。per_sink 给每个 sink
        # 独立的 max_paths 个记录槽，新增 sink 不再偷别人的。
        per_sink: dict[str, int] = defaultdict(int)
        queue: deque[tuple[str, list[str], list[str]]] = deque([(src, [src], [])])

        while queue:
            cur, node_path, edge_path = queue.popleft()
            if len(node_path) > max_depth:
                continue

            if cur in sink_set and cur != src and per_sink[cur] < max_paths:
                # 记录路径后【继续扩张】，不要终止：sink 节点可能是中间节点
                # （如被过宽规则误标成 sink 的赋值节点 ``String s = foo.build(p)``）。
                # 在此终止会遮蔽下游真 sink（漏报面 K 类：sink 遮蔽下游真 sink）——
                # ``s`` 后面跟着的 ``exec(s)`` 就永远探索不到。
                results.append((node_path, edge_path))
                per_sink[cur] += 1

            for succ in graph.successors(cur):
                # BUG 62: sink 走廊剪枝 —— reachable 外的节点到不了任何 sink，
                # 任何合法路径都不经过它们，剪掉不改结果，只省扩张。
                if reachable is not None and succ not in reachable:
                    continue
                etype = self._edge_type(cur, succ)
                if etype is None:
                    continue
                if succ in visited:
                    # BUG 47: 已访问节点恰是 sink 时，允许以另一条进入边再记录一次。
                    # 先到先得会让「第一条到达路径」占住 sink；若该路径被位置门控
                    # （_tainted_arg_position >= 1，参数绑定位不算注入）挡掉，合法
                    # 的 position-0 路径就再也不会被记录——同样是加边丢 finding 的
                    # 非单调问题。这里给每个 sink 补记录到 max_paths 条进入路径。
                    if succ in sink_set and succ != src and per_sink[succ] < max_paths:
                        results.append(([*node_path, succ], [*edge_path, etype]))
                        per_sink[succ] += 1
                    continue
                visited.add(succ)
                queue.append((succ, [*node_path, succ], [*edge_path, etype]))

        return results

    def _sink_reachable(self, sink_set: set[str], max_depth: int) -> set[str]:
        """sink 反向可达集 R（BUG 62）：反向 BFS 求「≤max_depth 跳内能到任一
        sink」的节点全集，供源点预筛与前向 BFS 剪枝。

        语义保证（与 _build_findings 的跳源、_bfs_to_sink 的剪枝配套）：
        - 源点 ∉ R ⇒ 前向 BFS 沿 DATA_FLOW/CALLS 最多 max_depth 跳够不到任何
          sink ⇒ 必然 0 条路径，整源跳过不改变任何 finding（产出本就为空）。
        - 任一合法 src→sink 路径（≤max_depth 跳）的每个中间节点都在 R 内——
          该路径本身就把每个节点带到了 sink。故前向 BFS 以 R 为后继白名单
          剪枝不会丢任何路径，结果恒等。
        - 反向多跑满 max_depth 跳：前向记录路径最长 max_depth+1 个节点
          （visited 重入分支），即 ≤max_depth 条边，R 是严格超集，安全。
        """
        graph = self.graph_builder.graph
        r: set[str] = set(sink_set)
        frontier: set[str] = set(sink_set)
        for _ in range(max_depth):
            nxt: set[str] = set()
            for cur in frontier:
                for pred in graph.predecessors(cur):
                    if pred in r:
                        continue
                    if self._edge_type(pred, cur) is None:
                        continue
                    nxt.add(pred)
            if not nxt:
                break
            r |= nxt
            frontier = nxt
        return r

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

    def _link_findings(self, findings: list[Finding], endpoints: list[Endpoint]) -> None:
        """把每条 finding 关联到最可能的接口（原地打上 ``f.endpoint``）。

        匹配依据见 :meth:`_endpoint_match_for_finding`；供 LLM 下游把漏洞
        直接对应到具体路由，无需自己 join ``endpoints`` 表。

        T12 (性能): 原实现每 finding 两次全 endpoints 列表推导 —— O(findings ×
        endpoints)，3.67M findings × 数千接口 = 10^10 元素比较。改为预建两个
        保序索引（O(endpoints)），每 finding 两次 O(1) 查表；``candidates[0]``
        仍取 endpoints 原序首个命中，语义逐字节一致。
        """
        by_file_handler: dict[tuple[str, str], list[Endpoint]] = {}
        by_file: dict[str, list[Endpoint]] = {}
        for ep in endpoints:
            by_file_handler.setdefault((ep.file_path, ep.handler_func), []).append(ep)
            by_file.setdefault(ep.file_path, []).append(ep)
        for f in findings:
            f.endpoint = self._endpoint_match_for_finding(f, by_file_handler, by_file)

    def _endpoint_match_for_finding(
        self,
        f: Finding,
        by_file_handler: dict[tuple[str, str], list[Endpoint]],
        by_file: dict[str, list[Endpoint]],
    ) -> EndpointMatch:
        """返回 finding 与接口的对应关系（``exact`` / ``same_file`` / ``unmatched``）。

        以 finding 的 source（污点入口）为准：优先 ``(文件, handler)`` 精确
        匹配，退回同文件第一个接口，都没有则 ``unmatched``。接口摘要字段
        冗余展开（不引用 endpoints 下标），保证 LLM 单条 finding 即可自洽。
        """
        src = f.source
        exact = by_file_handler.get((src.file_path, src.function), [])
        candidates = exact or by_file.get(src.file_path, [])
        if not candidates:
            return EndpointMatch(match="unmatched")
        ep = candidates[0]
        return EndpointMatch(
            match="exact" if exact else "same_file",
            route=ep.route,
            methods=list(ep.methods),
            handler_func=ep.handler_func,
            file_path=ep.file_path,
            line=ep.line,
            framework=ep.framework,
            params=list(ep.params),
        )

    def _build_canonical_findings(
        self, findings: list[Finding], progress: object | None = None
    ) -> list[CanonicalFinding]:
        """构建规范版报告：sink 函数完整源码 + 函数级真实调用链 + 接口信息。

        与正常报告一一对应，但更面向人工复核：调用链折叠成函数级
        ``x -> y -> z -> sink``，sink 函数整段贴出并标出 sink 行。

        ``progress``（可选）：按 finding 逐条 set_total+step。每个 finding 要
        遍历全图找 sink 函数（``_sink_function_block``）+ 渲染调用链 + 读源码
        —— finding 数大时是慢循环，零 step 会让「规范版报告」子阶段卡在 25%
        且 ETA 无速度样本（-:--:--）。
        """
        if progress is not None:
            progress.set_total(len(findings) or 1)
        out: list[CanonicalFinding] = []
        for f in findings:
            out.append(
                CanonicalFinding(
                    id=f.id,
                    vuln_type=f.vuln_type,
                    vuln_name=(
                        f"{vuln_display_name(f.vuln_type)} @ {f.sink.file_path}:{f.sink.line}"
                    ),
                    endpoint=self._render_endpoint(f.endpoint),
                    source_function=self._source_function_block(f),
                    sink_function=self._sink_function_block(f),
                    call_chain=self._render_chain(f),
                )
            )
            if progress is not None:
                progress.step(1)
        return out

    @staticmethod
    def _render_endpoint(m: EndpointMatch) -> str:
        """把 :class:`EndpointMatch` 渲染成规范版报告的接口串；``unmatched`` 返回空串。"""
        if m.match == "unmatched":
            return ""
        methods = "/".join(m.methods) or "ANY"
        return f"{methods} {m.route} @ {m.file_path}:{m.line} ({m.handler_func})"

    def _function_block(self, node: NodeRef, label: str, vuln_type: str, margin: int = 5) -> str:
        """返回 *node* 所在函数的完整源码：带行号，node 行标 ``▶`` 并尾注类别。

        在图中找 ``file_path`` 相同且包含 node 行的函数节点（取范围最小者）；
        找不到时退化为 node 行 ±*margin* 行的窗口。
        """
        best: tuple[int, int] | None = None
        # BUG 62: 用文件索引（_file_node_ids，含 pickle 恢复回退）代替全图扫描
        # —— 每条 finding 从 O(全图) 降到 O(本文件节点)。汇总阶段原先
        # O(findings×全图节点)。
        for nid in self.graph_builder._file_node_ids(node.file_path):
            data = self.graph_builder.graph.nodes[nid]
            if data.get("node_type") != NODE_FUNCTION:
                continue
            start = data.get("start_line") or 0
            end = data.get("end_line") or 0
            if start and end and start <= node.line <= end:
                if best is None or (end - start) < (best[1] - best[0]):
                    best = (start, end)
        if best is None:
            start, end = max(1, node.line - margin), node.line + margin
        else:
            start, end = best

        lines = self._src.slice(node.file_path, start, end)
        width = len(str(end))
        out: list[str] = []
        for n, text in enumerate(lines, start=start):
            flag = "▶" if n == node.line else " "
            # rstrip：源码行尾若有空白，紧贴代码放标注更整洁
            suffix = f"  // ← {label}: {vuln_type}" if n == node.line else ""
            out.append(f"{flag} {n:>{width}} | {text.rstrip()}{suffix}")
        return "\n".join(out)

    def _sink_function_block(self, f: Finding, margin: int = 5) -> str:
        """返回 sink 点所在函数的完整源码（见 :meth:`_function_block`）。"""
        return self._function_block(f.sink, "SINK", f.vuln_type, margin)

    def _source_function_block(self, f: Finding, margin: int = 5) -> str:
        """返回 source 点所在函数的完整源码（见 :meth:`_function_block`）。"""
        return self._function_block(f.source, "SOURCE", f.vuln_type, margin)

    def _callee_at_map(self) -> dict[tuple[str, int], str]:
        """(file, line) → callee 的惰性缓存（BUG 62）。

        原实现 _render_chain 每条 finding 全图扫一遍构建同一张表 —— 汇总阶段
        O(findings×全图节点)。这里首次调用构建一次（O(全图)），此后全部 finding
        复用。构建项与原逐条全扫完全一致（同 key 后写胜出、插入序相同），
        结果恒等。
        """
        if self._callee_at is None:
            callee_at: dict[tuple[str, int], str] = {}
            for _, data in self.graph_builder.graph.nodes(data=True):
                if (
                    data.get("node_type") == NODE_CALL_SITE
                    and data.get("callee")
                    and data.get("line")
                ):
                    callee_at[(data.get("file_path", ""), data.get("line"))] = data["callee"]
            self._callee_at = callee_at
        return self._callee_at

    def _render_chain(self, f: Finding) -> str:
        """把 finding 的节点路径折叠成函数级真实链 ``x -> y -> z -> sink``。

        每个 hop 取「所在函数（call_site 取被调用的 callee）」+ 相对扫描目录的
        ``file:line``；同一函数内的连续步骤折叠为一步。
        """
        # (file, line) → callee：call_site 步骤折叠成「被调用的函数」hop
        # BUG 62: 全图 callee 索引惰性构建一次（_callee_at_map），不再每条
        # finding 重扫全图（汇总阶段原 O(findings×全图节点)）。
        callee_at = self._callee_at_map()

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

    # ── 污点元素清单（漏报排查） ────────────────────────────────────────

    def _collect_taint_elements(
        self, findings: list[Finding], progress: object | None = None
    ) -> list[TaintElement]:
        """枚举规则引擎在整张图上识别到的 source / sink 点。

        与 finding 正交：每个被打上 ``taint_source`` / ``taint_sink`` 标签的
        节点都记一条（多类别节点逐类别展开），并用 ``covered`` 标注该位置
        是否出现在某条已产出 finding 的 source/sink 里 —— 排查漏报时
        「有 sink 规则、却没接住任何 finding」的裸 sink 一眼可见。

        ``progress``（可选）：按「有标签节点」粒度 set_total+step（有标签节点
        才是本循环的实际工作量，无标签节点秒过）。大图全量节点是慢循环，零
        step 会让「污点元素清单」子阶段同样卡死在本阶段 % 上。
        """
        rules = self.taint_loader.rules_for(self.language)
        src_covered = {(f.source.file_path, f.source.line) for f in findings}
        sink_covered = {(f.sink.file_path, f.sink.line) for f in findings}

        if progress is not None:
            # 预扫一遍数有标签节点数作 total，避免循环内 continue 跳过导致
            # total 与实际 step 数不符、子阶段条爬不到 100%。
            n_labeled = sum(
                1
                for _n, d in self.graph_builder.graph.nodes(data=True)
                if d.get("file_path")
                and d.get("line")
                and (d.get("taint_source") or d.get("taint_sink"))
            )
            progress.set_total(n_labeled or 1)

        elements: list[TaintElement] = []
        for _nid, data in self.graph_builder.graph.nodes(data=True):
            # T1（对抗审查）: 先判标签再求值字段 —— 无标签节点占绝大多数，先调
            # _node_fields（含 code 读回兜底）再弃是纯浪费；输出等价（被跳过的
            # 节点本就没有标签）。
            label = data.get("taint_source") or data.get("taint_sink")
            if not label:
                continue
            file_path, line, function, code = self._node_fields(data)
            if not file_path or not line:
                continue
            ntype = data.get("node_type", "")
            # source 优先：被标为 source 的节点不再评估 sink（与打标签一致）
            kind = "source" if data.get("taint_source") else "sink"
            covered = (file_path, line) in (src_covered if kind == "source" else sink_covered)
            for cat in _split_taint_labels(label):
                # BUG 41: 标签可能来自缓存残留（建图时规则集含该类别，本次
                # 不含），类别缺失时按空模式处理，不抛错。
                category = rules.categories.get(cat)
                if category is None:
                    matched: list[str] = []
                else:
                    pats = category.sources if kind == "source" else category.sinks
                    matched = [p for p in pats if p and p in code]
                elements.append(
                    TaintElement(
                        kind=kind,
                        category=cat,
                        file_path=file_path,
                        line=line,
                        function=function,
                        code=code,
                        node_type=ntype,
                        patterns=matched,
                        covered=covered,
                    )
                )
            if progress is not None:
                progress.step(1)
        elements.sort(key=lambda e: (e.kind, e.category, e.file_path, e.line))
        return elements

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
        sources = sum(1 for _, d in graph.nodes(data=True) if d.get("taint_source"))
        sinks = sum(1 for _, d in graph.nodes(data=True) if d.get("taint_sink"))
        return ScanSummary(
            files=len(self._source_files()),
            functions=functions,
            endpoints=len(endpoints),
            findings=len(findings),
            sources=sources,
            sinks=sinks,
            blind_spots=len(blind_spots),
            truncated_categories=dict(self._truncated_categories),
        )

    # ── 内部工具 ────────────────────────────────────────────────────────

    def _source_files(self) -> list[str]:
        """返回目录下、匹配目标语言的所有源码文件（绝对路径）。"""
        # T2（对抗审查）: 结果与 self.directory/self.language 绑定（init 后不变），
        # 缓存避免每次调用重做全目录 rglob + 排序（70k 文件级项目浪费两次遍历）。
        if self._source_files_cache is None:
            files: list[str] = []
            for entry in sorted(self.directory.rglob("*")):
                if not entry.is_file():
                    continue
                if any(p.startswith(".") or p == "__pycache__" for p in entry.parts):
                    continue
                if detect_by_extension(str(entry)) == self.language:
                    files.append(str(entry))
            self._source_files_cache = files
        return self._source_files_cache

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


def _split_taint_labels(label: str) -> list[str]:
    """拆分逗号分隔的 ``taint_source`` / ``taint_sink`` 类别标签。

    与 :meth:`Analyzer._sink_categories` 不同：这里保留全部类别（含
    ``injection_general``），供元素清单如实呈现规则引擎的标记结果。
    """
    return [c.strip() for c in label.split(",") if c.strip()]


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
