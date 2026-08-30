"""cpg/dataflow.py — Intra- and inter-procedural data-flow analysis.

Builds on the call-graph layer to track how variables flow through a
codebase: definition-use chains within functions, data flow across
function boundaries, and taint propagation from sources to sinks.

See DESIGN-IMPLEMENTATION.md Section 2.4 for the interface specification.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tree_sitter import Node, Tree

from hyqsast.cpg.traversal import Traverser, _loc, _source

if TYPE_CHECKING:
    from hyqsast.cpg.callgraph_builder import CallGraphBuilder
    from hyqsast.cpg.languages.base import LanguageProvider
    from hyqsast.cpg.parser import Parser
    from hyqsast.cpg.types import FunctionNode

from hyqsast.cpg.types import DataFlowStep, DefUsePair

# ─── 流敏感重赋值杀毒 helper（BUG 152）──────────────────────────────────────

# 复合/增强赋值算子。Python ``augmented_assignment``、JS
# ``augmented_assignment_expression`` 是独立 node type；Java 则是
# ``assignment_expression`` 子节点里的匿名算子 token（children[1]，命名算子
# field 为 None）。复合赋值隐式读旧值（``x += y`` ≡ ``x = x + y``），恒为
# 自引用 def——不可被当作杀毒 def，其链也要保留。
_COMPOUND_ASSIGNMENT_OPS = frozenset(
    {"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>="}
)

# 「条件/循环门控」节点类型（per-language）。杀毒 def 必须与被杀 def 处于
# 严格相同的门控上下文（直落，中间无 if/for/while/switch/catch/lambda），
# 否则 Dk 是条件执行、不能杀 Di（Interrupt_005/007_T 护栏）。try/finally
# 刻意**不**计入门控：ant 目标 FP 全在 try 块内直落，两 def 同在 try 仍同
# 上下文可杀。门控越保守 = 越不误杀 FN。
_GATE_TYPES: dict[str, frozenset[str]] = {
    "java": frozenset(
        {
            "if_statement",
            "for_statement",
            "enhanced_for_statement",
            "while_statement",
            "do_statement",
            "switch_expression",
            "catch_clause",
            "lambda_expression",
        }
    ),
    "python": frozenset(
        {
            "if_statement",
            "for_statement",
            "while_statement",
            "with_statement",
            "try_statement",
            "except_clause",
        }
    ),
    "javascript": frozenset(
        {
            "if_statement",
            "for_statement",
            "for_in_statement",
            "for_of_statement",
            "while_statement",
            "do_statement",
            "switch_statement",
            "catch_clause",
            "arrow_function",
        }
    ),
}


def _loc_line(loc: str) -> int | None:
    """从 ``file:line`` 位置串提取行号（rsplit 兼容 Windows 盘符冒号）。"""
    try:
        return int(loc.rsplit(":", 1)[-1])
    except (ValueError, AttributeError):
        return None


def _is_compound_assignment(node: Node) -> bool:
    """判断复合/增强赋值（``x += y`` 等，隐式读旧值）。

    Python ``augmented_assignment`` / JS ``augmented_assignment_expression``
    是独立 node type；Java ``assignment_expression`` 的算子是无名 token
    （``child_by_field_name("operator")`` 为 None，children[1] 是算子）。
    """
    if node.type in ("augmented_assignment", "augmented_assignment_expression"):
        return True
    if node.type == "assignment_expression":
        return any(not c.is_named and c.type in _COMPOUND_ASSIGNMENT_OPS for c in node.children)
    return False


def _assignment_rhs(node: Node) -> Node | None:
    """返回赋值 def 节点的 RHS 子树，取不到返回 None。"""
    right = node.child_by_field_name("right")
    if right is not None:
        return right
    if node.type == "named_expression":  # Python 海象 ``x := expr``
        return node.child_by_field_name("value")
    if node.type == "local_variable_declaration":  # Java ``int x = ...``
        for c in node.named_children:
            if c.type == "variable_declarator":
                return c.child_by_field_name("value")
    if node.type == "variable_declarator":  # JS ``var x = ...``
        return node.child_by_field_name("value")
    return None


def _is_plain_var_def(node: Node) -> bool:
    """该赋值 def 是否**覆盖变量绑定**（LHS 是裸标识符）。

    ``a.b = t`` / ``a[i] = t`` 是**字段/容器写**——改的是对象字段/元素，
    不覆盖宿主变量 ``a`` 的引用绑定（漏报面 A 类字段状态写读正是靠把污点
    写进宿主再接后续读取）。截断只对真变量重写生效，字段/容器写不得当
    「杀毒 def」截断宿主链（BUG 152 回归修复：ant 别名维度 8 个 TP 曾因此
    被误杀）。声明/增强 for/海象恒为新绑定。
    """
    if node.type in ("local_variable_declaration", "enhanced_for_statement", "variable_declarator"):
        return True
    if node.type == "named_expression":  # Python ``x := expr``
        return True
    if node.type in (
        "assignment",
        "augmented_assignment",
        "assignment_expression",
        "augmented_assignment_expression",
    ):
        left = node.child_by_field_name("left")
        return left is not None and left.type == "identifier"
    return False


# 循环「后置位」字段（per-language）：cond/update 在 body **之后**求值（loop
# backedge 可达），文本在前的 use 仍读得到后文 body 的 def；init 是前置位
# （先于 body），照切。do-while 的 cond 恒在 body 后。Python for 无 cond/update。
_LOOP_POST_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "java": {
        "for_statement": ("condition", "update"),
        "while_statement": ("condition",),
        "do_statement": ("condition",),
    },
    "javascript": {
        "for_statement": ("condition", "increment"),
        "while_statement": ("condition",),
        "do_statement": ("condition",),
    },
    "python": {"while_statement": ("condition",)},
}


def _loop_post_use(node: Node, language: str) -> bool:
    """use 是否落在某个循环的 cond/update 后置位（backedge 可达）。

    仅用于反向 use（行 < def 行）豁免：``for (;; exec(a)) { a = cmd; }`` 的
    exec 在 update 位，语义上 body 之后执行，行序却更靠前，不能切
    （ForStatement_update_001_T 真漏洞）。init/body 前置位照切
    （ForStatement_init_002_F 假阳性）。
    """
    fields = _LOOP_POST_FIELDS.get(language, {})
    cur = node.parent
    while cur is not None:
        names = fields.get(cur.type)
        if names:
            for f in names:
                fld = cur.child_by_field_name(f)
                if (
                    fld is not None
                    and fld.start_byte <= node.start_byte
                    and node.end_byte <= fld.end_byte
                ):
                    return True
        cur = cur.parent
    return False


_EMPTY_FSET: frozenset[int] = frozenset()


def _catch_try_ranges(node: Node) -> frozenset[int]:
    """use 所在的所有 catch_clause 对应 try_statement 的 start_byte 集合。

    try 体内 def 无法保证在进入 catch 前已执行（异常可能在其前抛起、跳过该
    def），故不得截断 catch 内 use（TryStatement_001_T 真漏洞：``data[15]``
    先抛异常，``cmd = ""`` 永不执行，catch 里 exec(cmd) 仍是污染参数）。
    """
    ranges: set[int] = set()
    cur = node.parent
    while cur is not None:
        if cur.type == "catch_clause":
            parent = cur.parent
            if parent is not None and parent.type == "try_statement":
                ranges.add(parent.start_byte)
        cur = cur.parent
    return _EMPTY_FSET if not ranges else frozenset(ranges)


def _def_try_ranges(node: Node) -> frozenset[int]:
    """def 所在的全部 try_statement 的 start_byte 集合（供 catch 保护判断）。"""
    ranges: set[int] = set()
    cur = node.parent
    while cur is not None:
        if cur.type == "try_statement":
            ranges.add(cur.start_byte)
        cur = cur.parent
    return frozenset(ranges)


# ─── Helper: location string ───────────────────────────────────────────────


# ─── Core class ────────────────────────────────────────────────────────────


class DataFlowBuilder:
    """Build def-use chains and trace data flow within / across functions.

    Usage::

        parser = Parser()
        df = DataFlowBuilder(parser)
        tree = parser.parse_file("app.py")
        funcs = parser.extract_functions(tree, "python")

        for func in funcs:
            chains = df.build_def_use_chains(tree, func_node, "python")
            for du in chains:
                print(f"{du.var_name}: defined at {du.def_location}, "
                      f"used at {du.use_locations}")

    With a call graph for cross-function tracing::

        cg_builder = CallGraphBuilder(parser)
        cg_builder.add_directory("./myapp")
        df = DataFlowBuilder(parser, cg_builder)
    """

    def __init__(
        self,
        parser: Parser,
        call_graph: CallGraphBuilder | None = None,
    ) -> None:
        self._parser = parser
        self._call_graph = call_graph

    # ── Intra-procedural: def-use chains ─────────────────────────────────

    def build_def_use_chains(
        self,
        tree: Tree,
        func_node: Node,
        language: str,
        file_path: str = "",
    ) -> list[DefUsePair]:
        """Build def-use pairs for every variable in *func_node*.

        Walks the function body to find assignment sites (definitions) and
        identifier references (uses), pairing each definition with all of
        its subsequent uses within the same function.

        Args:
            tree: The full tree-sitter parse tree (needed for traversal).
            func_node: A function / method definition node.
            language: Language name (``"python"``, ``"javascript"``, ``"java"``).
            file_path: Optional label used in location strings.

        Returns:
            One :class:`DefUsePair` per assigned variable, sorted by
            definition line number.

        """
        provider = self._parser.get_provider(language)
        assign_types = provider.assignment_types
        body = func_node.child_by_field_name("body")
        if body is None:
            return []

        traverser = Traverser(tree)

        # BUG 51 (性能): 用 body 子树遍历替代「全树遍历 + 字节区间过滤」——每
        # 函数从两遍整文件树遍历降为两遍 body 子树（单文件 O(F²)→O(F)）。
        # tree-sitter 节点区间互不重叠，body 字节区间内的节点必为其结构后代，
        # 干净文件（无语法错误）下两者完全等价（已对 6 类含错 Java 实证，差异
        # 仅限匿名括号节点，不影响 def-use 采集）。
        # 含语法错误（ERROR/MISSING）时回退全树 + 字节区间过滤，与历史行为逐
        # 字节一致 → 无条件零 FN 风险。``root_node.has_error`` 是 parse 后缓存
        # 标志，实测 ~0.0001ms/次，成本可忽略。
        def _body_nodes() -> Iterator[Node]:
            if tree.root_node.has_error:
                for n in traverser.traverse():
                    if self._node_in_range(n, body):
                        yield n
            else:
                yield from traverser.traverse(root=body)

        # Phase 1 + 2 merged (BUG 59): 旧实现两遍 body 子树遍历（先采赋值
        # 再采使用），单趟预序即可同时完成。遍历节点集合、过滤谓词、输出排序
        # 全部不变：assignments 仍按预序追加（Phase 1.5 紧随其后），var_uses
        # 是查表（追加顺序无关，输出时按 def_location 排序、每处 use 单独
        # sorted），故字节恒等。单文件两遍子树遍历 → 一遍，减半 def-use 的
        # AST 行走成本（大文件上占建图可观份额）。
        assignments: list[_Assign] = []
        # 每个 use 记录 (位置串, 循环后置位?, catch→try 集合)。后两维是 BUG 152
        # 流敏感截断的豁免信息，graph.py / analyzer.py 读不到（use_locations
        # 仍是纯 str 列表），零外部影响。
        var_uses: dict[str, list[tuple[str, bool, frozenset[int]]]] = {}
        for node in _body_nodes():
            if node.type in assign_types:
                target = provider.extract_assignment_target(node)
                if target:
                    assignments.append(
                        _Assign(
                            var_name=target,
                            node=node,
                            source=_source(node),
                            line=node.start_point[0] + 1,
                        )
                    )
            # Java 的 ``this`` 是独立节点类型（非 identifier）：``this.buf`` /
            # ``this.method()`` 里的实例引用同样参与 def-use（漏报面 A 类
            # 字段状态写读：``this.buf = t; sink(this.buf)``）。
            if node.type in ("identifier", "this") and provider.is_variable_identifier(node):
                var_name = _source(node)
                if var_name not in var_uses:
                    var_uses[var_name] = []
                var_uses[var_name].append(
                    (_loc(node, file_path), _loop_post_use(node, language), _catch_try_ranges(node))
                )

        # Phase 1.5 — collect parameter definitions (implicit assignments at
        # function entry).  This is critical for taint tracking: annotations
        # like ``@RequestParam`` mark parameters as sources, and data flow
        # must connect them to their uses in the function body.
        params_node = func_node.child_by_field_name("parameters")
        if params_node is not None:
            param_names = provider.extract_parameters(func_node)
            param_children = [c for c in params_node.children if c.is_named]
            func_def_line = func_node.start_point[0] + 1
            for i, pname in enumerate(param_names):
                # Parameter source text: the full declaration including
                # annotations (e.g. ``@RequestParam String fileName``).
                ptext = _source(param_children[i]) if i < len(param_children) else pname
                assignments.append(
                    _Assign(
                        var_name=pname,
                        node=func_node,
                        source=ptext,
                        line=func_def_line,
                    )
                )

        # BUG 152: 流敏感重赋值杀毒——每个 def 的 use 窗口截断到「本 def 行 ~
        # 下一个**杀毒 def** 行」。越界的 use 读的是杀毒 def 的值，前一个 def
        # 的污点不得穿过重赋值（``x = 源派生; x = 固定值; sink(x)``，ant 基础
        # 表达式/flow_sensitive 最大 FP 集群）。纯收窄：只删 def→use 边，不增
        # 边（真实项目放大风险为零）。护栏保零 FN（ant 首轮回归丢 10 TP 后补
        # 全的）：
        #   ① 自引用 def（``x = x + y`` / ``x += y``）读旧值——链保留且被越过；
        #   ② 杀毒 def 须与 Di 门控上下文严格相同（含 if 分支位：then/else 是
        #      互斥路径不能互杀，MayTaintKind_001_T）——Interrupt_005/007_T；
        #   ③ 反向 use 仅切裸变量重写 def 的前向不可达 use；循环后置位
        #      （for-update / cond / do-cond）backedge 可达豁免
        #      （ForStatement_update_001_T）；字段/容器写 def 的**自身**反向
        #      use 也保留（堆对象变异，宿主早期别名/拷贝同样读到——别名维 TP）；
        #   ④ 字段/容器写（``a.b=``/``a[i]=``）不覆盖宿主绑定、不构成杀毒 def
        #      （别名维 8 个 TP）；
        #   ⑤ 杀毒 def 在 try 体内、use 在同 try 的 catch 内时保护（异常路径
        #      可能跳过杀毒 def，TryStatement_001_T）。
        # 下界用 ``assign.line <= 行(u)`` 再叠 ``_loc_matches_def``（BUG 41：
        # enhanced_for 单行 body use 与循环头同行须保留，不能用严格 <）。
        self_refs = [self._is_self_referencing(a, provider, tree) for a in assignments]
        gate_ctxs = [self._gate_context(a.node, language) for a in assignments]
        plain_defs = [_is_plain_var_def(a.node) for a in assignments]
        def_trys = [_def_try_ranges(a.node) for a in assignments]
        by_var: dict[str, list[int]] = defaultdict(list)
        for i, a in enumerate(assignments):
            by_var[a.var_name].append(i)
        for idxs in by_var.values():
            idxs.sort(key=lambda i: assignments[i].line)

        results: list[DefUsePair] = []
        for i, assign in enumerate(assignments):
            # bound = 首个「杀毒 def」（裸变量重写、非自引用、门控严格相同）
            # 行。字段/容器写与自引用 def 不构成无条件重写点，直接越过。
            # bound_trys = **杀毒 def** 所在的 try 集合（护栏⑤ catch 保护要
            # 的是杀毒 def 的成员资格——param def 在 try 外、杀毒 def 在内）。
            bound: int | None = None
            bound_trys: frozenset[int] = _EMPTY_FSET
            for j in by_var.get(assign.var_name, ()):
                if j == i or assignments[j].line <= assign.line:
                    continue
                if not plain_defs[j]:
                    continue  # 护栏④：字段/容器写不覆盖绑定
                if self_refs[j]:
                    continue  # 护栏①：自引用读旧值，不杀
                if gate_ctxs[j] == gate_ctxs[i]:
                    bound = assignments[j].line
                    bound_trys = def_trys[j]
                    break

            use_locations: list[str] = []
            for loc, loop_post, catch_trys in var_uses.get(assign.var_name, ()):
                if self._loc_matches_def(loc, assign.node, file_path):
                    continue  # BUG 41: enhanced_for 同行 use 保留
                u_line = _loc_line(loc)
                if u_line is None:
                    continue
                if u_line < assign.line:
                    # 护栏③：反向 use 仅切「裸变量重写」def 的前向不可达 use；
                    # 循环后置位（for-update/cond）是 backedge 可达（豁免，
                    # ForStatement_update_001_T）。字段/容器写 def 是堆对象变异
                    # （``a.b=cmd`` 改字段不改绑定），宿主对象身份与行序无关，
                    # 早期别名/拷贝（``newSimpleLinkedList(a)``）同样读到变异
                    # → 反向 use 保留（ant 别名维 TP 依赖写 def 反向接到宿主
                    # 早期 use）。
                    if plain_defs[i] and not loop_post:
                        continue
                elif bound is not None and u_line >= bound:
                    # 护栏⑤：杀毒 def 在 try 体内、use 在同 try 的 catch 内时，
                    # 异常路径可能跳过杀毒 def → 保留链（TryStatement_001_T）。
                    if not (bound_trys and (catch_trys & bound_trys)):
                        continue  # 越过杀毒 def，归下一个 def 的窗口
                use_locations.append(loc)

            results.append(
                DefUsePair(
                    var_name=assign.var_name,
                    def_location=_loc(assign.node, file_path),
                    def_expression=assign.source,
                    use_locations=sorted(use_locations),
                    # BUG 48: 多行定义（``String sql =\\n "...'+bar+'"``）的 RHS
                    # var-ref 落在起始行之后，def_end_line 供 RHS→LHS 桥接按
                    # [起始行, 结束行] 区间匹配（与 BUG 46 调用侧同理）。
                    def_end_line=assign.node.end_point[0] + 1,
                )
            )

        results.sort(key=lambda d: d.def_location)
        return results

    # ── Inter-procedural: cross-function tracing ────────────────────────

    def trace_cross_function(
        self,
        var_name: str,
        from_func: str,
        to_func: str,
        file_path: str = "",
    ) -> list[DataFlowStep]:
        """Trace *var_name* from *from_func* to *to_func* across a call edge.

        Looks up *to_func* in the call graph, finds the call site in
        *from_func*, and traces how the argument flows into the callee's
        parameter.

        Requires *call_graph* to have been set via the constructor.

        Returns an empty list when the call graph is unavailable or the
        functions / edge cannot be resolved.
        """
        if self._call_graph is None:
            return []

        # Find the callee definition
        target_file = self._call_graph.find_definition(to_func)
        if target_file is None:
            return []

        # Parse callee file and find the function
        callee_tree = self._parser.parse_file(target_file)
        callee_lang = self._parser.get_language(callee_tree)
        callee_funcs = self._parser.extract_functions(callee_tree, callee_lang)

        callee_node = None
        for fn in callee_funcs:
            if fn.name == to_func:
                callee_node = fn
                break

        if callee_node is None:
            return []

        steps: list[DataFlowStep] = []

        # Step 1 — the variable at the call site
        loc_str = f"{file_path}:0" if file_path else "<string>:0"
        steps.append(
            DataFlowStep(
                location=loc_str,
                expression=var_name,
                enclosing_function=from_func,
                kind="call_arg",
            )
        )

        # Step 2 — the parameter in the callee
        for param in callee_node.params:
            loc_str2 = f"{target_file}:0"
            steps.append(
                DataFlowStep(
                    location=loc_str2,
                    expression=param,
                    enclosing_function=to_func,
                    kind="parameter",
                )
            )
            break  # First positional parameter

        # Trace parameter through callee body
        callee_ts_node = self._fn_to_node(callee_node, callee_tree)
        if callee_ts_node is not None:
            def_use = self.build_def_use_chains(
                callee_tree,
                callee_ts_node,
                callee_lang,
                target_file,
            )
        else:
            return steps

        for du in def_use:
            # Find def-use for the matched parameter
            if du.var_name in (p for p in (steps[-1].expression,)):
                for use_loc in du.use_locations:
                    steps.append(
                        DataFlowStep(
                            location=use_loc,
                            expression=du.var_name,
                            enclosing_function=to_func,
                            kind="assignment",
                        )
                    )

        # BUG 37 (was TODO): trace the callee's return value back to the
        # caller.  Previously the trace stopped at the callee's uses of the
        # parameter — ``result = calc(x); return result`` produced no step
        # past the call, so the value's fate at the call site was invisible.
        # Match ``return x`` directly and ``y = x ...; return y`` transitively
        # (one-or-more assignment hops), then hand the value back to the
        # caller's call-site line as a ``call_return`` step.
        if callee_ts_node is not None:
            traced = steps[-1].expression if steps else var_name
            return_steps = self._trace_return_statements(
                callee_tree,
                callee_ts_node,
                callee_node,
                target_file,
                callee_lang,
                traced,
            )
            if return_steps:
                steps.extend(return_steps)
                # Hand the value back to the caller's call site (line 0
                # placeholder, mirroring Step 1's ``call_arg``).
                steps.append(
                    DataFlowStep(
                        location=f"{file_path}:0" if file_path else "<string>:0",
                        expression="<callee return>",
                        enclosing_function=from_func,
                        kind="call_return",
                    )
                )

        return steps

    # ── Internal helpers ────────────────────────────────────────────────

    def _trace_return_statements(
        self,
        tree: Tree,
        callee_ts_node: Node,
        callee_node: FunctionNode,
        target_file: str,
        language: str,
        traced_name: str,
    ) -> list[DataFlowStep]:
        """收集从 *traced_name* 流出的 ``return`` 步骤。

        覆盖 ``return x``（直接返回）与 ``y = x ...; return y``（经一次或
        多次赋值中转）。只要 return 表达式里的变量能沿赋值边回溯到
        *traced_name*，就在 return 位置产出一条 ``kind="return"`` 步骤。
        """
        provider = self._parser.get_provider(language)
        body = callee_ts_node.child_by_field_name("body")
        if body is None:
            return []

        # 单趟遍历：记录赋值边（target ← RHS 中的标识符）与 return 语句。
        derived_from: dict[str, set[str]] = {}
        returns: list[Node] = []
        traverser = Traverser(tree)
        for node in traverser.traverse(root=body):
            if node.type in provider.assignment_types:
                target = provider.extract_assignment_target(node)
                if target:
                    src_idents = self._identifiers_in(node, provider, tree, exclude=target)
                    if src_idents:
                        derived_from.setdefault(target, set()).update(src_idents)
            elif node.type == "return_statement":
                returns.append(node)

        steps: list[DataFlowStep] = []
        for ret in returns:
            returned = self._identifiers_in(ret, provider, tree)
            if not returned:
                continue
            if self._reaches_traced(returned, traced_name, derived_from):
                steps.append(
                    DataFlowStep(
                        location=_loc(ret, target_file),
                        expression=_source(ret),
                        enclosing_function=callee_node.name,
                        kind="return",
                    )
                )
        return steps

    @staticmethod
    def _reaches_traced(
        returned: list[str],
        traced: str,
        derived: dict[str, set[str]],
    ) -> bool:
        """Return True if any returned identifier is (or is derived from) *traced*."""
        stack = list(returned)
        seen: set[str] = set()
        while stack:
            name = stack.pop()
            if name == traced:
                return True
            if name in seen:
                continue
            seen.add(name)
            stack.extend(derived.get(name, ()))
        return False

    def _identifiers_in(
        self,
        node: Node,
        provider: LanguageProvider,
        tree: Tree,
        exclude: str | None = None,
    ) -> list[str]:
        """收集 *node* 子树内去重后的变量标识符名。

        ``Traverser`` 需要整棵 ``Tree`` 才能构造，故 *tree* 由调用方传入，
        实际以 *node* 为根做子树遍历。
        """
        names: list[str] = []
        for child in Traverser(tree).traverse(root=node):
            if child.type != "identifier":
                continue
            if not provider.is_variable_identifier(child):
                continue
            name = _source(child)
            if name and name != exclude and name not in names:
                names.append(name)
        return names

    @staticmethod
    def _node_in_range(node: Node, container: Node) -> bool:
        """Return ``True`` if *node* is within *container*'s byte range."""
        return node.start_byte >= container.start_byte and node.end_byte <= container.end_byte

    def _loc_matches_def(self, loc: str, def_node: Node, file_path: str) -> bool:
        """Return True if *loc* refers to the definition site itself.

        Compares location strings since we no longer have the original
        use Node objects after the single-pass optimization.
        """
        # BUG 41: 增强 for（``for (String x : queue) { exec(x); }``）的 def 是
        # 整条循环语句，体内对 ``x`` 的用与循环头在同一行。按行排除会把这些
        # 真实 use 全剔掉 → x 的 def-use 链断（跨函数状态桥接接进 for 后无
        # 后继，漏报面 J 类静态容器遍历即此）。
        if def_node.type == "enhanced_for_statement":
            return False
        def_loc = _loc(def_node, file_path)
        return loc == def_loc

    def _is_self_referencing(self, assign: _Assign, provider, tree) -> bool:
        """True 当该 def 读取了变量的旧值（自引用），不可当杀毒 def。

        复合赋值恒读旧值；``x = expr`` 仅在 RHS 提及 x 时读旧值（``x = x + y``
        的旧污点合法流入新值，链须保留）。注意 ``_identifiers_in`` 的
        ``exclude`` 按**名字**过滤，会把 RHS 同名 occurrence 也滤掉，故检测
        必须对 RHS 子树调用且**不传** exclude。参数 def（node=func_node）RHS
        为 None → False（参数是函数入口的真 def，可杀内体重赋值）。
        """
        if _is_compound_assignment(assign.node):
            return True
        rhs = _assignment_rhs(assign.node)
        if rhs is None:
            return False
        return assign.var_name in self._identifiers_in(rhs, provider, tree)

    def _gate_context(
        self, node: Node, language: str
    ) -> frozenset[tuple[str, int, int, str, int, int]]:
        """该 def 的外层「条件/循环门控」链身份。

        杀毒 def Dk 只有在与被杀 def Di 门控严格相同（直落，中间无 if/for/
        while/switch/catch/lambda）时才是无条件重写——内层嵌套的 Dk 是条件
        执行，不能杀 Di（Interrupt_005/007_T 护栏：``a=cmd+"|"`` 在 for 体内、
        ``a="ls"`` 在 if 内，上下文不同 → 不杀 → TP 保留）。以 (type,
        start_byte, end_byte) 区分兄弟同型语句（两个并列 if 判为不同上下文，
        不误杀）。

        元组含**下降子节点身份** (child_type, child_start, child_end)：同一
        门控节点内不同分支的子块 byte 区间不同，使 then/else 分支、不同 case
        臂判为不同上下文——跨分支 def 是**互斥路径**不是顺序覆盖，不能互杀
        （MayTaintKind_001_T 真漏洞：if 分支 ``sql=...name`` 被 else 分支
        ``sql=...zhangsan`` 错杀）。同 body 内顺序 def 子节点相同 → 仍可杀。
        参数 def（node=func_node）无祖先门控 → 空集。
        """
        gates = _GATE_TYPES.get(language, _GATE_TYPES["java"])
        ctx: set[tuple[str, int, int, str, int, int]] = set()
        child = node
        cur = node.parent
        while cur is not None:
            if cur.type in gates:
                ctx.add(
                    (
                        cur.type,
                        cur.start_byte,
                        cur.end_byte,
                        child.type,
                        child.start_byte,
                        child.end_byte,
                    )
                )
            child = cur
            cur = cur.parent
        return frozenset(ctx)

    def _fn_to_node(self, fn: FunctionNode, tree: Tree) -> Node | None:
        """Convert a FunctionNode (dataclass) back to a tree-sitter Node.

        Uses a per-tree cache to avoid repeated full-tree traversals.

        BUG 23: The cache is capped at ``_max_fn_cache`` entries with
        FIFO eviction to prevent unbounded growth across many parses.
        """
        _max_fn_cache = 8192
        cache_key = (id(tree), fn.name, fn.start_line)
        if not hasattr(self, "_fn_cache"):
            self._fn_cache: dict[tuple, Node | None] = {}
            self._fn_cache_keys: list[tuple] = []
        if cache_key in self._fn_cache:
            return self._fn_cache[cache_key]

        # Evict oldest entry if at capacity
        if len(self._fn_cache) >= _max_fn_cache and self._fn_cache_keys:
            old_key = self._fn_cache_keys.pop(0)
            self._fn_cache.pop(old_key, None)

        for node in Traverser(tree).traverse():
            line = node.start_point[0] + 1
            if line == fn.start_line:
                provider = self._parser.get_provider(self._parser.get_language(tree))
                if node.type in provider.func_def_types:
                    name = provider.extract_function_name(node)
                    if name == fn.name:
                        self._fn_cache[cache_key] = node
                        self._fn_cache_keys.append(cache_key)
                        return node
        self._fn_cache[cache_key] = None
        self._fn_cache_keys.append(cache_key)
        return None


# ─── Internal helpers ──────────────────────────────────────────────────────


@dataclass
class _Assign:
    """Internal: a single assignment found during def-use analysis."""

    var_name: str
    node: Node
    source: str = ""
    line: int = 0
