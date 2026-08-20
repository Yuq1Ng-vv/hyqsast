"""cpg/dataflow.py — Intra- and inter-procedural data-flow analysis.

Builds on the call-graph layer to track how variables flow through a
codebase: definition-use chains within functions, data flow across
function boundaries, and taint propagation from sources to sinks.

See DESIGN-IMPLEMENTATION.md Section 2.4 for the interface specification.
"""

from __future__ import annotations

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

        # Phase 1 — collect assignment targets within the function body
        # _Assign: (var_name, def_node, def_source, def_line)
        assignments: list[_Assign] = []
        for node in traverser.traverse():
            if not self._node_in_range(node, body):
                continue
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

        # Phase 2 — single pass: collect all variable uses, then associate with defs
        # Build a map from var_name → list of use locations in one tree traversal
        var_uses: dict[str, list[str]] = {}
        for node in traverser.traverse():
            if not self._node_in_range(node, body):
                continue
            # Java 的 ``this`` 是独立节点类型（非 identifier）：``this.buf`` /
            # ``this.method()`` 里的实例引用同样参与 def-use（漏报面 A 类
            # 字段状态写读：``this.buf = t; sink(this.buf)``）。
            if node.type not in ("identifier", "this"):
                continue
            if not provider.is_variable_identifier(node):
                continue
            var_name = _source(node)
            if var_name not in var_uses:
                var_uses[var_name] = []
            var_uses[var_name].append(_loc(node, file_path))

        # Associate each assignment with its uses (skip the definition site itself)
        results: list[DefUsePair] = []
        for assign in assignments:
            use_locations = [
                loc
                for loc in var_uses.get(assign.var_name, [])
                if not self._loc_matches_def(loc, assign.node, file_path)
            ]

            results.append(
                DefUsePair(
                    var_name=assign.var_name,
                    def_location=_loc(assign.node, file_path),
                    def_expression=assign.source,
                    use_locations=sorted(use_locations),
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
