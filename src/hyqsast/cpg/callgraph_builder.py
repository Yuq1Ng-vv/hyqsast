"""cpg/callgraph_builder.py — Cross-file call graph builder.

Extends :class:`SingleFileCallGraph` to span multiple files.  Parses an
entire project directory, resolves imports between files, and produces
cross-file caller→callee edges.

See DESIGN-IMPLEMENTATION.md Section 2.2 for the interface specification.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from hyqsast.cpg.callgraph import CallEdge, SingleFileCallGraph
from hyqsast.cpg.languages import detect_by_extension
from hyqsast.cpg.parser import Parser


class CallGraphBuilder:
    """Build a cross-file call graph for a project.

    Usage::

        parser = Parser()
        builder = CallGraphBuilder(parser)
        builder.add_directory("./myapp")
        builder.resolve_imports()
        cross_edges = builder.build_calls()

        for edge in cross_edges:
            print(f"[{edge.file_path}] {edge.caller} -> {edge.callee}")
    """

    # Extensions we know how to parse (populated from provider registry)
    _KNOWN_EXTS: ClassVar[set[str]]

    def __init__(self, parser: Parser) -> None:
        self._parser = parser
        self._graphs: dict[str, SingleFileCallGraph] = {}
        self._imports: dict[str, list[_ResolvedImport]] = {}
        self._all_functions: dict[str, list[str]] = {}  # func_name → [file_paths]
        self._file_funcs: dict[str, set[str]] = {}  # file_path → {func_names}
        # Java receiver 类型收窄（BUG N）用的类型信息，add_file 时填充：
        #   _var_types:      file_path → {var_name → 显式声明简单类型}
        #   _method_classes: file_path → {method_name → 所属类简单名}
        #   _class_extends:  file_path → {class_name → {父类/接口简单名}}
        self._var_types: dict[str, dict[str, str]] = {}
        self._method_classes: dict[str, dict[str, str]] = {}
        self._class_extends: dict[str, dict[str, set[str]]] = {}

    # ── File management ─────────────────────────────────────────────────

    def add_file(self, file_path: str | Path) -> None:
        """Parse a single file and index its functions and imports.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            ValueError: If the file's language is unsupported.

        """
        path = str(Path(file_path).resolve())
        if path in self._graphs:
            return

        # Parse once, reuse tree for both call graph and imports
        tree = self._parser.parse_file(path)
        language = self._parser.get_language(tree)

        cg = SingleFileCallGraph(self._parser)
        cg.build_from_tree(tree, language, path)
        self._graphs[path] = cg

        # Index functions: which file defines each function
        self._file_funcs[path] = cg.function_names
        for name in cg.function_names:
            self._all_functions.setdefault(name, []).append(path)
        # BUG 9: Also index qualified names (ClassName.methodName) for Java
        for qname in cg.qualified_function_names:
            self._all_functions.setdefault(qname, []).append(path)

        # Extract imports for later resolution (reuse same tree)
        imports = self._parser.extract_imports(tree, language)
        self._imports[path] = [
            _ResolvedImport(
                module=imp.module,
                names=imp.names,
                is_relative=imp.is_relative,
                file_path=path,
                alias=imp.alias,
            )
            for imp in imports
        ]

        # Extract field-type names as virtual imports.  Frameworks like
        # Spring inject dependencies without explicit imports, but the
        # field type (e.g. `private ReportParser reportParser`) tells
        # us exactly which class is being used.  We add these type names
        # so that `resolve_imports` can connect them via the file_index.
        # BUG N: Java 类型信息（receiver 收窄用）。非 Java 语言跳过 ——
        # Python/JS 保持裸名多目标全连（sound 过近似）。
        if language == "java":
            vt, mc, ce = self._extract_type_info(tree)
            self._var_types[path] = vt
            self._method_classes[path] = mc
            self._class_extends[path] = ce

        virtual_types = self._extract_field_types(tree, language)
        for vt in virtual_types:
            # Only add if not already covered by a real import
            already_imported = any(vt in imp.names for imp in imports)
            if not already_imported:
                self._imports[path].append(
                    _ResolvedImport(
                        module=vt,
                        names=[vt],
                        is_relative=False,
                        file_path=path,
                    )
                )

    def add_directory(self, dir_path: str | Path) -> None:
        """Recursively add all source files in *dir_path*.

        Only files whose extension matches a registered language provider
        are included.  Hidden directories and ``__pycache__`` are skipped.
        """
        root = Path(dir_path).resolve()
        for entry in sorted(root.rglob("*")):
            if not entry.is_file():
                continue
            # Skip hidden dirs and __pycache__
            if any(p.startswith(".") or p == "__pycache__" for p in entry.parts):
                continue
            lang = detect_by_extension(str(entry))
            if lang is not None:
                self.add_file(str(entry))

    # ── Import resolution ───────────────────────────────────────────────

    def resolve_imports(self) -> dict[str, str]:
        """Resolve imports across all added files.

        Returns a mapping ``{qualified_name: file_path}`` for all
        successfully-resolved imports.  Currently handles:

        * **Relative imports** (``from .module import X``) — resolved
          relative to the importing file's directory.
        * **Direct name matches** (``from mymodule import X`` where
          ``mymodule.py`` exists in the project).

        Third-party and standard-library imports are left unresolved.

        """
        # Pre-build a filename → [paths] index for collision-aware lookup.
        # Multiple directories may contain e.g. `utils.py` — we collect
        # all candidates and let `_resolve_module_path` pick the best one.
        file_index: dict[str, list[str]] = {}
        for fp in self._graphs:
            stem = Path(fp).stem
            file_index.setdefault(stem, []).append(fp)

        resolved: dict[str, str] = {}

        for file_path, imp_list in self._imports.items():
            base_dir = str(Path(file_path).parent)

            for imp in imp_list:
                if not imp.module:
                    continue

                target = self._resolve_module_path(
                    imp.module,
                    base_dir,
                    file_index,
                )
                if target is not None and target in self._graphs:
                    # Map each imported name to the target file
                    for name in imp.names:
                        if name == "*":
                            # Wildcard — resolve all exports from target
                            continue
                        qualified = f"{imp.module}.{name}"
                        resolved[qualified] = target
                        # Also register bare name for direct import style
                        resolved[name] = target

                    # Also resolve the module itself
                    resolved[imp.module] = target

        return resolved

    # ── Cross-file call resolution ──────────────────────────────────────

    def build_calls(self, progress: object | None = None) -> list[CallEdge]:
        """Build cross-file call edges.

        For each file's unresolved calls, checks whether the callee is
        defined in another file that the caller imports.  Returns a flat
        list of all cross-file resolved call edges.

        BUG N: 本地同名遮蔽 —— 一个文件既定义了本地函数 ``foo``、又 ``from b
        import foo`` 时，调用点 ``foo(...)`` 的运行时绑定可能是 import 的那个。
        单文件解析按裸名把调用吸收进本地函数，跨文件目标漏连 → BFS 断链。这里
        对「本地已解析 + callee 名被 import」的调用**额外**补发跨文件边（过近似）。

        ``progress``（可选）：按文件上报进度（set_total + 每文件 step），
        供 CPGGraphBuilder.add_directory 的「跨文件调用边」阶段实时出 ETA。
        """
        resolved_imports = self.resolve_imports()
        cross_edges: list[CallEdge] = []

        # BUG 54: 每文件 alias→模块 表（``import X as Y`` 的 Y）。receiver 解析用：
        # 调用点 ``Y.process(...)`` → 按 Y 反查 module → 解析到具体文件，把跨模块
        # 同名函数扇出收窄到 receiver 指向的那一个。
        #
        # 安全性（铁律：收窄不得增漏报）：同一文件里同一 alias 绑定到**多个不同
        # 模块**（如 dense2 的 handler 文件内 20 个函数各自 ``import svXX as svmod``）
        # 时标记 ambiguous —— receiver 解析不可靠，回退旧全连接逻辑，不收紧。
        alias_to_module, alias_ambiguous = self._alias_tables()
        file_index = self._file_index()

        # 每文件 import 的名字集合（遮蔽检测用）
        imported_names: dict[str, set[str]] = {}
        for fp, imps in self._imports.items():
            imported_names[fp] = {n for imp in imps for n in imp.names}

        if progress is not None:
            # 工作单元 = 文件数 + 未解析调用数 + 本地遮蔽补发调用数。
            # 按调用粒度 step（而非每文件一步）：真实项目里单个文件几十个跨
            # 文件调用 × 上千同名定义文件时，解析要跑很久——每文件一步会让
            # 进度条卡在 0% 看着像冻住（「卡在跨文件调用边」）。按调用推进，
            # 病态文件里条也持续走、ETA 反映真实速率。
            total_units = len(self._graphs)
            for fp, cg in self._graphs.items():
                total_units += len(cg.unresolved)
                imp = imported_names.get(fp, set())
                total_units += sum(
                    1 for e in cg.edges if e.is_resolved and e.callee in imp
                )
            progress.set_total(total_units)
        for file_path, cg in self._graphs.items():
            imports_for_file = self._imports.get(file_path, [])
            imported_modules = {imp.module for imp in imports_for_file}
            imp_names = imported_names.get(file_path, set())

            def _append(
                callee: str,
                caller: str,
                receiver: str | None,
                call_line: int,
                call_end_line: int | None,
                full_expression: str,
                is_method: bool,
                *,
                # 默认参数在定义时绑定当前迭代的循环变量（B023：闭包延迟
                # 绑定会拿到最后一次迭代的值，绑定为默认参数规避）。
                file_path: str = file_path,
                imported_modules: set[str] = imported_modules,
            ) -> None:
                # Java receiver 收窄（BUG N）：receiver 有显式声明类型时传给
                # _reachable_callee_files 按类型过滤候选类；无则 None 保持全连。
                receiver_type = (
                    self._var_types.get(file_path, {}).get(receiver)
                    if receiver is not None
                    else None
                )
                reachable_files = self._reachable_callee_files(
                    file_path,
                    callee,
                    receiver,
                    receiver_type,
                    imported_modules,
                    resolved_imports,
                    alias_to_module,
                    alias_ambiguous,
                    file_index,
                )
                if not reachable_files:
                    return
                cross_edges.append(
                    CallEdge(
                        caller=caller,
                        callee=callee,
                        call_line=call_line,
                        call_end_line=call_end_line,
                        full_expression=full_expression,
                        is_resolved=True,
                        is_method_call=is_method,
                        file_path=file_path,
                        receiver=receiver,
                        resolved_files=reachable_files,
                    )
                )

            # 1) 未解析调用 → 跨文件解析（原逻辑）
            for uc in cg.unresolved:
                _append(
                    uc.callee,
                    uc.caller,
                    uc.receiver,
                    uc.call_line,
                    uc.call_end_line,
                    uc.full_expression,
                    uc.is_method_call,
                )
                if progress is not None:
                    progress.step(1)

            # 2) 本地遮蔽调用（本地已解析、但 callee 名被 import）→ 补发跨文件边。
            #    图建阶段：同一 call_site 节点（file,line,caller,callee 同键）会被
            #    cross edge 标记 cross_file=True，跨文件目标补连；本地边保留（CALLS
            #    + function→param 桥），两侧都可达。
            for e in cg.edges:
                if not e.is_resolved:
                    continue
                if e.callee not in imp_names:
                    continue
                _append(
                    e.callee,
                    e.caller,
                    e.receiver,
                    e.call_line,
                    e.call_end_line,
                    e.full_expression,
                    e.is_method_call,
                )
                if progress is not None:
                    progress.step(1)

        return cross_edges

    def _alias_tables(self) -> tuple[dict[str, dict[str, str]], dict[str, set[str]]]:
        """构建每文件 alias→module 表 + 歧义别名集合（receiver 解析用）。

        BUG 54: 同一文件里同一 alias 绑定到多个不同模块时标记 ambiguous ——
        receiver 解析不可靠，回退旧全连接逻辑（铁律：收窄不得增漏报）。
        ``from X import f as p`` 的 p 是函数别名不是模块，留在 names 里，这里
        不覆盖，避免把函数别名误当模块。
        """
        alias_to_module: dict[str, dict[str, str]] = {}
        alias_ambiguous: dict[str, set[str]] = {}
        for fp, imps in self._imports.items():
            table: dict[str, str] = {}
            for imp in imps:
                if imp.alias and imp.module:
                    prev = table.get(imp.alias)
                    if prev is not None and prev != imp.module:
                        alias_ambiguous.setdefault(fp, set()).add(imp.alias)
                    table[imp.alias] = imp.module
            alias_to_module[fp] = table
        return alias_to_module, alias_ambiguous

    def _reachable_callee_files(
        self,
        file_path: str,
        callee: str,
        receiver: str | None,
        receiver_type: str | None,
        imported_modules: set[str],
        resolved_imports: dict[str, str],
        alias_to_module: dict[str, dict[str, str]],
        alias_ambiguous: dict[str, set[str]],
        file_index: dict[str, list[str]],
    ) -> list[str]:
        """返回 ``file_path`` 调用 ``callee`` 的所有可达目标文件（不含自身）。

        BUG 53: 按 import 过滤，只收「调用方实际可达」的同名定义文件，避免全库
        同名函数全连（稠密伪边）。BUG 54: receiver 命中时精确收紧到 receiver
        指向的文件。BUG N: 本地遮蔽调用（本地已解析）也走这里补发跨文件边，
        保证过近似不漏报；Java receiver 有显式类型时按类型收窄候选类。
        """
        candidates = self._all_functions.get(callee, [])
        if not candidates:
            return []

        # BUG 54: receiver 别名解析。命中 → 候选收窄到 receiver 指向的具体文件
        # （且必须是可达的）；未命中/解析失败/alias 歧义 → 回退旧逻辑。
        receiver_candidates: list[str] | None = None
        ambiguous = receiver in alias_ambiguous.get(file_path, set())
        if receiver and not ambiguous:
            module = alias_to_module.get(file_path, {}).get(receiver)
            if module:
                target = self._resolve_module_path(
                    module,
                    str(Path(file_path).parent),
                    file_index,
                )
                if target is not None and target in candidates:
                    receiver_candidates = [target]

        reachable_files: list[str] = []
        for target_file in candidates:
            if target_file == file_path:
                continue  # intra-file already resolved elsewhere

            # Same-directory always reachable for Java (same-package
            # visibility).  Python and JS require explicit imports
            # even for same-directory files, so we scope this to
            # Java only.
            same_dir = Path(file_path).parent == Path(target_file).parent and file_path.endswith(
                ".java"
            )

            if same_dir or self._is_reachable(
                file_path, target_file, imported_modules, resolved_imports
            ):
                reachable_files.append(target_file)

        if receiver_candidates is not None:
            # BUG 54: receiver 命中时精确收紧 —— 只连 receiver 指向的文件。
            # 但该文件必须也在可达集里（别名 import 天然可达，此处防御）。
            precise = [t for t in receiver_candidates if t in reachable_files]
            if precise:
                reachable_files = precise

        # BUG N: Java receiver 类型收窄 —— receiver 有**显式声明类型**时，只保留
        # 方法所属类与类型相关（== 或 implements/extends）的候选。无相关类（如
        # 接口实现类不在扫描集，OWASP ``thing.doSomething`` 的 ThingInterface 实
        # 现在 helpers 包）→ 回退只连第一个（= 旧 resolved_files[0] 行为），避免
        # 同名全库全连的稠密伪边（OWASP doSomething 1923 文件撞衫）。类型提取
        # 不到 → 保持多目标全连（sound 过近似，不漏报）。
        if receiver_type:
            related = [
                f for f in reachable_files if self._receiver_type_matches(f, callee, receiver_type)
            ]
            if related:
                reachable_files = related
            else:
                reachable_files = reachable_files[:1]
        return reachable_files

    def _receiver_type_matches(self, file_path: str, method: str, receiver_type: str) -> bool:
        """``method`` 在 ``file_path`` 里是否与 receiver 显式类型相关。

        匹配条件：方法所属类 == receiver 类型，或所属类 implements/extends 该
        类型（多态：``Shape s = new Circle()`` 时 Circle 里声明的 draw 匹配
        Shape receiver）。方法无类信息 → 保守返回 True（不排除）。
        """
        cls = self._method_classes.get(file_path, {}).get(method)
        if cls is None:
            return True
        if cls == receiver_type:
            return True
        parents = self._class_extends.get(file_path, {}).get(cls)
        return bool(parents and receiver_type in parents)

    def _file_index(self) -> dict[str, list[str]]:
        """文件名（stem）→ 路径列表 索引，供 receiver 模块解析复用。"""
        index: dict[str, list[str]] = {}
        for fp in self._graphs:
            stem = Path(fp).stem
            index.setdefault(stem, []).append(fp)
        return index

    # ── Query helpers ───────────────────────────────────────────────────

    @property
    def files(self) -> set[str]:
        """All file paths currently indexed."""
        return set(self._graphs.keys())

    @property
    def all_functions(self) -> dict[str, list[str]]:
        """Mapping ``{file_path: [function_names]}`` for all indexed files."""
        return {fp: sorted(fns) for fp, fns in self._file_funcs.items()}

    @property
    def function_index(self) -> dict[str, list[str]]:
        """Mapping ``{func_name: [file_paths]}`` (all definitions)."""
        return dict(self._all_functions)

    def find_definition(self, func_name: str) -> str | None:
        """Return the file path where *func_name* is defined, or None.

        When multiple files define a function with the same name, the
        first one indexed is returned.  Use :meth:`find_all_definitions`
        to get every candidate.
        """
        paths = self._all_functions.get(func_name, [])
        return paths[0] if paths else None

    def find_all_definitions(self, func_name: str) -> list[str]:
        """Return ALL file paths where *func_name* is defined."""
        return list(self._all_functions.get(func_name, []))

    def var_types(self, file_path: str) -> dict[str, str]:
        """该文件显式声明的变量名 → 简单类型（供容器桥接类型门控用）。

        只覆盖 Java 的局部变量/参数/字段的显式声明（``Map m`` / ``List<X> l`` /
        ``StringBuilder sb``）；``var`` 推断、动态语言不在内 → 返回空 dict。
        """
        return self._var_types.get(file_path, {})

    # ── Internal helpers ────────────────────────────────────────────────

    # Extensions we try for JS/TS relative imports and absolute module paths
    _SRC_EXTS = (".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")

    @staticmethod
    def _extract_field_types(tree: object, language: str) -> list[str]:
        """Extract type names from field/variable declarations.

        Captures the class name from patterns like
        ``private ReportParser reportParser;`` so that
        framework-injected dependencies become reachable
        even when the source file has no explicit import.

        Filters out primitive types and common stdlib container
        names that would never resolve to a project file.
        """
        from hyqsast.cpg.traversal import Traverser

        _primitives = {
            "int",
            "long",
            "float",
            "double",
            "boolean",
            "byte",
            "short",
            "char",
            "void",
            "String",
            "Integer",
            "Long",
            "Float",
            "Double",
            "Boolean",
            "Byte",
            "Short",
        }
        _containers = {
            "List",
            "Map",
            "Set",
            "Collection",
            "ArrayList",
            "HashMap",
            "HashSet",
            "Optional",
            "Array",
            "Object",
            "HttpServletRequest",
            "HttpServletResponse",
            "ServletRequest",
            "ServletResponse",
            "ServletException",
            "IOException",
        }
        skip = _primitives | _containers

        types: list[str] = []
        seen: set[str] = set()

        for node in Traverser(tree).traverse():
            ntype = node.type

            # ── Java field declarations ────────────────────────────
            if ntype == "field_declaration" and language == "java":
                type_node = node.child_by_field_name("type")
                if type_node is not None:
                    # Collect every `type_identifier` descendant
                    # (handles generics: List<ReportProvider> →
                    #  we collect ReportProvider)
                    self_nodes = [type_node]
                    while self_nodes:
                        cur = self_nodes.pop()
                        if cur.type == "type_identifier":
                            name = cur.text.decode()
                            if name not in skip and name not in seen:
                                types.append(name)
                                seen.add(name)
                        for child in cur.children:
                            self_nodes.append(child)

            # ── Python typed assignments ───────────────────────────
            elif (ntype == "assignment" and language == "python") or (
                ntype
                in (
                    "field_definition",
                    "public_field_definition",
                    "variable_declarator",
                )
                and language in ("javascript", "typescript")
            ):
                type_node = node.child_by_field_name("type")
                if type_node is not None:
                    name = type_node.text.decode()
                    if name not in skip and name not in seen:
                        types.append(name)
                        seen.add(name)

        return types

    def _extract_type_info(
        self, tree: object
    ) -> tuple[dict[str, str], dict[str, str], dict[str, set[str]]]:
        """提取 Java 类型信息：var→简单类型、method→所属类、class→父类/接口。

        receiver 收窄（BUG N）依赖三类信息：
        - 局部变量/参数/字段的**显式声明类型**（``ThingInterface thing = ...``）
        - 每个方法所属的**类名**（``doSomething`` 属于哪个 class，取最近类，
          内部类方法记为内部类名，与 SingleFileCallGraph 的 qualified 名一致）
        - 每个类的**父类/接口名**（多态：``Shape s = new Circle()`` 时 Circle
          里声明的 draw 也要能匹配 Shape receiver）
        """
        from hyqsast.cpg.traversal import Traverser

        var_types: dict[str, str] = {}
        method_classes: dict[str, str] = {}
        class_extends: dict[str, set[str]] = {}

        def _simple_type(node: object) -> str | None:
            """从类型/父类/接口节点取简单类型名（剥掉泛型参数与包前缀）。

            容器节点（superclass/``extends B``、super_interfaces/``implements I``、
            generic_type/``List<String>``）递归找第一个类型标识符。
            """
            ntype = node.type
            if ntype == "type_identifier":
                return node.text.decode("utf-8")
            if ntype == "scoped_type_identifier":
                name = node.child_by_field_name("name")
                if name is not None:
                    return name.text.decode("utf-8")
                return node.text.decode("utf-8").rsplit(".", 1)[-1]
            for child in node.named_children:
                t = _simple_type(child)
                if t:
                    return t
            return None

        def _declared_names(holder: object) -> list[str]:
            """取 declarator 列表里的变量名（``int a, b;`` 可能多个）。"""
            names: list[str] = []
            for dn in holder.children_by_field_name("declarator"):
                name_node = dn.child_by_field_name("name")
                if name_node is not None:
                    names.append(name_node.text.decode("utf-8"))
            return names

        for node in Traverser(tree).traverse():
            ntype = node.type
            if ntype == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    continue
                cname = name_node.text.decode("utf-8")
                supers: set[str] = set()
                sup = node.child_by_field_name("superclass")
                if sup is not None:
                    t = _simple_type(sup)
                    if t:
                        supers.add(t)
                itf = node.child_by_field_name("interfaces")
                if itf is not None:
                    for c in itf.named_children:
                        t = _simple_type(c)
                        if t:
                            supers.add(t)
                if supers:
                    class_extends[cname] = supers
            elif ntype == "method_declaration":
                mname_node = node.child_by_field_name("name")
                if mname_node is None:
                    continue
                mname = mname_node.text.decode("utf-8")
                cls: str | None = None
                anc = node.parent
                while anc is not None:
                    if anc.type == "class_declaration":
                        nm = anc.child_by_field_name("name")
                        cls = nm.text.decode("utf-8") if nm is not None else None
                        break
                    anc = anc.parent
                if cls:
                    method_classes[mname] = cls
            elif ntype == "local_variable_declaration":
                tn = node.child_by_field_name("type")
                if tn is not None:
                    t = _simple_type(tn)
                    if t:
                        for name in _declared_names(node):
                            var_types[name] = t
            elif ntype == "formal_parameter":
                tn = node.child_by_field_name("type")
                name_node = node.child_by_field_name("name")
                if tn is not None and name_node is not None:
                    t = _simple_type(tn)
                    if t:
                        var_types[name_node.text.decode("utf-8")] = t
            elif ntype == "field_declaration":
                tn = node.child_by_field_name("type")
                if tn is not None:
                    t = _simple_type(tn)
                    if t:
                        for name in _declared_names(node):
                            var_types[name] = t

        return var_types, method_classes, class_extends

    @staticmethod
    def _resolve_module_path(
        module: str,
        base_dir: str,
        file_index: dict[str, list[str]],
    ) -> str | None:
        """Convert a module name to a file path.

        Python
            ``".utils"`` → ``base_dir/../utils.py``
            ``"app.models"`` → ``root/app/models.py``

        Java
            ``"com.example.Foo"`` → ``root/com/example/Foo.java``

        JavaScript / TypeScript
            ``"./utils"`` → ``base_dir/utils.js`` (also tries .ts/.mjs/…)
            ``"../lib/foo"`` → ``base_dir/../lib/foo.js``
        """
        # ── JavaScript-style relative imports (./foo  or  ../foo) ─────
        if module.startswith("./") or module.startswith("../"):
            parts = module.split("/")
            # Count `..` segments (parent-directory steps)
            up_count = sum(1 for p in parts if p == "..")
            # The rest is everything except `.` and `..` segments
            rest_parts = [p for p in parts if p not in (".", "..")]
            parent = Path(base_dir)
            for _ in range(up_count):
                parent = parent.parent
            rest = "/".join(rest_parts) if rest_parts else ""
            if not rest:
                return None
            # Strip a known extension if present
            rest_no_ext = rest
            for ext in CallGraphBuilder._SRC_EXTS:
                if rest.endswith(ext):
                    rest_no_ext = rest[: -len(ext)]
                    break
            for ext in CallGraphBuilder._SRC_EXTS:
                candidate = parent / (rest_no_ext + ext)
                if candidate.exists():
                    return str(candidate.resolve())
                # Also try index files: ./foo/index.js
                candidate_index = parent / rest_no_ext / ("index" + ext)
                if candidate_index.exists():
                    return str(candidate_index.resolve())
            return None

        # ── Python relative imports (.module  or  ..module) ────────────
        if module.startswith("."):
            dots = len(module) - len(module.lstrip("."))
            rest = module.lstrip(".")
            parent = Path(base_dir)
            for _ in range(dots - 1):
                parent = parent.parent
            if rest:
                target = parent / (rest.replace(".", "/") + ".py")
            else:
                target = parent / "__init__.py"
            return str(target.resolve())

        # ── Absolute module paths ──────────────────────────────────────
        parts = module.split(".")

        # Walk up from base_dir, try *every* source-root
        # so we match the nearest parent directory.
        current = Path(base_dir)
        while current != current.parent:
            for ext in CallGraphBuilder._SRC_EXTS:
                candidate = current / (str(Path(*parts)) + ext)
                if candidate.exists():
                    return str(candidate.resolve())
            # Package init (Python)
            candidate_init = current / str(Path(*parts)) / "__init__.py"
            if candidate_init.exists():
                return str(candidate_init.resolve())
            # Index files (JS/TS package entry)
            for ext in (".js", ".ts", ".mjs"):
                candidate_index = current / str(Path(*parts)) / ("index" + ext)
                if candidate_index.exists():
                    return str(candidate_index.resolve())
            current = current.parent

        # ── Fallback: match by class name / module basename ────────────
        class_name = parts[-1]
        candidates = file_index.get(class_name, [])
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        # Multiple candidates → pick the one whose path best matches
        # the expected package structure (e.g. com/example/Foo.java).
        expected_suffix = str(Path(*parts))
        for fp in candidates:
            if fp.endswith(expected_suffix + Path(fp).suffix) or expected_suffix in fp:
                return fp
        # Tie-break: shortest path (closest to base_dir usually)
        return min(candidates, key=len)

    @staticmethod
    def _is_reachable(
        caller_file: str,
        target_file: str,
        imported_modules: set[str],
        resolved_imports: dict[str, str],
    ) -> bool:
        """Check if *caller_file* can reach *target_file* via imports."""
        # Direct resolution: check if any resolved import points to target
        for qualified, resolved_path in resolved_imports.items():
            if resolved_path == target_file:
                # Check if the caller imports some part of this module
                for mod in imported_modules:
                    if qualified.startswith(mod) or mod == qualified:
                        return True
        return False


# ─── Internal data type ──────────────────────────────────────────────────


class _ResolvedImport:
    """Internal: a single import statement, resolved to a file path."""

    __slots__ = ("file_path", "is_relative", "module", "names", "alias")

    def __init__(
        self,
        module: str,
        names: list[str],
        is_relative: bool,
        file_path: str,
        alias: str | None = None,
    ) -> None:
        self.module = module
        self.names = names
        self.is_relative = is_relative
        self.file_path = file_path
        # BUG 54: ``import X as Y`` / ``from X import f as Y`` 的接收端别名 Y。
        # receiver 解析用：调用点 ``Y.process(...)`` 时 Y 指向 module。
        self.alias = alias
