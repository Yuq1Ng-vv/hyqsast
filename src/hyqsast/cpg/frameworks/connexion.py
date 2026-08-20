"""cpg/frameworks/connexion.py — Connexion（OpenAPI-First）路由提取器.

Connexion 没有路由装饰器：路由定义在项目内的 ``openapi*.yml`` / ``swagger*.yml``
里，handler 通过 ``operationId`` 关联到 Python 函数（如
``api_views.users.get_by_username`` → ``api_views/users.py`` 的 ``get_by_username``）。

本提取器解析 spec，把每个 operation 转成 :class:`HttpEndpoint`：
- handler 函数名取 operationId 末段，文件取 module 路径（点号 → 目录分隔）；
- 参数从 path 级 + operation 级 ``parameters`` 收集（``in: path/query/header/cookie``），
  有 ``requestBody`` 时补一个 ``body`` 参数。

RouteParam 里的参数名随后由 Analyzer 注入到 CPG 图的 NODE_PARAMETER 上作为
source —— 这是 Connexion 应用里 URL 参数唯一的入口（函数参数，无 ``request.*``）。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from hyqsast.cpg.frameworks.base import BaseFrameworkExtractor, HttpEndpoint, RouteParam

if TYPE_CHECKING:
    from hyqsast.cpg.parser import Parser

_HTTP_METHODS = {
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
}
_SPEC_NAMES = ("openapi*.yml", "openapi*.yaml", "swagger*.yml", "swagger*.yaml")
_MAX_WALK = 12  # 向上找项目根的深度上限


class ConnexionExtractor(BaseFrameworkExtractor):
    """从 OpenAPI spec 提取 Connexion 路由（确定性，纯 YAML 解析）。"""

    framework_name = "connexion"

    def __init__(self, parser: Parser) -> None:
        super().__init__(parser)
        # 项目根 → 已解析 spec（一次解析，多次复用）
        self._specs: dict[Path, dict] = {}
        # 已知项目根（快速判断文件是否属于某项目，避免反复向上 glob）
        self._roots: list[Path] = []

    # ── spec 定位 / 解析 ────────────────────────────────────────────────

    def _project_root(self, file_path: str | Path) -> Path | None:
        """从源文件向上找含 OpenAPI spec 的项目根目录。"""
        p = Path(file_path).resolve()
        for root in self._roots:
            if root == p.parent or root in p.parents:
                return root
        current = p.parent
        for _ in range(_MAX_WALK):
            for pat in _SPEC_NAMES:
                if any(current.glob(pat)):
                    self._roots.append(current)
                    return current
            sub = current / "openapi_specs"
            if sub.is_dir() and any(sub.glob(pat) for pat in _SPEC_NAMES):
                self._roots.append(current)
                return current
            if current == current.parent:
                break
            current = current.parent
        return None

    def _load_spec(self, file_path: str | Path) -> dict | None:
        """解析项目根下的第一个 OpenAPI spec（带缓存）。"""
        root = self._project_root(file_path)
        if root is None:
            return None
        if root in self._specs:
            return self._specs[root]
        spec_path = next((p for pat in _SPEC_NAMES for p in root.glob(pat)), None)
        if spec_path is None:
            sub = root / "openapi_specs"
            spec_path = next((p for pat in _SPEC_NAMES for p in sub.glob(pat)), None)
        if spec_path is None:
            return None
        try:
            spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            return None
        if not isinstance(spec, dict):
            return None
        self._specs[root] = spec
        return spec

    def _relative_module(self, file_path: str | Path) -> str:
        """``.../api_views/users.py`` → ``api_views.users``（相对项目根）。"""
        root = self._project_root(file_path)
        p = Path(file_path).resolve()
        if root is None:
            return ""
        try:
            rel = p.relative_to(root)
        except ValueError:
            return ""
        parts = list(rel.parts)
        if not parts:
            return ""
        if parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]
        if parts[-1] == "__init__":
            parts.pop()
        if not parts:
            return ""
        return ".".join(parts)

    @staticmethod
    def _operation_ids(spec: dict) -> set[str]:
        """收集 spec 里所有 operationId。"""
        ids: set[str] = set()
        for path_item in (spec.get("paths") or {}).values():
            if not isinstance(path_item, dict):
                continue
            for op in path_item.values():
                if isinstance(op, dict) and op.get("operationId"):
                    ids.add(op["operationId"])
        return ids

    @staticmethod
    def _collect_params(path_item: dict, op: dict) -> list[RouteParam]:
        """从 path 级 + operation 级 parameters + requestBody 提取参数。"""
        params: list[RouteParam] = []
        seen: set[tuple[str, str]] = set()
        raw = list((path_item or {}).get("parameters") or []) + list(
            (op or {}).get("parameters") or []
        )
        for p in raw:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name", ""))
            source = str(p.get("in", "query"))
            if (name, source) in seen:
                continue
            seen.add((name, source))
            schema = p.get("schema") or {}
            params.append(
                RouteParam(
                    name=name,
                    source=source,
                    type_hint=str(schema.get("type", "")),
                    required=bool(p.get("required", source == "path")),
                )
            )
        if (op or {}).get("requestBody"):
            params.append(RouteParam(name="body", source="body"))
        return params

    # ── BaseFrameworkExtractor 契约 ────────────────────────────────────

    def detect(self, file_path: str | Path) -> bool:
        """仅对本项目的 controller 模块（operationId 前缀匹配）返回 True。"""
        if not str(file_path).endswith(".py"):
            return False
        spec = self._load_spec(file_path)
        if spec is None:
            return False
        rel = self._relative_module(file_path)
        if not rel:
            return False
        return any(oid == rel or oid.startswith(rel + ".") for oid in self._operation_ids(spec))

    def extract_routes(self, file_path: str | Path) -> list[HttpEndpoint]:
        spec = self._load_spec(file_path)
        if spec is None:
            return []
        rel = self._relative_module(file_path)
        if not rel:
            return []

        tree = self._parser.parse_file(file_path)
        lang = self._parser.get_language(tree)
        funcs = {fn.name: fn for fn in self._parser.extract_functions(tree, lang)}

        routes: list[HttpEndpoint] = []
        for route, path_item in (spec.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                    continue
                oid = op.get("operationId", "")
                if not isinstance(oid, str):
                    continue
                if not (oid == rel or oid.startswith(rel + ".")):
                    continue
                handler = oid.rsplit(".", 1)[-1]
                fn = funcs.get(handler)
                # handler 必须定义在本文件 —— 否则包 __init__.py 会因前缀匹配
                # 误收不属于它的路由（line=0 噪音），且无法注入参数 source。
                if fn is None:
                    continue
                routes.append(
                    HttpEndpoint(
                        route=str(route),
                        methods=[method.upper()],
                        handler_func=handler,
                        file_path=str(Path(file_path).resolve()),
                        line=fn.start_line,
                        params=self._collect_params(path_item, op),
                        framework=self.framework_name,
                    )
                )
        return routes
