"""server.py — MCP 服务器：把确定性污点分析包装成 LLM 可调用的工具。

设计（见 ``docs/MCP接入设计.md``）：

- **纯静态**：工具内部无任何 LLM 决策，LLM 只负责「何时调 / 怎么调 / 根据
  错误调整参数」。
- **产出契约**：``scan`` 结果只返回「6 份 JSON 的落盘路径 + 文件结构」，
  重数据全部落盘，供下游聚合 MCP 直接按 ``path`` 读文件、按 ``structure``
  解析——不经 LLM 中转、不重复扫描。
- **transport**：默认 stdio（客户端把本进程当子进程拉起，走 stdin/stdout 的
  JSON-RPC），零端口零网络，契合离线/vendor 路线。
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from mcp.server.fastmcp import FastMCP

from hyqsast.analyzer import default_frameworks_for
from hyqsast.cpg.languages import detect_by_extension

if TYPE_CHECKING:
    from hyqsast.schema import ScanResult

mcp = FastMCP(
    "hyqsast",
    instructions=(
        "确定性污点分析（SAST）工具：对源码目录输出接口列表、候选漏洞与调用链。"
        "先用 discover 探测语言/框架，再调 scan。scan 返回的是 6 份 JSON 报告的"
        "落盘路径与文件结构，需要详情时按 path 读文件。边界：高召回、允许误报，"
        "结果是「需人工复核的候选」而非最终判定。"
    ),
)

# 6 份产物的 (名称, 文件名, 结构说明)。structure 是与下游的解析契约，
# 字段对齐 schema.py，改动报告结构时需同步更新。
_ARTIFACTS: list[tuple[str, str, str]] = [
    (
        "report",
        "report.json",
        "顶层 {summary, endpoints, findings, blind_spots}；findings 每项 {id, "
        "vuln_type, severity, source{file_path,line,function,code}, sink{...}, "
        "call_chain[{file_path,line,function,code,kind,edge_type}], sanitizers, "
        "sanitized, related_categories, endpoint{route,methods,handler_func,...}}",
    ),
    (
        "canonical",
        "report.canonical.json",
        "list；与 findings 一一对应，每项 {id, vuln_type, vuln_name, endpoint, "
        "sink_function, call_chain}；sink_function 为 sink 函数整段源码，endpoint "
        '形如 "GET /users @ 文件:行 (handler)"，call_chain 为函数级 "a -> b -> sink"（人工复核用）',
    ),
    (
        "elements",
        "report.elements.json",
        "list；规则引擎识别到的全部 source/sink 点，每项 {kind(source|sink), "
        "category, file_path, line, function, code, node_type, patterns, covered}"
        "（漏报排查用）",
    ),
    (
        "flat",
        "report.flat.json",
        "{endpoints[{route,methods,handler_func,file_path,line}], findings[{id,"
        "vuln_type,severity,endpoint(纯接口如 /users),source,sink}]}（聚合友好）",
    ),
    (
        "canonical_route",
        "report.canonical.route.json",
        'list；同 canonical，但 endpoint 只留纯接口（如 "/users"），去掉方法/文件/处理器信息',
    ),
    (
        "canonical_agg",
        "report.canonical.agg.json",
        "list；按 source 点+sink 点(file:line)相同聚合，每项 {id, vuln_type, "
        "vuln_name, endpoint, source, sink, sink_function, "
        "call_chains{call_chain_1, call_chain_2, ...}}",
    ),
]


def _err(code: str, message: str, hint: str) -> str:
    """统一的错误契约：``{ok: false, error: {code, message, hint}}``。"""
    return json.dumps(
        {"ok": False, "error": {"code": code, "message": message, "hint": hint}},
        ensure_ascii=False,
    )


def _count_languages(root: Path) -> Counter[str]:
    """按扩展名统计目录里受支持语言的源码文件数（discover 与 scan 复用）。"""
    counter: Counter[str] = Counter()
    for entry in root.rglob("*"):
        if entry.is_file():
            lang = detect_by_extension(str(entry))
            if lang:
                counter[lang] += 1
    return counter


@mcp.tool()
def discover(directory: str) -> str:
    """探测源码目录的语言与可用框架候选，供 scan 传参（减少一次错误重试）。

    Args:
        directory: 源码根目录绝对路径。
    """
    root = Path(directory).expanduser()
    if not root.is_dir():
        return _err(
            "directory_not_found",
            f"目录不存在或不是目录：{directory}",
            "传绝对路径；先确认该目录存在",
        )
    counter = _count_languages(root)
    if not counter:
        return json.dumps(
            {
                "ok": True,
                "language": None,
                "language_counts": {},
                "framework_candidates": [],
                "source_files": 0,
                "note": "未发现受支持语言（java/python/javascript）的源码文件",
            },
            ensure_ascii=False,
        )
    top = counter.most_common(1)[0][0]
    return json.dumps(
        {
            "ok": True,
            "language": top,
            "language_counts": dict(counter.most_common()),
            "framework_candidates": default_frameworks_for(top),
            "source_files": sum(counter.values()),
        },
        ensure_ascii=False,
    )


@mcp.tool()
def scan(
    directory: str,
    language: str | None = None,
    framework: str | None = None,
    max_findings_per_category: int = 50,
    enable_container_bridge: bool = False,
    enable_state_bridge: bool = False,
    rules_paths: list[str] | None = None,
    output_dir: str | None = None,
) -> str:
    """对源码目录做确定性污点分析（SAST），返回 6 份 JSON 报告的落盘路径与结构。

    适用：代码审计的静态阶段、盘点接口/漏洞候选、理解跨函数调用链。
    边界：高召回、允许误报，结果是「需人工复核的候选」而非最终判定；
    不做语义级别名/反射/动态特性分析。拿不准语言/框架时先调 discover。

    Args:
        directory: 源码根目录绝对路径。
        language: java / python / javascript；缺省自动探测。
        framework: 框架提取器名（spring / flask / express ...）；缺省按语言默认。
        max_findings_per_category: 每个漏洞类别最多产出多少条 finding。
        enable_container_bridge: 容器/Builder 状态写读桥接（默认关，提高召回略增误报）。
        enable_state_bridge: 跨函数状态桥接（默认关）。
        rules_paths: 额外规则文件或目录（在内置 taint_rules.yaml 上追加合并）。
        output_dir: 报告落盘目录；缺省 <directory>/.hyqsast-report/。
    """
    root = Path(directory).expanduser()
    if not root.is_dir():
        return _err(
            "directory_not_found",
            f"目录不存在或不是目录：{directory}",
            "传绝对路径；不确定时先用 discover 确认",
        )

    try:
        from hyqsast import scan as _scan

        result = _scan(
            root,
            language=language,
            framework=framework,
            max_findings_per_category=max_findings_per_category,
            include_blind_spots=True,
            use_cache=True,
            rules_paths=rules_paths,
            enable_container_bridge=enable_container_bridge,
            enable_state_bridge=enable_state_bridge,
        )
    except Exception as exc:  # noqa: BLE001 —— MCP 层要兜住一切，转成统一错误契约
        return _map_error(exc, root)

    out_dir = Path(output_dir).expanduser() if output_dir else root / ".hyqsast-report"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        _write_artifacts(result, out_dir)
    except OSError as exc:
        return _err(
            "output_unwritable",
            f"报告写入失败：{exc}",
            f"换一个可写的 output_dir，或检查 {out_dir} 目录权限",
        )

    lang = language or (counter_top(_count_languages(root)) if root.is_dir() else None)
    fw = framework or (default_frameworks_for(lang) or [None])[0]
    return json.dumps(
        {
            "ok": True,
            "language": lang,
            "framework": fw,
            "summary": asdict(result.summary),
            "artifacts": [
                {
                    "name": name,
                    "path": str(out_dir / fname),
                    "structure": structure,
                }
                for name, fname, structure in _ARTIFACTS
            ],
        },
        ensure_ascii=False,
        indent=2,
    )


def _write_artifacts(result: ScanResult, out_dir: Path) -> None:
    """把 ScanResult 写成 6 份 JSON（顺序与 _ARTIFACTS 一一对应）。"""
    result.to_json(out_dir / "report.json")
    result.to_canonical_json(out_dir / "report.canonical.json")
    result.to_elements_json(out_dir / "report.elements.json")
    result.to_flat_json(out_dir / "report.flat.json")
    result.to_canonical_route_json(out_dir / "report.canonical.route.json")
    result.to_canonical_agg_json(out_dir / "report.canonical.agg.json")


def counter_top(counter: Counter[str]) -> str | None:
    """Counter 中出现次数最多的键；空则 None。"""
    return counter.most_common(1)[0][0] if counter else None


def _map_error(exc: Exception, root: Path) -> str:
    """把底层异常映射成统一的错误契约（hint 直接告诉 LLM 怎么调整）。"""
    msg = str(exc)
    if "未发现受支持语言" in msg:
        return _err(
            "empty_scan",
            msg,
            f"目录 {root} 没有 java/python/javascript 源码；检查目录内容",
        )
    if "Unsupported language" in msg:
        return _err(
            "language_unsupported",
            msg,
            "只支持 java/python/javascript；换一种语言，或省略 language 自动探测",
        )
    if "未知框架" in msg or "Unknown framework" in msg:
        return _err(
            "framework_unknown",
            msg,
            "framework 传合法名，或省略用语言默认；可先调 discover 拿候选",
        )
    if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        return _err(
            "rules_invalid",
            msg,
            "检查 rules_paths 指向的规则文件/目录存在且 YAML 合法；不用就不传",
        )
    return _err(
        "internal_error",
        msg,
        "把 message 原样带回工具维护者（内部异常）",
    )


def main() -> int:
    """启动 MCP server（默认 stdio 传输，不开端口）。"""
    mcp.run(transport="stdio")
    return 0
