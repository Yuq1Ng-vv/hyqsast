# MCP 接入设计（草案）

> 状态：设计稿，未实现。目标：在**完全保留现有 CLI 流程**的前提下，给 LLM
> 一条"通过 MCP 调用 HyqSast"的路径。HyqSast 本身纯静态、确定性、零 LLM——
> MCP 层只是把 `scan()` 包成一个工具，不做任何内部决策。

## 1. 定位与原则

- **个人用**：还是老流程 `uv run hyqsast <项目> --language java -o report.json`，一条都不改。
- **LLM 用**：客户端拉起 MCP server，暴露一个 `scan` 工具。LLM 只负责三件事：
  什么时候调、怎么调、以及根据错误信息怎么调整参数。
- 工具是**同步、无状态、幂等**的：每次调用独立扫描，返回结构化结果 + 6 份
  JSON 的落盘路径。不建长连接、不存会话状态。
- 内存铁律继承：默认单次完整扫描（大项目有分块/`per_file` 逃生舱，见 §5）。

## 2. MCP 是怎么实现的（transport）

MCP（Model Context Protocol）是客户端 ⇄ 服务端的 JSON-RPC 协议。服务端暴露
tools/resources/prompts，客户端调 `tools/call`。**本地工具默认用 stdio，不开端口**：

```
Claude Code / Claude Desktop
   │  启动时把 server 当子进程拉起
   ▼
python scripts/hyqsast_mcp.py        ← MCP server（stdio 传输）
   │  stdin/stdout 走 JSON-RPC 消息
   ▼
hyqsast.scan(directory, language, ...)   ← 复用现有 api.py，零改动
```

- **stdio（本地，推荐）**：零端口、零网络、离线可用——契合 `vendor/` 离线路线。
- **HTTP/streamable-http（远程）**：只有"server 跑在别的机器 / 多客户端共享"
  才需要，那才开一个 HTTP 端口。当前阶段不做。

## 3. 目录与依赖

```
src/hyqsast_mcp/
├── __init__.py
└── server.py          # FastMCP，注册 scan 工具（见 §4）
scripts/hyqsast_mcp.py # 启动器：挂 vendor+src 到 sys.path，再 mcp.run()
pyproject.toml         # [project.optional-dependencies] mcp = ["mcp>=1.x"]
```

- `mcp` SDK 是**optional extra**：`uv sync --extra mcp` 才装，核心 `hyqsast`
  依赖零新增（依赖铁律不受影响）。
- `scripts/hyqsast_mcp.py` 复用 `scripts/hyqsast.py` 的离线启动逻辑（挂
  `vendor/common + vendor/<平台> + src`），所以断网机器照样能跑 MCP server。

## 4. 工具规格

### 4.1 `scan`

**description**（就是 LLM 看到的契约，要写清楚"何时调、输出是什么、边界在哪"）：

> 对源码目录做确定性污点分析（SAST），返回接口列表 + 候选漏洞 + 调用链。
> 适用：代码审计的静态阶段、需要了解项目入口/接口、按漏洞类别盘点代码。
> 边界：高召回、允许误报，结果是"需人工复核的候选"，非最终判定；不做语义级
> 别名/反射/动态特性分析。调用前可用 `discover` 探测语言与框架。

**inputs**（JSON Schema）：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `directory` | string | ✅ | 源码根目录**绝对路径** |
| `language` | string | | 枚举 `java`/`python`/`javascript`；缺省自动探测 |
| `framework` | string | | 框架提取器名（`spring`/`flask`/`express`...）；缺省按语言默认 |
| `max_findings_per_category` | integer | | 每类别最多 finding 数，默认 50 |
| `enable_container_bridge` | boolean | | 容器/Builder 状态桥接，默认 false（开则提高召回、略增误报） |
| `enable_state_bridge` | boolean | | 跨函数状态桥接，默认 false |
| `rules_paths` | string[] | | 额外规则文件或目录（在内置 `taint_rules.yaml` 上追加去重合并） |
| `output_dir` | string | | 报告落盘目录；缺省 `<directory>/.hyqsast-report/` |

> v1 无 `mode`（`per_file` 分块扫描）与 `include_findings`——结果本就只回
> 路径+结构，`mode=per_file` 留到 v2 需要时再加。

**outputs**（成功）：

```json
{
  "ok": true,
  "language": "java",
  "framework": "spring",
  "summary": {
    "files": 12, "functions": 45, "endpoints": 5,
    "findings": 6, "sources": 67, "sinks": 16, "blind_spots": 0
  },
  "artifacts": [
    {
      "name": "report",
      "path": "/abs/path/.hyqsast-report/report.json",
      "structure": "顶层 {summary, endpoints, findings, blind_spots}；findings 每项 {id, vuln_type, severity, source{file_path,line,function,code}, sink{...}, call_chain[{file_path,line,function,code,kind,edge_type}], sanitizers, sanitized, related_categories, endpoint{route,methods,handler_func,...}}"
    },
    {
      "name": "canonical",
      "path": "/abs/path/.hyqsast-report/report.canonical.json",
      "structure": "list，与 findings 一一对应；每项 {id, vuln_type, vuln_name, endpoint, sink_function, call_chain}，sink_function 为 sink 函数整段源码（人工复核用）"
    },
    {
      "name": "flat",
      "path": "/abs/path/.hyqsast-report/report.flat.json",
      "structure": "{endpoints[{route,methods,handler_func,file_path,line}], findings[{id,vuln_type,severity,endpoint(纯接口),source,sink}]}，聚合友好"
    },
    {
      "name": "canonical_route",
      "path": "/abs/path/.hyqsast-report/report.canonical.route.json",
      "structure": "list；同 canonical，但 endpoint 只留纯接口 /cmd/exec（去掉方法/文件/处理器）"
    },
    {
      "name": "canonical_agg",
      "path": "/abs/path/.hyqsast-report/report.canonical.agg.json",
      "structure": "list；按 source 点+sink 点相同聚合，{id, vuln_type, vuln_name, endpoint, source, sink, sink_function, call_chains:{call_chain_1, call_chain_2, ...}}"
    },
    {
      "name": "elements",
      "path": "/abs/path/.hyqsast-report/report.elements.json",
      "structure": "list；规则引擎识别到的全部 source/sink 点 {kind, category, file_path, line, function, code, node_type, patterns, covered}，漏报排查用"
    }
  ]
}
```

**设计要点：结果本身刻意保持小，重数据全部落盘。**

- 返回给 LLM 的只有：**文件路径 + 文件结构描述**（`structure` 字段就是"怎么解析
  这个文件"的契约）。LLM 据此知道该读哪个文件、读哪些字段。
- 6 份 JSON 是**与下游 MCP 的交换格式**：后续聚合 MCP 直接按 `path` 读文件、
  按 `structure` 解析，不必经过 LLM 中转或再调一次 HyqSast。
- `summary` 只给计数，让 LLM 不用开文件就能决定下一步（是否读文件、扫得够不够）。
- 需要 sink 函数整段源码 / 完整调用链等重内容时，LLM 去读 `canonical` /
  `canonical_agg` 对应文件。

### 4.2 `discover`（可选，先探测再扫）

```json
{"directory": "..."}
→ {"ok": true, "language": ["java"], "framework_candidates": ["spring"],
   "file_count": 42, "estimated_scale": "small"}
```

LLM 拿探测结果决定传哪个 `language`/`framework`，减少一次错误重试。

## 5. 错误情况与 LLM 应如何调整（工具契约的一部分）

错误输出统一为 `{"ok": false, "error": {"code": "...", "message": "...", "hint": "..."}}`。
`hint` 直接写"该怎么改"：

| code | message 要点 | hint（LLM 照做） |
|---|---|---|
| `directory_not_found` | 路径不存在 / 不是目录 | 传**绝对路径**，先用 `discover` 确认存在 |
| `language_undetected` | 自动探测失败 | 显式传 `language` |
| `language_unsupported` | 收到 go/ruby/c++ 等 | 只有 `java`/`python`/`javascript`；换语言或不扫 |
| `framework_unknown` | 提取器名不存在 | 去掉 `framework`（用语言默认）或传合法名 |
| `rules_invalid` | 规则文件缺失 / YAML 非法 | 修正 `rules_paths`；不用就不传 |
| `scan_timeout` | 超时（大项目同步扫太久） | 开 `mode=per_file`，或缩小 `directory`，或 `include_findings=false` 先拿 summary |
| `empty_scan` | 目录里无可解析源码 | 不是错误；检查目录内容，空结果也是合法输出 |
| `internal_error` | 未知异常 | 把 `message`（含 stderr 尾部）原样带回 |

## 6. 客户端接入示例

```bash
# Claude Code（项目内 .mcp.json 或命令注册）
claude mcp add hyqsast -- python3 scripts/hyqsast_mcp.py

# Claude Desktop：claude_desktop_config.json 里加
{
  "mcpServers": {
    "hyqsast": { "command": "python3", "args": ["/path/to/scripts/hyqsast_mcp.py"] }
  }
}
```

## 7. 决策记录（v1 已定，v2 待定）

1. **同步 vs 带 job**：v1 定案为**同步**。大项目超时由错误契约（`scan_timeout`
   思路）+ `per_file` 逃生舱兜底；`async: true → job_id + scan_status/scan_result`
   等真有"等不起"的需求再上。
2. **resources vs 只给路径**：定案**只给路径**。下游聚合 MCP 直接按 `path` 读
   文件、按 `structure` 解析，resource 懒加载没有意义。
3. **`discover`**：已实现为独立工具（v1）。
4. **MCP 离线约束（v1 明确）**：核心 CLI 完全离线（vendor/ 六依赖）；但 MCP
   server 依赖 `mcp` SDK（含 pydantic/starlette 等重依赖），**需联网装一次**
   `uv sync --extra mcp`，vendor/ 不打包它。`scripts/hyqsast_mcp.py` 启动器只
   保证在有 mcp 的 python 环境里能跑。
