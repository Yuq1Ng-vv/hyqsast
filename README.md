# HyqSast

独立确定性污点分析模块。输入一个源码目录 + 语言/框架配置，输出三类结构化产物：

1. **接口**（`Endpoint`）— HTTP 路由、方法、参数、鉴权注解
2. **漏洞类型**（`vuln_type`）— SQL 注入 / XSS / SSRF / 路径穿越 / XXE / 反序列化 … 共 20+ 类
3. **调用链**（`call_chain`）— source → sink 的跨函数传播路径（含每一步文件/行号/函数/源码/边类型）

全部**零 LLM**，纯 tree-sitter + NetworkX 图遍历，可在 CI 里直接跑。

## 安装

```bash
cd ~/hyqsast
uv sync              # 只装 6 个轻依赖，无 LLM / langgraph / 报告栈
```

依赖仅：`tree-sitter`、`tree-sitter-python/java/javascript`、`networkx`、`pyyaml`。

## 快速开始

### Python API

```python
from hyqsast import scan

result = scan("/path/to/java/project", language="java")   # language 可省略（自动探测）
result.to_json("report.json")                             # 完整报告 JSON
result.to_canonical_json("report.canonical.json")         # 规范版（人工复核用）

for f in result.findings:
    print(f.vuln_type, f.severity, f.source.file_path, f.source.line)
    for step in f.call_chain:
        print("  ", step.function, step.file_path, step.line, step.code)
```

`result.canonical_findings` 是与 `result.findings` 一一对应的规范版条目
（每条含中文漏洞名 + 接口 + sink 函数完整源码 + 函数级真实调用链）。

### 命令行

```bash
uv run hyqsast /path/to/java/project --language java -o report.json
# 生成 report.json 的同时自动写出 report.canonical.json；
# 加 --no-canonical 可只出完整报告
```

## 自定义规则库

规则库在 `src/hyqsast/cpg/taint_rules.yaml`。可以不改这个大文件，用**额外规则
文件**（或目录）在它之上追加合并——适合批量适配 CodeQL 规则等场景：

```bash
# 仓库根目录下存在 rules/ 时自动加载（零配置）；--rules 可显式覆盖
uv run hyqsast /path/to/project --language java -o report.json
uv run hyqsast /path/to/project --language java --rules rules/fastjson.yaml --rules rules/ -o report.json
```

```python
result = scan("/path/to/project", language="java", rules_paths=["rules/fastjson.yaml"])
```

- 额外文件结构与内置 YAML 一致：`语言 → {sources, sinks, sanitizers, sink_excludes}`；
  `sources/sinks/sanitizers` 是**子串**列表，`sink_excludes` 是**正则**。
- 合并语义：按 `(语言, 区块, 类别)` **追加去重**，不覆盖内置规则。
- 模板与 CodeQL 适配契约见 `examples/rules/`（`example.rules.yaml` + `README.md`）；
  你的适配规则放仓库根目录 `rules/`（自动加载，契约见 `rules/README.md`）。

## 结果结构（`ScanResult`）

```jsonc
{
  "summary": { "files": 0, "functions": 0, "endpoints": 0,
               "findings": 0, "sinks": 0, "blind_spots": 0 },
  "endpoints": [
    { "route": "/api/users/{id}", "methods": ["GET"],
      "handler_func": "getUser", "file_path": "...", "line": 12,
      "params": [{"name":"id","source":"path","type_hint":"String","required":true}],
      "auth_required": false, "framework": "spring" }
  ],
  "findings": [
    { "id": "sql_injection-...", "vuln_type": "sql_injection", "severity": "critical",
      "source": {"file_path":"...","line":20,"function":"getUser","code":"...","category":"sql_injection"},
      "sink":   {"file_path":"...","line":35,"function":"query","code":"...","category":"sql_injection"},
      "call_chain": [
        {"file_path":"...","line":20,"function":"getUser","code":"...",
         "kind":"assignment","edge_type":"DATA_FLOW"}
      ],
      "sanitizers": [], "sanitized": false }
  ],
  "blind_spots": [ { "kind":"endpoint_no_source", "location":"...", "reason":"...", "recommendation":"..." } ]
}
```

## 规范版报告（`report.canonical.json`）

与完整报告同时生成，专为**人工复核**设计。结构是一个列表，每条对应一个 finding，
六个字段：`id` / `vuln_type` / `vuln_name` / `endpoint` / `sink_function` / `call_chain`。

```jsonc
[
  {
    "id": "sql_injection-.../UserController.java:11->...:14",
    "vuln_type": "sql_injection",
    "vuln_name": "SQL 注入 @ .../UserController.java:14",
    "endpoint": "GET /user @ .../UserController.java:11 (getUser)",
    "sink_function": "  12 | public String getUser(@RequestParam String id) {\n"
                   "  13 |     String sql = \"SELECT * FROM users WHERE id = \" + id;\n"
                   "▶ 14 |     return jdbc.queryForObject(sql, String.class);  // ← SINK: sql_injection\n"
                   "  15 | }",
    "call_chain": "getUser @ src/UserController.java:11 -> queryForObject @ src/UserController.java:14  ← SINK"
  }
]
```

- **`vuln_name`**：中文漏洞名 + 漏洞所在文件位置（sink 行）。
- **`endpoint`**：漏洞所在 HTTP 接口；按 `(文件, handler)` 匹配，匹配不到则为空串。
- **`sink_function`**：sink 点所在函数**完整源码**，带行号，sink 行前缀 `▶` 并尾注 `← SINK: 类别`。
- **`call_chain`**：函数级**真实调用链** `x -> y -> z -> sink`，每个 hop 带相对扫描目录的
  `file:line`；同一函数内步骤折叠为一步，方法链 sink（如 `a.b().c()`）取链尾真实调用名。

## 漏洞类型 → 严重级别

默认映射在 `src/hyqsast/schema.py` 的 `SEVERITY_MAP`，可通过
`scan(..., severity_overrides={"xss": "high"})` 覆盖。

| 级别 | 类别 |
|---|---|
| critical | code_injection / command_injection / deserialization / jndi_injection / ssti / sql_injection / xpath_injection / xxe / ldap_injection |
| high | ssrf / path_traversal / auth_bypass / header_injection / format_string |
| medium | xss / open_redirect / crypto_weakness / log_injection / info_disclosure / injection_general |

## 支持范围

- **语言**：Java、Python、JavaScript（缺省自动探测目录主语言）
- **框架**（接口提取）：Spring、Flask、Django、FastAPI、Express
- **分析**：污点 source→sink 传播（`taint_rules.yaml` 驱动，Java 20 类 / Python / JS 各有对应规则）

## 边界与免责

- 这是**确定性、正则/tree-sitter 级**的污点分析，追求**高召回**，会有一批**误报**；
  跨文件参数↔实参采用「位置匹配 + 兜底全连接」的过近似。产出是**需人工复核的候选**，
  不是最终判定。
- 未做语义级别名/反射/动态特性分析；跨函数 CFG 不展开（每个函数 CFG 自洽）。
- `blind_spots` 只含「无已知污点源的接口」这一种；未标记危险调用（`uncovered_sink`）
  在 `cpg/discovery.py` 里可另行调用，默认不产出以避免真实项目噪声爆炸。

## 目录结构

```
src/hyqsast/
├── api.py        # scan() 门面
├── analyzer.py   # 编排：建图 → 接口 → 污点 → 汇总
├── schema.py     # 结果数据模型 + severity 映射
├── cli.py        # 命令行入口
└── cpg/          # 从 hyqagent 抽取的 CPG 引擎（tree-sitter/图/污点/框架提取器）
```
