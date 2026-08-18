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
result.to_json("report.json")                             # 落盘 JSON

for f in result.findings:
    print(f.vuln_type, f.severity, f.source.file_path, f.source.line)
    for step in f.call_chain:
        print("  ", step.function, step.file_path, step.line, step.code)
```

### 命令行

```bash
uv run hyqsast /path/to/java/project --language java -o report.json
```

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
