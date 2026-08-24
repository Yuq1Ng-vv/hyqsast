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

result = scan("/path/to/java/project", language="java")  # language 可省略（自动探测）
result.to_json("report.json")  # 完整报告 JSON
result.to_canonical_json("report.canonical.json")  # 规范版（人工复核用）
result.to_elements_json("report.elements.json")  # 污点元素清单（漏报排查用）
# 以下三份为新增的聚合友好产物（可与上面几份自由取舍）
result.to_flat_json("report.flat.json")  # 扁平版：接口列表 + 每条 finding 的 source/sink 点与纯接口
result.to_canonical_route_json("report.canonical.route.json")  # 规范版变体，endpoint 只留纯接口 /cmd/exec
result.to_canonical_agg_json("report.canonical.agg.json")  # 规范版变体，按 source+sink 聚合调用链

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
# 生成 report.json 的同时自动写出 report.canonical.json（规范版）、
# report.elements.json（污点元素清单），以及三份聚合友好产物：
# report.flat.json / report.canonical.route.json / report.canonical.agg.json。
# 各自可用 --no-canonical / --no-elements / --no-flat / --no-canonical-route /
# --no-canonical-agg 单独关掉，方便按需取舍。
```

## 离线执行（断网 / 无 uv venv）

整个工具（不只 benchmark）都支持在**离线机器**上运行：依赖打包进仓库内
`vendor/`（gitignored，不随 git 走），目标机只要系统有 **python 3.12**，无需
uv / pip / 网络。

```bash
# ① 在联网机上构建 vendor/（一次；linux/win/mac 三平台，--all = 全构建）
uv run python scripts/build_vendor.py --all        # 任意平台都能交叉构建其它平台

# ② 把整个仓库（含 vendor/ 目录）拷到离线机，然后：
python3 scripts/hyqsast.py /path/to/project --language java -o report.json
#     ^ 等价于 uv run hyqsast ...，启动器按当前平台自动挂 vendor/ 依赖 + src/

# 不想用启动器，或要跑 scripts/ 下其它脚本（如 OWASP 分块扫描）时手动挂 PYTHONPATH：
export PYTHONPATH=$PWD/vendor/common:$PWD/vendor/linux-x86_64:$PWD/src   # 路径分隔符 Linux 是 :
python3 -m hyqsast /path/to/project --language java -o report.json
python3 benchmarks/owasp/chunk_scan.py --per-file ...                    # OWASP 基准也能离线跑
```

**Windows（PowerShell）**：vendor 用 `build_vendor.py --platform win` 构建（本机
直接跑，或任一联网机交叉构建）；命令分隔符换成 `;`，目录换 `win-amd64`：

```powershell
python scripts\hyqsast.py D:\project --language java -o report.json     # 启动器自动识别
$env:PYTHONPATH = "$PWD\vendor\common;$PWD\vendor\win-amd64;$PWD\src"   # 手动挂
python -m hyqsast D:\project --language java -o report.json
```

注意：
- vendor 是给**特定 python 小版本**构建的（tree-sitter 核心是 cp312 专用 `.so`/
  `.pyd`），离线机 python 小版本须与构建时一致（默认 3.12；目标机是 3.13 就用
  `build_vendor.py --python-version 3.13` 重新构建）。
- OWASP Benchmark 源码是另一个网络依赖：离线机上基准的自动 clone 也会失败，
  需把联网机上的 `benchmarks/owasp-benchmark/`（约 240MB）一起拷过去，或
  `export OWASP_BENCH_DIR=已拷位置`。

## MCP 接入（LLM 调用 HyqSast）

个人用仍走上面的 CLI；要让 **LLM 通过 MCP 调用**，另有一层薄封装（纯静态、
零内部 LLM 决策，工具只负责「扫描 → 返回 6 份 JSON 的落盘路径 + 结构」，
重数据落盘供下游聚合 MCP 直接读文件）。设计详见 `docs/MCP接入设计.md`。

```bash
# 装 mcp 依赖（optional extra，需联网一次；核心分析依赖不受影响）
uv sync --extra mcp

# 启动 MCP server（默认 stdio，不开端口），或在 Claude Code 里注册：
claude mcp add hyqsast -- uv run python scripts/hyqsast_mcp.py
```

工具：`discover(directory)` 探测语言/框架候选；`scan(directory, language?,
framework?, max_findings_per_category?, enable_container_bridge?,
enable_state_bridge?, rules_paths?, output_dir?)` 扫描并返回
`{ok, language, framework, summary, artifacts:[{name, path, structure}...]}`。
注意：MCP server 依赖 `mcp` SDK，**不进离线 vendor/**，离线机上跑 MCP 需要
联网装过一次的环境。

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

## 过近似桥接启发式开关（BUG 55/56）

两个为补漏报面加的过近似桥接默认**关**（真项目曾因它们测出几十万 finding）：

- **容器写桥接**（`sb.append(t); s = sb.toString()` 这类对象内部状态写读）
- **跨函数状态桥接**（模块全局 / static / 实例字段一处写、另一处读）

需要高召回、愿意接受这两类桥接引入的误报时，从代码层或 CLI 显式开启：

```python
result = scan(
    "/path/to/project",
    language="python",
    enable_container_bridge=True,   # 容器/Builder 状态写读桥接
    enable_state_bridge=True,       # 跨函数状态桥接
)
```

```bash
uv run hyqsast /path/to/project --language python \
    --enable-container-bridge --enable-state-bridge
```

桥接开关拼进 CPG 图缓存 key，开/关切换不会复用旧图。

**BUG 56 精确化（2026-08-23）**：容器桥接初版（BUG 55）在真实代码 FP 爆炸的根因
有两层——① `_is_container_write` 的 `setXxx/addXxx/putXxx` 前缀兜底把普通 setter
（`Cookie.setPath/setDomain`）当容器写，污点写进宿主 → header_injection FP；② 方法名
白名单在真实代码大量出现在**领域对象**方法上（`order.add(item)`）。修法 = 删 setter
兜底只认白名单 + **宿主类型门控**：Java 下宿主声明类型必须 ∈ `_CONTAINER_TYPES`
（Map/List/Set/Collection/StringBuilder/HttpSession/Cookie 等约 45 个），由
`callgraph_builder.var_types(file_path)` 提供显式声明类型；非 Java 无类型信息维持旧
行为。OWASP 容器 FN（`map.put` / `List.add` / `argList.add`）宿主全显式声明为容器
类型，不受影响。

**开启成本（精确化后，OWASP per-file 口径，2026-08-23 实测）**：FN 50→40（
**10 容器 FN 全恢复**：cmdi -4 / sqli -5 / pathtraver -1），TPR 96.5%→**97.2%**；
findings 24206→24679（**+473，对比旧桥接 +6024，爆炸缩小 92%**）；安全用例新标
**+5 全为集合键不敏感**（`map.put("keyB",taint)` 后 `get("keyA")` 读安全键、`add`
后 `remove/get` 偏移），即既有 FPR 71.8% 的主流来源（需 P3 键敏感数据流），
**header_injection 零新增**（setter 兜底删除彻底生效）。归档
`benchmarks/owasp/results/2026-08-23-bridge-precise/`。

**真实项目验证（ureport2，469 文件整体扫描）**：bridge-on 5213→5243（+30/+0.6%），
**不爆炸**。但 30 条 sql_injection 逐条验证**全部是 FP**——规则级假 sink（java
sql_injection sink 模式 `List(` 命中 `orderBindDataList(`（GroupAggregate 的 **Java
内存排序**，"orderBindData**List(**" 含 "List("）+ `.insert(` 命中
`sb.insert(0, "style=\"")`（**StringBuilder 拼 HTML**））+ 容器桥接过近似把 taint
灌进 `list`/`sb` 参数。这些假 sink 模式基线上就存在（off 口径 1512 条 sqli 里
`List(` 已占 278、`.insert(` 占 22），桥接只是多接了几条流；真 SQL 源
（`req.getParameter("sql")`）的真执行点（`jdbc.execute` / `queryForList`）基线已报，
**+30 不是任何新增真实命中**。这指向 P3「规则清洗」（收紧 `List(` / `.insert(`）。

**默认关是有意权衡**：真项目可用性优先，代价是这两类桥接补的 A/J 类漏报面召回
缩水；要补 A/J 类召回时开启，成本已从旧版「findings +24% + header FP」压到
「+0.6%~+2% + 键不敏感 FP」（见上）。全量对比见 `benchmarks/owasp/results/`。

## 结果结构（`ScanResult`）

```jsonc
{
  "summary": { "files": 0, "functions": 0, "endpoints": 0,
               "findings": 0, "sources": 0, "sinks": 0, "blind_spots": 0 },
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
      "sanitizers": [], "sanitized": false,
      "endpoint": { "match": "exact", "route": "/users", "methods": ["GET"],
                    "handler_func": "getUser", "file_path": "...", "line": 12,
                    "framework": "spring", "params": [...] } }
  ],
  "blind_spots": [ { "kind":"endpoint_no_source", "location":"...", "reason":"...", "recommendation":"..." } ]
}
```

每条 finding 的 **`endpoint`** 字段把漏洞对应到具体 HTTP 接口（冗余展开接口摘要，
供 LLM 下游直接消费，无需再 join `endpoints` 表）。`match` 表示匹配程度：

- `"exact"`：finding 的 source 所在 `(文件, 函数)` 与接口的 `(file_path, handler_func)` 完全一致；
- `"same_file"`：同文件内有接口但 handler 名对不上，按同文件第一个接口退化匹配（相关但不完全确定）；
- `"unmatched"`：source 所在文件里没有识别到任何接口。

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

## 污点元素清单（`report.elements.json`）

与完整报告同时生成，列出本次扫描**规则引擎识别到的全部 source / sink 点**，供**排查漏报**
（某条真实漏洞为什么没出 finding）。结构是一个列表，每个元素对应图上一个被打
`taint_source` / `taint_sink` 标签的节点（多类别节点逐类别展开）：

```jsonc
[
  {
    "kind": "sink", "category": "sql_injection",
    "file_path": ".../UserController.java", "line": 14,
    "function": "getUser", "code": "jdbc.queryForObject(sql, String.class)",
    "node_type": "call_site", "patterns": [".queryForObject("], "covered": true
  }
]
```

- **`kind`**：`"source"` / `"sink"`。
- **`category`**：命中的漏洞类别（如 `sql_injection`；source 常用兜底的 `injection_general`）。
- **`patterns`**：该点命中的具体规则模式（参数节点的 source 由注解推导，此列为空）。
- **`covered`**：该 `(file, line)` 是否出现在某条已产出 finding 的 source/sink 里。
  `covered: false` 的 sink 即「规则命中了、却没接住任何 finding」——漏报排查从这里入手
  （要么上游没有可到达的 source，要么数据流链在某处断了）。

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

## 验证（基准回归）

**[OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava)**（Java
servlet 漏洞基准，2766 个测试用例、11 个漏洞类别）全量评分 —— 官方口径
**TPR = TP/(TP+FN)**（仅脆弱用例）、**FPR = FP/(FP+TN)**（仅安全用例）：

| 类别 | 脆弱用例 | TP | TPR% | FPR% |
|---|---|---|---|---|
| weakrand | 218 | 218 | **100** | 18.9 |
| securecookie | 36 | 36 | **100** | 0.0 |
| trustbound | 83 | 83 | **100** | 100 |
| xss | 246 | 246 | **100** | 100 |
| ldapi | 27 | 27 | **100** | 100 |
| sqli | 272 | 272 | **100** | 99.1 |
| xpathi | 15 | 15 | **100** | 100 |
| crypto | 130 | 130 | **100** | 90.5 |
| cmdi | 126 | 126 | **100** | 100 |
| hash | 129 | 89 | 69.0 | 0.0 |
| pathtraver | 133 | 133 | **100** | 100 |
| **TOTAL** | **1415** | **1375** | **97.2** | 71.8 |

其中 `hash` / `weakrand` / `securecookie` / `weak_crypto` 是「危险 API 使用本身」
的非污点流漏洞（无 source 流入），由 `pattern_sinks` 机制接住；`trust_boundary`
是污点流。hash 的 40 个 FN 全是配置驱动算法（`getInstance(algorithm)` ←
`getProperty("hashAlg1")`），静态不可判定。`weak_crypto`（硬编码弱算法 DES/RC 等）
带 `related_categories=["crypto_weakness"]` 并入 crypto 评分，crypto 由 92.3% 补到
**100%** 且 FP 零增加（safe 用例 0 命中）。回归铁律（不增漏报）：五基准
（vfa / flask-xss / vampi / demo-java + 探针）A/B 全部零丢失。

复现：`uv run python benchmarks/owasp/run.py`（1GB 小机器须**分块扫描**，
275 文件/块 × 10，方法见 `docs/TODO.md`；全量结果存档于
`benchmarks/owasp/results/`）。

**逐例溯源清单**（sink 源码位置 + 根因归类 + 可修性）见
[`docs/OWASP漏报清单.md`](docs/OWASP漏报清单.md)：初始 143 条 FN，P0 已修 pathtraver
FQN 规则缺口 40 条（TPR 89.9%→92.7%），P1 已修 cmdi 37 条（TPR 70.6%→100%，
根因 `System.getProperty` source 误吞 sink 标签 + envp 位置门控），P2 已修 sqli
10 条 + 顺带恢复 pathtraver 5 / xpathi 1（TPR 95.3%→96.5%，根因多行调用/赋值
桥接断链 BUG 46/48 + BFS 非单调 BUG 47），P3 已修 crypto 10 条（TPR 92.3%→100%，
新建 `weak_crypto` 精确 pattern 类别，4 个「配置驱动」实证含硬编码
`KeyGenerator.getInstance("DES")` 一并恢复；FP 零增加）。现剩 **40 条**全部为
hash 配置驱动算法（静态不可判定，固有）；四轮修复引入的 FP 代价也如实记录在案。

## 边界与免责

- 这是**确定性、正则/tree-sitter 级**的污点分析，追求**高召回**，会有一批**误报**；
  跨文件参数↔实参采用「参数名→位置→兜底全连接」的分级匹配（边带
  `confidence` 属性）。产出是**需人工复核的候选**，不是最终判定。
- 未做语义级别名/反射/动态特性分析；跨函数 CFG 不展开（每个函数 CFG 自洽）。
- `blind_spots` 只含「无已知污点源的接口」这一种；未标记危险调用（`uncovered_sink`）
  在 `cpg/discovery.py` 里可另行调用，默认不产出以避免真实项目噪声爆炸。
- 容器/状态两个过近似桥接**默认关**，可显式开启（见「过近似桥接启发式开关」节）。
- 已知限制与优化路线图见 [`docs/TODO.md`](docs/TODO.md)（P0/P1 已完成、P2/P3 待做）。
- 全量漏报面排查见 [`docs/漏报面清单.md`](docs/漏报面清单.md)（A–I 分类、实测断点、优化顺序）。

## 目录结构

```
src/hyqsast/
├── api.py        # scan() 门面
├── analyzer.py   # 编排：建图 → 接口 → 污点 → 汇总
├── schema.py     # 结果数据模型 + severity 映射
├── cli.py        # 命令行入口
└── cpg/          # 从 hyqagent 抽取的 CPG 引擎（tree-sitter/图/污点/框架提取器）
```
