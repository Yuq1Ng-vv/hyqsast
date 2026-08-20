# CLAUDE.md

本文件为 Claude Code（claude.ai/code）在此仓库工作时提供指导。

## 项目概述

**HyqSast** 是一个独立、确定性的**污点分析（SAST）模块**。输入一个源码目录 + 语言/框架配置，输出三类结构化产物：

1. **接口**（`Endpoint`）— HTTP 路由、方法、参数、鉴权注解
2. **漏洞类型**（`vuln_type`）— SQL 注入 / XSS / SSRF / 路径穿越 / XXE / 反序列化等 20+ 类
3. **调用链**（`call_chain`）— source → sink 的跨函数传播路径（含每步文件/行号/函数/源码/边类型）

**核心原则：零 LLM。** 全部基于 tree-sitter（AST 解析）+ NetworkX（图遍历）+ 子串/正则匹配，可在 CI 里直接跑。追求**高召回**，会有一批误报，产出是「需人工复核的候选」，不是最终判定。

**缺陷平衡铁律：解决误报（FP）的前提是不增加漏报（FN）。** 任何收窄规则 / 切断桥接 / 位置门控的改动，都必须先在既有基准（vfa / flask-xss / vampi / demo-java 及探针样例）上证明「原有命中一条不少」再落地；做不到就保留过近似，靠规则更精确而非靠砍路径。

## 常用命令

```bash
# 安装（uv，Python >= 3.12）
uv sync

# 运行 CLI
uv run hyqsast /path/to/project --language java -o report.json

# 运行示例脚本
uv run python examples/scan_demo.py /path/to/project [language]

# 测试 / 静态检查（dev 依赖组，当前仓库尚无 tests/ 目录）
uv run pytest
uv run ruff check .
uv run ruff format .
```

依赖仅 6 个轻量包：`tree-sitter`、`tree-sitter-python/java/javascript`、`networkx`、`pyyaml`。**不要**引入 LLM / langgraph / 报告栈等重依赖。

## 架构与数据流

入口 `src/hyqsast/api.py` 的 `scan()` → `Analyzer.run()` 编排四步：

```
建图 → 提取接口 → 跑污点 → 汇总
CPGGraphBuilder.add_directory  → _extract_endpoints → _build_findings → _summarize
```

### 目录结构

```
src/hyqsast/
├── api.py          # scan() 公开门面（薄封装，转发给 Analyzer）
├── analyzer.py     # 编排层：建图 → 接口 → 污点(BFS) → 盲区 → 汇总
├── schema.py       # 结果数据模型（纯 dataclass）+ SEVERITY_MAP
├── cli.py          # argparse 命令行入口
└── cpg/            # 从 hyqagent 抽取的 CPG 引擎（可独立复用）
    ├── parser.py         # 多语言 tree-sitter 解析封装（语言无关）
    ├── graph.py          # CPGGraphBuilder：构建 nx.MultiDiGraph + 污点标签
    ├── query.py          # CPGQuery：路径查询 / 支配分析 / 覆盖率查询
    ├── taint_loader.py   # 从 taint_rules.yaml 加载规则
    ├── taint_rules.yaml  # source/sink/sanitizer 规则（~4600 行，规则引擎数据）
    ├── dataflow.py       # def-use 链分析
    ├── callgraph.py      # 单文件调用图
    ├── callgraph_builder.py # 跨文件调用图 + import 解析
    ├── cfg.py            # CFG 构建 + 支配/后支配/控制依赖分析
    ├── discovery.py      # 启发式 sink 发现 + 接口盲区检查
    ├── coverage.py       # 覆盖率统计
    ├── traversal.py      # AST 遍历器
    ├── types.py          # 共享 dataclass 类型（避免循环依赖）
    ├── languages/        # 语言适配器（LanguageProvider 注册表）
    └── frameworks/       # Web 框架路由提取器（BaseFrameworkExtractor 注册表）
```

## 核心概念

### CPG 图（`cpg/graph.py`）

`nx.MultiDiGraph`，节点与边类型常量定义在 `graph.py` 顶部：

- **节点类型**：`function` / `parameter` / `assignment` / `variable_ref` / `call_site` / `basic_block`
- **边类型**：`AST`（语法）、`CALLS`（调用）、`DATA_FLOW`（数据流）、`CTRL_FLOW`（控制流）

污点标签通过 `_label_taint_nodes()` 打到 `assignment` / `call_site` / `parameter` 节点上，属性为 `taint_source` / `taint_sink` / `taint_category`（逗号分隔的多类别）。**source 优先于 sink**：一个节点匹配了 source 就不再评估 sink（节点不可能同时是 source 和 sink）。

污点传播关键设计（见 `graph.py` 内注释）：
- **跨函数**（P1-3）：参数名匹配（high）→ 位置匹配（medium）→ 全连接兜底（low），
  边带 `confidence` 属性；两级都未命中才全连接（过近似，保证不漏报）
- **RHS→LHS 边**：`list = jdbc.query(sql)` 中 `sql` 的 var_ref → `list` 的 assignment
- **var_ref → call_site 边**：`jdbcTemplate.query(sql)` 这种表达式语句的 sink 桥接

### 漏洞类型由 sink 决定（`analyzer.py`）

source 只表示「有用户输入」，精确 vuln_type 由 sink 决定（如 `jdbcTemplate.query` → `sql_injection`）。从任意 source 前向 BFS（沿 `DATA_FLOW`/`CALLS`），命中 sink 后用 sink 类别作为 vuln_type。`injection_general` 是兜底类别，与具体类别共存时被丢弃以避免重复 finding。

严重级别映射在 `schema.py` 的 `SEVERITY_MAP`，可通过 `scan(severity_overrides={...})` 覆盖。

### 规则引擎（`cpg/taint_rules.yaml` + `taint_loader.py`）

`taint_rules.yaml` 是分析的知识库，结构为 `语言 → {sources, sinks, sanitizers, sink_excludes}`，每个类别下是子串/正则模式列表。**新增漏洞规则只改这个 YAML，不改代码**。`taint_loader.py` 负责加载、校验（`_validate()`）和匹配（`match_source`/`match_sink`/`match_all_*`）。

## 扩展点（新增能力时的入口）

1. **新语言**：创建 `cpg/languages/<name>.py` 实现 `LanguageProvider`，在 `languages/__init__.py` 的 `_BUILDER` 注册一行即可。`parser.py` / `callgraph.py` 无需改动。契约见 `languages/base.py`。
2. **新框架**：创建 `cpg/frameworks/<name>.py` 实现 `BaseFrameworkExtractor`，在 `frameworks/__init__.py` `_register()`。契约见 `frameworks/base.py`。
3. **新漏洞类别 / 规则**：编辑 `cpg/taint_rules.yaml`（对应语言的 sources/sinks/sanitizers），并在 `schema.py` 的 `SEVERITY_MAP` 加一行严重级别。不想动内置大文件时，可用 `scan(rules_paths=[...])` / CLI `--rules` 传额外规则文件或目录（在 `taint_rules.yaml` 之上按 `(语言,区块,类别)` 追加去重合并，见 `taint_loader.py` 的 `_merge`）。模板与 CodeQL 适配契约见 `examples/rules/`。

## 约定与风格

- **注释与 docstring 用中文**，代码/标识符用英文。每个模块顶部有 `"""module — 一句话职责"""` 的 docstring。
- Python 3.12+，`from __future__ import annotations`。类型标注完整，用 `|` 联合类型。
- 数据模型一律纯 `dataclass`（`schema.py`、`types.py`），避免引入 pydantic 等重依赖。
- Ruff 配置在 `pyproject.toml`：`line-length=100`，`select = ["E","F","W","B","I","N","UP"]`，`target-version=py312`。
- 图节点 id 用 `_uid()` 以 `:` 拼接；位置字符串统一 `file_path:line` 格式，解析用 `rsplit(":", 1)` 以兼容 Windows 路径。
- 大量历史修复以 `BUG N:` 注释标注在代码里（如 `graph.py` 的 `BUG 30` 重载方法去重、`BUG 26` Windows 路径），修改这些地方时先读注释理解上下文。

## 边界与已知限制（README 原文）

- 这是**确定性、正则/tree-sitter 级**的污点分析，追求高召回，会有误报；跨文件参数↔实参采用「位置匹配 + 兜底全连接」过近似。
- 未做语义级别名/反射/动态特性分析；跨函数 CFG 不展开（每个函数 CFG 自洽）。
- `blind_spots` 默认只含「无已知污点源的接口」（`endpoint_no_source`）。未标记危险调用（`uncovered_sink`）在 `cpg/discovery.py` 里可另行调用，默认不产出以避免真实项目噪声爆炸。

## 相关资源

- 完整用法与结果结构示例见 `README.md`。
- 最小可运行示例见 `examples/scan_demo.py`。
- 已知限制与优化路线图（P0/P1 已完成、P2/P3 待做）见 `docs/TODO.md`。
- 全量漏报面排查（A–I 分类 + 复现材料 + 优化顺序）见 `docs/漏报面清单.md`。
- 面向汇报的通俗进展介绍稿（给混合听众讲设计/实现/目的）见 `docs/项目进展介绍.md`。
