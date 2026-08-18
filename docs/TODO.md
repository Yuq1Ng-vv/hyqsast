# HyqSast 优化路线图（TODO）

> 按「什么时候想起来了什么时候做」的记录。已完成项也列出，避免重复评估。
> 条目带估算优先级（P0/P1/P2/P3）与动机；P0/P1 已全部落地（见下文「已完成」）。

## 已完成（P0/P1，2026-08）

- **P0-1 sanitizer 净化语义 def-use 级**（`analyzer.py::_sanitizers_on_path`，BUG 38）
  只检查语句级节点（CALL_SITE / ASSIGNMENT），不再匹配整个函数体；CALL_SITE
  在能拿到污点变量与实参时要求污点确实作为实参流入净化调用。
- **P0-2 finding 截断可见化**（`ScanSummary.truncated_categories` + CLI ⚠ 提示）
  每类别因 `max_findings_per_category` 被截断多少，不再静默吞掉。
- **P1-3 跨函数匹配分级**（`graph.py::_add_cross_function_edges`，缓存 v3）
  参数名匹配（high）→ 位置匹配（medium）→ 全连接兜底（low），边带
  `confidence` 属性。后续可用它做加权 BFS / 低置信边过滤。
- **P1-4 sink 危险参数位置门控**（`analyzer.py`，`_SINK_STR_TEMPLATE_CATS`）
  字符串模板型注入（sql/command/code/xpath/ssti）只认首参为危险载荷；
  污点在绑定参数位（`query(sql, tainted_param)`）不算命中，消参数绑定误报。
- **P1-5 多类别聚合**（`Finding.related_categories` + `_aggregate_multi_category`）
  相同 (source, sink) 的多类别候选合并为一条主 finding；主类别按严重级别、
  sink 模式特异性（最长匹配模式）裁定。ureport2 cap=500 下 (src,sink) 路径
  272=272 无召回损失，342→272 条全部来自聚合。
- **dataflow 返回值追踪**（`dataflow.py::_trace_return_statements`，BUG 37）
  callee `return x` / `y=x; return y` 跨函数追回 caller（`call_return` 步骤）。

## P2（想起来了就做）

- **字段敏感 / 对象属性级污点**：现在污点是「变量名级」，`obj.userInput` 和
  `obj.isAdmin` 都按变量 `obj` 传播。理想是按「敏感字段访问」传播
  （source 只进 `obj.userInput`，`obj.isAdmin` 不传播）。
- **JSON 链 / 链式方法返回值**：`JSON.parseObject(payload).getString("name")`
  这类链式调用的返回值污染（`getString(...)` 的结果继续传播）未建模；
  `_trace_return_statements` 已做整函数 return 追踪，但链式 call 返回值未桥接。
- **配置类漏洞**：`@Value` 注入、`application.yml/properties` 硬编码密钥、
  env 变量使用检测（`hardcoded_secret` / `cleartext_transmission` 的配置侧来源）。
- **`uncovered_sink` 开关**：`cpg/discovery.py` 已有
  `SourceCompletenessChecker.find_uncovered_sinks()`，因真实项目噪声大默认不产出；
  做成 `scan(uncovered_sinks=True)` / CLI `--uncovered-sinks` 显式开关。
- **反射 / 动态特性**：`Class.forName(...).newInstance()`、反射 `invoke` 的动态
  调用解析（README 已知限制，可在 `callgraph.py` 里做模式化兜底）。

## P3（低优先级）

- **测试体系**：当前无 `tests/`。把本批验证用的反例固化为回归用例：
  `/tmp/sanittest`（sanitizer 无关调用不吞 finding）、`/tmp/posittest`
  （绑定参数位门控 + 聚合）、`/tmp/dftest`（return 追踪）。覆盖规则加载 /
  def-use / 跨函数 / sanitizer / 聚合 / 位置门控。
- **性能**：`_build_findings` 外层对每个 source 做 BFS，大型项目（几千函数）
  是 O(源数 × 图遍历)；可做按 sink 反向 BFS 剪枝、同源合并、并行化。
- **`taint_rules.yaml` 清洗**：内置规则混入了 CodeQL 风格模板模式（如
  `'String;I)I:2,4('`、`'(String $A)'`、`'List('`、`'Object('`、`'Query('`），
  子串匹配下制造噪音（`doQuery(` 命中 `Query(` 即一例）。需逐条评估删除，
  或迁到 codeql 专用区块由 `rules/` 接管。
- **多语言冒烟矩阵**：python / javascript / go / php 各写一个最小样例跑通
  `scan()`（go/php 引擎适配器未实现，规则已备好在 `rules/go.yaml`、`rules/php.yaml`）。

## 已知限制（与 README 原文对齐）

- 确定性、正则/tree-sitter 级污点分析，追求**高召回**，会有误报；
  产出是「需人工复核的候选」，不是最终判定。
- 跨文件参数↔实参原为「位置匹配 + 兜底全连接」过近似 —— P1-3 已改为
  名→位置→全连接并给边打 `confidence`，但 BFS 仍走所有 DATA_FLOW 边。
- 未做语义级别名 / 反射 / 动态特性分析；跨函数 CFG 不展开（每函数 CFG 自洽）。
- `blind_spots` 默认只含「无已知污点源的接口」（`endpoint_no_source`）；
  `uncovered_sink`（未标记危险调用）默认不产出，见 P2。
