# HyqSast 优化路线图（TODO）

> 按「什么时候想起来了什么时候做」的记录。已完成项也列出，避免重复评估。
> 条目带估算优先级（P0/P1/P2/P3）与动机；P0/P1/P2(sqli)/P3(crypto) + BUG 53-56
> 已落地（见下文「已完成」）。

## 已完成（P0/P1，2026-08）

- **污点元素清单**（`TaintElement` + `ScanResult.taint_elements` + `to_elements_json`）
  报告副产品 `report.elements.json`：列出规则引擎识别到的全部 source/sink 点
  （类别、命中规则、covered 标记），供排查漏报（`covered: false` 的裸 sink 即
  「规则命中但没接住 finding」）。CLI `--no-elements` 可关。
- **P0-1 sanitizer 净化语义 def-use 级**（`analyzer.py::_sanitizers_on_path`，BUG 38）
  只检查语句级节点（CALL_SITE / ASSIGNMENT），不再匹配整个函数体；CALL_SITE
  在能拿到污点变量与实参时要求污点确实作为实参流入净化调用。
- **P0-2 finding 截断可见化**（`ScanSummary.truncated_categories` + CLI ⚠ 提示）
  每类别因 `max_findings_per_category` 被截断多少，不再静默吞掉。
- **P1-3 跨函数匹配分级**（`graph.py::_add_cross_function_edges`，缓存 v3）
  参数名匹配（high）→ 位置匹配（medium）→ 全连接兜底（low），边带
  `confidence` 属性。后续可用它做加权 BFS / 低置信边过滤。
- **P1-4 sink 危险参数位置门控**（`analyzer.py`，`_SINK_STR_TEMPLATE_CATS`）
  字符串模板型注入（sql/code/xpath/ssti）只认首参为危险载荷；污点在绑定参数位
  （`query(sql, tainted_param)`）不算命中，消参数绑定误报。**例外**：
  `command_injection` 于 2026-08-21 移出门控——命令执行类 sink（`Runtime.exec`）
  的 envp（第 2 实参）在 OWASP cmdi 语义里是真实攻击面（15/37 FN 经此位置），
  任一实参携带 taint 都算命中（见 `docs/OWASP漏报清单.md` §3）。
- **P1-5 多类别聚合**（`Finding.related_categories` + `_aggregate_multi_category`）
  相同 (source, sink) 的多类别候选合并为一条主 finding；主类别按严重级别、
  sink 模式特异性（最长匹配模式）裁定。ureport2 cap=500 下 (src,sink) 路径
  272=272 无召回损失，342→272 条全部来自聚合。
- **dataflow 返回值追踪**（`dataflow.py::_trace_return_statements`，BUG 37）
  callee `return x` / `y=x; return y` 跨函数追回 caller（`call_return` 步骤）。
- **容器 / Builder 状态写读桥接**（`graph.py::_add_container_state_edges`，
  漏报面 A 类）：`host.put(k,t)` / `host.append(t)` / `host.setXxx(t)` 识别为
  「对宿主内部状态写」，从写调用点连 DATA_FLOW 边到同函数内该宿主所有 var_ref，
  读侧复用 RHS→LHS / var_ref→call_site 桥接。demo ⑥ 容器与 Builder 形态
  实测接住。**BUG 55（2026-08-22）：真项目 800k finding 主凶，默认关**，
  代码层/CLI `enable_container_bridge` 显式开启（README「过近似桥接启发式开关」）。
  **BUG 56（2026-08-23）精确化**：删 `_is_container_write` 的
  `setXxx/addXxx/putXxx` 前缀兜底（普通 setter 如 `Cookie.setPath` 不再当容器写 →
  header FP 清零），只认白名单 + **宿主类型门控**（Java 下宿主声明类型必须 ∈
  `_CONTAINER_TYPES` 约 45 个容器类型，`callgraph_builder.var_types(file_path)`
  提供显式声明类型；非 Java 无类型信息维持旧行为）。OWASP per-file bridge-on
  回归：**10 容器 FN 全恢复**（FN 50→40，TPR 96.5→**97.2%**），findings
  24206→24679（**+473 vs 旧桥接 +6024**，爆炸缩小 92%），FP +5 全集合键不敏感，
  header 零新增；ureport2 真实代码 +30/+0.6% 不爆炸（30 条逐条验证全为规则级假
  sink，见 P3「规则清洗」）。
- **cmdi 全量修复**（P1，`analyzer.py::_SINK_STR_TEMPLATE_CATS` 移除
  `command_injection` + `taint_rules.yaml` java sources 移除 `System.getProperty(`，
  BUG 45）：OWASP cmdi TPR 70.6%→**100%**（FN 37→0，含 envp 位置 15 例 +
  位置 0 两组 22 例），其余 10 类 + demo-java 全零丢失；代价 cmdi FP 87→125
  （FPR 69.6%→100%，均为流可达性过近似，与 pathtraver/trustbound/xss 同类，
  靠人工复核消化，分支敏感列入 P3）。
- **数组下标归一化收尾**（`languages/java.py::_container_host` +
  `languages/python.py::_container_host`，漏报面 A 类剩余）：简单
  `a[0] = t; sink(a[0])` 早在容器桥接提交就归一化到宿主 `a`；本批把**残留
  嵌套形态**补上——多维 `m[0][0] = t`、字段数组 `this.f[0] = t` /
  `self.arr[0] = t`（数组宿主取字段名，对齐 J 类 slot 约定）递归下钻归一化。
  改动**纯增量**（原有非 None 结果逐字节不变，只把原 None 的嵌套形态补上
  宿主），五条基准 A/B 全部零变化（demo-java 7 / vampi 64 / vfa 20 /
  flask-xss 22 / OWASP 200 文件子集 1226）。
- **缓存陈旧修复**（`graph.py::_compute_source_fingerprint` / `_cache_path_for`
  + `taint_loader.py::TaintRuleLoader.fingerprint` + `parser.py::configured_languages`，
  漏报面 G 类）：指纹由文件大小改为**内容 sha256**，缓存 key 拼入
  **language + rules 内容指纹**，`_CACHE_VERSION` bump v4→v5。修复了实测
  暴露的两类漏报：①改源码但字节数不变 → 旧图复用，新漏洞扫不出来；
  ②换 language / 换规则 → 复用错图。数组下标修复后 CLI 默认缓存扫出 0
  findings、`--no-cache` 才有 2 条，正是此缺陷的活体现场。
- **跨函数静态/全局/实例字段状态桥接**（`graph.py::_add_state_bridge` +
  各语言 `collect_state_slots`，漏报面 J 类）：模块全局 / static 字段 /
  `this`/`self` 实例字段的跨函数写→读连通；`this`/`self` 按类收敛避免跨类
  串扰。静态字段 / 静态容器 / 模块全局 / 实例字段探针全部实测命中。
  **BUG 55（2026-08-22）：真项目 800k finding 主凶，默认关**，代码层/CLI
  `enable_state_bridge` 显式开启。
- **sink 遮蔽修复**（`analyzer.py::_bfs_to_sink` record-and-continue，
  漏报面 K 类）：BFS 命中 sink 后**记录路径并继续扩张**，不再让中间被过宽规则
  误标成 sink 的节点遮蔽下游真 sink（如 `String s = foo.build(p)` 遮蔽
  `exec(s)`）。
- **BUG 42 联动收窄**（防误报、不增漏报，基准 TP 零变化）：移除裸 `.build(`
  （java ssrf）与 `String(`（java sql_injection）；容器写跳过 sanitizer 调用
  （`ps.setString(1,q)` 不再向宿主 `ps` 传污点）。三条都以「真实执行 API 另有
  更精确 pattern 覆盖 / 本身是安全绑定 API」为前提，按缺陷平衡铁律保留其余
  裸类型名（`Query(` / `SQLiteStatement(` 等）防漏报。
- **非污点流 pattern 型漏洞引擎**（`analyzer.py::_pattern_findings` +
  `taint_rules.yaml` 的 `pattern_sinks` 标记 + `taint_loader.py`，2026-08-21）：
  弱哈希 / 弱随机数 / cookie 未加 secure 这类「危险 API 使用本身」漏洞**没有
  source 流入**，前向 BFS 永远够不到 → 此前在 OWASP 上恒 FN。新增机制：对每个
  被标上 pattern 型类别的图节点**无条件产出 finding**（source==sink==节点，
  edge_type=PATTERN，单步调用链），放在多类别聚合之后追加避免误合并。
  **关键设计决策**：不用 crypto_weakness 当 pattern 型（其 sinks 含
  `getInstance(、` `Random(` 等宽模式，会命中 SHA-256 / SecureRandom 等强算法，
  FP 爆炸，且会被 `rules/` 原 CodeQL 适配层再放大（该层 2026-08 已审计 fold 进
  内置并删除——宽模式现在直接在总库里），而是新建**精确专用类别**
  `insecure_hash`（硬编码弱算法精确子串）/ `weak_randomness`（`java.util.Random`
  / `Math.random` / `new Random(`，避开 `SecureRandom()` 子串碰撞）/
  `secure_cookie`（`setSecure(false)`）标记 pattern 型；`trust_boundary`
  （`getSession().setAttribute(` / `putValue(`）本身是污点流，保持 taint 型。
  OWASP 全量 TPR：hash 69.0%（89/129，40 个配置驱动是固有边界）、weakrand
  **100%**（218/218）、securecookie **100%**（36/36）、trustbound **100%**
  （83/83），总分 89.9%（1272/1415）。五基准 A/B 全部零丢失；OWASP 200 文件
  子集 A/B 每类别 TP ≥ before（12 条丢失全是跨方法 `@Override` 样板 FP 产物，
  无一条真实检测）。分块扫描结果见
  `benchmarks/owasp/results/2026-08-21-pattern/`。
- **P0：pathtraver FQN sink 规则补齐**（`taint_rules.yaml`，2026-08-21）：40 条
  pathtraver FN 源自 FQN 构造形式没进 sink 规则——`new java.io.FileOutputStream(`
  匹配不到短名 `new FileOutputStream(`（中间隔 `java.io.`），`match_all_sinks`
  纯子串匹配 → 返回 `[]`。纯追加 5 个全限定类名模式后：TOTAL TPR **89.9%→92.7%**
  （TP 1272→1312，FN 143→103），其余 10 类零 TP 丢失；pathtraver FPR 66.7%→98.5%
  （+43 安全用例 FP，全部流可达性过近似：常量真三元死分支 / 集合索引不敏感 /
  反射返回值过近似，非规则误匹配，与 trustbound/xss FPR 100% 同类）。逐例溯源 +
  FP 代价见 `docs/OWASP漏报清单.md`（§0.6、§2.1）；修复后结果
  `owasp-after-fqn.json`。残余 FN 103 = 可修 59 / 固有 44。
- **sqli 多行桥接 + BFS 非单调修复**（P2，`graph.py` / `dataflow.py` /
  `callgraph_builder.py` / `analyzer.py`，BUG 46/47/48）：sqli 10 条 FN 根因实证为
  图桥接层两处多行断链 + 一处 BFS 非单调——
  ① **BUG 46 调用侧多行实参**：`prepareStatement(sql, …)` 实参落换行后，
  var_ref→call_site 按精确行号匹配断链；改为用 `call_node.end_point` 按
  `[start_line, end_line]` 区间匹配。
  ② **BUG 48 赋值侧多行 RHS→LHS**：`String sql =\n "…'+bar+'"` 的 `bar` 与定义行
  不同行，RHS→LHS 边键 `{file}:{line}` 命不中；`DefUsePair` 增 `def_end_line`，
  赋值节点存 `end_line`，按 `[起始行, 结束行]` 区间匹配 + `_word_in_text` 精度闸
  防共享行过连接（vampi 由 range-only 的 167 回落到 102）。
  ③ **BUG 47 BFS 非单调**：全局 `max_paths=5` sink 达预算 + visited 首次胜出，先达
  sink 饿死后达 sink（且位置 ≥1 路径抢注后位置 0 路径不再重记 → 位置门控误挡）；
  改为**按 sink 独立预算** + visited 恰是 sink 时允许另一进入边重记。
  效果：sqli TPR 96.3%→**100%**（FN 10→0，00100/102/103/109/997/998/1000/1006/
  1007/1882），顺带恢复 pathtraver 5 + xpathi 1（同受 BUG 47 饿死），TOTAL TPR
  **95.3%→96.5%**（FN 66→50），其余 8 类 + demo-java + vfa/flask-xss/vampi/python
  基准零丢失。代价：安全用例新标 29（sqli 4 / pathtraver 2 / xpathi 2 / crypto
  21，FPR 四类升 1.7–18.1 个百分点），流可达性过近似，分支敏感列入 P3。逐例溯源
  + FP 代价见 `docs/OWASP漏报清单.md` §4；结果存档
  `benchmarks/owasp/results/2026-08-21-sqli-final/`。
- **crypto 硬编码弱算法 pattern 类别 `weak_crypto`（P3，`taint_rules.yaml` +
  `analyzer.py`，BUG 49）**：OWASP crypto 10 FN（00053/55/56/57/1822/1823 硬编码
  `Cipher.getInstance("DES/CBC/…")` + 00945/46/1829/1830 配置驱动）——弱算法是
  「API 使用本身」无 source 流入，而 `crypto_weakness` 永不可标 pattern 型（红线：
  sinks 含宽模式会 FP 爆炸）。新建精确专用类别 `weak_crypto`，进 `pattern_sinks`，
  只列硬编码弱算法精确子串：`getInstance("DES"`（闭引号避开 `"DESede`）、裸
  `DES/CBC`（`/` 避开 `DESede/CBC`）、RC4/RC2/Blowfish/AES-ECB/AES-CBC-NoPadding。
  **实证推翻「4 个配置驱动固有」**：它们虽 `Cipher.getInstance(algorithm)` 配置
  驱动，但密钥生成是硬编码 `KeyGenerator.getInstance("DES")`，一并接住。评分侧
  weak_crypto finding 带 `related_categories=["crypto_weakness"]`（score.py 零
  改动即算 crypto）；`_pattern_findings` 新增 covered 位置去重（节点已被 taint 型
  crypto_weakness 同位置报过则让位），避免 ~217 已命中测试各多一条重复。
  效果：crypto TPR **92.3%→100%**（FN 10→0），TOTAL TPR **96.5%→97.2%**
  （FN 50→40），其余 10 类逐项零 TP 丢失、**FP 零增加**（crypto FPR 90.5%、
  TOTAL FPR 71.8% 不变），四基准 A/B 零丢失（铁律通过）。结果存档
  `benchmarks/owasp/results/2026-08-21-crypto-pattern/`。逐例溯源见
  `docs/OWASP漏报清单.md` §5。可修 FN 至此全部清零。
- **跨模块调用扇出收紧（BUG 53/54，2026-08-22）**：383 文件 Python 项目 finding
  从 ~500 涨到 800k 的根因链 = BUG 47 全前沿 BFS × `rules/` 自动加载（sink
  500→3163）× 跨文件同名函数按 per-file import 并集全连接兜底 → source 前向到达
  所有模块的同一函数。修复 = **BUG 54** 方法调用对象前缀（receiver）提取 +
  import 别名表解析，把 `svmod.process()` 收窄到 alias 指向的具体模块文件
  （无 receiver / 解析失败 / alias 歧义三重安全回退 → 回退旧全连接，宁可过近似
  不漏报）+ **BUG 53（slim）** 跨文件调用只连 `build_calls` 算出的可达目标文件。
  OWASP 全量 TP=1375 / FN=40 / TPR 97.2% 与 HEAD 逐条一致（铁律满足）；真实形态
  多模块 import 样例 **480→80（6× 削减，0 跨模块污染）**。
- **per-file 回归工具规则对齐（2026-08-22）**：`chunk_scan.py::scan_per_file`
  复刻 CLI 的 `rules/` 自动发现（`rules_paths`），修复 per-file 曾漏加载 `rules/`
  的 cmdi sink 标签缺口（`exec@78` 从 path_traversal 恢复 command_injection，
  **cmdi TPR 23%→96.8%**）；顺带补全 BUG 54 系列的跨文件同名 BFS 断链
  （CALLS 边连所有 resolved_files 目标，`param_by_name` 改 dict[str,list[str]]）。
  口径注记：per-file 96.5% 与整体基线持平，但 per-file 无跨文件撞衫伪链
  （findings 24206 vs 整体 35932），是更诚实口径（详见
  `docs/OWASP漏报清单.md` §0 与 README「验证」节）。
- **规则库安全批（2026-08-22，commit 0953721）**：`docs/规则库审查报告-2026-08.md`
  落地第一批可证明零损失改动——死规则 / 跨语言残留 / 复制粘贴清理：① Python xss
  sources 删 JS DOM 专属 `.innerHTML` / `document.getElementById(`；② Python
  path_traversal sinks 删 Java 方法 `.getCanonicalPath(` / `.getRealPath(`；
  ③ Python xpath_injection 85 条 sql 复制 → 4 条真 XPath sink；④ JS sql_injection
  删垃圾 token `dropb` / `biselect`；⑤ Java sql_injection 删 JVM 签名残片
  `String;I)I:2,4(` / `String;I)I(`；⑥ Java sources 7×38 相同 source 集去重只留
  `injection_general` 一份。回归证据：OWASP 分块回归（10 块，bridge 关）
  TP 1365 / TPR 96.5% / findings 24571 与 HEAD 基线逐类别完全一致；五基准 A/B
  （新增 `benchmarks/baseline_snapshot.py`）丢失=0 新增=0。方向修正类建议
  （防御函数当 sink、auth_bypass 重构等）需独立回归批次，未纳入。

## P0/P1 性能：大项目建图 O(F×G) 卡死（2026-08-22 实测）

> 真实项目 9879 java 文件 / 1,029,783 行跑一下午不完成，已停。完整分析见
> `docs/性能分析-大项目卡死.md`。根因在**建图**，不是 BFS。
> **主凶**：`graph.py:627/636/643` 三个边构建函数（`_add_rhs_to_lhs_edges` /
> `_add_varref_to_callsite_edges` / `_add_container_state_edges`）缩进在
> `for fn in funcs:` **循环体内**——每函数调用一次、每次遍历全图 → O(函数数 × 图规模)。
> 单文件 500 方法实测 115.5s（rhs 44s + vrc 45s + def-use 24s）；200 文件 source 密集
> 建图 69.1s（rhs/vrc/cs 各 3200 次全图扫描）。外推 9879 文件 F≈60k、G≈270 万 →
> **800 亿次节点迭代 ≈ 11–22 小时**。
>
> - **P0-1 [✅ 2026-08-22]**：三个边构建函数移出 `for fn` 循环（12→8 空格缩进，
>   每文件一次）。语义不变（内部已按 file_path 过滤），纯重构。
> - **P0-2 [✅ 2026-08-22]**：新增 `_nodes_by_file` 文件索引（BUG 50），三个边
>   函数、4.55 参数→赋值桥、`_label_taint_nodes` 全部从全图扫描收窄到本文件
>   节点遍历；缓存恢复重建索引、跨文件 call-site 补登记。总工作量 O(F×G) →
>   O(总节点数)。
> - **P1-3 [✅ 2026-08-22]**：`build_def_use_chains`（`dataflow.py`）Phase 1/2 由
>   「全树遍历 + 字节区间过滤」改为 `_body_nodes()`：干净文件走 `traverse(root=body)`
>   子树遍历（单文件 O(F²)→O(F)），含语法错误文件回退历史字节区间过滤（零 FN，
>   因 tree-sitter ERROR 恢复可能把命名节点甩到 body 结构外，实证 6 类含错 Java
>   无此形态，仍保留回退双保险）。BUG 51。500 方法 def-use **23.8s→0.055s**。
> - **P2 预留**：修完建图若 BFS 仍慢（真实项目跨文件 CALLS 扩散），再按反向
>   BFS / 同源合并处理（见下方 P3 性能条）。
>
> 验证（✅ 2026-08-22 完成）：P0-1/2 轮 OWASP 全量逐条 A/B 对比存档基线零差异，
> TOTAL TPR 97.2% / FPR 71.8% 一致，demo-java 7 findings 一致（铁律通过）；
> 500 方法单文件 **115.5s→17.2s（6.7×）**、200 文件 source 密集 **69.1s→5.9s（11.7×）**。
> P1-3 轮（2026-08-22）：同分块布局下 **P1-3 前后逐条指纹零差异**（30634/30634，
> 用 stash 还原对照 + `compare_findings.py`），评分与基线逐项相同 → P1-3 铁律通过；
> def-use **15.7s→0.058s**（perfprobe2，~270×）、总建图 **17.2s→1.6s**；perfprobe4
> 6.2s→0.268s、总 5.9s→4.8s。存档
> `benchmarks/owasp/results/2026-08-22-perf-p01-p02/`（P0 轮）、
> `benchmarks/owasp/results/2026-08-22-p13-defuse/`（P1-3 轮）+ 还原对照
> `2026-08-22-p13-revert-ab/`。分块扫描/合并/A-B 工具已固化进 harness：
> `benchmarks/owasp/chunk_scan.py` / `compare_findings.py`（README「分块尚未落地」
> 空缺已补）。探针生成器/插桩计时脚本在仓库根 `perf_gen_probes.py` /
> `perf_probe_bench.py`（gitignore）。
>
> 口径注记：P1-3 轮 findings 30634 vs 旧存档 30554（+80，cross +59）——**分块边界
> 差异**所致（跨文件全连接兜底产生的伪跨文件 finding 集合随块边界变化），评分
> 逐项零变化、P1-3 前后逐条零差异，P1-3 无贡献（详见 p13-defuse 归档 README）。

## P2（想起来了就做）

- **findings 复核去重工具 `dedup_findings.py`**（2026-08-21 用户建议，消费侧零
  引擎风险）：**✅ 已落地（`90df903`）**——归并键升级为 source 函数 × sink 函数 ×
  vuln_type（跨文件同名函数正确分离），OWASP 21281 → 10528（2.0x），function
  空值 0%；附分布统计（--out-stats）与归并键可靠性诊断（--diagnose）。**未做**：
  「已知误报模式」打标与过滤（`encode 了还报 XSS`、`绑参了还报 SQL`——同一模式
  一次判定整类标记）；对外交付只给 top N 详情 + 汇总表。**误报模式清单是后续
  FP 治理（sanitizer 收窄、sink 位置精度）的直接输入**——一条模式 = 一个待修点。
  另：跑之前先用 `owasp-merged.json` 做一次 FP 普查（951 条按 类别×根因 归类
  成表），当收窄基线，后面每轮对比 FPR 是否下降。A/B 验证只影响呈现不影响召回，
  无需铁律回归。
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
- **性能（BFS 阶段，建图修复后的下一步）**：`_build_findings` 外层对每个
  source 做 BFS，大型项目（几千函数）是 O(源数 × 图遍历)；可做按 sink 反向
  BFS 剪枝、同源合并、并行化。**注**：2026-08-22 实测建图阶段才是当前大项目
  卡死主因（见上方 P0/P1 性能节），BFS 在 source 密集形态仅 0.1s；跨文件
  CALLS 扩散后 BFS 才会成为下一个瓶颈。
- **`taint_rules.yaml` 清洗**：内置规则混入 CodeQL 风格模板模式。安全批
  （2026-08-22，commit 0953721）已删实证零召回价值的 JVM 签名残片
  `String;I)I:2,4(` / `String;I)I(` 与垃圾 token；仍剩 `'List('`、`'Object('`、
  `'Query('` 等裸模式，子串匹配下制造噪音（`doQuery(` 命中 `Query(` 即一例）。
  **实证（2026-08-23，ureport2）**：`List(` 命中 `orderBindDataList(`（GroupAggregate
  的 **Java 内存排序**，"orderBindData**List(**" 含 "List("）在 ureport2 基线上就
  产生 278 条 sql_injection FP（`.insert(` 命中 StringBuilder.insert 再 +22；容器
  桥接开启再 +30）——**裸模式是真实代码 FP 主力**。收紧 `List(` → 带限定符的
  `.getResultList(` 等、`.insert(` 同理，几乎肯定不伤 OWASP 真 TP（OWASP sqli sink
  都是 `executeQuery/executeUpdate` 类），待回归验证后落地；或迁到 codeql 专用
  区块（2026-08 审查已把原 rules/ 适配规则 fold 进内置 taint_rules.yaml，此路已通，
  但已 fold 的模式同样要过 A/B 闸门再收窄）。
- **多语言冒烟矩阵**：python / javascript / go / php 各写一个最小样例跑通
  `scan()`（go/php 引擎适配器未实现，规则已备好在 `taint_rules.yaml` 的 go/php 区块，
  2026-08 审查已 fold 进内置）。

## 漏报面清单（FN surfaces，2026-08 全量排查）

> 每条都标了来源：✅=实测确认断链（demo 样例 ⑥ / /tmp/fnprobe 五连探针），
> ⚙️=按代码机制核实。修的顺序建议：先补 A 类状态写读（最高频真漏报），
> 再 C/D 类（配置与规则完整性），F/G 类顺手（纯参数/缓存）。
>
> **已修复（2026-08-20）**：A 类（容器/Builder 状态写读）、J 类（跨函数
> 状态桥接）、K 类（sink 遮蔽 record-and-continue）均已落地，详见「已完成」
> 节；完整细节与代价见 `docs/漏报面清单.md`。剩余断点按底部「建议优先顺序」。
> **已知代价**：状态桥接 + record-and-continue 使 Python 基准误报上升
> （vfa 5→14 / flask-xss 9→19 / vampi 20→62），**TP 不变（6/3/1）**。
>
> **实测盲区**：确认「优化不动/暂缓」的漏报按项目累积在
> `docs/结构性漏报盲区.md`（A–G 分类，与本文档 A–I 是两套编号）。
>
> **已完成**：2026-08-20 用 Connexion 提取器 + 路由参数 source 注入补上
> 「框架路由参数无 source」缺口（见结构性盲区文档 F 节），vampi SQLi 转 TP。

### A. 对象/容器内部状态写读 —— ✅ 已修复（2026-08-20，除数组下标）

数据流是「标量变量名级」：污点写进对象内部（容器 / Builder / 数组 / 字段 /
setter）再从另一处读出来，链必断。写侧是表达式语句不建模，读侧只见未污染的
宿主变量。**同一根因，四种形态**：
- 容器：`m.put("k", t); m.get("k")`（样例 ⑥）—— ✅ `_add_container_state_edges`
- Builder / 可变累加器：`sb.append(t); sb.toString()` —— ✅ 同上
- 数组下标：`a[0] = t; sink(a[0])`（def 的 var_name 是 `a[0]`，用是 `a`，配不上）—— ⚠️ 仍断
- setter/getter 与 `this.field`：`o.setX(t); o.getX()`、`this.buf = t; sink(this.buf)`—— ✅ 容器桥接 + `_add_state_bridge`

修法（已落地）：`put/append/setXxx` 识别为「写」、`get/getXxx/toString` 识别
为「读」，对同一宿主做别名/内部状态传播；`this.field` 按类成员表打通
（`collect_state_slots` + `_add_state_bridge`，见漏报面 J 类）。剩余数组下标
需把 var_name 归一化到宿主 `a`。

### B. 调用图解析盲区（⚙️ 机制确定）

- **同名方法 first-wins**：`callgraph_builder.py:219` 多个文件都有 `execute` 时
  只连第一个可达候选；危险实现在第二个 → 污点进安全实现 → 真 sink 接不到。
- **未解析调用点整段断链**：`graph.py:747` 只有 `is_resolved` 的 call_site 才建
  arg→param 边。接收者链 / 泛型 / 静态导入歧义解析失败时，`doThing(t)` 这种
  表达式语句调用（无 LHS 可被 RHS→LHS 抢救）污点死在调用点 → 函数内 sink 漏。
- **接口/多态分派**：`Base b = getImpl(); b.method(t)` 按声明类型解析，命中
  错的实现或无实现。
- **跨包不可达**：Java 跨包类未 import 且不同目录 → 不解析；Python/JS 相对
  导入、`from x import *` 解析不全。
- **依赖 jar 内部**：库包装方法内部调 sink 不可见（部分属预期，但 `Commons` /
  `HttpClient` 等封装层很常见）。

### C. 返回值追踪盲区（⚙️ dataflow.py::_trace_return_statements）

- return 追踪只认「标识符 + 赋值中转」（`return x` / `y=x; return y`）：
  `return this.x`、`return arr[0]`、`return sb.toString()` 不追踪。
- caller 侧 return 桥接只在**调用行有 assignment** 时生效（`graph.py:853`）：
  调用点在表达式内部 / 无 LHS（`if (isOk(t))`）返回值不接回。

### D. 规则 / 匹配完整性（⚙️ taint_loader.py）

- **未收录的 source/sink API 完全不可见**：子串匹配，任何不在规则表里的调用
  连标签都不打，elements.json 里也没有 —— 新框架 / 私有封装 / 新漏洞类的最大
  实践漏报面（`request.newName` 即此）。
- **大小写敏感**：`pat in text`，代码里 `Request.GetParameter` 之类大小写不符
  即不命中。
- **sink_excludes 过宽**：正则排除表把真 sink 也排掉 → FN（`graph.py:1162`）。
- 内置 YAML 里 CodeQL 模板噪音（`String(` 等）主要造成误报，但也稀释排查。

### E. 参数 / 来源标记盲区（⚙️ graph.py::_classify_parameter_source）

- **隐式绑定**：Spring 无注解的简单类型参数（`f(String id)`）按 @RequestParam
  绑定，但分类器只认注解与 `HttpServletRequest` 类型 → 不标 source。
- **@ModelAttribute / Body 反序列化对象字段**：整体标 `injection_general`，
  `u.name` 的字段级传播依赖 A 类状态写读（断）。
- **source 优先于 sink**：节点同时命中两者时只标 source（`graph.py:1150`）。
- **重载签名查表 last-write-wins**：`func_signature_by_name` 按函数名覆盖，
  重载方法拿错签名 → 注解分类错/漏。

### F. BFS / 枚举截断（⚙️ analyzer.py::_bfs_to_sink）

- **max_depth=20**：链长 >20 步的 sink 永远够不到。
- **max_paths=5**：前 5 条 src→sink 路径填满即停，第 6+ 条路径独有的 sink 漏。
- **max_findings_per_category=50**：单类别截断（P0-2 只提示不补全）。

### G. 缓存陈旧 —— ✅ 已修复（2026-08-21）

- 指纹改**内容 sha256**（不再只看文件大小）——同尺寸内容变化也触发重建；
- 缓存 key 拼入 **language + rules 内容指纹**——换语言/`--rules` 不复用错图；
- `_CACHE_VERSION` v4→v5（数组下标归一化改了结构边，旧图作废）。
  实测：同字节 safe/vuln 配对 0→1 finding；rules 变化新建 key；不变源码正常命中。

### H. 行键控桥接对跨行语句（⚠️ graph.py::_add_rhs_to_lhs_edges）

RHS→LHS / var_ref→call_site 按「location 字符串」精确对齐：跨行语句（拼接
续行、多行实参）var_ref 行 ≠ assignment/call_site 行 → 桥接边漏 → 断链。
低风险，待实测。

### I. 多语言缺口（⚙️ languages/__init__.py）

Go / PHP 引擎适配器未实现（规则已备在 `taint_rules.yaml` 的 go/php 区块，
2026-08 审查已 fold 进内置）——整个语言扫不出来；`_detect_language` 自动探测
只取主语言，混合语言项目漏扫。

### J. 跨函数静态/全局/实例字段状态 —— ✅ 已修复（2026-08-20）

def-use 是函数内的、容器写桥接也只在同函数生效 —— 状态（模块全局 /
static 字段 / `this`/`self` 实例字段）一旦越过函数边界就断链：

- `gbuf = p`（端点 A）→ `exec(gbuf)`（端点 B）
- `queue.add(p)`（A）→ `for x : queue { exec(x) }`（B）
- `this.buf = p`（A）→ `exec(this.buf)`（B）

修法：`graph.py::_add_state_bridge` + 各语言 `collect_state_slots` —— 收拢
「越函数边界仍存活」的名字（字段声明 / 模块顶层赋值 / `self.X=`，排除函数内
局部变量），建图末期把状态写节点连到状态读节点；`this`/`self` 按类收敛。
探针（静态字段/静态容器/模块全局/实例字段）全部实测命中；Python 基准误报
上升但 TP 一条不少（见上「已知代价」）。

### K. sink 遮蔽下游真 sink —— ✅ 已修复（2026-08-20）

BFS 旧实现**命中 sink 即终止路径**——中间节点被过宽规则误标成 sink（如
`String s = foo.build(p)` 命中裸 `.build(`）时，下游真 sink（`exec(s)`）
永远探索不到，真实漏洞被误报遮蔽成漏报。

修法：`_bfs_to_sink` record-and-continue（命中 sink 记录路径后继续扩张）。
联动收窄（BUG 42，防误报、不增漏报）：移除裸 `.build(`（java ssrf）、
`String(`（java sql_injection），容器写跳过 sanitizer 调用 —— 三条都以
更精确 pattern 覆盖 / 安全绑定 API 为前提，基准 TP 零变化。

### L. pattern 型类别的固有边界（⚠️ 2026-08-21 新增，记录未来 FN 面）

非污点流 pattern 型类别（`insecure_hash` / `weak_randomness` / `secure_cookie` /
`weak_crypto`）对「硬编码危险 API 使用」100% 接住，但以下形态**确定性引擎接不住，
是固有 FN**，写下来避免将来误当 bug 或误砍规则：

- **算法/参数来自外部配置或变量**（`getInstance(algorithm)` ←
  `getProperty("hashAlg1", "SHA512")`）：字符串在变量里，无法确定性判定强弱。
  OWASP hash 40/129 FN 全部是这种（测试在运行期用 MD5 配置，静态不可见）。
  **不要**为了抓它把 `getInstance(` 加进 pattern 型类别 —— 那会把 SHA-256/
  SHA-384 强算法全报（FP 爆炸）。正确做法是配置侧分析（见 P2「配置类漏洞」）。
- **`crypto_weakness` 永不可标为 pattern 型**：其 sinks 含宽模式
  （`getInstance(、` `Random(` 等；原 `rules/` CodeQL 适配层的
  `Cipher.getInstance(` / `MessageDigest.getInstance(` 已 fold 进内置，宽面只增不减），
  一旦无条件产出，任何强算法/强随机数使用全报。它保持 taint 型（有 source 流入才产出）。
- **大小写敏感**：`pat in text`。`getInstance("md5"` 等小写变体已补，
  但任意大小写混排（`"Md5"`）仍漏 —— 子串匹配的固有边界，别指望穷举。
- **间接会话访问**：`trust_boundary` 只认 `getSession().setAttribute(` /
  `putValue(`；`HttpSession s = req.getSession(); s.setAttribute(...)` 经变量
  中转未覆盖（漏报面清单信任边界一条同理）。
- **import 别名弱随机**：`new Random(` 已补（已验证不与 `new SecureRandom(`
  / `new RandomAccess(` 碰撞）；但 `ThreadLocalRandom` / `SplittableRandom` /
  `Random` 经包装类（`MyRand.getInstance()`）形态漏。
- **pattern 型 vs taint 型同节点**：某节点既是 pattern 型又是 BFS 可达 sink，
  会产出两条 finding（类别不同），聚合只对 BFS 侧生效。`weak_crypto` 例外：已按
  (文件, 行, 类别[含别名]) covered 集让位给同位置 taint 型 `crypto_weakness`
  （BUG 49），避免 ~217 已命中测试各多一条重复；其余 pattern 类别未做此类
  （`insecure_hash`/`weak_randomness` 无同名 taint 类别，不冲突）——已知重复候选，OK。

## 已知限制（与 README 原文对齐）

- 确定性、正则/tree-sitter 级污点分析，追求**高召回**，会有误报；
  产出是「需人工复核的候选」，不是最终判定。
- 跨文件参数↔实参原为「位置匹配 + 兜底全连接」过近似 —— P1-3 已改为
  名→位置→全连接并给边打 `confidence`，但 BFS 仍走所有 DATA_FLOW 边。
- 未做语义级别名 / 反射 / 动态特性分析；跨函数 CFG 不展开（每函数 CFG 自洽）。
- `blind_spots` 默认只含「无已知污点源的接口」（`endpoint_no_source`）；
  `uncovered_sink`（未标记危险调用）默认不产出，见 P2。
