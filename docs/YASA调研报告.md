# YASA 调研报告（蚂蚁开源统一多语言污点分析）

> 调研日期：2026-08-30。本地克隆：`/root/yasa/YASA-Engine`（分析引擎，TS）、`/root/yasa/YASA-UAST`（统一 IR + parser）。
> 论文：FSE 2026《YASA: Scalable Multi-Language Taint Analysis on the Unified AST at Ant Group》（arXiv:2601.17390）。
> 背景：对照 HyqSast（确定性、零 LLM、tree-sitter+NetworkX+子串/正则、高召回+人工复核），评估可借鉴的设计。

## 一、一句话定位

YASA 是一个**统一多语言符号解释器**（~57k 行 TypeScript）：
语言 → UAST（统一 IR）→ 按源码顺序解释执行，污点以 tag 挂在符号值上随解释流动。
宣称支持 field/context/object/path/flow 五敏感，生产已跑 7300 应用 / 1 亿+ 行，
扫描 31.8 KLOC/min（约 CodeQL 3.4×、Joern 1.9×）。

两个仓：`YASA-Engine`（核心引擎 + checker）与 `YASA-UAST`（统一 AST 规范 + 各语言 parser）。
UAST-parser 包也发布到 npm（如 `@ant-yasa/uast-parser-java-js`）。

## 二、架构三基石

### 2.1 统一 IR：UAST

- `specification/specification.md`（v0.1.64，1081 行）定义 ~50 个通用节点。
- 三层继承：`BaseNode` → 6 大分类基类（`CompileUnitBase/StmtBase/ExprBase/DeclBase/TypeBase/NameBase`）→ 48 个具体节点。
- 节点清单：17 个 Stmt（`IfStatement/SwitchStatement/ForStatement/WhileStatement/RangeStatement/ReturnStatement/TryStatement/CatchClause/...`）、
  21 个 Expr（`Literal/Identifier/CallExpression/NewExpression/MemberAccess/AssignmentExpression/BinaryExpression/Sequence/...`）、
  4 个 Decl（`FunctionDefinition/ClassDefinition/VariableDeclaration/PackageDeclaration`）、
  10 个 Type（`PrimitiveType/DynamicType/VoidType/ArrayType/TupleType/MapType/PointerType/ScopedType/FuncType/ChanType`）。
- 每个节点带 `loc`（位置）+ `meta`（注解/扩展信息）。`CompileUnit` 带 `language` 字段。
- 节点 Aliases 用于统一分析：`Conditional` 覆盖 三目+if+switch；`Scopable` 覆盖函数/类/块；`LVal` 覆盖赋值左侧 `Identifier+MemberAccess`。
- 跨语言归一化：parser-Python / parser-Java-Js（ANTLR）/ parser-Go / parser-PHP 各自产出同一套 UAST。
- 语言特有语义放到 parser 之后的 resolver/analyzer 层：
  - Go 鸭子类型：`resolver/go/go-type-related-info-resolver.ts` 提取 interface 方法名集合，逐个 struct 检查 `every(m => structMethods.has(m))` 建立 implements/implementedBy。
  - JS 原型链：`analyzer/javascript/common/js-initializer.ts` 处理 `prototype` 字段，内置方法挂到 prototype 子 scope。

### 2.2 传播算法：符号解释器（非 IFDS/IDE）

- `BaseAnalyzer`（`engine/analyzer/common/base-analyzer.ts`）为每个 UAST 节点定义 `processXxx`；
  `Analyzer.processInstruction`（analyzer.ts:1456）按节点类型分发、按源码顺序解释执行。
- 污点以 tag 挂在符号值上（`source-util.ts markTaintSource` → `unit.taint.addTag(kind)` + SOURCE trace）。
- 跨函数实参↔形参：`buildCallArgs` → `bindReceiverParam`（`self/cls/this` 绑第一个形参）→ `bindPositionalArgs`，
  按参数 kind（vararg/varkw/keyword_only/positional_only）+ spread/kwspread 展开；重载按形参数量 + `rtype.definiteType` 匹配。
- 敏感性：
  - field：`memSpace.ts resolveIndices` → `MemberExprValue(object, index)` 内存模型。
  - object：`ClassDefinition` 建 class scope，`_this`/`getThisObj()` 追踪 receiver。
  - path：`memState.ts forkStates` 分支点 fork + BVT（Branch Value Tree）分叉树合并，`brs`="L"/"R" 分支串沿读写。
  - context：state 携带 `callstack`/`callsites`，入口点隔离执行 + call-summary（库函数走 summary）。

### 2.3 规则：声明式 JSON（fsig/calleeType/args/attribute）

- 规则是 JSON 数组，按 `checkerIds` 绑定 checker，含 `sources` / `sinks` / `sanitizers` 三块。
- sink 通过 `attribute` 区分漏洞类别（`JavaSSRF`/`JavaCommandExec`/`PythonSqlInjection`/`PhpXSS`/`NodejsSSRF`/...），
  `fsig`（函数签名）匹配调用点、`calleeType` 匹配 receiver 类型、`args` 指定污点参数位（`"0"` 或 `"*"`）。

```json
{ "args": ["0"], "attribute": "JavaSSRF", "calleeType": "java.net.HttpURLConnection", "fsig": "openConnection" }
{ "args": ["0"], "attribute": "JavaCommandExec", "calleeType": "", "fsig": "Runtime.getRuntime().exec" }
{ "args": ["*"], "attribute": "PythonSqlInjection", "fsig": "cursor.execute" }
```

- source 三分类：
  - `TaintSource`：变量路径（`path: "req.body"` / `process.env`）
  - `FuncCallReturnValueTaintSource`：按 `fsig`+`calleeType` 匹配返回值
  - `FuncCallArgTaintSource`：按 `fsig`+`args` 匹配形参
- sink 匹配（`checker/taint/common-kit/sink-util.ts matchSinkAtFuncCallWithCalleeType`）：
  `matchField`（fsig 逐段匹配）+ receiver `rtype.definiteType/vagueType` 匹配 `calleeType`，
  带 class hierarchy 兜底、Go interface→concrete 穿透。
- 规则加载：`checker/common/rules-basic-handler.ts`（FileUtil.loadJSONfile）。

## 三、其他关键机制

### 3.1 调用图：解释期动态构建

- 调用图在符号解释过程中动态建（`callgraph-checker.ts triggerAtFunctionCallBefore`：每次真实调用加节点/边，
  callee 由 fclos 函数闭包 + 类型决定），非单独一趟 CFG 分析。
- 跨文件依赖全局 `PackageValue` 包树（`analyzer.ts initValTreeStruct` → `context.packages`）；
  Java 用 `assembleClassMap` 汇全部类 + CHA（`classHierarchyMap` + `findBaseTypes/findSubTypes`）。
- README 表述："新语言只要支持 package structure 就能用通用分析器"——包树是唯一必须语言定制的部分。
- 入口点（跨文件 web 框架 handler）：`engine/analyzer/common/entrypoint/`，各框架各自收集。

### 3.2 Sanitizer：规则匹配 + 场景化 tag 挂载

- 两类：`FunctionCallSanitizer`（复用 fsig/calleeType）+ `BinaryOperationSanitizer`（`operator` + `targetValue` 正则）。
- 场景（`sanitizer-checker.ts`）决定 tag 挂哪：
  - `FILTER_BY_FUNCTIONCALL` → 给返回值打 tag
  - `VALIDATE_BY_FUNCTIONCALL` → 给实参打 tag
  - `CALLSTACK_HAS_FUNCTIONCALL` / `DEFAULT` → 调用栈级 tag
  - `BinaryOperationSanitizer`：`operator` 匹配且另一侧 primitive 匹配 `targetValue` 则给另一侧打 tag
- sink 命中时沿污点路径 **BFS 回溯**（`findTagAndMatchedSanitizer` + `satisfy(args, fFlow)`）找匹配 tag，收集 flow/validate/config 类 tag。
- precondition：sink rule 声明 `preconditionIds`，命中任一 id 才保留 finding（OR 语义）。

## 四、xAST 基准数据（直接对标）

xAST（ant-application-security-testing-benchmark）在 YASA 里作为变更后回归靶场
（clone `main-forYasaTest` 分支，逐 finding 比对 trace 准确率）。
README 只有对比图，具体数字在 FSE'26 论文 Table 6（soundness/completeness，括号为百分比）：

| 工具 | Java (111/58) | Go (105/68) | JS (134/49) | Python (252/74) |
|---|---|---|---|---|
| Doop | 53/43 | — | — | — |
| Tai-e | 68/41 | — | — | — |
| ARGOT | — | 64/56 | — | — |
| DoubleX | — | — | 24/31 | — |
| ODGen | — | — | 45/39 | — |
| PySA | — | — | — | 55/46 |
| CodeQL | 50/36 | 60/56 | 66/51 | 48/41 |
| Joern | 63/29 | 51/19 | 59/37 | 50/34 |
| **YASA** | **72/55** | **91/66** | **88/71** | **70/59** |

注意：xAST 的 soundness/completeness ≠ ant 的 TPR/FPR（`_T`/`_F` 文件级）。
YASA 在 Go/JS 最强，Java 一般（72% soundness，与 HyqSast 的 sast-java 基线 TPR 72.4% 相近）。

## 五、vs HyqSast 对比表

| 维度 | YASA | HyqSast |
|---|---|---|
| IR | ~50 通用 UAST 节点，跨语言归一 | tree-sitter 原生节点 + 逐语言 provider |
| 传播 | 符号解释，污点 tag 挂符号值，五敏感 | NetworkX 图 + 前向 BFS 沿 DATA_FLOW/CALLS |
| 规则 | JSON：fsig+calleeType+args+attribute | taint_rules.yaml 子串/正则 |
| 调用图 | 解释期动态建，包树+CHA | 跨文件调用图 + import 解析 + 桥接 |
| 定位 | 精度优先，工业级生产 | 召回优先，人工复核候选 |

## 六、值得借鉴（按性价比排）

1. **`fsig`+`calleeType` 分离的 sink 规则**——sink 子串匹配会误标裸方法名（如 `query(`），
   「方法名 + 接收者类型」双条件能精确卡掉。代价是需接收者类型解析；
   HyqSast 已有 `var_types`/`method_classes`/`class_extends`（BUG 152 收窄时建立），可评估接入 `matchField` 链式匹配算法。
2. **source 三分类**——成本低（改 YAML 规则结构 + loader 增加两类 source），召回面提升明显。
3. **sink 处 sanitizer 沿污点路径 BFS 回溯**——目前 sanitizer 是节点级，改路径级回溯是降误报实质进展。
4. **callstack 级 sanitizer**——「调用栈里出现过消毒函数」低成本高召回，适合人工复核定位。
5. **动态建调用图**——建图与传播合一规避桥接断链整类问题，但架构级改动，成本高，暂不建议。

## 七、不建议借鉴

- 完整符号解释器 + 五敏感：HyqSast 定位「确定性高召回 + 人工复核」，YASA 精度机制（BVT/object 内存模型/per-call summary）
  是几千行级工程，与零 LLM 轻依赖原则冲突。
- 逐框架 entrypoint 建模（Spring/egg/gin/django…几十个）：HyqSast 框架提取器增量可扩展，不需对标该规模。

## 附：参考来源

- 本地：`/root/yasa/YASA-Engine`、`/root/yasa/YASA-UAST`（`specification/specification.md`）
- 论文：FSE 2026《YASA: Scalable Multi-Language Taint Analysis on the Unified AST at Ant Group》 arXiv:2601.17390
- [YASA-Engine](https://github.com/antgroup/YASA-Engine) / [YASA-UAST](https://github.com/antgroup/YASA-UAST)
- [xAST 评估系统](https://github.com/alipay/ant-application-security-testing-benchmark)
