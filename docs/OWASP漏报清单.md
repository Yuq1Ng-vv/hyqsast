# OWASP Benchmark 漏报（FN）清单

> 生成日期：2026-08-21。对 **2026-08-21-pattern** 全量分块扫描结果（
> `benchmarks/owasp/results/2026-08-21-pattern/owasp-full.json`，findings 17733 条）
> 按 OWASP 官方口径逐 `(测试, 类别)` 核对：**脆弱用例 1415，检出 1272，漏报 143**。
> 本清单即这 143 条漏报，每条带 sink 源码位置 + 根因归类 + 可修性判定。
>
> 类别 → vuln_type 映射与 `benchmarks/owasp/score.py` 的 `CAT_MAP` 完全一致
> （含 `related_categories` 判定），因此本清单与评分结果对得上（TOTAL FN = 143）。
>
> 复现/核对：`uv run python benchmarks/owasp/run.py`（1GB 小机分块方法见
> `docs/TODO.md`）。

## 汇总

| 类别 | FN 数 | 根因归类 | 可修性 |
|---|---|---|---|
| hash | 40 | 配置驱动算法（`getProperty` → `getInstance(algorithm)`） | 固有（静态不可判定） |
| pathtraver | 45 | 40 = FQN sink 规则缺口；5 = 流断裂 | **40 可直接修**（纯追加规则） |
| cmdi | 37 | 数组字面量 `{bar}` 元素→数组 taint 传播断裂 | 可修（漏报面 A 类扩展） |
| sqli | 10 | receiver 由跨文件 helper 赋值时实参 var_ref→call_site 桥接缺失 | 可修（需定位图构建细节） |
| crypto | 10 | 6 = 硬编码弱算法（DES，无 source 流入）；4 = 配置驱动 | 6 可修（精确 pattern 类别）；4 固有 |
| xpathi | 1 | 流断裂（`evaluate(expression, …)`） | 可修 |
| **TOTAL** | **143** | | |

> 注：`weakrand`（218）、`securecookie`（36）、`trustbound`（83）、`xss`（246）、
> `ldapi`（27）全部 **0 FN**。

---

## 0. 评分客观性说明（汇报时如被问「这评分可靠吗」）

**结论：口径客观、数字诚实、且没往好里刷；但 TPR 是文件级召回上界，不等于精准命中率。**

1. **地面真值是第三方**：对照 OWASP 官方 `expectedresults-1.2.csv`（独立标注），
   判定为确定性逐 `(测试, 类别)` 比对，不挑测试、不拟合参数。
2. **口径与官方一致**：TPR = TP/(TP+FN)（仅脆弱用例）、FPR = FP/(FP+TN)（仅安全
   用例），与 OWASP 官方评分脚本一致（曾用「TP/全部用例」的稀释口径，已修正为
   官方 TPR/FPR 双列）。
3. **FPR 高 = 没刷分**：总 FPR 63.5%（trustbound/xss 100%、sqli 97.4%）。一个对着
   测试集作弊的工具 FPR 应接近 0；FPR 难看说明确实把可疑的都报了——这是「高召回」
   设计的真实代价，不是演戏。
4. **TPR 的固有性质（必须讲清）**：OWASP 按测试用例计分——一个脆弱测试只要该文件
   里**任一条**类别匹配的 finding 就算命中，哪怕那条 finding 的 sink 不是真正的
   脆弱点。因此 **TPR 是「文件级召回」的上界，不是「每条都精准命中正确 sink」**。
   这是所有 OWASP 式评分的固有口径；精准性要靠本清单（逐条漏报溯源）+ 人工复核回答。
5. **四类规则确由基准暴露才补，但受铁律约束**：weakrand / hash / securecookie /
   trustbound 是基准暴露的缺口，但补的是**通用精确规则**（硬编码弱算法子串），
   非硬编码测试 ID；安全用例 FPR（weakrand 18.9%、hash 0.0%）证明模式未过宽；
   且五基准（vfa / flask-xss / vampi / demo-java + 探针）A/B 全部零丢失。

---

## 1. hash — 40 FN（配置驱动，固有）

**形态 100% 统一**（40/40），以 BenchmarkTest00003 为例：

```java
// L71-72
String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
```

**根因**：弱算法名写在 `benchmark.properties` 配置里（本工具不读配置文件），
源码里 `getInstance(algorithm)` 的实参是变量、默认值又是强算法 SHA512 ——
静态分析无法判定算法强弱。属**确定性引擎固有盲区**（已记入 `docs/TODO.md` L 节
与 `docs/漏报面清单.md` L 节，即「算法来自配置/变量」）。

**可修性**：需配置解析能力（P2「配置文件类漏洞」范围），超出当前纯源码分析边界。
不建议为抓这 40 个把 `getInstance(` 标成 pattern 型（会撞强算法 → FP 爆炸，红线）。

**FN 用例**（40）：00003, 00029, 00074, 00143, 00226, 00227, 00273, 00274, 00374,
00638, 00710, 00796, 00797, 00875, 00876, 01041, 01042, 01043, 01044, 01124,
01168, 01248, 01414, 01415, 01416, 01579, 01580, 01654, 01765, 01766, 01996,
01997, 02121, 02219, 02391, 02392, 02393, 02478, 02577, 02677。

---

## 2. pathtraver — 45 FN（40 规则缺口可修 + 5 流断裂）

### 2.1 主体 40 个：FQN（带包名）构造形式 sink 规则缺口 【可直接修】

**形态**：sink 全部是**全限定名**构造调用，如 BenchmarkTest00002 L73：

```java
fos = new java.io.FileOutputStream(fileName, false);
```

**根因（规则缺口，非流断裂）**：`taint_rules.yaml` 的 `path_traversal` sinks 里，
只有**短名** `new FileOutputStream(`、`new FileInputStream(`、`new FileReader(`、
`new FileWriter(`、`new RandomAccessFile(` 等，以及**带 `$FILE` 占位符的模板**
（`new java.io.FileOutputStream($FILE, ...)`）。`match_all_sinks` 是纯子串匹配：
`new java.io.FileOutputStream(fileName, false)` 里**没有** `new FileOutputStream(`
（中间隔了 `java.io.`），而 `$FILE` 占位符模式永远匹配不到真实代码。

实测：`match_all_sinks("java", "fos = new java.io.FileOutputStream(fileName, false)")`
→ **`[]`**（而短名版本 → `['path_traversal']`）。单文件扫 BenchmarkTest00002
同样无 path_traversal finding。

**修复**：向 `path_traversal` sinks 追加 FQN 形式：
`new java.io.FileOutputStream(`、`new java.io.FileInputStream(`、
`new java.io.FileReader(`、`new java.io.FileWriter(`、`new java.io.RandomAccessFile(`。
这些是精确类名限定，几乎零 FP 风险，属**纯追加**，不违反铁律。

**FN 用例（FQN 缺口，40）**：00002, 00028, 00045, 00133, 00222, 00363, 00455,
00456, 00459, 00529, 00627, 00785, 00787, 00788, 00953, 00956, 01034, 01111,
01112, 01116, 01117, 01161, 01408, 01496, 01498, 01645, 01647, 01836, 01989,
02032, 02034, 02112, 02205, 02304, 02383, 02469, 02561, 02562, 02565, 02567,
02569。

### 2.2 其余 5 个：流断裂 【可修，需逐例定位】

sink 本身能匹配（`new java.io.File(` 走裸 `File(` 兜底模式 / `Files.newInputStream(`），
但 taint 未到达。代表性用例：

- BenchmarkTest00060 L75-77：`bar = new String(param.getBytes(...))`（cookie source）→
  `new java.io.File(new java.io.File(TESTFILES_DIR), bar)`；
- BenchmarkTest00065 L80：`java.nio.file.Files.newInputStream(path, ...)`；
- 0952 / 1836：`new java.io.File(fileURI)`。

**FN 用例（流断裂，5）**：00060, 00061, 00065, 00952, 01836。

---

## 3. cmdi — 37 FN（数组字面量 taint 传播断裂）【可修】

**形态 100% 统一**（37/37）：用户输入经各种变换进入 **`String[]` 数组字面量**，
再把数组整个传给 `Runtime.exec` 的实参：

```java
String bar = ...;                       // ← 用户输入（cookie/header/param 中转）
String[] args = {cmd};
String[] argsEnv = {bar};               // ← taint 进数组元素
Runtime r = Runtime.getRuntime();
Process p = r.exec(args, argsEnv, ...); // ← sink
```

**根因**：sink 规则匹配没问题（`ProcessBuilder(` / `Runtime.exec(` 都在），但
**数组字面量 `{bar}` 的元素 → 数组 → exec 调用实参** 的 taint 传播没有桥接，
污染死在 `{bar}` 里。

**证据**：最小复现 `param → String[] argsEnv = {param} → r.exec(args, argsEnv)` →
**0 findings**；把 `{param}` 改成直接 `r.exec(param)` 即可检出。

**修复**：漏报面 A 类（数组/容器状态写读）扩展 —— 数组字面量初始化
`T[] x = {a, b}` 应把元素 taint 并入数组；同时 `exec` 的**任一实参**携带 taint
即应触发（含 envp 位置）。注意与「危险参数位置门控」的平衡：cmdi 没有 sqli 那种
「第 1 个实参才是攻击面」的语义，envp 位置 taint 在 OWASP 里也算脆弱。

**FN 用例（37）**：00172, 00176, 00304, 00306, 00311, 00409, 00498, 00500, 00575,
00576, 00824, 00825, 00981, 01288, 01362, 01446, 01533, 01609, 01610, 01938,
01942, 01944, 02070, 02151, 02152, 02154, 02155, 02343, 02344, 02432, 02433,
02512, 02516, 02517, 02611, 02612, 02613。

---

## 4. sqli — 10 FN（receiver 由跨文件 helper 赋值时实参桥接缺失）【可修】

**根因（00100 实证）**：sink 调用 `connection.prepareStatement(sql, ...)` 的
receiver 变量 `connection` 由**跨文件 helper 调用**赋值：

```java
// L76-79
java.sql.Connection connection =
        org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
java.sql.PreparedStatement statement =
        connection.prepareStatement(sql, TYPE_FORWARD_ONLY, ...);
```

此时 `sql` 实参的 var_ref → call_site 的 DATA_FLOW 桥接**缺失**（图里该 var_ref
消失/错位），BFS 到不了 sink。

**A/B 证据**：把真实 BenchmarkTest00100 **仅改一行** ——
`connection = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection()`
换成 `connection = java.sql.DriverManager.getConnection("jdbc:sqlite:x")` ——
同一文件立即由 **FN → 检出 sql_injection**。对照 sqli TP 用例（如 BenchmarkTest00008
单行 `connection.prepareCall(sql)`）实参 var_ref 正常桥接。

**其余 9 个**多为同形态（cookie source + helper/静态字段 receiver + 各种变换），
sink 规则本身都覆盖（`prepareStatement`/`executeQuery`/`queryForMap` 等），
流断在调用侧。需按 00100 的 A/B 方法逐例定位后统一修图构建（调用侧桥接）。

**FN 用例（10）**：00100, 00102, 00103, 00109, 00997, 00998, 01000, 01006,
01007, 01882。

---

## 5. crypto — 10 FN（6 硬编码弱算法 + 4 配置驱动）

### 5.1 6 个：硬编码弱算法，无 source 流入 【可修，需新精确 pattern 类别】

**形态**：`Cipher.getInstance("DES/CBC/PKCS5Padding", ...)` / `KeyGenerator
.getInstance("DES")` —— **弱算法是硬编码字符串，没有任何 source 流入 sink 配置**：

```java
// BenchmarkTest00053 L80-89
java.security.SecureRandom random = new java.security.SecureRandom();
javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE");
javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();
```

**根因**：`crypto_weakness` 是 **taint 型**（source 流入弱加密 API 才报）。
这里弱算法是「API 使用本身」，与 hash/weakrand 同类，但 **crypto_weakness 永不可
标 pattern 型**（红线：其 sinks 含宽模式，无条件产出会 FP 爆炸）。

**修复**：按 hash 的先例，新建**精确专用 pattern 类别**（如 `weak_crypto`），只列
硬编码弱算法子串（`"DES/`、`"RC4`、`"RC2`、`"Blowfish`、`"AES/ECB` 等，避开
强算法/`DESede` 子串冲突），进 `pattern_sinks`。落地前按铁律跑五基准 + OWASP 回归。

**FN 用例（硬编码弱算法，6）**：00053, 00055, 00056, 00057, 01822, 01823。

### 5.2 4 个：配置驱动算法（固有）

```java
// BenchmarkTest00945 L73
javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(algorithm);  // algorithm ← getProperty
```

同 hash：算法名在配置里，静态不可判定。**固有**。

**FN 用例（配置驱动，4）**：00945, 00946, 01829, 01830。

---

## 6. xpathi — 1 FN（流断裂）【可修】

**BenchmarkTest00207 L75**：

```java
xp.evaluate(expression, xmlDocument);   // expression ← 用户输入（含 param.getBytes() 变换）
```

sink 规则覆盖（`evaluate(`），但 `expression ← param` 的传播在某步断裂
（cookie/字符串变换组合），需逐例定位。

---

## 7. 修复优先级建议

| 优先级 | 项 | FN 影响 | 工作量/风险 |
|---|---|---|---|
| P0 | pathtraver 追加 FQN sink 模式（40 FN） | 40 | 极小，纯追加，近零 FP 风险 |
| P1 | cmdi 数组字面量 taint 桥接（37 FN） | 37 | 中，涉及图构建；注意 envp 位置判定 |
| P1 | sqli 调用侧实参桥接（10 FN） | 10 | 中，需按 A/B 方法定位图构建细节 |
| P2 | crypto 硬编码弱算法精确 pattern 类别（6 FN） | 6 | 中，受 crypto_weakness 红线约束需新类别 |
| P2 | pathtraver/xpathi 残余流断裂（6 FN） | 6 | 需逐例定位 |
| — | hash(40) / crypto(4) 配置驱动 | 44 | 固有，等配置解析能力（P2 路线图） |

> 合计可修 99，固有 44。修完可修项后理论 TPR ≈ 96.9%（1272+99 → 1371/1415）。
>
> **铁律提醒**：上述任何收窄/桥接改动落地前，必须先在 vfa / flask-xss / vampi /
> demo-java 四基准 + OWASP 分块回归上证明「原有命中一条不少」。
