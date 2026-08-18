# Demo：Java 漏洞样例（汇报 / 演示用）

一个**刻意挑选**的最小 Java Web 项目，用于现场演示 HyqSast 的「源 → 链 → 汇」三步。
总共 1 个文件、10 个函数、5 个接口，覆盖 4 种漏洞形态 + 1 个安全样例。

## 运行

```bash
# 在仓库根目录执行（会自动加载 rules/ 额外规则）
uv run hyqsast examples/demo-java --language java -o report.json

# 输出：report.json + report.canonical.json（规范版，人工复核用）
```

## 预期结果

```
文件: 1  函数: 10  接口: 5  finding: 6  sink: 15  盲区: 0

── 接口 ──
  GET    /users    -> users
  GET    /run      -> run
  GET    /download -> download
  GET    /profile  -> profile
  GET    /items    -> items
```

5 个接口全部被 Spring 提取器识别（`@GetMapping` + `@RequestParam` 参数）。

## 6 条 finding 怎么读

### ✅ 4 条真漏洞

| # | 类别 | 接口 | 调用链 | 看点 |
|---|---|---|---|---|
| ① | sql_injection | `GET /users` | `users → queryUser → execute → executeQuery` | **跨 3 个函数**的完整传播链（source → 拼接 → 透传 → sink） |
| ② | command_injection | `GET /run` | `run → exec → Runtime.getRuntime().exec` | 单层透传 |
| ③ | path_traversal | `GET /download` | `download → readFile → new FileInputStream` | 拼接后进文件系统 |
| ④ | xss | `GET /profile` | `profile → write` | **`sanitized: escapeHtml4`**，净化场景 |

演示讲解顺序（对着规范版报告念）：

> **① SQL 注入**：`/users` 接口的 `id` 参数（源）→ 拼进 `sql` 字符串 → 传给 `execute` → 最后流进 `executeQuery`（汇）。一条跨 3 个函数的链，每步都有文件和行号。
>
> **④ XSS**：`bio` 进了 `escapeHtml4` 再输出，所以这条标了 **sanitized=True** —— 它仍然上报，但注明「已净化」，让复核的人知道这条危险度低。这正是不靠黑名单一刀切的净化语义。

### ⚠️ 2 条已知误报（真实项目里必然伴随，正说明后续 LLM 审查层的价值）

| # | 类别 | 误报原因 |
|---|---|---|
| ⑤ | sql_injection @ `conn.createStatement()` | 规则把 `.createStatement(` 当 sink，但 `createStatement()` 本身不是注入点（注入发生在它返回的 statement 上再 `executeQuery`） |
| ⑥ | path_traversal @ `readFile(filename)` | 规则里的 `File(` 模板把任何含 `File(` 的调用都当文件打开，`readFile(` 撞上了 |

这两条正是 **HyqSast 刻意高召回** 的产物：宁可多标，不漏真问题。
它们不靠「删规则」消除（删了 `File(` 可能漏真 `new File(...)`），
而是由后续的 **LLM 审查层** 消化 —— 扫描负责全量圈定候选，LLM 负责把候选里
的误报剔掉、把真漏洞提级。

### 🔒 1 个安全样例（不报，证明不冤枉好人）

`GET /items`：`q` 只进 `PreparedStatement.setString`，没拼进 SQL，`executeQuery`
无污点到达 → 不产生 finding。盲区里也不会出现它。

## 设计原则

- **代码写实**：JDBC 样板（`createStatement`/`prepareStatement`）、工具类方法
  （`escapeHtml4`）、常见命名（`readFile`）都刻意保留，保证演示的是真实项目的
  输出形态，而不是「为过扫描而写的玩具」。
- **每个漏洞一种形态**：跨函数链 / 单层透传 / 拼接进文件系统 / 净化场景，
  一次讲全四类传播。
