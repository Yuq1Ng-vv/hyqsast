# 规则适配指南：CodeQL → HyqSast

本目录是给 **LLM 批量适配 CodeQL 规则库**用的契约说明。把这一整份 README
连同你的 CodeQL 规则一起丢给 LLM，让它按下面的映射产出 `*.yaml`，再用
`--rules` 加载（见文末「用法」）。

## 核心差异：一个正则谓词系统 → 一个子串列表

CodeQL 的查询用「谓词 + 数据流」描述漏洞；HyqSast 的规则库是
**纯字符串列表**。适配的本质是：**把 CodeQL 谓词变成真实代码里会出现的一串字面量**。

| CodeQL 概念 | CodeQL 写法（示意） | HyqSast 适配产物 |
|---|---|---|
| Sink（危险调用） | `node.asExpr().(MethodAccess).getMethod().getName() = "parseObject"` | `sinks.<类别>` 加一行 `JSON.parseObject(` |
| Source（用户输入） | `node.asParameter().isParameterOf(...)` / `TaintTracking` source | `sources.<类别>` 加一行，如 `.getParameter(` |
| Sanitizer（消毒） | `isSanitizer` / 数据流上的净化 | `sanitizers.<类别>` 加一行，如 `setString` |
| 排除工具调用 | `node.getExpr().(MethodAccess).getMethod().getName() in ["toString", ...]` | `sink_excludes`（这里是**正则**）加一行 `\.toString\s*\(` |

## 硬性规则（必须遵守，否则适配产物无效）

1. **匹配是子串**：`pat in text`，不是正则、不是 glob。`JSON.parseObject(` 会命中
   `JSON.parseObject(str)`，也会命中 `xxx.JSON.parseObject(yyy)`——只要字面量出现即可。
2. **sources / sinks / sanitizers 全部子串**；**只有 `sink_excludes` 是正则**
   （`re.search`，用于豁免含 sink 子串但无害的通用调用）。
3. **带上 `(`**：sink 模式建议写成 `方法名(` 而不是裸方法名，否则 `.parse` 会命中
   `parseInt`、`parser`、`.parseState` 等一切含该子串的调用。这是子串系统的防误报关键。
4. **模式别超过 120 字符**：assignment 节点的匹配文本被截断到 120 字符，
   更长的模式永远匹配不上（call_site 节点是完整表达式，不受此限）。
5. **参数注解不走 YAML**：Java 参数上的 `@RequestParam` / `@PathVariable` 等，
   由代码映射 `_PARAM_ANNOTATION_TO_CATEGORY`（`src/hyqsast/cpg/graph.py:86`）分类。
   新增注解 source 要改那个映射；YAML 里写 `@RequestParam` 这类字面量是无效的。
6. **占位符是死字面量**：内置库里遗留的 `$VAR` / `$ARG` 模板型模式（如
   `(HttpServletRequest $REQ).$REQFUNC(...)`）在真实代码里不会出现，基本匹配不到。
   新适配的规则**不要**写 `$` 占位符，写具体方法名。
7. **类别名即 vuln_type**：sources/sinks 里出现的新类别名会自动成为报告里的
   `vuln_type`。新增类别时如需规范严重级别和中文名，还要在 `schema.py` 的
   `SEVERITY_MAP` 与 `VULN_DISPLAY_NAMES` 各加一行。
8. **多文件按 (语言, 区块, 类别) 追加去重**：额外规则不会覆盖内置规则，
   只会往对应列表里追加。想彻底替换某个类别做不到（追加是唯一语义）。

## 适配模板（喂给 LLM 的最小示例）

从一段 CodeQL 判断到 YAML 产物的推演：

```ql
// CodeQL：Fastjson 反序列化注入
import java
from MethodAccess ma
where ma.getMethod().getName() = "parseObject"
  and ma.getMethod().getDeclaringType().hasQualifiedName("com.alibaba.fastjson", "JSON")
select ma
```

```yaml
# 适配产物 → examples/rules/ 下新建 fastjson.yaml
java:
  sinks:
    deserialization:
    - JSON.parseObject(
    - JSONObject.parseObject(
    - com.alibaba.fastjson.JSON.parseObject(
```

注意：`JSON.parseObject(` 既命中全限定名也命中短名（子串），所以一行往往足够。

## LLM 适配时逐条的输出规范

对每条 CodeQL 规则，LLM 应产出：

1. `规则名`（CodeQL 原始 `@name`，便于回溯）
2. `语言`（java / python / javascript）
3. `类别`（vuln_type）——尽量复用内置类别（sql_injection / xss / ssrf / path_traversal /
   xxe / deserialization / code_injection / command_injection / ssti / jndi_injection /
   ldap_injection / xpath_injection / open_redirect / header_injection / log_injection /
   crypto_weakness / info_disclosure / format_string / auth_bypass / injection_general），
   没有合适的内置类别再发明新类别（需同步补 `schema.py` 两处）
4. `sources`：该规则要识别的用户输入入口（取参方法、请求对象字段）
5. `sinks`：危险调用字面量（方法名 + `(`）
6. `sanitizers`：路径上的净化点（参数化、编码、校验）
7. `sink_excludes`（可选）：该规则里需要豁免的通用工具调用

## 用法

```bash
# CLI：一次可传多个 --rules（文件或目录均可）
uv run hyqsast /path/to/project --language java \
    --rules rules/fastjson.yaml --rules rules/  -o report.json

# Python API
from hyqsast import scan
result = scan("/path/to/project", language="java",
              rules_paths=["rules/fastjson.yaml", "rules/"])
```

> 改规则后务必 `--no-cache`（或删 `~/.cache/hyqsast/cpg/`），否则 CPG 图缓存里
> 的旧污点标签不会重算，新规则看不到效果。

## 单条快速验证（不用跑整个项目）

```bash
uv run python -c "
from hyqsast.cpg.taint_loader import TaintRuleLoader
l = TaintRuleLoader(rules_paths=['rules/fastjson.yaml'])
print(l.match_all_sinks('java', 'JSON.parseObject(input)'))   # → ['deserialization']
print(l.match_all_sources('java', 'request.getParameter(\"x\")'))
"
```
