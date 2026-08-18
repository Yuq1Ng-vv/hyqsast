# rules/ — 额外规则目录

把 LLM 从 CodeQL 适配过来的规则 `*.yaml` 放进这个目录。在仓库根目录运行扫描时
**自动加载**（cwd 下发现 `rules/` 目录即生效），与内置 `taint_rules.yaml` 按
`(语言, 区块, 类别)` **追加去重合并**，不覆盖内置。

```bash
# 仓库根目录运行，自动加载 rules/*.yaml
uv run hyqsast /path/to/project --language java -o report.json

# 显式指定其他文件/目录（此时不自动加载 cwd 的 rules/）
uv run hyqsast /path/to/project --rules path/to/other-rules/ -o report.json
```

## 文件契约

- 结构与内置 YAML 一致：`语言 → {sources, sinks, sanitizers, sink_excludes}`
- `sources / sinks / sanitizers` 是**子串**列表；`sink_excludes` 是**正则**（`re.search`）
- 一个区块键（`sources`/`sinks`/`sanitizers`）在一份文件里只能出现一次
  （YAML 重复键后者覆盖前者，会静默丢规则）
- 完整适配契约 + CodeQL 映射规范：**`examples/rules/README.md`**
- 可直接套用的模板：**`examples/rules/example.rules.yaml`**

## 约定

- **一规则一文件**：如 `fastjson.yaml` / `log4j2.yaml` / `xxe.yaml`
- 新漏洞类别：还要在 `src/hyqsast/schema.py` 的 `SEVERITY_MAP` 和
  `VULN_DISPLAY_NAMES` 各加一行（严重级别 + 规范版中文名）
- 改规则后务必 `--no-cache`（或删 `~/.cache/hyqsast/cpg/`），否则 CPG 图缓存里的
  旧污点标签不会重算，新规则看不到效果
