# OWASP Benchmark 回归基准（Java web taint）

给 hyqsast 在 **OWASP Benchmark**（Java Servlet taint 测试套件）上做回归验证的可复用工具集。
2766 个测试用例，每个 `BenchmarkTestNNNNN.java` 是一个 servlet，`expectedresults-1.2.csv`
给出每个测试的期望类别 + 真漏洞/误报标注（11 类 CWE）。这正是「缺陷平衡铁律」要的
Java 基准：改规则/图引擎后跑一遍，证明**原有命中一条不少**。

## 用法

```bash
# 全量扫描 + 评分（默认 --no-cache，图一定是新构建的）
uv run python benchmarks/owasp/run.py

# 只评分已有报告（不重扫）
uv run python benchmarks/owasp/run.py --score-only /tmp/owasp_report.json

# 确定源码未变、只想快速看结果时复用缓存
uv run python benchmarks/owasp/run.py --cache
```

- BenchmarkJava 默认浅克隆到 `/root/benchmarks/owasp-benchmark`（env `OWASP_BENCH_DIR` 覆盖），源码不入仓。
- **必须给高 `--max-findings`**（run.py 默认 50000）：sqli 一类 504 个用例，默认每类别 50 会把召回截断成假 FN。

## 结果口径

评分器（`score.py`）对照 `expectedresults-1.2.csv`，按「(测试, 类别)」对计分：

- **strict TP/FP**：finding 的 `vuln_type`（含 `related_categories`）等于该测试期望类别才命中。
- **loose**：类别不精确但流接住了（`vuln_type = injection_general` 兜底），单独计数，供评估召回上限。
- **cross**：测试上报告了与期望类别不一致的 finding（信息性）。
- **recall% = TP / (TP + FN)**；`hash / weakrand / trustbound / securecookie`
  四类映射为「规则表缺失」→ 恒为严格 FN，是明确的**覆盖缺口**（见下）。

## 覆盖缺口（benchmark 有、hyqsast 规则表没有）

| 期望类别 | CWE | hyqsast 类别 | 现状 |
|---|---|---|---|
| sqli | 89 | `sql_injection` | ✅ |
| pathtraver | 22 | `path_traversal` | ✅ |
| cmdi | 78 | `command_injection` | ✅ |
| xss | 79 | `xss` | ✅ |
| crypto | 327 | `crypto_weakness` | ✅ |
| ldapi | 90 | `ldap_injection` | ✅ |
| xpathi | 643 | `xpath_injection` | ✅ |
| **hash** | 328 | — | ❌ 缺 `insecure_hash` 规则 |
| **weakrand** | 330 | — | ❌ 缺 `weak_randomness` 规则 |
| **trustbound** | 501 | — | ❌ 缺 `trust_boundary` 规则 |
| **securecookie** | 614 | — | ❌ 缺 `secure_cookie` 规则 |

补规则方向（待做）：hash = `MessageDigest.getInstance("MD5"/"SHA-1")`、`DigestUtils.md5`；
weakrand = `Random()` / `Math.random()`；securecookie = `Cookie.setSecure(false)` /
缺失 `setSecure(true)`；trustbound = 会话/请求可信数据流入风险操作。

## 注意

- 源码 `request.getParameter(...)` 等已被 java source 规则覆盖，框架提取器
  （spring/jaxrs）认不出 `@WebServlet` servlet，但 taint 分析不依赖端点提取，
  finding 照常产出（`endpoints` 为空不影响评分）。
- **内存注意（2026-08-20 实测）**：2766 文件全量单进程建图在 1.6GiB 内存的
  机器上会 **OOM 被杀**（跨文件调用图是内存大头）。修复方向：分块扫描 ——
  每块 ~400 文件一个进程、内存有界，再合并 findings 评分（每个测试用例
  自包含，跨块边不需要）。分块支持尚未落地，见 TODO。
- 源码 `request.getParameter(...)` 等已被 java source 规则覆盖，框架提取器
  （spring/jaxrs）认不出 `@WebServlet` servlet，但 taint 分析不依赖端点提取，
  finding 照常产出（`endpoints` 为空不影响评分）。
