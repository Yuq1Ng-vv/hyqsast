# benchmarks/ant — xAST Benchmark 回归工具

对蚂蚁安全+浙大 [xAST Benchmark](https://xastbenchmark.github.io/)
（`benchmarks/ant-application-security-testing-benchmark/`，含独立 .git，不入库）
跑 hyqsast 并评分的回归工具。与 `benchmarks/owasp/` 同约定：**结果归档
`benchmarks/ant/results/<date>-<label>/`，score.txt/score.json 可 diff 对比**。

## 基准与 ground truth

- `sast-java/` 等各语言目录含 `*_T.java`（真漏洞）/ `*_F.java`（安全样本）。
- ground truth 取每个用例头部注释 `// real case = true/false`（与文件名后缀
  100% 一致，已验证 485/485）；评估维度取 `// evaluation item`（"体检报告"口径）。
- 典型用例：`@PostMapping` handler 带 `@RequestParam/@PathVariable` 参数 → 一路
  传到 sink（`Runtime.exec` 等）。按引擎能力维度（完整度/准确度）系统性测 source→sink
  跟踪。

## 用法

```bash
# 一键：扫描 sast-java + 评分 + 归档
uv run python benchmarks/ant/run.py

# 其它语言（sast-python3 / sast-js / sast-java-cross-module；go/php 引擎无 parser 会拒绝）
uv run python benchmarks/ant/run.py --lang-dir sast-python3 --label my-change

# 只评分已有报告（不重扫）
uv run python benchmarks/ant/run.py --score-only /tmp/report.json

# 单独跑打分器
uv run python benchmarks/ant/score.py /tmp/report.json --verbose
```

## 铁律（两个坑，2026-08-27 实测踩过）

1. **`--max-findings` 必须给高**（run.py 默认 50000）。CLI 默认每类别 50 会把
   稠密类别截断成假 FN：sast-java 上默认 50 → TPR **13.0%**，无截断 → **72.8%**。
   评分前先查 `summary.truncated_categories` 是否为空。
2. **go/php 只有规则没有引擎 parser**：sast-go/sast-php 传参直接报错退出，
   不会用空结果自欺。

## 回归基准集成（baseline_snapshot.py）

`benchmarks/baseline_snapshot.py` 的 BASELINES 已含 sast-java（路径与 run.py
的 `ANT_BENCH/lang_dir` 一致），做 finding 键集合 A/B 零丢失回归门。该工具
对全部基准强制 `--max-findings 50000 --no-cache`（铁律：默认 50 截断成假 FN；
回归门全量重建图防 stale 缓存掩盖真实回归）。

## BUG 64 影响（2026-08-28，Return 桥去共享化）

`src/hyqsast/cpg/graph.py` 的 Return value 桥从「callee 函数节点 → 每个调用方
赋值」改为「call_site → 本调用行赋值」（提交 1624991），修复污点 BFS 蝴蝶结爆炸
（同一 callee 被多文件调用时，任一路 source 达 callee 即浪进全部调用方赋值与
sink 的巨型连通块）。在 sast-java 上的效果：

```
                    findings   TP    FP    TPR      FPR
2026-08-27-first-run    447   174    90   72.8%    36.6%   (BUG 64 前)
2026-08-28-bug64        357   173    85   72.4%    34.6%   (BUG 64 后)
```

- **90 条 findings 被移除** = 跨测试用例假连通（source 从 X 用例进共享 callee、
  从 Y 用例赋值出）。打分格上：1 个"TP"（FlowSensitiveAlias_003_T）+ 5 个 FP 被
  移除，0 新增。
- **FlowSensitiveAlias_003_T 不是回归**：其唯一命中走跨用例假路径（source=003、
  sink=ReturnAlias_001，错误 sink）。真实 alias 路径（`a.b=cmd` → 对象 `a` 上卷为
  污点 → `alias(b,a)` → `b.attr=a` → `exec(b.attr.b)`）需要「对象级字段污点传播 +
  points-to 分析」——`--enable-state-bridge`（默认关，且全量 sast-java + 该旗标
  会 OOM）经定向小目录验证**也接不通**，属工具固有限制（非回归，P2/P3 待做）。
- **净效果是质量提升**：错误判 TP 变 FN 是「打假」不是漏真；FP 减少 5 条。
  默认路径（vfa/flask-xss/vampi/demo-java + OWASP）finding 键零丢失验证通过。

## 当前基线（2026-08-28-bug64，sast-java，无截断）

```
TP=173  FN=66  FP=85  TN=161
召回率 TPR = 72.4%  (173/239)    误报率 FPR = 34.6%  (85/246)
```

主要短板（逐维度见 score.txt）：
- **FN**：对象/域敏感（`setCmd/getCmd` 字段级传播，21+ 漏）、对象级别名
  （FlowSensitiveAlias_003_T 类，需 points-to）、集合/Map 元素
  （`list.add/get` 容器状态桥默认关）、多线程异步。
- **FP**：流不敏感（`result=cmd+100; result=-1` 重赋值不杀旧污点）、上下文不敏感
  （同函数不同参数全连接兜底）。
