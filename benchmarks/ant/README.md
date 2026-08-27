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

## 当前基线（2026-08-27-first-run，sast-java，无截断）

```
TP=174  FN=65  FP=90  TN=156
召回率 TPR = 72.8%  (174/239)    误报率 FPR = 36.6%  (90/246)
```

主要短板（逐维度见 score.txt）：
- **FN**：对象/域敏感（`setCmd/getCmd` 字段级传播，21+ 漏）、集合/Map 元素
  （`list.add/get` 容器状态桥默认关）、多线程异步。
- **FP**：流不敏感（`result=cmd+100; result=-1` 重赋值不杀旧污点）、上下文不敏感
  （同函数不同参数全连接兜底）。
