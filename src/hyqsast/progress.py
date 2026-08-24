"""progress.py — 扫描进度上报接口 + rich 双进度条（可选）与纯文本兜底。

Analyzer / CPGGraphBuilder 只在阶段边界与长循环里调用 :class:`Progress` 接口
（setup/begin/stage/set_total/step/end），不感知渲染细节，进度与逻辑解耦。

- ``make_progress()``：tty 且有 rich → 富双进度条；否则 → 写 stderr 的纯文本
  阶段日志（stdout 保持干净，chunk_scan 等子进程调用不会被污染）。
- MCP 等 stdout 承载 JSON-RPC 协议的场景**不要**调 make_progress，直接不传
  progress 参数（默认 no-op，零输出）。
- 离线 vendor 环境没有 rich 时自动走纯文本兜底，离线执行不受影响。

总体条按**时间权重**爬（``_PHASE_WEIGHTS`` 作先验），ETA 从同一完成度外推：
``已用 × (1 - 比例) / 比例``。权重会随实测自适应：阶段超时→实际占比上浮
（吃剩余阶段权重）、先验按当前子阶段实测速率上修——所以 ETA 收敛到真实量级，
而不是建图 55% 权重被一个子阶段吃满后永远线性上涨。先验只是起点，不是精确值。
"""

from __future__ import annotations

import sys
import time

# 总体进度条的阶段节点（顺序固定；Analyzer.run 按此 begin）
PHASES = ("建图", "接口提取", "污点传播", "汇总")

# 阶段时间权重（用于总体条填充 + 总体 ETA 外推）。建图最重、污点传播次之，
# 接口/汇总很轻。改 PHASES 或新增阶段时在此补一条；缺省 1.0。
_PHASE_WEIGHTS: dict[str, float] = {
    "建图": 55.0,
    "接口提取": 5.0,
    "污点传播": 30.0,
    "汇总": 10.0,
}

# rich 是可选运行时（离线 vendor 不打包）；import 失败时只走 _PlainProgress 兜底。
try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        ProgressColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.progress import (
        Progress as RichBar,
    )
    from rich.text import Text

    class _EtaColumn(ProgressColumn):
        """双任务 ETA 列：总体条走时间权重外推，阶段条走 rich 原生采样。

        总体条不能直接用 rich 自带 TimeRemainingColumn：权重爬满后 completed
        平台化（如建图的 55% 在索引文件阶段就爬完）→ 无新 speed 样本 → ETA
        冻结在旧值（「还剩 8 秒」卡住 7 分钟）。本列对总体任务每次渲染按最新
        权重完成度重算；阶段任务则委托 TimeRemainingColumn（每子阶段 reset
        后样本新鲜，原生 ETA 可用）。
        """

        def __init__(self, overall_eta_func: object) -> None:
            super().__init__()
            self._overall_eta_func = overall_eta_func
            self.overall_id: int | None = None
            self._rich_remaining = TimeRemainingColumn()

        def render(self, task: object) -> Text:
            if task.id == self.overall_id:
                eta = self._overall_eta_func()
                return Text(eta or "-:--:--", style="progress.remaining")
            return self._rich_remaining.render(task)

except ImportError:  # pragma: no cover —— 离线 vendor 环境触发
    Console = None  # type: ignore[assignment,misc]
    BarColumn = TextColumn = TimeElapsedColumn = TimeRemainingColumn = None  # type: ignore[assignment]
    ProgressColumn = Text = None  # type: ignore[assignment]
    RichBar = None  # type: ignore[assignment]


def _fmt_elapsed(secs: float) -> str:
    """秒 → M:SS（超过 1 小时 → H:MM:SS）。"""
    secs = int(secs)
    if secs >= 3600:
        return f"{secs // 3600}:{secs % 3600 // 60:02d}:{secs % 60:02d}"
    return f"{secs // 60}:{secs % 60:02d}"


class Progress:
    """进度上报接口。默认实现全部 no-op，任何一步都不产生输出。"""

    def setup(self, phases: list[str] | None = None) -> None:
        """预注册阶段节点列表，供总体条提前渲染全部节点。"""

    def begin(self, phase: str, total: int | None = None) -> None:
        """进入新阶段。total 为该阶段预计 step() 总次数；None 表示不定长。"""

    def stage(self, label: str) -> None:
        """设置当前阶段的子阶段标签（如「索引文件 / 跨文件连边」）。"""

    def set_total(self, n: int) -> None:
        """补设/更新当前阶段总步数（建图阶段索引完才知道文件数）。"""

    def step(self, n: int = 1) -> None:
        """推进当前阶段 n 步。"""

    def end(self) -> None:
        """全部完成。"""


def make_progress(stream: object | None = None) -> Progress:
    """按环境选择进度渲染器：tty + rich → 双进度条；否则纯文本阶段日志。

    Args:
        stream: 输出流；默认 ``sys.stdout``。非 tty（管道/CI/子进程）时自动
            退化为写 stderr 的纯文本日志，stdout 保持干净。
    """
    stream = stream or sys.stdout
    if getattr(stream, "isatty", lambda: False)() and RichBar is not None:
        return _RichProgress(stream)
    return _PlainProgress()


class _RichProgress(Progress):
    """rich 富双进度条：总体（带阶段节点 + 权重填充 + ETA）+ 当前阶段（带 ETA）。

    两个任务共用一次 Live 刷新（同一 rich Progress 实例）。总体任务的
    completed 每步按权重重算（``_overall_completed``），使总条在建图这种
    最长阶段里也持续爬升、ETA 实时跳动，而不是卡在 0%。
    """

    def __init__(self, stream: object) -> None:
        super().__init__()
        self._console = Console(file=stream, highlight=False)
        # 自定义 ETA 列（总体走权重外推，见 _EtaColumn 注释）；overall_id 在
        # 两个任务 add 完之后补设。
        self._eta_col = _EtaColumn(self._overall_eta)
        cols = [
            TextColumn("{task.description}", markup=True),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TextColumn("·"),
            self._eta_col,
        ]
        self._bar = RichBar(
            *cols,
            console=self._console,
            refresh_per_second=8,
        )
        # 总体任务 total=100（权重单位）；当前阶段任务 total 随阶段补设
        self._overall_id = self._bar.add_task("", total=100, completed=0)
        self._phase_id = self._bar.add_task("", total=None)
        self._eta_col.overall_id = self._overall_id
        self._t0 = 0.0
        # ── 自适应总体完成度状态（见 _overall_completed）─────────────────
        # 先验权重模型把建图 55% 吃满后，慢子阶段期间 c 不动 → ETA 线性涨。
        # 改为：阶段超时→实际占比上浮（吃剩余权重）→ c 跟着实际用时走，
        # ETA 收敛而不是永远增长。
        self._prior_total = 3600.0  # 名义总时长（秒），仅初始化每个阶段的先验
        self._phase_t0 = 0.0        # 当前阶段 begin 时刻（monotonic）
        self._phase_prior = 1.0     # 当前阶段预估总时长（秒）
        self._cur_w_eff = 0.0       # 当前阶段实际权重（超时上浮）
        self._weight_done = 0.0     # 已完成阶段的实际权重累计（fold 折入）
        self._phase_has_substages = False  # 本阶段是否调过 set_total（子阶段模式）
        self._phases: list[str] = []
        self._cur = -1
        self._phase_done = 0
        self._phase_total: int | None = None
        # 当前阶段内已完成的子阶段链（stage() 累计，不替换丢失）+
        # 当前子阶段标签
        self._stage_chain: list[str] = []
        self._stage_current: str | None = None
        self._ended = False

    # ── Progress 接口 ─────────────────────────────────────────────────

    def setup(self, phases: list[str] | None = None) -> None:
        self._phases = list(phases or [])
        self._t0 = time.monotonic()
        self._bar.update(self._overall_id, description=self._nodes())
        self._bar.start()

    def begin(self, phase: str, total: int | None = None) -> None:
        if phase not in self._phases:
            self._phases.append(phase)
        # 上一阶段完成：把它的实际权重（含超时上浮）折进已完成权重，阶段切换
        # 时总条不往回缩（超时阶段占的实际比重在切换后必须保留）。
        if self._cur >= 0:
            self._weight_done += self._cur_w_eff
        self._cur = self._phases.index(phase)
        self._phase_done = 0
        self._phase_total = total
        self._phase_has_substages = False
        self._stage_chain = []
        self._stage_current = None
        self._phase_t0 = time.monotonic()
        self._cur_w_eff = _PHASE_WEIGHTS.get(phase, 1.0)
        self._phase_prior = max(1.0, self._cur_w_eff / 100.0 * self._prior_total)
        self._bar.update(
            self._overall_id,
            completed=self._overall_completed(),
            description=self._nodes(),
        )
        self._bar.reset(self._phase_id, total=total, description=self._phase_desc())

    def stage(self, label: str) -> None:
        # 上一个子阶段收进已完成链 —— 阶段条累计显示，不替换丢失
        if self._stage_current is not None:
            self._stage_chain.append(self._stage_current)
        self._stage_current = label
        self._bar.update(self._phase_id, description=self._phase_desc())

    def set_total(self, n: int) -> None:
        self._phase_total = n
        self._phase_has_substages = True  # 子阶段模式：task.elapsed 随 reset 归零
        # reset（而非 update）：同一阶段内跨子阶段切换（索引→连边各有 total）
        # 时 completed 必须清零重爬——否则上一子阶段爬满 100% 后下一子阶段仍
        # 显示 100%（视觉假象）。reset 同时清空 speed 样本 → 子阶段 ETA 新鲜。
        self._bar.reset(self._phase_id, total=n, description=self._phase_desc())

    def step(self, n: int = 1) -> None:
        self._phase_done += n
        self._bar.advance(self._phase_id, n)
        # 自适应先验：用当前子阶段实测速率推阶段全长——阶段若实际比先验慢，
        # 先验上修 → 总体 ETA 的冻结值跟着涨，不会一直停在乐观值。set_total
        # 会 reset rich 任务（start_time 归零），所以 task.elapsed 在子阶段
        # 模式下就是当前子阶段已用时间。frac 太小时跳过，避免子阶段起步瞬间
        # 的微小进度把先验撑爆。
        task = self._bar.tasks[self._phase_id]
        if task.total and task.completed > 0 and task.elapsed > 0:
            frac = task.completed / task.total
            if frac > 0.02:
                projected = task.elapsed / frac
                mult = 2.0 if self._phase_has_substages else 1.0
                cap = self._cur_w_eff / 100.0 * self._prior_total * 6.0
                self._phase_prior = max(self._phase_prior, min(projected * mult, cap))
        self._bar.update(self._overall_id, completed=self._overall_completed())

    def end(self) -> None:
        # Analyzer.run 与 CLI finally 都会调 end()，必须幂等（双调用只收一次尾）
        if self._ended:
            return
        self._ended = True
        if self._phases:
            self._bar.update(
                self._overall_id,
                completed=100.0,
                description=self._nodes(final=True),
            )
            total = self._bar.tasks[self._phase_id].total
            if total:
                self._bar.update(self._phase_id, completed=total)
        self._bar.stop()

    # ── 内部 ──────────────────────────────────────────────────────────

    def _phase_desc(self) -> str:
        """阶段条描述：已完成子阶段（✓）+ 当前子阶段（▶），累计不替换。"""
        parts = ["[bold cyan]本阶段[/bold cyan]"]
        for done in self._stage_chain:
            parts.append(f"[green]✓[/green] {done}")
        if self._stage_current:
            parts.append(f"[bold yellow]▶[/bold yellow] {self._stage_current}")
        return "  ".join(parts)

    def _nodes(self, final: bool = False) -> str:
        """阶段节点链：✓ 已完成 / ▶ 进行中 / ○ 未开始。"""
        parts = []
        for i, ph in enumerate(self._phases):
            if i < self._cur or (i == self._cur and final):
                parts.append(f"[green]✓[/green] {ph}")
            elif i == self._cur:
                parts.append(f"[bold yellow]▶[/bold yellow] {ph}")
            else:
                parts.append(f"[dim]○[/dim] {ph}")
        return "[bold cyan]总体[/bold cyan]  " + "  ".join(parts)

    def _overall_completed(self) -> float:
        """自适应总体完成度（0~100）。每步重算，供 ETA 外推。

        旧模型 c = (已完成权重 + 当前权重 × 子阶段完成度)/100：建图第一个子
        阶段（索引文件）total 与后续子阶段相同，一步就爬到 55% → 慢子阶段期间
        c 平台化 → ETA = 已用×45/55 线性上涨，永远不收敛（用户实测「总体一直
        55% + 总时间一直在增」）。

        新模型让权重跟着**实际用时**走：
        - 阶段未超时：c 按 elapsed/先验 平滑爬（c ∝ 时间 → ETA 稳定不线性涨）；
        - 阶段超时：当前阶段实际权重上浮（吃剩余阶段权重），分母同步放大
          （total_w = 已完成实际权重 + 当前实际权重 + 剩余先验权重），c 不
          提前封顶、ETA 不塌成 0，收敛到真实量级。
        """
        if not self._phases or self._cur < 0:
            return 0.0
        cur = self._phases[self._cur]
        w = _PHASE_WEIGHTS.get(cur, 1.0)
        elapsed = time.monotonic() - self._phase_t0
        if elapsed <= 0:
            frac, self._cur_w_eff = 0.0, w
        elif elapsed <= self._phase_prior:
            frac, self._cur_w_eff = elapsed / self._phase_prior, w
        else:
            # 阶段超时：实际占比按超时比例上浮；分母同步放大，c 不提前封顶
            self._cur_w_eff = w * elapsed / self._phase_prior
            frac = 1.0
        # 剩余阶段按先验权重预留给未来（分母随当前阶段超时一起放大）
        remaining = sum(
            _PHASE_WEIGHTS.get(p, 1.0) for p in self._phases[self._cur + 1 :]
        )
        total_w = self._weight_done + self._cur_w_eff + remaining
        if total_w <= 0:
            return 0.0
        return (self._weight_done + self._cur_w_eff * frac) * 100.0 / total_w

    def _overall_eta(self) -> str | None:
        """总体 ETA：``已用 × (1 - 完成度) / 完成度`` 线性外推。

        不能依赖 rich 采样（见 _EtaColumn 注释）：权重爬满后 completed 平台化
        → 无新 speed 样本 → 自带 TimeRemainingColumn 冻结在旧值。这里每次
        渲染按最新权重完成度重算，ETA 一直动。
        """
        c = self._overall_completed()
        if c <= 0 or not self._t0:
            return None
        elapsed = time.monotonic() - self._t0
        if elapsed <= 0:
            return None
        return _fmt_elapsed(elapsed * (100.0 - c) / c)


class _PlainProgress(Progress):
    """无 rich / 非 tty 时的纯文本阶段日志（写 stderr，不污染 stdout）。

    进入新阶段打印「▶ 阶段」，切换时补打上一阶段用时；子阶段标签缩进打印。
    不显示条/ETA——只保证离线 / CI / 子进程调用下用户仍能看到阶段推进。
    """

    def __init__(self) -> None:
        self._phases: list[str] = []
        self._cur = -1
        self._t0 = 0.0
        self._phase_t0 = 0.0
        self._ended = False

    def setup(self, phases: list[str] | None = None) -> None:
        self._phases = list(phases or [])

    def begin(self, phase: str, total: int | None = None) -> None:
        if self._cur >= 0:
            prev = self._phases[self._cur]
            self._emit(f"✓ {prev}（{_fmt_elapsed(time.time() - self._phase_t0)}）")
        if phase not in self._phases:
            self._phases.append(phase)
        self._cur = self._phases.index(phase)
        self._phase_t0 = time.time()
        if not self._t0:
            self._t0 = self._phase_t0
        self._emit(f"▶ {phase}")

    def stage(self, label: str) -> None:
        self._emit(f"   · {label}")

    def end(self) -> None:
        # Analyzer.run 与 CLI finally 都会调 end()，必须幂等（双调用只收一次尾）
        if self._ended:
            return
        self._ended = True
        if self._cur >= 0:
            prev = self._phases[self._cur]
            self._emit(f"✓ {prev}（{_fmt_elapsed(time.time() - self._phase_t0)}）")
            # 单阶段实例（如 CLI 的「统计概况」预扫描）不算「全部完成」，不打印
            if len(self._phases) > 1:
                self._emit(f"✓ 全部完成（总用时 {_fmt_elapsed(time.time() - self._t0)}）")

    @staticmethod
    def _emit(msg: str) -> None:
        print(msg, file=sys.stderr)
