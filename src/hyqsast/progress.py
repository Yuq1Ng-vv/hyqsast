"""progress.py — 扫描进度上报接口 + rich 双进度条（可选）与纯文本兜底。

Analyzer / CPGGraphBuilder 只在阶段边界与长循环里调用 :class:`Progress` 接口
（setup/begin/stage/set_total/step/end），不感知渲染细节，进度与逻辑解耦。

- ``make_progress()``：tty 且有 rich → 富双进度条；否则 → 写 stderr 的纯文本
  阶段日志（stdout 保持干净，chunk_scan 等子进程调用不会被污染）。
- MCP 等 stdout 承载 JSON-RPC 协议的场景**不要**调 make_progress，直接不传
  progress 参数（默认 no-op，零输出）。
- 离线 vendor 环境没有 rich 时自动走纯文本兜底，离线执行不受影响。

总体条按**时间权重**爬（``_PHASE_WEIGHTS``），ETA 从同一比例线性外推：
``已用 × (1 - 比例) / 比例``。阶段权重是静态启发式（建图/污点传播最重），
不是实测校准——提前说明，避免用户把 ETA 当精确值。
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
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.progress import (
        Progress as RichBar,
    )
except ImportError:  # pragma: no cover —— 离线 vendor 环境触发
    Console = None  # type: ignore[assignment,misc]
    BarColumn = TextColumn = TimeElapsedColumn = TimeRemainingColumn = None  # type: ignore[assignment]
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
        cols = [
            TextColumn("{task.description}", markup=True),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TextColumn("·"),
            TimeRemainingColumn(),
        ]
        self._bar = RichBar(
            *cols,
            console=self._console,
            refresh_per_second=8,
        )
        # 总体任务 total=100（权重单位）；当前阶段任务 total 随阶段补设
        self._overall_id = self._bar.add_task("", total=100, completed=0)
        self._phase_id = self._bar.add_task("", total=None)
        self._phases: list[str] = []
        self._cur = -1
        self._phase_done = 0
        self._phase_total: int | None = None
        self._ended = False

    # ── Progress 接口 ─────────────────────────────────────────────────

    def setup(self, phases: list[str] | None = None) -> None:
        self._phases = list(phases or [])
        self._bar.update(self._overall_id, description=self._nodes())
        self._bar.start()

    def begin(self, phase: str, total: int | None = None) -> None:
        if phase not in self._phases:
            self._phases.append(phase)
        self._cur = self._phases.index(phase)
        self._phase_done = 0
        self._phase_total = total
        self._bar.update(
            self._overall_id,
            completed=self._overall_completed(),
            description=self._nodes(),
        )
        self._bar.reset(self._phase_id, total=total, description=self._phase_desc(phase))

    def stage(self, label: str) -> None:
        self._bar.update(self._phase_id, description=self._phase_desc(label))

    def set_total(self, n: int) -> None:
        self._phase_total = n
        self._bar.update(self._phase_id, total=n)

    def step(self, n: int = 1) -> None:
        self._phase_done += n
        self._bar.advance(self._phase_id, n)
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

    def _phase_desc(self, label: str) -> str:
        return f"[bold cyan]本阶段[/bold cyan] {label}"

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
        """按时间权重折算的总体完成度（0~100）。每步重算，供 ETA 外推。"""
        if not self._phases or self._cur < 0:
            return 0.0
        cur = self._phases[self._cur]
        base = sum(_PHASE_WEIGHTS.get(p, 1.0) for p in self._phases[: self._cur])
        w = _PHASE_WEIGHTS.get(cur, 1.0)
        total = sum(_PHASE_WEIGHTS.get(p, 1.0) for p in self._phases)
        if total <= 0:
            return 0.0
        frac = 1.0
        if self._phase_total:
            frac = min(self._phase_done / self._phase_total, 1.0)
        else:
            frac = 0.0  # 不定长阶段（兜底）：保持不动，end() 再拉满
        return (base + w * frac) * 100.0 / total


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
