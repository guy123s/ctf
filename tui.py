#!/usr/bin/env python3
"""Memory Pool CTF — Textual TUI.

Run with: python3 tui.py  (inside the project's .venv with `textual` installed).
"""

from __future__ import annotations

import asyncio
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from pyfiglet import Figlet
from rich.syntax import Syntax
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    ProgressBar,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

ROOT = Path(__file__).resolve().parent

TEST_DESCRIPTIONS: dict[int, str] = {
    1: "data leakage after free",
    2: "heap overflow corrupts neighbor",
    3: "double-free detection",
    4: "stale data on realloc",
    5: "header corruption → wrong pool",
    6: "use-after-free",
    7: "off-by-one canary",
    8: "heap scan for secrets",
    9: "free(stack_ptr) injection",
    10: "allocation size confusion",
    11: "header metadata exposure",
    12: "freed memory still readable",
    13: "heap grooming overflow",
    14: "alignment",
    15: "deterministic address prediction",
    16: "allocator memory leak",
    17: "header bit-flip bypass",
    18: "fake chunk forgery",
    19: "pool boundary overflow",
    20: "ASLR / heap randomization",
}


@dataclass
class TestResult:
    __test__ = False  # tell pytest this is not a test class

    num: int
    desc: str
    status: str = "pending"  # pending | building | running | pass | fail | error
    detail: str = ""

    @property
    def icon(self) -> str:
        return {
            "pending": "·",
            "building": "◌",
            "running": "◐",
            "pass": "✓",
            "fail": "✗",
            "error": "!",
        }[self.status]

    @property
    def style(self) -> str:
        return {
            "pending": "dim",
            "building": "yellow",
            "running": "cyan",
            "pass": "bold green",
            "fail": "bold red",
            "error": "bold yellow",
        }[self.status]


def banner(title: str = "MEMPOOL CTF", font: str = "slant") -> Text:
    """Generate the title banner as ASCII art via pyfiglet, with a gradient."""
    art = Figlet(font=font, width=200).renderText(title).rstrip("\n")
    lines = art.splitlines()

    palette = ["magenta", "bright_magenta", "bright_blue", "cyan", "bright_cyan"]
    txt = Text(justify="left")
    for i, line in enumerate(lines):
        colour = palette[i % len(palette)]
        txt.append(line + "\n", style=f"bold {colour}")
    txt.append("       pool allocator · CTF challenge harness\n", style="dim cyan")
    return txt


class StatusBar(Static):
    score = reactive("0 / 0")
    state = reactive("idle")

    def render(self) -> Text:
        bar = Text()
        bar.append(" ⬢ ", style="bold cyan")
        bar.append("score ", style="dim")
        bar.append(self.score, style="bold green")
        bar.append("    ", style="dim")
        bar.append("state ", style="dim")
        bar.append(self.state, style="bold yellow")
        return bar


class CtfApp(App):
    CSS = """
    Screen {
        layers: base overlay;
        background: $surface;
    }

    #banner {
        height: 8;
        content-align: center middle;
        padding: 0 2;
        background: $panel;
        color: $text;
    }

    #statusbar {
        height: 1;
        background: $boost;
        padding: 0 1;
    }

    #main {
        height: 1fr;
    }

    #left {
        width: 55%;
        border: round $primary;
        padding: 0 1;
    }

    #right {
        width: 45%;
        border: round $accent;
        padding: 0 1;
    }

    DataTable {
        height: 1fr;
    }

    DataTable > .datatable--cursor {
        background: $accent 50%;
    }

    #controls {
        height: auto;
        padding: 1 0;
        align: center middle;
    }

    Button {
        margin: 0 1;
    }

    #progress {
        height: 1;
        margin-top: 1;
    }

    RichLog {
        background: $surface-darken-1;
        border: round $secondary;
        padding: 0 1;
    }

    #detail {
        height: 1fr;
    }

    TabbedContent {
        height: 1fr;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "run_selected", "Run selected"),
        Binding("a", "run_all", "Run all"),
        Binding("s", "smoke", "Smoke (test)"),
        Binding("c", "self_check", "self_check"),
        Binding("t", "testing", "testing.bin"),
        Binding("x", "clear_log", "Clear log"),
        Binding("j", "cursor_down", "↓", show=False),
        Binding("k", "cursor_up", "↑", show=False),
    ]

    results: dict[int, TestResult]

    def __init__(self) -> None:
        super().__init__()
        self.title = "MEMPOOLS"
        self.sub_title = "an allocator from beyond"
        self.results = {
            n: TestResult(num=n, desc=desc) for n, desc in TEST_DESCRIPTIONS.items()
        }
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(banner(), id="banner")
        yield StatusBar(id="statusbar")
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Label("[b]Tests[/b] — pick a test, then press [b]r[/b] to run it", markup=True)
                table: DataTable = DataTable(zebra_stripes=True, cursor_type="row", id="tests")
                yield table
                with Horizontal(id="controls"):
                    yield Button("Run [r]", id="btn-run", variant="primary")
                    yield Button("Run All [a]", id="btn-all", variant="success")
                    yield Button("Smoke [s]", id="btn-smoke")
                    yield Button("Clear [x]", id="btn-clear", variant="warning")
                yield ProgressBar(id="progress", total=100, show_eta=False)
            with Vertical(id="right"):
                with TabbedContent(initial="tab-log"):
                    with TabPane("Log", id="tab-log"):
                        yield RichLog(id="log", highlight=True, markup=True, wrap=True)
                    with TabPane("Source", id="tab-src"):
                        yield VerticalScroll(Static(id="source"), id="detail")
                    with TabPane("Detail", id="tab-detail"):
                        yield VerticalScroll(Static(id="info"), id="info-wrap")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("#", key="num")
        table.add_column("status", key="status")
        table.add_column("vulnerability", key="desc")
        for r in self.results.values():
            table.add_row(str(r.num), self._status_cell(r), r.desc, key=str(r.num))
        self.query_one(ProgressBar).update(total=len(self.results), progress=0)
        self.log_line("[bold cyan]Welcome to the Memory Pool CTF tester.[/bold cyan]")
        self.log_line("Press [b]?[/b] for keys, [b]r[/b] to run the selected test, [b]a[/b] for all.")
        self._update_status()

    # ---------- helpers ----------

    def _status_cell(self, r: TestResult) -> Text:
        return Text(f"{r.icon}  {r.status:<8}", style=r.style)

    def log_line(self, text: str) -> None:
        log = self.query_one("#log", RichLog)
        log.write(text)

    def _refresh_row(self, num: int) -> None:
        table = self.query_one(DataTable)
        r = self.results[num]
        table.update_cell(str(num), "status", self._status_cell(r))

    def _update_status(self) -> None:
        passes = sum(1 for r in self.results.values() if r.status == "pass")
        ran = sum(1 for r in self.results.values() if r.status in ("pass", "fail", "error"))
        bar = self.query_one(StatusBar)
        bar.score = f"{passes} / {ran or len(self.results)}"
        bar.state = "busy" if self._busy else "idle"
        self.query_one(ProgressBar).update(progress=ran)

    def _selected_num(self) -> int | None:
        table = self.query_one(DataTable)
        if table.cursor_row is None or table.cursor_row < 0:
            return None
        try:
            row_key = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key
            return int(row_key.value)
        except Exception:
            return None

    async def _run_proc(self, cmd: list[str], cwd: Path = ROOT) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "TERM": "xterm-256color"},
        )
        out, err = await proc.communicate()
        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")

    # ---------- actions ----------

    async def _run_test(self, num: int) -> None:
        r = self.results[num]
        src = ROOT / "tests" / f"test{num}.c"
        bin_path = ROOT / "tests" / f"test{num}"

        r.status = "building"
        self._refresh_row(num)
        self.log_line(f"[yellow]▶ building[/yellow] test{num}  [dim]({r.desc})[/dim]")

        rc, _, err = await self._run_proc(
            ["gcc", str(src), "malloc.c", "-ldl", "-o", str(bin_path)]
        )
        if rc != 0:
            r.status = "error"
            r.detail = err.strip()
            self._refresh_row(num)
            self.log_line(f"[bold yellow][ERR][/bold yellow] test{num} failed to build")
            if err.strip():
                self.log_line(Text(err.strip(), style="dim"))
            return

        r.status = "running"
        self._refresh_row(num)
        rc, out, err = await self._run_proc([str(bin_path)])
        r.status = "pass" if rc == 0 else "fail"
        r.detail = (out + err).strip()
        self._refresh_row(num)

        tag = "[bold green][PASS][/bold green]" if rc == 0 else "[bold red][FAIL][/bold red]"
        self.log_line(f"{tag}  test{num:<2}  exit={rc}  [dim]{r.desc}[/dim]")

    @work(exclusive=True)
    async def action_run_selected(self) -> None:
        num = self._selected_num()
        if num is None:
            self.log_line("[yellow]nothing selected[/yellow]")
            return
        self._busy = True
        self._update_status()
        await self._run_test(num)
        self._busy = False
        self._update_status()
        self._show_detail(num)

    @work(exclusive=True)
    async def action_run_all(self) -> None:
        self._busy = True
        self._update_status()
        self.log_line("[bold cyan]── running all 20 tests ──[/bold cyan]")
        for num in sorted(self.results):
            await self._run_test(num)
        self._busy = False
        self._update_status()
        passes = sum(1 for r in self.results.values() if r.status == "pass")
        self.log_line(f"[bold]── done. score: {passes} / {len(self.results)} ──[/bold]")

    @work(exclusive=True)
    async def action_smoke(self) -> None:
        await self._run_named("test", "test.c")

    @work(exclusive=True)
    async def action_self_check(self) -> None:
        await self._run_named("self_check", "self_check.c")

    @work(exclusive=True)
    async def action_testing(self) -> None:
        await self._run_named("testing", "testing.c")

    async def _run_named(self, name: str, src: str) -> None:
        self._busy = True
        self._update_status()
        out_path = ROOT / name
        self.log_line(f"[yellow]▶ building[/yellow] {name}")
        rc, _, err = await self._run_proc(
            ["gcc", src, "malloc.c", "-ldl", "-o", str(out_path)]
        )
        if rc != 0:
            self.log_line(f"[bold yellow][ERR][/bold yellow] {name} build failed")
            self.log_line(Text(err.strip(), style="dim"))
            self._busy = False
            self._update_status()
            return
        self.log_line(f"[cyan]▶ running[/cyan] ./{name}")
        rc, out, err = await self._run_proc([str(out_path)])
        if out.strip():
            self.log_line(Text(out.rstrip(), style="white"))
        if err.strip():
            self.log_line(Text(err.rstrip(), style="red"))
        tag = "[bold green]✓[/bold green]" if rc == 0 else "[bold red]✗[/bold red]"
        self.log_line(f"{tag} {name} exit={rc}")
        self._busy = False
        self._update_status()

    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_cursor_down(self) -> None:
        self.query_one(DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one(DataTable).action_cursor_up()

    # ---------- interactions ----------

    @on(Button.Pressed, "#btn-run")
    def _btn_run(self) -> None:
        self.action_run_selected()

    @on(Button.Pressed, "#btn-all")
    def _btn_all(self) -> None:
        self.action_run_all()

    @on(Button.Pressed, "#btn-smoke")
    def _btn_smoke(self) -> None:
        self.action_smoke()

    @on(Button.Pressed, "#btn-clear")
    def _btn_clear(self) -> None:
        self.action_clear_log()

    @on(DataTable.RowHighlighted)
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        try:
            num = int(event.row_key.value)
        except (TypeError, ValueError):
            return
        self._show_source(num)
        self._show_detail(num)

    def _show_source(self, num: int) -> None:
        path = ROOT / "tests" / f"test{num}.c"
        widget = self.query_one("#source", Static)
        if not path.exists():
            widget.update(Text(f"missing: {path}", style="red"))
            return
        try:
            code = path.read_text()
        except Exception as e:
            widget.update(Text(f"read error: {e}", style="red"))
            return
        widget.update(Syntax(code, "c", theme="monokai", line_numbers=True, word_wrap=False))

    def _show_detail(self, num: int) -> None:
        r = self.results[num]
        widget = self.query_one("#info", Static)
        body = Text()
        body.append(f"test{num}", style="bold magenta")
        body.append(f"  {r.desc}\n\n", style="cyan")
        body.append("status: ", style="dim")
        body.append(f"{r.icon} {r.status}\n", style=r.style)
        body.append(f"source: tests/test{num}.c\n", style="dim")
        body.append("\n")
        if r.detail:
            body.append("── output ──\n", style="bold")
            body.append(r.detail + "\n", style="white")
        else:
            body.append("(not yet run)\n", style="dim italic")
        widget.update(body)


if __name__ == "__main__":
    CtfApp().run()
