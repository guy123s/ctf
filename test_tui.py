"""Pytest suite for tui.py — exercises the Textual app via its Pilot harness."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.widgets import DataTable, ProgressBar, RichLog

from tui import TEST_DESCRIPTIONS, CtfApp, StatusBar, TestResult

ROOT = Path(__file__).resolve().parent


@pytest.fixture
def app() -> CtfApp:
    return CtfApp()


# ---------- pure-data unit tests ----------


def test_test_result_icons_and_styles_cover_all_statuses():
    for status in ("pending", "building", "running", "pass", "fail", "error"):
        r = TestResult(num=1, desc="x", status=status)
        assert r.icon
        assert r.style


def test_descriptions_are_complete():
    assert set(TEST_DESCRIPTIONS) == set(range(1, 21))


# ---------- pilot-driven integration tests ----------


@pytest.mark.asyncio
async def test_app_mounts_with_all_rows(app: CtfApp):
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        assert table.row_count == 20
        bar = app.query_one(StatusBar)
        assert bar.state == "idle"


@pytest.mark.asyncio
async def test_progress_bar_initialised(app: CtfApp):
    async with app.run_test() as pilot:
        await pilot.pause()
        pb = app.query_one(ProgressBar)
        assert pb.total == 20
        assert pb.progress == 0


@pytest.mark.asyncio
async def test_columns_have_keys_for_update_cell(app: CtfApp):
    """Regression: clicking Run crashed because columns had no keys."""
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        # Should not raise CellDoesNotExist.
        table.update_cell("1", "status", "x")


@pytest.mark.asyncio
async def test_clear_log_action(app: CtfApp):
    async with app.run_test() as pilot:
        await pilot.pause()
        log = app.query_one("#log", RichLog)
        log.write("noise")
        await pilot.pause()
        await pilot.press("x")
        await pilot.pause()
        assert len(log.lines) == 0


@pytest.mark.asyncio
async def test_cursor_navigation_keys(app: CtfApp):
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        start = table.cursor_row
        await pilot.press("j")
        await pilot.pause()
        assert table.cursor_row == start + 1
        await pilot.press("k")
        await pilot.pause()
        assert table.cursor_row == start


@pytest.mark.asyncio
async def test_run_button_does_not_crash(app: CtfApp, monkeypatch):
    """The crash the user reported: clicking Run blew up with CellDoesNotExist."""

    async def fake_run_proc(self, cmd, cwd=ROOT):
        return 0, "", ""

    monkeypatch.setattr(CtfApp, "_run_proc", fake_run_proc)

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#btn-run")
        # let the worker finish
        for _ in range(20):
            await pilot.pause()
            if not app._busy:
                break
        # any worker exception would have been re-raised on exit


@pytest.mark.asyncio
async def test_run_selected_marks_pass(app: CtfApp, monkeypatch):
    async def fake_run_proc(self, cmd, cwd=ROOT):
        return 0, "ok", ""

    monkeypatch.setattr(CtfApp, "_run_proc", fake_run_proc)

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("r")
        for _ in range(30):
            await pilot.pause()
            if not app._busy:
                break
        # cursor starts on row 0 → test num 1
        assert app.results[1].status == "pass"
        assert "1" in app.query_one(StatusBar).score


@pytest.mark.asyncio
async def test_run_selected_marks_fail_on_nonzero(app: CtfApp, monkeypatch):
    async def fake_run_proc(self, cmd, cwd=ROOT):
        # build succeeds, run fails
        if cmd[0] == "gcc":
            return 0, "", ""
        return 1, "boom", ""

    monkeypatch.setattr(CtfApp, "_run_proc", fake_run_proc)

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("r")
        for _ in range(30):
            await pilot.pause()
            if not app._busy:
                break
        assert app.results[1].status == "fail"


@pytest.mark.asyncio
async def test_build_error_marks_status_error(app: CtfApp, monkeypatch):
    async def fake_run_proc(self, cmd, cwd=ROOT):
        return 1, "", "build broke"

    monkeypatch.setattr(CtfApp, "_run_proc", fake_run_proc)

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("r")
        for _ in range(30):
            await pilot.pause()
            if not app._busy:
                break
        assert app.results[1].status == "error"


@pytest.mark.asyncio
async def test_run_all_walks_every_test(app: CtfApp, monkeypatch):
    seen: list[int] = []

    async def fake_run_proc(self, cmd, cwd=ROOT):
        if cmd[0] != "gcc":
            # binary path looks like .../tests/testN
            try:
                seen.append(int(Path(cmd[0]).name.removeprefix("test")))
            except ValueError:
                pass
        return 0, "", ""

    monkeypatch.setattr(CtfApp, "_run_proc", fake_run_proc)

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("a")
        for _ in range(200):
            await pilot.pause()
            if not app._busy and seen and len(seen) == 20:
                break
        assert sorted(seen) == list(range(1, 21))
        assert all(r.status == "pass" for r in app.results.values())


@pytest.mark.asyncio
async def test_row_highlight_renders_source(app: CtfApp, monkeypatch):
    captured: list[int] = []
    real_show = CtfApp._show_source

    def spy(self, num):
        captured.append(num)
        real_show(self, num)

    monkeypatch.setattr(CtfApp, "_show_source", spy)

    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("j")  # move cursor → triggers RowHighlighted
        await pilot.pause()
        assert captured, "moving the cursor should refresh the source pane"
