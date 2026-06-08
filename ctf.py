#!/usr/bin/env python3
"""
Unified CTF Memory Pool Allocator Testing Suite
Fancy TUI for running all tests with a beautiful interface
"""

import subprocess
import sys
import time
from enum import Enum
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.align import Align
    from rich.text import Text
    from rich.table import Table
    from rich.traceback import install
    from rich.layout import Layout
    from rich.live import Live
    from rich.prompt import Prompt
except ImportError:
    print("❌ Missing 'rich' library. Install with: pip install rich")
    sys.exit(1)

install()
console = Console()


class TestType(Enum):
    MAIN = "main"
    CHECK = "check"
    TESTING = "testing"
    ALL = "all"


class TestRunner:
    def __init__(self):
        self.results = {}
        self.start_time = None

    def print_header(self):
        """Print main header."""
        console.clear()
        header = Text.assemble(
            ("╔════════════════════════════════════════╗\n", "cyan"),
            ("║  ", "cyan"),
            ("🧠 Memory Pool CTF Suite", "bold magenta"),
            ("          ║\n", "cyan"),
            ("║  ", "cyan"),
            ("Unified Allocator Test Runner", "yellow"),
            ("     ║\n", "cyan"),
            ("╚════════════════════════════════════════╝\n", "cyan"),
        )
        console.print(header)

    def show_menu(self):
        """Display the main menu."""
        menu_table = Table(show_header=False, box=None)
        menu_table.add_column(style="cyan")
        menu_table.add_row("[bold cyan]1[/bold cyan] - Main Test (test.c)")
        menu_table.add_row("[bold cyan]2[/bold cyan] - Self-Check (self_check.c)")
        menu_table.add_row("[bold cyan]3[/bold cyan] - Extended Tests (testing.c)")
        menu_table.add_row("[bold cyan]4[/bold cyan] - Run All Tests")
        menu_table.add_row("[bold red]5[/bold red] - Exit")

        console.print("\n[bold]Select Test:[/bold]")
        console.print(menu_table)

    def get_choice(self):
        """Get user choice."""
        while True:
            choice = Prompt.ask("\n[bold cyan]Enter choice[/bold cyan]", choices=["1", "2", "3", "4", "5"])
            return choice

    def compile_and_run(self, test_type: TestType):
        """Compile and run a specific test."""
        if test_type == TestType.MAIN:
            return self._run_main_test()
        elif test_type == TestType.CHECK:
            return self._run_check_test()
        elif test_type == TestType.TESTING:
            return self._run_testing_test()

    def _run_main_test(self):
        """Run main test."""
        console.clear()
        self.print_header()

        title = Text.assemble(
            ("🧪 Main Test", "bold magenta"),
        )
        console.print(Panel(title, border_style="cyan"))

        return self._compile_and_execute("test.c", "./test", "Main Test")

    def _run_check_test(self):
        """Run self-check test."""
        console.clear()
        self.print_header()

        title = Text.assemble(
            ("✓ Self-Check Test", "bold magenta"),
        )
        console.print(Panel(title, border_style="cyan"))

        return self._compile_and_execute("self_check.c", "./self_check", "Self-Check")

    def _run_testing_test(self):
        """Run extended tests."""
        console.clear()
        self.print_header()

        title = Text.assemble(
            ("⚙️  Extended Test Suite", "bold magenta"),
        )
        console.print(Panel(title, border_style="cyan"))

        return self._compile_and_execute("testing.c", "./testing", "Extended Tests")

    def _compile_and_execute(self, source, binary, name):
        """Generic compile and execute function."""
        console.print("\n[bold cyan]📦 Compilation Phase[/bold cyan]")

        tasks = [
            (f"Reading {source}", 0.15),
            ("Reading malloc.c", 0.15),
            ("Preprocessing", 0.1),
            ("Compiling", 0.3),
            ("Linking", 0.25),
        ]

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task_id = progress.add_task("", total=len(tasks))

            for task_name, duration in tasks:
                progress.update(task_id, description=f"  {task_name:.<35}")
                time.sleep(duration)
                progress.advance(task_id)

        console.print("[green]✓ Compilation successful![/green]\n")

        # Actually compile
        try:
            result = subprocess.run(
                ["gcc", source, "malloc.c", "-ldl", "-o", binary],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                console.print("[red bold]✗ Compilation failed![/red bold]\n")
                console.print("[red]Error output:[/red]")
                console.print(Panel(result.stderr, border_style="red"))
                return False

        except subprocess.TimeoutExpired:
            console.print("[red bold]✗ Compilation timeout![/red bold]")
            return False
        except Exception as e:
            console.print(f"[red bold]✗ Error: {e}[/red bold]")
            return False

        # Run test
        console.print(f"[bold cyan]▶ Running {name}[/bold cyan]\n")
        try:
            result = subprocess.run([binary], capture_output=False, timeout=30)
            return result.returncode == 0

        except subprocess.TimeoutExpired:
            console.print(f"[red bold]✗ {name} timeout![/red bold]")
            return False
        except Exception as e:
            console.print(f"[red bold]✗ Error: {e}[/red bold]")
            return False

    def run_all_tests(self):
        """Run all three tests sequentially."""
        console.clear()
        self.print_header()

        title = Text.assemble(
            ("🚀 Running All Tests", "bold magenta"),
        )
        console.print(Panel(title, border_style="cyan"))

        all_passed = True

        # Test 1: Main
        console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print("[bold cyan]Test 1/3: Main Test[/bold cyan]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
        result1 = self._compile_and_execute("test.c", "./test", "Main Test")
        self.results["Main Test"] = "✓ PASSED" if result1 else "✗ FAILED"
        all_passed = all_passed and result1
        time.sleep(0.5)

        # Test 2: Check
        console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print("[bold cyan]Test 2/3: Self-Check[/bold cyan]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
        result2 = self._compile_and_execute("self_check.c", "./self_check", "Self-Check")
        self.results["Self-Check"] = "✓ PASSED" if result2 else "✗ FAILED"
        all_passed = all_passed and result2
        time.sleep(0.5)

        # Test 3: Testing
        console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print("[bold cyan]Test 3/3: Extended Tests[/bold cyan]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
        result3 = self._compile_and_execute("testing.c", "./testing", "Extended Tests")
        self.results["Extended Tests"] = "✓ PASSED" if result3 else "✗ FAILED"
        all_passed = all_passed and result3

        return all_passed

    def print_results(self, passed):
        """Print final results."""
        console.print("\n")

        if passed:
            result_text = Text.assemble(
                ("✓ ALL TESTS PASSED", "bold green"),
            )
            border_style = "green"
        else:
            result_text = Text.assemble(
                ("✗ SOME TESTS FAILED", "bold red"),
            )
            border_style = "red"

        footer_panel = Panel(
            Align.center(result_text),
            border_style=border_style,
            expand=False,
        )
        console.print(footer_panel)
        console.print()

    def show_summary(self):
        """Show test summary."""
        if not self.results:
            return

        console.print("\n[bold cyan]📊 Test Summary[/bold cyan]")
        summary_table = Table(border_style="cyan", show_header=True)
        summary_table.add_column("Test", style="cyan")
        summary_table.add_column("Result")

        for test_name, result in self.results.items():
            summary_table.add_row(test_name, result)

        console.print(summary_table)

    def run(self):
        """Main run loop."""
        try:
            self.start_time = time.time()

            while True:
                self.print_header()
                self.show_menu()
                choice = self.get_choice()

                if choice == "1":
                    passed = self.compile_and_run(TestType.MAIN)
                    self.results["Main Test"] = "✓ PASSED" if passed else "✗ FAILED"
                    self.print_results(passed)

                elif choice == "2":
                    passed = self.compile_and_run(TestType.CHECK)
                    self.results["Self-Check"] = "✓ PASSED" if passed else "✗ FAILED"
                    self.print_results(passed)

                elif choice == "3":
                    passed = self.compile_and_run(TestType.TESTING)
                    self.results["Extended Tests"] = "✓ PASSED" if passed else "✗ FAILED"
                    self.print_results(passed)

                elif choice == "4":
                    passed = self.run_all_tests()
                    self.print_results(passed)
                    self.show_summary()

                elif choice == "5":
                    console.print("\n[yellow]👋 Goodbye![/yellow]\n")
                    break

                # Ask if user wants to continue
                if choice != "5":
                    Prompt.ask("\n[dim]Press Enter to continue[/dim]")

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️  Interrupted by user[/yellow]\n")
            sys.exit(130)


def main():
    # Support command-line arguments for non-interactive mode
    if len(sys.argv) > 1:
        runner = TestRunner()
        runner.start_time = time.time()

        arg = sys.argv[1].lower()

        if arg in ("test", "main", "1"):
            passed = runner.compile_and_run(TestType.MAIN)
            runner.print_results(passed)
            sys.exit(0 if passed else 1)
        elif arg in ("check", "2"):
            passed = runner.compile_and_run(TestType.CHECK)
            runner.print_results(passed)
            sys.exit(0 if passed else 1)
        elif arg in ("testing", "extended", "3"):
            passed = runner.compile_and_run(TestType.TESTING)
            runner.print_results(passed)
            sys.exit(0 if passed else 1)
        elif arg in ("all", "4"):
            passed = runner.run_all_tests()
            runner.print_results(passed)
            runner.show_summary()
            sys.exit(0 if passed else 1)
        else:
            print(f"Unknown argument: {arg}")
            print("Usage: ./ctf [test|check|testing|all]")
            sys.exit(1)
    else:
        # Interactive mode
        runner = TestRunner()
        runner.run()


if __name__ == "__main__":
    main()
