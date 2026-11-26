"""Production-grade interactive and pipeable CLI for the Password Strength Checker."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from checker import MAX_LENGTH, PasswordReport, evaluate_password, validate_password_input

EXIT_COMMANDS = frozenset({"exit", "quit"})

_RATING_STYLES: dict[str, str] = {
    "Weak": "bold red",
    "Fair": "bold yellow",
    "Strong": "bold green",
    "Very Strong": "bold bright_cyan",
}


def _configure_utf8_streams() -> None:
    """Best-effort UTF-8 stream configuration so Unicode prints cleanly on Windows."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="password-checker",
        description="Analyze password strength with entropy, pattern detection, and optional HIBP breach checks.",
    )
    parser.add_argument(
        "--visible",
        action="store_true",
        help="Show typed password characters instead of masking input with getpass.",
    )
    parser.add_argument(
        "--breach-check",
        action="store_true",
        help="Check password against Have I Been Pwned using privacy-safe k-anonymity.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output machine-readable JSON instead of Rich terminal formatting.",
    )
    return parser.parse_args(argv)


def _entropy_label(entropy_bits: float) -> str:
    """Classify numeric bit entropy into a concise human-readable tier."""
    if entropy_bits >= 80:
        return "Very High"
    if entropy_bits >= 60:
        return "High"
    if entropy_bits >= 40:
        return "Moderate"
    return "Low"


def _build_strength_bar(score: int, rating: str, width: int = 30) -> Text:
    """Build a color-coded visual strength meter using Rich Text."""
    filled = round((score / 100) * width)
    empty = max(0, width - filled)
    style = _RATING_STYLES.get(rating, "bold white")

    bar = Text()
    bar.append("[", style="dim")
    bar.append("█" * filled, style=style)
    bar.append("░" * empty, style="dim")
    bar.append("]", style="dim")
    bar.append(f"  {score}/100  ", style="bold")
    bar.append(rating, style=style)
    return bar


def _breach_status_text(report: PasswordReport, breach_check_enabled: bool) -> Text:
    """Format the breach-check status cell for the breakdown table."""
    if not breach_check_enabled:
        return Text("Skipped (use --breach-check)", style="dim")
    if report.is_breached is True:
        if report.breach_count is not None:
            return Text(f"BREACHED ({report.breach_count:,} exposures)", style="bold red")
        return Text("BREACHED", style="bold red")
    if report.is_breached is False:
        return Text("Safe (0 known exposures)", style="bold green")
    return Text("Unavailable (offline / timeout)", style="yellow")


def render_report(
    report: PasswordReport,
    console: Console,
    *,
    breach_check_enabled: bool = False,
) -> None:
    """Render a :class:`PasswordReport` using Rich panels and tables."""
    rating_style = _RATING_STYLES.get(report.rating, "bold white")

    # 1. Summary header panel with strength meter and entropy readout
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold", no_wrap=True)
    summary.add_column()
    summary.add_row("Strength", _build_strength_bar(report.score, report.rating))
    summary.add_row(
        "Entropy",
        Text(
            f"{report.entropy_bits:.2f} bits ({_entropy_label(report.entropy_bits)})",
            style="bold cyan" if report.entropy_bits >= 60 else "yellow",
        ),
    )
    if report.is_passphrase:
        summary.add_row("Type", Text("Multi-word passphrase detected", style="bold green"))
    summary.add_row("Breach Check", _breach_status_text(report, breach_check_enabled))

    console.print(
        Panel(
            summary,
            title="[bold]Password Analysis[/bold]",
            border_style=rating_style.replace("bold ", ""),
            box=box.ROUNDED,
        )
    )

    # 2. Security breakdown table
    checks = report.checks
    breakdown = Table(
        title="Security Breakdown",
        box=box.SIMPLE_HEAD,
        show_edge=False,
        header_style="bold",
    )
    breakdown.add_column("Rule", style="white")
    breakdown.add_column("Status", justify="right")

    rule_rows: list[tuple[str, bool, str, str]] = [
        ("Minimum length (8+ chars)", checks.get("min_length", False), "PASS", "FAIL"),
        ("Recommended length (12+ chars)", checks.get("recommended_length", False), "PASS", "INFO"),
        ("Strong length (16+ chars)", checks.get("strong_length", False), "PASS", "INFO"),
        ("Lowercase letters", checks.get("has_lowercase", False), "PASS", "MISSING"),
        (
            "Uppercase letters",
            checks.get("has_uppercase", False),
            "PASS",
            "OPTIONAL" if report.is_passphrase else "MISSING",
        ),
        (
            "Digits (0-9)",
            checks.get("has_digit", False),
            "PASS",
            "OPTIONAL" if report.is_passphrase else "MISSING",
        ),
        (
            "Special characters",
            checks.get("has_special", False),
            "PASS",
            "OPTIONAL" if report.is_passphrase else "MISSING",
        ),
        ("Common / leet-speak check", checks.get("not_common", True), "PASS", "FAIL"),
        ("No repeated characters", checks.get("no_repeated_chars", True), "PASS", "WARN"),
        ("No sequential runs", checks.get("no_sequential_runs", True), "PASS", "WARN"),
        ("No keyboard walks", checks.get("no_keyboard_walks", True), "PASS", "WARN"),
        ("No leading/trailing spaces", checks.get("no_edge_whitespace", True), "PASS", "WARN"),
    ]

    for label, passed, pass_text, fail_text in rule_rows:
        if passed:
            status = Text(pass_text, style="bold green")
        elif fail_text in {"INFO", "OPTIONAL"}:
            status = Text(fail_text, style="dim")
        elif fail_text == "WARN":
            status = Text(fail_text, style="bold yellow")
        else:
            status = Text(fail_text, style="bold red")
        breakdown.add_row(label, status)

    console.print(breakdown)

    # 3. Suggestions panel
    if report.suggestions:
        suggestion_text = Text()
        for idx, suggestion in enumerate(report.suggestions):
            if idx > 0:
                suggestion_text.append("\n")
            suggestion_text.append("• ", style="bold yellow")
            suggestion_text.append(suggestion)
        console.print(
            Panel(
                suggestion_text,
                title="[bold yellow]Improvement Suggestions[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    else:
        console.print(
            Panel(
                Text("Your password meets all security guidelines!", style="bold green"),
                title="[bold green]All Checks Passed[/bold green]",
                border_style="green",
                box=box.ROUNDED,
            )
        )


def format_json_report(report: PasswordReport) -> str:
    """Format a :class:`PasswordReport` as indented JSON."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def _read_piped_password(stdin: TextIO) -> str:
    """Read a single password line from a non-interactive stdin stream."""
    raw = stdin.readline()
    return raw.rstrip("\r\n")


def run_piped(
    stdin: TextIO,
    *,
    breach_check: bool = False,
    json_output: bool = False,
    console: Console | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """Evaluate a password read from piped ``stdin`` and print the result."""
    password = _read_piped_password(stdin)
    report = evaluate_password(password, check_breach=breach_check)

    if json_output:
        stream = output_stream or sys.stdout
        stream.write(format_json_report(report) + "\n")
        stream.flush()
        return 0

    active_console = console or Console(file=output_stream or sys.stdout)
    render_report(report, active_console, breach_check_enabled=breach_check)
    return 0


def run_interactive(
    *,
    visible: bool = False,
    breach_check: bool = False,
    json_output: bool = False,
    input_func: Callable[[str], str] | None = None,
    console: Console | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """Run the interactive password evaluation loop."""
    prompt_fn = input_func or (input if visible else getpass.getpass)
    stream = output_stream or sys.stdout
    active_console = console or Console(file=stream)

    mode_label = "visible" if visible else "masked"
    breach_label = "enabled" if breach_check else "disabled"

    if not json_output:
        active_console.print(
            Panel(
                Text.assemble(
                    ("Input mode: ", "bold"),
                    (mode_label, "cyan"),
                    ("  |  Breach check: ", "bold"),
                    (breach_label, "green" if breach_check else "dim"),
                    ("  |  Max length: ", "bold"),
                    (f"{MAX_LENGTH} chars", "cyan"),
                    ("\nType ", "dim"),
                    ("exit", "bold"),
                    (" or ", "dim"),
                    ("quit", "bold"),
                    (" (or press Ctrl+C) to stop.", "dim"),
                ),
                title="[bold bright_cyan]Password Strength Checker[/bold bright_cyan]",
                border_style="bright_cyan",
                box=box.ROUNDED,
            )
        )

    while True:
        try:
            password = prompt_fn("Enter password to check (or 'exit'/'quit'): ")
        except (KeyboardInterrupt, EOFError):
            if not json_output:
                active_console.print("\n[dim]Exiting Password Strength Checker. Goodbye![/dim]")
            return 0

        if password.strip().lower() in EXIT_COMMANDS:
            if not json_output:
                active_console.print("[dim]Exiting Password Strength Checker. Goodbye![/dim]")
            return 0

        error = validate_password_input(password)
        if error is not None:
            if json_output:
                report = evaluate_password(password, check_breach=False)
                stream.write(format_json_report(report) + "\n")
                stream.flush()
            else:
                active_console.print(
                    Panel(
                        Text(f"{error} Please try again.", style="bold red"),
                        title="[bold red]Invalid Input[/bold red]",
                        border_style="red",
                        box=box.ROUNDED,
                    )
                )
            continue

        report = evaluate_password(password, check_breach=breach_check)
        if json_output:
            stream.write(format_json_report(report) + "\n")
            stream.flush()
        else:
            render_report(report, active_console, breach_check_enabled=breach_check)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    output_stream: TextIO | None = None,
    input_func: Callable[[str], str] | None = None,
    console: Console | None = None,
) -> int:
    """CLI main entry point supporting both piped stdin and interactive mode."""
    _configure_utf8_streams()
    args = parse_args(argv)
    active_stdin = stdin if stdin is not None else sys.stdin

    try:
        is_tty = active_stdin.isatty()
    except (OSError, ValueError):
        is_tty = False

    if not is_tty and input_func is None:
        return run_piped(
            active_stdin,
            breach_check=args.breach_check,
            json_output=args.json_output,
            console=console,
            output_stream=output_stream,
        )

    return run_interactive(
        visible=args.visible,
        breach_check=args.breach_check,
        json_output=args.json_output,
        input_func=input_func,
        console=console,
        output_stream=output_stream,
    )


if __name__ == "__main__":
    raise SystemExit(main())
