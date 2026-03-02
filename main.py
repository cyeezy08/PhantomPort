#!/usr/bin/env python3
"""
PhantomPort - AI-Guided Reconnaissance Engine 
Author: Cyeezy
Version: 0.1.0
"""

import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from phantomport.state import ScanState
from phantomport.ai_engine import AIEngine
from phantomport.scanner import Scanner
from phantomport.validator import Validator
from phantomport.evaluator import Evaluator
from phantomport import config

console = Console()

BANNER = """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██████╗  ██████╗ ██████╗ ████████╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██████╔╝██║   ██║██████╔╝   ██║   
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔═══╝ ██║   ██║██╔══██╗   ██║   
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║     ╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="PhantomPort — AI-guided recon engine",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Target IP or hostname")
    parser.add_argument("--mode", choices=["stealth", "balanced", "aggressive"],
                        default="balanced", help="Scan aggressiveness (default: balanced)")
    parser.add_argument("--resume", metavar="SESSION_FILE",
                        help="Resume a previous session from JSON state file")
    parser.add_argument("--max-iter", type=int, default=config.MAX_ITERATIONS,
                        help=f"Max scan iterations (default: {config.MAX_ITERATIONS})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show AI suggestions without executing scans")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Text(BANNER, style="bold red"))
    console.print(Panel("AI-Guided Reconnaissance Engine | For authorized targets only",
                        style="dim red"))

    # --- Load or create state ---
    if args.resume:
        state = ScanState.load(args.resume)
        console.print(f"[yellow]Resuming session:[/yellow] {args.resume}")
    else:
        if not args.target:
            console.print("[red]Error:[/red] A target is required unless resuming a session.")
            sys.exit(1)
        state = ScanState(target=args.target, mode=args.mode)

    # --- Initialize modules ---
    ai      = AIEngine(api_key=config.OPENROUTER_API_KEY, model=config.MODEL)
    scanner = Scanner(dry_run=args.dry_run)
    validator = Validator()
    evaluator = Evaluator()

    # --- Phase 0: Goal elicitation ---
    if not state.goal:
        goal = ai.elicit_goal(state.target)
        state.set_goal(goal)
        state.save()

    console.print(f"\n[bold green]Goal set:[/bold green] {state.goal['summary']}")
    console.print(f"[bold cyan]Target:[/bold cyan] {state.target}  |  "
                  f"[bold cyan]Mode:[/bold cyan] {state.mode}\n")

    # --- Phase 1: Baseline scan (no AI control yet) ---
    if state.iteration == 0:
        console.print("[bold yellow]>> Phase 1: Baseline scan[/bold yellow]")
        baseline_cmd = scanner.baseline_command(state.target, state.mode)
        result = scanner.run(baseline_cmd, state.target)
        score = evaluator.score(result, state)
        state.record_scan(command=baseline_cmd, result=result, score=score)
        state.save()

    # --- Phase 2: AI-guided decision loop ---
    console.print("[bold yellow]>> Phase 2: AI decision loop[/bold yellow]\n")

    while state.iteration < args.max_iter:

        # 2a. AI proposes next command
        proposed = ai.propose_next_command(state)

        if proposed.strip().upper() == "DONE":
            console.print("[bold green]\n✓ AI signalled completion. Mission accomplished.[/bold green]")
            break

        # 2b. Reasonability gate — separate AI call validates the proposal
        is_reasonable, reason = ai.validate_reasonability(proposed, state)
        if not is_reasonable:
            console.print(f"[yellow]⚠ Reasonability gate rejected proposal:[/yellow] {reason}")
            state.mark_strategy_stale()
            continue

        # 2c. Safety validator — hard rule-based check
        is_safe, violation = validator.check(proposed, state.target)
        if not is_safe:
            console.print(f"[red]✗ Safety validator blocked:[/red] {violation}")
            continue

        console.print(f"[bold white]>> Executing:[/bold white] [cyan]{proposed}[/cyan]")

        # 2d. Execute
        result = scanner.run(proposed, state.target)

        # 2e. Score result
        score = evaluator.score(result, state)
        console.print(f"[dim]   Scan score: {score:+d}[/dim]")

        # 2f. Update state
        state.record_scan(command=proposed, result=result, score=score)
        state.save()

        if score <= 0:
            console.print("[yellow]   No new info gained — flagging strategy as stale.[/yellow]")
            state.mark_strategy_stale()

    else:
        console.print(f"[yellow]\nMax iterations ({args.max_iter}) reached.[/yellow]")

    # --- Final report ---
    console.print("\n[bold magenta]== Session Summary ==[/bold magenta]")
    console.print(state.summary())
    console.print(f"\n[dim]State saved to: {state.session_file}[/dim]")


if __name__ == "__main__":
    main()
