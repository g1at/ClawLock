from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()


@dataclass
class HardenMeasure:
    id: str
    title: str
    desc: str
    ux_impact: str
    apply: Callable[[], bool]
    adapters: List[str]
    auto_fixable: bool = False


def _g(msg: str):
    console.print(f"  [dim]{msg}[/dim]")


def _fix_cred_perms():
    from ..utils import fix_file_permission

    fixed = 0
    for d in [
        Path.home() / ".openclaw",
        Path.home() / ".zeroclaw",
        Path.home() / ".claude",
        Path.home() / ".config" / "openclaw",
    ]:
        if d.exists():
            if fix_file_permission(d, private=True):
                fixed += 1
                _g(f"Tightened: {d}")
            for f in d.iterdir():
                if f.is_file() and f.suffix in (
                    ".json",
                    ".key",
                    ".pem",
                    ".token",
                    ".env",
                ):
                    fix_file_permission(f, private=True)
                    _g(f"Tightened: {f}")
    return fixed > 0


MEASURES: List[HardenMeasure] = [
    HardenMeasure(
        "H001",
        "Restrict file access to the workspace",
        "Tighten allowedDirectories / allowedPaths to project paths only.",
        "May block skills that need cross-directory access.",
        lambda: (_g('"allowedDirectories": ["~/projects"]'), True)[-1],
        ["openclaw", "zeroclaw", "claude-code"],
    ),
    HardenMeasure(
        "H002",
        "Enable gateway / API auth",
        "Require a token for gateway access.",
        "External tools may need a new token.",
        lambda: (_g('"gatewayAuth": true + "gatewayToken": "<your-token>"'), True)[-1],
        ["openclaw", "zeroclaw"],
    ),
    HardenMeasure(
        "H003",
        "Shorten session retention",
        "Keep session logs for 7 days or less.",
        "Older session history will no longer be available.",
        lambda: (_g('"sessionRetentionDays": 7, "logLevel": "warn"'), True)[-1],
        [],
    ),
    HardenMeasure(
        "H004",
        "Disable browser control",
        "Turn off enableBrowserControl.",
        "Browser-driven skills may stop working.",
        lambda: (_g('"enableBrowserControl": false'), True)[-1],
        ["openclaw"],
    ),
    HardenMeasure(
        "H005",
        "Set an outbound allowlist",
        "Limit skills to approved domains only.",
        "",
        lambda: (_g('"allowedNetworkDomains": ["api.anthropic.com"]'), True)[-1],
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H006",
        "Review MCP server config",
        "Check bind addresses and remote endpoints.",
        "",
        lambda: (
            _g("Change 0.0.0.0 to 127.0.0.1; remove unused remote MCP servers"),
            True,
        )[-1],
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H007",
        "Create a prompt baseline",
        "Record a SHA-256 baseline for SOUL.md / CLAUDE.md / MEMORY.md.",
        "",
        lambda: (_g("Run `clawlock soul --update-baseline` to save a baseline"), True)[
            -1
        ],
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H008",
        "Enable approval mode",
        "Require confirmation before high-risk actions.",
        "High-risk actions will pause for confirmation.",
        lambda: (_g('"approvalMode": "always"'), True)[-1],
        ["openclaw", "zeroclaw"],
    ),
    HardenMeasure(
        "H009",
        "Tighten credential permissions",
        "Limit config and credential paths to the current user.",
        "",
        _fix_cred_perms,
        [],
        auto_fixable=True,
    ),
    HardenMeasure(
        "H010",
        "Set rate limits",
        "Add request limits to reduce brute force and API abuse.",
        "",
        lambda: (
            _g('"rateLimit": {"enabled": true, "maxRequestsPerMinute": 60}'),
            True,
        )[-1],
        [],
        auto_fixable=False,
    ),
]


def run_hardening(adapter_name: str, auto: bool = False, auto_fix: bool = False):
    mode = "auto-fix" if auto_fix else "auto" if auto else "interactive"
    console.print(
        Panel(
            "[bold cyan]ClawLock Hardening Wizard[/bold cyan]",
            subtitle=f"Adapter: [bold]{adapter_name}[/bold]  |  Mode: {mode}",
        )
    )
    console.print()
    applicable = [m for m in MEASURES if not m.adapters or adapter_name in m.adapters]
    applied = 0
    for m in applicable:
        console.print(f"[bold][{m.id}][/bold] {m.title}")
        console.print(f"  [dim]{m.desc}[/dim]")
        if m.ux_impact:
            console.print(f"  [yellow]{m.ux_impact}[/yellow]")
            if auto or auto_fix:
                console.print(
                    "  [dim]Auto mode: skipped (manual confirmation required)[/dim]\n"
                )
                continue
            if not Confirm.ask(f"  Apply hardening [{m.id}]?", default=False):
                console.print(f"  [dim]Skipped {m.id}[/dim]\n")
                continue
        else:
            if auto_fix and m.auto_fixable:
                console.print("  [green]Auto-fix: applying now[/green]")
            elif not auto and not Confirm.ask(
                f"  Apply hardening [{m.id}]?", default=True
            ):
                console.print(f"  [dim]Skipped {m.id}[/dim]\n")
                continue
        if m.apply():
            applied += 1
            console.print(f"  [green]{m.id} done[/green]\n")
        else:
            console.print(f"  [red]{m.id} failed[/red]\n")
    console.print(
        f"[bold green]Hardening complete[/bold green]: {applied}/{len(applicable)} applied."
    )
