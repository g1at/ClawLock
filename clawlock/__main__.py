"""ClawLock v1.4.0 CLI - 12 commands."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.panel import Panel

from . import __version__
from .adapters import get_adapter, get_claw_version, load_config, resolve_cve_lookup
from .hardening import run_hardening
from .reporters import console, render_scan_report
from .scanners import (
    CRIT,
    HIGH,
    INFO,
    Finding,
    discover_installations,
    precheck_skill_md,
    scan_all_skills,
    scan_config,
    scan_credential_dirs,
    scan_mcp,
    scan_memory_files,
    scan_processes,
    scan_skill,
    scan_soul,
)

app = typer.Typer(
    name="clawlock",
    help="ClawLock v1.4.0 - security scan and hardening for Claw platforms",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
A = Annotated[
    str,
    typer.Option(
        "--adapter", "-a", help="Adapter [auto|openclaw|zeroclaw|claude-code|generic]"
    ),
]
F = Annotated[
    str, typer.Option("--format", "-f", help="Output format [text|json|html]")
]

BANNER = "[bold cyan]ClawLock[/bold cyan] [dim]v{ver} | github.com/g1at/clawlock[/dim]"


def _tag(level: str) -> str:
    if level in (CRIT, HIGH):
        return "HIGH"
    if level == "medium":
        return "WARN"
    return "INFO"


@app.command()
def scan(
    adapter: A = "auto",
    skills_dir: Annotated[
        Optional[str], typer.Option("--skills-dir", help="Extra skills path")
    ] = None,
    soul_path: Annotated[
        Optional[str], typer.Option("--soul", help="Custom SOUL.md path")
    ] = None,
    mcp_config: Annotated[
        Optional[str], typer.Option("--mcp-config", help="Custom MCP config path")
    ] = None,
    endpoint: Annotated[
        Optional[str], typer.Option("--endpoint", help="LLM endpoint for red team")
    ] = None,
    no_cve: Annotated[
        bool, typer.Option("--no-cve", help="Skip online CVE matching")
    ] = False,
    no_redteam: Annotated[
        bool, typer.Option("--no-redteam", help="Skip red-team checks")
    ] = False,
    deep: Annotated[
        bool, typer.Option("--deep", help="Run deeper checks where supported")
    ] = False,
    mode: Annotated[
        str,
        typer.Option(
            "--mode", help="monitor (report only) | enforce (exit 1 on high severity)"
        ),
    ] = "enforce",
    output_format: F = "text",
    output: Annotated[
        Optional[str], typer.Option("--output", "-o", help="Write report to file")
    ] = None,
):
    """Run the full security scan."""
    if output_format == "text":
        console.print(BANNER.format(ver=__version__))
    spec = get_adapter(adapter)
    ver = get_claw_version(spec)
    config, cfg_path = load_config(spec)
    if output_format == "text":
        console.print(
            f"  [dim]Adapter: [bold]{spec.display}[/bold]  Version: {ver}  Mode: {mode}[/dim]\n"
        )

    findings_map = {}

    def _step(n: int, total: int, label: str):
        if output_format == "text":
            console.print(f"[bold cyan][Step {n}/{total}] {label}...[/bold cyan]")

    total = 9
    _step(1, total, "Config audit + risky env")
    cfg_f, _ = scan_config(spec)
    findings_map["Config"] = cfg_f

    _step(2, total, "Process + port exposure")
    findings_map["Processes"] = scan_processes(spec)

    _step(3, total, "Credential permissions")
    findings_map["Credentials"] = scan_credential_dirs(spec)

    _step(4, total, "Skill supply chain")
    sk_f, _ = scan_all_skills(spec, extra_dir=skills_dir)
    findings_map["Skills"] = sk_f

    _step(5, total, "Prompt + memory drift")
    soul_f, _ = scan_soul(spec, soul_path=soul_path)
    mem_f = scan_memory_files(spec)
    findings_map["Prompt & Memory"] = soul_f + mem_f

    _step(6, total, "MCP exposure + poisoning")
    findings_map["MCP"] = scan_mcp(spec, extra_mcp=mcp_config)

    cve_f = []
    if not no_cve:
        _step(7, total, "CVE matching")
        from .integrations import lookup_cve

        cve_target, skip_reason = resolve_cve_lookup(spec, ver)
        if cve_target:
            cve_f = asyncio.run(lookup_cve(cve_target.product, cve_target.version))
        else:
            cve_f = [Finding("cve", INFO, "Skipped online CVE matching", skip_reason)]
    findings_map["CVEs"] = cve_f

    _step(8, total, "Cost review")
    from .integrations import analyze_cost

    findings_map["Cost"] = analyze_cost(config, cfg_path or "")

    redteam_f = []
    if not no_redteam and endpoint:
        _step(9, total, "LLM red team")
        from .integrations.promptfoo import run_redteam

        redteam_f = run_redteam(endpoint, deep=deep)
    if redteam_f:
        findings_map["Red Team"] = redteam_f

    if output_format == "text":
        console.print()
    render_scan_report(spec.display, ver, findings_map, output_format, output)

    all_f = [f for fs in findings_map.values() for f in fs]
    if mode == "enforce" and any(f.level in (CRIT, HIGH) for f in all_f):
        raise typer.Exit(code=1)


@app.command()
def discover():
    """Discover local Claw installations."""
    findings = discover_installations()
    for f in findings:
        console.print(f"  {_tag(f.level)} [bold]{f.title}[/bold]")
        if f.detail:
            console.print(f"     [dim]{f.detail}[/dim]")


@app.command()
def skill(
    path: Annotated[str, typer.Argument(help="Skill directory or SKILL.md path")],
    adapter: A = "auto",
    check_cloud: Annotated[
        bool, typer.Option("--cloud/--no-cloud", help="Check cloud intel if available")
    ] = True,
    output_format: F = "text",
):
    """Audit one skill."""
    p = Path(path).expanduser()
    if not p.exists():
        console.print(f"[red]Path not found: {p}[/red]")
        raise typer.Exit(1)
    findings = scan_skill(p)
    skill_name = p.stem if p.is_file() else p.name
    if check_cloud:
        from .integrations import lookup_skill_intel, verdict_to_finding

        intel = asyncio.run(lookup_skill_intel(skill_name))
        cf = verdict_to_finding(skill_name, intel)
        if cf:
            findings.insert(0, cf)
    if output_format == "json":
        console.print_json(
            json.dumps(
                [
                    {"level": f.level, "title": f.title, "detail": f.detail}
                    for f in findings
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    crits = [f for f in findings if f.level in (CRIT, HIGH)]
    warns = [f for f in findings if f.level == "medium"]
    if crits:
        console.print(
            Panel(
                "[bold red]Risk found. Do not install yet.[/bold red]\n\n"
                + "\n".join(f"  HIGH {f.title}\n     {f.detail}" for f in crits[:5]),
                title=f"Skill Audit: {skill_name}",
                border_style="red",
            )
        )
    elif warns:
        console.print(
            Panel(
                "[yellow]Review required.[/yellow]\n\n"
                + "\n".join(f"  WARN {f.title}" for f in warns[:5])
                + "\n\n[dim]Use only if the source is trusted.[/dim]",
                title=f"Skill Audit: {skill_name}",
                border_style="yellow",
            )
        )
    else:
        console.print(
            Panel(
                "[green]No high-risk issue found.[/green]\n[dim]Static checks only.[/dim]",
                title=f"Skill Audit: {skill_name}",
                border_style="green",
            )
        )
    if crits:
        raise typer.Exit(1)


@app.command()
def precheck(path: Annotated[str, typer.Argument(help="Path to a new SKILL.md file")]):
    """Precheck a new skill before import."""
    p = Path(path).expanduser()
    if not p.exists():
        console.print(f"[red]File not found: {p}[/red]")
        raise typer.Exit(1)
    findings, is_safe = precheck_skill_md(p)
    name = p.parent.name if p.name == "SKILL.md" else p.stem
    if is_safe and not findings:
        console.print(
            Panel(
                f"[green][{name}] Precheck passed.[/green]\n"
                "[dim]Run `clawlock skill` before install.[/dim]",
                title="Skill Precheck",
                border_style="green",
            )
        )
    elif is_safe:
        console.print(
            Panel(
                f"[yellow][{name}] {len(findings)} item(s) to review[/yellow]\n"
                + "\n".join(f"  WARN {f.title}" for f in findings[:5]),
                title="Skill Precheck",
                border_style="yellow",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red][{name}] High risk. Do not install.[/bold red]\n\n"
                + "\n".join(
                    f"  HIGH {f.title}\n     {f.detail[:80]}"
                    for f in findings
                    if f.level in (CRIT, HIGH)
                ),
                title="Skill Precheck",
                border_style="red",
            )
        )
        raise typer.Exit(1)


@app.command()
def soul(
    path: Annotated[Optional[str], typer.Argument(help="SOUL.md path")] = None,
    adapter: A = "auto",
    update_baseline: Annotated[
        bool, typer.Option("--update-baseline", help="Save a new baseline hash")
    ] = False,
):
    """Check prompt and memory drift."""
    spec = get_adapter(adapter)
    findings, found = scan_soul(spec, soul_path=path)
    mem_findings = scan_memory_files(spec)
    all_f = findings + mem_findings
    if update_baseline and found:
        import hashlib

        from .scanners import _load_hashes, _save_hashes

        h = hashlib.sha256(found.read_text(errors="ignore").encode()).hexdigest()
        stored = _load_hashes()
        stored[str(found.resolve())] = h
        _save_hashes(stored)
        console.print(f"[green]Baseline updated: {found.name}[/green]")
        return
    if not found and not mem_findings:
        console.print("[yellow]No SOUL.md or MEMORY.md found[/yellow]")
        return
    if not all_f:
        console.print("[green]No injection or drift issue found[/green]")
    else:
        for f in all_f:
            console.print(f"  {_tag(f.level)} [bold]{f.title}[/bold]")
            console.print(f"     [dim]{f.detail}[/dim]")
            if f.remediation:
                console.print(f"     Fix: {f.remediation}")


@app.command()
def harden(
    adapter: A = "auto",
    auto: Annotated[bool, typer.Option("--auto")] = False,
    auto_fix: Annotated[
        bool,
        typer.Option(
            "--auto-fix", help="Auto-apply safe fixes such as file permissions"
        ),
    ] = False,
):
    """Run the interactive hardening wizard."""
    run_hardening(get_adapter(adapter).name, auto=auto, auto_fix=auto_fix)


@app.command()
def redteam(
    endpoint: Annotated[str, typer.Argument(help="LLM API endpoint URL")],
    purpose: Annotated[
        str, typer.Option("--purpose", help="Target system purpose")
    ] = "Claw-family AI agent",
    num_tests: Annotated[
        int, typer.Option("--num-tests", "-n", help="Number of tests")
    ] = 10,
    deep: Annotated[bool, typer.Option("--deep", help="Use a deeper test set")] = False,
    save_config: Annotated[
        Optional[str], typer.Option("--save-config", help="Save config only")
    ] = None,
):
    """Run promptfoo red-team tests."""
    from .integrations.promptfoo import generate_redteam_config_file, run_redteam

    if save_config:
        generate_redteam_config_file(
            Path(save_config), endpoint, purpose, num_tests, deep
        )
        console.print(f"[green]Config saved: {save_config}[/green]")
        return
    console.print(f"[cyan]Red Team[/cyan]  endpoint={endpoint}")
    for f in run_redteam(endpoint, purpose=purpose, num_tests=num_tests, deep=deep):
        console.print(
            f"  {'HIGH' if f.level in (CRIT, HIGH) else 'WARN'} {f.title}: {f.detail[:80]}"
        )


@app.command(name="mcp-scan")
def mcp_scan(
    code_path: Annotated[str, typer.Argument(help="MCP server source path")],
    model: Annotated[
        str, typer.Option("--model", help="LLM model for ai-infra-guard")
    ] = "",
    token: Annotated[
        str,
        typer.Option(
            "--token", envvar="OPENAI_API_KEY", help="API key for ai-infra-guard"
        ),
    ] = "",
    base_url: Annotated[
        str, typer.Option("--base-url", help="Custom API base URL")
    ] = "",
):
    """Deep-scan MCP server source code."""
    from .integrations import run_mcp_deep_scan

    p = Path(code_path).expanduser()
    console.print(f"[cyan]MCP Deep Scan[/cyan]  path={p}")
    findings = run_mcp_deep_scan(p, model, token, base_url)
    for f in findings:
        console.print(f"  {_tag(f.level)} {f.title}")
        if f.detail:
            console.print(f"     [dim]{f.detail}[/dim]")
        if f.location:
            console.print(f"     Location: {f.location}")
        if f.remediation:
            console.print(f"     Fix: {f.remediation}")
    if any(f.level in (CRIT, HIGH) for f in findings):
        raise typer.Exit(1)


@app.command(name="agent-scan")
def agent_scan(
    code: Annotated[
        Optional[str], typer.Option("--code", help="Agent source path")
    ] = None,
    config_file: Annotated[
        Optional[str], typer.Option("--config", help="Agent config file path")
    ] = None,
    model: Annotated[str, typer.Option("--model", help="LLM model name")] = "",
    token: Annotated[
        str, typer.Option("--token", envvar="ANTHROPIC_API_KEY", help="LLM API key")
    ] = "",
    base_url: Annotated[
        str, typer.Option("--base-url", help="Custom API base URL")
    ] = "",
    llm: Annotated[
        bool,
        typer.Option("--llm/--no-llm", help="Enable LLM-assisted semantic analysis"),
    ] = False,
    adapter: A = "auto",
):
    """Run the OWASP ASI agent scan."""
    from .adapters import get_adapter, load_config
    from .integrations import run_agent_scan

    config = None
    if config_file:
        try:
            config = json.loads(Path(config_file).expanduser().read_text())
        except Exception:
            pass
    if not config:
        spec = get_adapter(adapter)
        config, _ = load_config(spec)

    layers = []
    if config:
        layers.append("Config")
    if code:
        layers.append("Code")
    if llm:
        layers.append("LLM")
    console.print("[cyan]Agent-Scan (OWASP ASI 14)[/cyan]")
    console.print(f"  Layers: {' + '.join(layers) if layers else 'Config'}")

    findings = run_agent_scan(
        model=model,
        token=token,
        base_url=base_url,
        config=config,
        code_path=Path(code).expanduser() if code else None,
        enable_llm=llm,
    )

    for f in findings:
        console.print(f"  {_tag(f.level)} [bold]{f.title}[/bold]")
        if f.detail:
            console.print(f"     [dim]{f.detail}[/dim]")
        if f.location:
            console.print(f"     Location: {f.location}")
        if f.remediation:
            console.print(f"     Fix: {f.remediation}")
    if any(f.level in (CRIT, HIGH) for f in findings):
        raise typer.Exit(1)


@app.command()
def history(
    limit: Annotated[
        int, typer.Option("--limit", "-n", help="Show the last N records")
    ] = 20,
):
    """Show recent scan history."""
    from rich.table import Table

    from .utils import get_scan_history

    records = get_scan_history(limit)
    if not records:
        console.print(
            "[yellow]No scan history yet. Run `clawlock scan` first.[/yellow]"
        )
        return
    tbl = Table(title="ClawLock History", show_header=True, header_style="bold cyan")
    tbl.add_column("Time", min_width=20)
    tbl.add_column("Adapter", min_width=10)
    tbl.add_column("Score", min_width=6, justify="center")
    tbl.add_column("High", min_width=6, justify="center")
    tbl.add_column("Warn", min_width=6, justify="center")
    tbl.add_column("Device", min_width=14)
    for r in records:
        sc = r.get("score", 0)
        sc_style = "red" if sc < 60 else ("yellow" if sc < 80 else "green")
        tbl.add_row(
            r.get("time", "")[:19],
            r.get("adapter", ""),
            f"[{sc_style}]{sc}[/{sc_style}]",
            str(r.get("critical", 0)),
            str(r.get("warning", 0)),
            r.get("device", ""),
        )
    console.print(tbl)
    if len(records) >= 2:
        prev, curr = records[-2]["score"], records[-1]["score"]
        if curr > prev:
            console.print(f"  [green]Score up {prev} -> {curr}[/green]")
        elif curr < prev:
            console.print(f"  [red]Score down {prev} -> {curr}[/red]")
        else:
            console.print(f"  [dim]-> Score unchanged {curr}[/dim]")


@app.command()
def watch(
    adapter: A = "auto",
    interval: Annotated[
        int, typer.Option("--interval", "-i", help="Scan interval in seconds")
    ] = 300,
    count: Annotated[
        int, typer.Option("--count", "-c", help="Number of runs (0 = unlimited)")
    ] = 0,
):
    """Watch key checks for changes."""
    import time

    spec = get_adapter(adapter)
    console.print(
        f"[cyan]ClawLock Watch[/cyan]  interval={interval}s  adapter={spec.display}"
    )
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    iteration = 0
    try:
        while count == 0 or iteration < count:
            iteration += 1
            t = time.strftime("%H:%M:%S")
            console.print(f"[bold cyan]-- Run {iteration} ({t}) --[/bold cyan]")
            cfg_f, _ = scan_config(spec)
            soul_f, _ = scan_soul(spec)
            mem_f = scan_memory_files(spec)
            proc_f = scan_processes(spec)
            all_f = cfg_f + soul_f + mem_f + proc_f
            crits = [f for f in all_f if f.level in ("critical", "high")]
            warns = [f for f in all_f if f.level == "medium"]
            if crits:
                console.print(
                    f"  [bold red]{len(crits)} high-severity change(s) found[/bold red]"
                )
                for f in crits[:3]:
                    console.print(f"    HIGH {f.title}: {f.detail[:60]}")
            elif warns:
                console.print(f"  [yellow]{len(warns)} warning(s)[/yellow]")
            else:
                console.print("  [green]No change detected[/green]")
            if count == 0 or iteration < count:
                console.print(f"  [dim]Next run in {interval}s[/dim]\n")
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print(f"\n[dim]Watch stopped after {iteration} run(s).[/dim]")


@app.command()
def version():
    """Show version info."""
    from .integrations import _ext_version
    from .utils import platform_label

    console.print(f"ClawLock v[bold]{__version__}[/bold]")
    console.print("[dim]https://github.com/g1at/clawlock[/dim]")
    console.print(f"[dim]Platform: {platform_label()}[/dim]")
    console.print(f"[dim]External scanner: {_ext_version()}[/dim]")


if __name__ == "__main__":
    app()
