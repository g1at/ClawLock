"""ClawLock v1.0.0 CLI — 12 commands."""
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Annotated, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from . import __version__
from .adapters import ADAPTERS, get_adapter, get_claw_version, load_config
from .hardening import run_hardening
from .reporters import render_scan_report, console
from .scanners import (scan_config, scan_all_skills, scan_skill, scan_soul, scan_mcp,
    scan_processes, scan_credential_dirs, scan_memory_files, discover_installations,
    precheck_skill_md, CRIT, HIGH)

app = typer.Typer(name="clawlock", help="🔒 ClawLock v1.0.0 — Claw 平台综合安全扫描与加固工具",
    rich_markup_mode="rich", no_args_is_help=True)
A = Annotated[str, typer.Option("--adapter", "-a", help="适配器 [auto|openclaw|zeroclaw|claude-code|generic]")]
F = Annotated[str, typer.Option("--format", "-f", help="输出格式 [text|json|html]")]

BANNER = """[bold cyan]
   ██████╗██╗      █████╗ ██╗    ██╗██╗      ██████╗  ██████╗██╗  ██╗
  ██╔════╝██║     ██╔══██╗██║    ██║██║     ██╔═══██╗██╔════╝██║ ██╔╝
  ██║     ██║     ███████║██║ █╗ ██║██║     ██║   ██║██║     █████╔╝
  ██║     ██║     ██╔══██║██║███╗██║██║     ██║   ██║██║     ██╔═██╗
  ╚██████╗███████╗██║  ██║╚███╔███╔╝███████╗╚██████╔╝╚██████╗██║  ██╗
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
[/bold cyan][dim]  v{ver}  ·  github.com/g1at/clawlock[/dim]
"""


@app.command()
def scan(adapter: A = "auto",
    skills_dir: Annotated[Optional[str], typer.Option("--skills-dir")] = None,
    soul_path: Annotated[Optional[str], typer.Option("--soul")] = None,
    mcp_config: Annotated[Optional[str], typer.Option("--mcp-config")] = None,
    endpoint: Annotated[Optional[str], typer.Option("--endpoint")] = None,
    no_cve: Annotated[bool, typer.Option("--no-cve")] = False,
    no_redteam: Annotated[bool, typer.Option("--no-redteam")] = False,
    deep: Annotated[bool, typer.Option("--deep")] = False,
    mode: Annotated[str, typer.Option("--mode", help="monitor (仅报告) | enforce (发现高危 exit 1)")] = "enforce",
    output_format: F = "text",
    output: Annotated[Optional[str], typer.Option("--output", "-o")] = None):
    """执行全面安全扫描（配置 + 进程 + 凭证 + Skill + SOUL + Memory + MCP + CVE + 成本 + 红队）"""
    if output_format == "text": console.print(BANNER.format(ver=__version__))
    spec = get_adapter(adapter); ver = get_claw_version(spec)
    config, cfg_path = load_config(spec)
    if output_format == "text": console.print(f"  [dim]适配器: [bold]{spec.display}[/bold]  版本: {ver}  模式: {mode}[/dim]\n")

    findings_map = {}
    def _step(n, total, label):
        if output_format == "text": console.print(f"[bold cyan][Step {n}/{total}] {label}...[/bold cyan]")

    total = 9
    _step(1, total, "配置安全审计 + 危险环境变量"); cfg_f, _ = scan_config(spec); findings_map["配置审计"] = cfg_f
    _step(2, total, "进程检测 + 端口暴露"); findings_map["进程检测"] = scan_processes(spec)
    _step(3, total, "凭证目录权限审计"); findings_map["凭证审计"] = scan_credential_dirs(spec)
    _step(4, total, "Skill 供应链扫描 (55+ 模式)"); sk_f, sk_n = scan_all_skills(spec, extra_dir=skills_dir); findings_map["Skill 供应链"] = sk_f
    _step(5, total, "系统提示词 + 记忆文件 Drift"); soul_f, soul_found = scan_soul(spec, soul_path=soul_path); mem_f = scan_memory_files(spec); findings_map["提示词 & 记忆文件"] = soul_f + mem_f
    _step(6, total, "MCP 暴露面 + 工具投毒"); findings_map["MCP 暴露面"] = scan_mcp(spec, extra_mcp=mcp_config)

    cve_f = []
    if not no_cve:
        _step(7, total, "CVE 漏洞匹配")
        from .integrations import lookup_cve
        cve_f = asyncio.run(lookup_cve("OpenClaw", ver))
    findings_map["CVE 漏洞"] = cve_f

    _step(8, total, "成本分析")
    from .integrations import analyze_cost
    findings_map["成本分析"] = analyze_cost(config, cfg_path or "")

    redteam_f = []
    if not no_redteam and endpoint:
        _step(9, total, "LLM 红队测试")
        from .integrations.promptfoo import run_redteam
        redteam_f = run_redteam(endpoint, deep=deep)
    if redteam_f: findings_map["红队测试"] = redteam_f

    if output_format == "text": console.print()
    render_scan_report(spec.display, ver, findings_map, output_format, output)

    all_f = [f for fs in findings_map.values() for f in fs]
    if mode == "enforce" and any(f.level in (CRIT, HIGH) for f in all_f):
        raise typer.Exit(code=1)


@app.command()
def discover():
    """🔎 扫描系统中所有 Claw 产品安装实例、配置、工作区"""
    from .scanners import discover_installations
    findings = discover_installations()
    for f in findings:
        console.print(f"  {f.emoji} [bold]{f.title}[/bold]")
        if f.detail: console.print(f"     [dim]{f.detail}[/dim]")


@app.command()
def probe(url: Annotated[str, typer.Argument(help="目标 Claw 实例 URL (如 http://your-server:3000)")]):
    """🌐 从外部探测 Claw 实例安全状态（TLS/认证/Header/端点暴露/提示词泄露）"""
    from .integrations import probe_remote_instance
    console.print(f"[cyan]🌐 远程探测[/cyan]  target={url}")
    findings = probe_remote_instance(url)
    for f in findings:
        icon = "🔴" if f.level in (CRIT, HIGH) else ("⚠️ " if f.level == WARN else "ℹ️ ")
        console.print(f"  {icon} [bold]{f.title}[/bold]")
        console.print(f"     [dim]{f.detail}[/dim]")
        if f.remediation: console.print(f"     → {f.remediation}")
    if any(f.level in (CRIT, HIGH) for f in findings):
        raise typer.Exit(1)


@app.command()
def skill(path: Annotated[str, typer.Argument(help="skill 目录或 SKILL.md 路径")],
    adapter: A = "auto",
    check_cloud: Annotated[bool, typer.Option("--cloud/--no-cloud")] = True,
    output_format: F = "text"):
    """扫描单个 skill（安装前审计 / 供应链检查）"""
    p = Path(path).expanduser()
    if not p.exists(): console.print(f"[red]路径不存在: {p}[/red]"); raise typer.Exit(1)
    findings = scan_skill(p)
    skill_name = p.stem if p.is_file() else p.name
    if check_cloud:
        from .integrations import lookup_skill_intel, verdict_to_finding
        intel = asyncio.run(lookup_skill_intel(skill_name))
        cf = verdict_to_finding(skill_name, intel)
        if cf: findings.insert(0, cf)
    if output_format == "json":
        import json; console.print_json(json.dumps([{"level":f.level,"title":f.title,"detail":f.detail} for f in findings], ensure_ascii=False, indent=2)); return
    crits = [f for f in findings if f.level in (CRIT, HIGH)]
    warns = [f for f in findings if f.level == WARN]
    if crits:
        console.print(Panel(f"[bold red]发现风险，不建议直接安装。[/bold red]\n\n" + "\n".join(f"  🔴 {f.title}\n     {f.detail}" for f in crits[:5]),
            title=f"🔍 Skill 安全审计: {skill_name}", border_style="red"))
    elif warns:
        console.print(Panel(f"[yellow]发现需关注项。[/yellow]\n\n" + "\n".join(f"  ⚠️  {f.title}" for f in warns[:5]) + "\n\n[dim]确认来源可信后使用。[/dim]",
            title=f"🔍 Skill 安全审计: {skill_name}", border_style="yellow"))
    else:
        console.print(Panel("[green]经检测暂未发现高风险问题。[/green]\n[dim]结论仅限当前静态检查范围。[/dim]",
            title=f"🔍 Skill 安全审计: {skill_name}", border_style="green"))
    if crits: raise typer.Exit(1)


@app.command()
def precheck(path: Annotated[str, typer.Argument(help="新 SKILL.md 文件路径")]):
    """🛡️ 新 Skill 导入前安全预检（5 维度自动检测）"""
    p = Path(path).expanduser()
    if not p.exists(): console.print(f"[red]文件不存在: {p}[/red]"); raise typer.Exit(1)
    findings, is_safe = precheck_skill_md(p)
    name = p.parent.name if p.name == "SKILL.md" else p.stem
    if is_safe and not findings:
        console.print(Panel(f"[green]✅ [{name}] 预检通过。[/green]\n[dim]建议 `clawlock skill` 完整审计后安装。[/dim]",
            title="🛡️ Skill 预检", border_style="green"))
    elif is_safe:
        console.print(Panel(f"[yellow]⚠️ [{name}] {len(findings)} 项需关注[/yellow]\n" +
            "\n".join(f"  ⚠️  {f.title}" for f in findings[:5]),
            title="🛡️ Skill 预检", border_style="yellow"))
    else:
        console.print(Panel(f"[bold red]🚨 [{name}] 高危风险！不建议安装！[/bold red]\n\n" +
            "\n".join(f"  🔴 {f.title}\n     {f.detail[:80]}" for f in findings if f.level in (CRIT, HIGH)),
            title="🛡️ Skill 预检", border_style="red"))
        raise typer.Exit(1)


@app.command()
def soul(path: Annotated[Optional[str], typer.Argument(help="SOUL.md 路径")] = None,
    adapter: A = "auto",
    update_baseline: Annotated[bool, typer.Option("--update-baseline")] = False):
    """检测系统提示词 + 记忆文件完整性 & Drift"""
    spec = get_adapter(adapter)
    findings, found = scan_soul(spec, soul_path=path)
    mem_findings = scan_memory_files(spec)
    all_f = findings + mem_findings
    if update_baseline and found:
        import hashlib; from .scanners import _save_hashes, _load_hashes
        h = hashlib.sha256(found.read_text(errors="ignore").encode()).hexdigest()
        stored = _load_hashes(); stored[str(found.resolve())] = h; _save_hashes(stored)
        console.print(f"[green]✓ 已更新基准哈希: {found.name}[/green]"); return
    if not found and not mem_findings: console.print("[yellow]未发现 SOUL.md / MEMORY.md[/yellow]"); return
    if not all_f: console.print("[green]✅ 未发现注入或 drift 问题[/green]")
    else:
        for f in all_f:
            console.print(f"  {f.emoji} [bold]{f.title}[/bold]"); console.print(f"     [dim]{f.detail}[/dim]")
            if f.remediation: console.print(f"     → {f.remediation}")


@app.command()
def harden(adapter: A = "auto", auto: Annotated[bool, typer.Option("--auto")] = False,
    auto_fix: Annotated[bool, typer.Option("--auto-fix", help="自动修复无破坏性项（如文件权限）")] = False):
    """交互式安全加固向导（v1.1: --auto-fix 自动修复无破坏性项）"""
    run_hardening(get_adapter(adapter).name, auto=auto, auto_fix=auto_fix)


@app.command()
def redteam(endpoint: Annotated[str, typer.Argument(help="LLM API 端点 URL")],
    purpose: Annotated[str, typer.Option("--purpose")] = "Claw-family AI agent",
    num_tests: Annotated[int, typer.Option("--num-tests", "-n")] = 10,
    deep: Annotated[bool, typer.Option("--deep")] = False,
    save_config: Annotated[Optional[str], typer.Option("--save-config")] = None):
    """运行 promptfoo LLM 红队测试"""
    from .integrations.promptfoo import run_redteam, generate_redteam_config_file
    if save_config:
        generate_redteam_config_file(Path(save_config), endpoint, purpose, num_tests, deep)
        console.print(f"[green]✓ 配置已保存: {save_config}[/green]"); return
    console.print(f"[cyan]🎯 红队测试[/cyan]  endpoint={endpoint}")
    for f in run_redteam(endpoint, purpose=purpose, num_tests=num_tests, deep=deep):
        console.print(f"  {'🔴' if f.level in (CRIT,HIGH) else '⚠️ '} {f.title}: {f.detail[:80]}")


@app.command(name="mcp-scan")
def mcp_scan(code_path: Annotated[str, typer.Argument(help="MCP Server 源代码路径")],
    model: Annotated[str, typer.Option("--model", help="LLM 模型 (ai-infra-guard 增强用)")] = "",
    token: Annotated[str, typer.Option("--token", envvar="OPENAI_API_KEY", help="API key (ai-infra-guard 增强用)")] = "",
    base_url: Annotated[str, typer.Option("--base-url")] = ""):
    """MCP Server 源码深度安全分析 (内建引擎 + 可选 ai-infra-guard 增强)"""
    from .integrations import run_mcp_deep_scan
    p = Path(code_path).expanduser()
    console.print(f"[cyan]🔬 MCP 深度扫描[/cyan]  path={p}")
    findings = run_mcp_deep_scan(p, model, token, base_url)
    for f in findings:
        console.print(f"  {f.emoji} {f.title}")
        if f.detail: console.print(f"     [dim]{f.detail}[/dim]")
        if f.location: console.print(f"     📍 {f.location}")
        if f.remediation: console.print(f"     → {f.remediation}")
    if any(f.level in (CRIT, HIGH) for f in findings): raise typer.Exit(1)


@app.command(name="agent-scan")
def agent_scan(
    target: Annotated[Optional[str], typer.Argument(help="目标 agent URL (可选, 用于主动探测)")] = None,
    code: Annotated[Optional[str], typer.Option("--code", help="Agent 源码路径 (用于代码扫描)")] = None,
    config_file: Annotated[Optional[str], typer.Option("--config", help="Agent 配置文件路径")] = None,
    model: Annotated[str, typer.Option("--model")] = "",
    token: Annotated[str, typer.Option("--token", envvar="ANTHROPIC_API_KEY")] = "",
    base_url: Annotated[str, typer.Option("--base-url")] = "",
    llm: Annotated[bool, typer.Option("--llm/--no-llm", help="启用 LLM 辅助语义分析")] = False,
    probe: Annotated[bool, typer.Option("--probe/--no-probe", help="启用主动探测 (向目标发请求)")] = False,
    adapter: A = "auto"):
    """OWASP ASI 14 类别 Agent 安全扫描 (4 层检测架构)

    Layer 1: 静态配置分析 (零成本, 自动运行)
    Layer 2: 代码模式检测 (零成本, 需 --code)
    Layer 3: LLM 语义评估 (需 --llm + API key)
    Layer 4: 主动探测 (需 --probe + 目标 URL)
    """
    from .integrations import run_agent_scan
    from .adapters import get_adapter, load_config

    # Load config from file or auto-detect
    config = None
    if config_file:
        try: config = json.loads(Path(config_file).expanduser().read_text())
        except Exception: pass
    if not config:
        spec = get_adapter(adapter)
        config, _ = load_config(spec)

    layers = []
    if config: layers.append("配置分析")
    if code: layers.append("代码扫描")
    if llm: layers.append("LLM 评估")
    if probe and target: layers.append("主动探测")
    console.print(f"[cyan]🤖 Agent-Scan (OWASP ASI 14)[/cyan]")
    console.print(f"  检测层: {' + '.join(layers) if layers else '配置分析'}")
    if target: console.print(f"  目标: {target}")

    findings = run_agent_scan(
        target_url=target or "", model=model, token=token, base_url=base_url,
        config=config, code_path=Path(code).expanduser() if code else None,
        enable_llm=llm, enable_probe=probe)

    for f in findings:
        console.print(f"  {f.emoji} [bold]{f.title}[/bold]")
        if f.detail: console.print(f"     [dim]{f.detail}[/dim]")
        if f.location: console.print(f"     📍 {f.location}")
        if f.remediation: console.print(f"     → {f.remediation}")
    if any(f.level in (CRIT, HIGH) for f in findings): raise typer.Exit(1)


@app.command(name="react2shell")
def react2shell_scan(path: Annotated[str, typer.Argument(help="项目目录路径")] = "."):
    """扫描 CVE-2025-55182 React2Shell (CVSS 10.0)"""
    from .integrations import scan_react2shell
    findings = scan_react2shell(Path(path).expanduser())
    if not findings: console.print("[green]✅ 未发现受影响依赖[/green]")
    else:
        for f in findings: console.print(f"  {f.emoji} [bold]{f.title}[/bold]\n     [yellow]→ {f.remediation}[/yellow]")
        raise typer.Exit(1)


@app.command()
def history(limit: Annotated[int, typer.Option("--limit", "-n", help="显示最近 N 条记录")] = 20):
    """📊 查看扫描历史趋势（评分变化、高危数变化）"""
    from .utils import get_scan_history
    from rich.table import Table
    records = get_scan_history(limit)
    if not records:
        console.print("[yellow]暂无扫描历史记录。运行 `clawlock scan` 后会自动记录。[/yellow]"); return
    tbl = Table(title="📊 ClawLock 扫描历史", show_header=True, header_style="bold cyan")
    tbl.add_column("时间", min_width=20); tbl.add_column("适配器", min_width=10)
    tbl.add_column("评分", min_width=6, justify="center"); tbl.add_column("高危", min_width=6, justify="center")
    tbl.add_column("需关注", min_width=6, justify="center"); tbl.add_column("设备", min_width=14)
    for r in records:
        sc = r.get("score", 0)
        sc_style = "red" if sc < 60 else ("yellow" if sc < 80 else "green")
        tbl.add_row(r.get("time", "")[:19], r.get("adapter", ""),
            f"[{sc_style}]{sc}[/{sc_style}]",
            str(r.get("critical", 0)), str(r.get("warning", 0)), r.get("device", ""))
    console.print(tbl)
    # Trend indicator
    if len(records) >= 2:
        prev, curr = records[-2]["score"], records[-1]["score"]
        if curr > prev: console.print(f"  [green]📈 评分提升 {prev} → {curr}[/green]")
        elif curr < prev: console.print(f"  [red]📉 评分下降 {prev} → {curr}[/red]")
        else: console.print(f"  [dim]→ 评分持平 {curr}[/dim]")


@app.command()
def watch(adapter: A = "auto",
    interval: Annotated[int, typer.Option("--interval", "-i", help="扫描间隔（秒）")] = 300,
    count: Annotated[int, typer.Option("--count", "-c", help="扫描次数（0=无限）")] = 0):
    """👁️ 持续监控模式 — 定期重扫关键项，发现变化时告警"""
    import time
    spec = get_adapter(adapter)
    console.print(f"[cyan]👁️ ClawLock 持续监控模式[/cyan]  间隔={interval}s  适配器={spec.display}")
    console.print("[dim]Ctrl+C 停止[/dim]\n")
    iteration = 0
    try:
        while count == 0 or iteration < count:
            iteration += 1
            t = time.strftime("%H:%M:%S")
            console.print(f"[bold cyan]── 第 {iteration} 轮扫描 ({t}) ──[/bold cyan]")
            # Quick scan: config + soul drift + memory drift + processes
            cfg_f, _ = scan_config(spec)
            soul_f, _ = scan_soul(spec)
            mem_f = scan_memory_files(spec)
            proc_f = scan_processes(spec)
            all_f = cfg_f + soul_f + mem_f + proc_f
            crits = [f for f in all_f if f.level in ("critical", "high")]
            warns = [f for f in all_f if f.level == "medium"]
            if crits:
                console.print(f"  [bold red]🚨 发现 {len(crits)} 个高危变化！[/bold red]")
                for f in crits[:3]:
                    console.print(f"    🔴 {f.title}: {f.detail[:60]}")
            elif warns:
                console.print(f"  [yellow]⚠️ {len(warns)} 项需关注[/yellow]")
            else:
                console.print(f"  [green]✅ 一切正常[/green]")
            if count == 0 or iteration < count:
                console.print(f"  [dim]下次扫描: {interval}s 后[/dim]\n")
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print(f"\n[dim]监控已停止，共执行 {iteration} 轮。[/dim]")


@app.command()
def version():
    """显示版本信息"""
    from .integrations import _ext_version
    from .utils import platform_label
    console.print(f"ClawLock v[bold]{__version__}[/bold]")
    console.print(f"[dim]https://github.com/g1at/clawlock[/dim]")
    console.print(f"[dim]平台: {platform_label()}[/dim]")
    console.print(f"[dim]外部扫描器: {_ext_version()}[/dim]")


if __name__ == "__main__": app()
