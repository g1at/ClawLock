"""ClawLock v2.0.0 CLI - 12 commands."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.text import Text
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import __version__
from .adapters import get_adapter, get_claw_version, resolve_cve_lookup
from .hardening import run_hardening
from .i18n import t
from .reporters import console, render_focus_report, render_scan_report
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


def _cli_gettext(message: str) -> str:
    translations = {
        "Usage:": "用法：",
        "Options": "选项",
        "Commands": "命令",
        "Arguments": "参数",
        "Show this message and exit.": "显示此消息并退出。",
        "Install completion for the current shell.": "为当前 shell 安装补全。",
        "Show completion for the current shell, to copy it or customize the installation.": "显示当前 shell 的补全脚本，用于复制或自定义安装。",
        "Install completion for the specified shell.": "为指定 shell 安装补全。",
        "Show completion for the specified shell, to copy it or customize the installation.": "显示指定 shell 的补全脚本，用于复制或自定义安装。",
        "env var: {var}": "环境变量: {var}",
        "default: {default}": "默认值: {default}",
        "required": "必填",
        "Missing command.": "缺少命令。",
        "No such command {name!r}.": "不存在命令 {name!r}。",
        "Missing parameter: {param_name}": "缺少参数: {param_name}",
    }
    return t(translations.get(message, message), message)


def _patch_cli_i18n() -> None:
    import click.core
    import click.decorators
    import click.formatting
    import typer.completion
    import typer.rich_utils

    click.core._ = _cli_gettext
    click.decorators._ = _cli_gettext
    click.formatting._ = _cli_gettext
    typer.rich_utils._ = _cli_gettext

    typer.rich_utils.ARGUMENTS_PANEL_TITLE = _cli_gettext("Arguments")
    typer.rich_utils.OPTIONS_PANEL_TITLE = _cli_gettext("Options")
    typer.rich_utils.COMMANDS_PANEL_TITLE = _cli_gettext("Commands")
    typer.rich_utils.OptionHighlighter.highlights = [
        r"(^|\W)(?P<switch>\-\w+)(?![a-zA-Z0-9])",
        r"(^|\W)(?P<option>\-\-[\w\-]+)(?![a-zA-Z0-9])",
        r"(?P<metavar>\<[^\>]+\>)",
        r"(?P<usage>(?:Usage: |用法[:：] ))",
    ]

    completion_defaults = typer.completion._install_completion_placeholder_function.__defaults__
    if completion_defaults:
        completion_defaults[0].help = _cli_gettext("Install completion for the current shell.")
        completion_defaults[1].help = _cli_gettext(
            "Show completion for the current shell, to copy it or customize the installation."
        )
    completion_defaults = typer.completion._install_completion_no_auto_placeholder_function.__defaults__
    if completion_defaults:
        completion_defaults[0].help = _cli_gettext("Install completion for the specified shell.")
        completion_defaults[1].help = _cli_gettext(
            "Show completion for the specified shell, to copy it or customize the installation."
        )

    def _install_callback(ctx, param, value):
        if not value or ctx.resilient_parsing:
            return value
        if isinstance(value, str):
            shell, path = typer.completion.install(shell=value)
        else:
            shell, path = typer.completion.install()
        import click

        click.secho(
            t(
                f"{shell} 补全已安装到 {path}",
                f"{shell} completion installed in {path}",
            ),
            fg="green",
        )
        click.echo(
            t(
                "重启终端后补全将生效",
                "Completion will take effect once you restart the terminal",
            )
        )
        sys.exit(0)

    def _shell_complete(cli, ctx_args, prog_name, complete_var, instruction):
        import click
        import click.shell_completion

        if "_" not in instruction:
            click.echo(t("无效的补全指令。", "Invalid completion instruction."), err=True)
            return 1

        instruction, _, shell = instruction.partition("_")
        comp_cls = click.shell_completion.get_completion_class(shell)
        if comp_cls is None:
            click.echo(t(f"不支持的 shell: {shell}", f"Shell {shell} not supported."), err=True)
            return 1

        comp = comp_cls(cli, ctx_args, prog_name, complete_var)
        if instruction == "source":
            click.echo(comp.source())
            return 0
        if instruction == "complete":
            click.echo(comp.complete())
            return 0
        click.echo(
            t(
                f'不支持的补全指令 "{instruction}"。',
                f'Completion instruction "{instruction}" not supported.',
            ),
            err=True,
        )
        return 1

    typer.completion.install_callback = _install_callback
    typer.completion.shell_complete = _shell_complete
    completion_defaults = typer.completion._install_completion_placeholder_function.__defaults__
    if completion_defaults:
        completion_defaults[0].callback = _install_callback
    completion_defaults = typer.completion._install_completion_no_auto_placeholder_function.__defaults__
    if completion_defaults:
        completion_defaults[0].callback = _install_callback


_patch_cli_i18n()

app = typer.Typer(
    name="clawlock",
    help=t(
        "ClawLock v2.0.0 - 面向 Claw 平台的安全扫描与加固工具",
        "ClawLock v2.0.0 - security scan and hardening for Claw platforms",
    ),
    rich_markup_mode="rich",
    no_args_is_help=False,
)
LOGO = """  ██████╗██╗      █████╗ ██╗    ██╗██╗      ██████╗  ██████╗██╗  ██╗
  ██╔════╝██║     ██╔══██╗██║    ██║██║     ██╔═══██╗██╔════╝██║ ██╔╝
  ██║     ██║     ███████║██║ █╗ ██║██║     ██║   ██║██║     █████╔╝
  ██║     ██║     ██╔══██║██║███╗██║██║     ██║   ██║██║     ██╔═██╗
  ╚██████╗███████╗██║  ██║╚███╔███╔╝███████╗╚██████╔╝╚██████╗██║  ██╗
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝

        >> Agent Security Enforcement <<"""
A = Annotated[
    str,
    typer.Option(
        "--adapter",
        "-a",
        help=t(
            "适配器 [auto|openclaw|zeroclaw|claude-code|generic]",
            "Adapter [auto|openclaw|zeroclaw|claude-code|generic]",
        ),
    ),
]
F = Annotated[
    str,
    typer.Option(
        "--format",
        "-f",
        help=t(
            "输出格式：text 适合终端阅读，json 适合自动化与 skill，html 适合审计归档",
            "Output format: text for terminal review, json for automation/skills, html for archived review",
        ),
    ),
]

BANNER = "[bold cyan]ClawLock[/bold cyan] [dim]v{ver} | github.com/g1at/clawlock[/dim]"


def _tag(level: str) -> str:
    if level in (CRIT, HIGH):
        return t("高危", "HIGH")
    if level == "medium":
        return t("警告", "WARN")
    return t("信息", "INFO")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Render the brand logo when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        console.print(Text(LOGO, style="bold cyan"))


@app.command(help=t("执行全量安全扫描", "Run the full security scan."))
def scan(
    adapter: A = "auto",
    skills_dir: Annotated[
        Optional[str], typer.Option("--skills-dir", help=t("额外 skills 路径", "Extra skills path"))
    ] = None,
    soul_path: Annotated[
        Optional[str], typer.Option("--soul", help=t("自定义 SOUL.md 路径", "Custom SOUL.md path"))
    ] = None,
    mcp_config: Annotated[
        Optional[str], typer.Option("--mcp-config", help=t("自定义 MCP 配置路径", "Custom MCP config path"))
    ] = None,
    endpoint: Annotated[
        Optional[str], typer.Option("--endpoint", help=t("红队测试的 LLM 接口地址", "LLM endpoint for red team"))
    ] = None,
    no_cve: Annotated[
        bool, typer.Option("--no-cve", help=t("跳过在线 CVE 匹配", "Skip online CVE matching"))
    ] = False,
    no_redteam: Annotated[
        bool, typer.Option("--no-redteam", help=t("跳过红队测试", "Skip red-team checks"))
    ] = False,
    deep: Annotated[
        bool, typer.Option("--deep", help=t("在支持的场景执行更深入检查", "Run deeper checks where supported"))
    ] = False,
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help=t(
                "monitor（仅报告，始终退出 0） | enforce（发现严重/高危时退出码 1，适合 CI）",
                "monitor (report only; exit 0) | enforce (exit 1 on critical/high; recommended for CI)",
            ),
        ),
    ] = "enforce",
    output_format: F = "text",
    output: Annotated[
        Optional[str],
        typer.Option(
            "--output",
            "-o",
            help=t(
                "将报告写入文件（推荐用于 json/html 归档）",
                "Write report to file (recommended for json/html archives)",
            ),
        ),
    ] = None,
):
    """Run the full security scan."""
    rich_text = output_format == "text"
    if rich_text:
        console.print(BANNER.format(ver=__version__))
    spec = get_adapter(adapter)
    ver = get_claw_version(spec)
    if rich_text:
        console.print(
            f"  [dim]{t('适配器', 'Adapter')}: [bold]{spec.display}[/bold]  "
            f"{t('版本', 'Version')}: {ver}  {t('模式', 'Mode')}: {mode}[/dim]\n"
        )

    findings_map = {}

    # Define independent scan tasks
    def _scan_config():
        return scan_config(spec)[0]

    def _scan_skills():
        return scan_all_skills(spec, extra_dir=skills_dir)[0]

    def _scan_soul_mem():
        sf, _ = scan_soul(spec, soul_path=soul_path)
        return sf + scan_memory_files(spec)

    def _scan_cve():
        if no_cve:
            return []
        from .integrations import lookup_cve
        cve_target, skip_reason = resolve_cve_lookup(spec, ver)
        if cve_target:
            return asyncio.run(lookup_cve(cve_target.product, cve_target.version))
        return [Finding("cve", INFO, t("已跳过在线 CVE 匹配", "Skipped online CVE matching"), skip_reason)]

    # Step labels for progress display, mapped to their scan functions
    tasks = [
        (t("配置审计", "Config"), _scan_config),
        (t("进程暴露", "Processes"), lambda: scan_processes(spec)),
        (t("凭证审计", "Credentials"), lambda: scan_credential_dirs(spec)),
        (t("Skill 供应链", "Skills"), _scan_skills),
        (t("提示词与记忆", "Prompt & Memory"), _scan_soul_mem),
        (t("MCP", "MCP"), lambda: scan_mcp(spec, extra_mcp=mcp_config)),
        (t("CVE", "CVEs"), _scan_cve),
    ]

    if rich_text:
        with Progress(
            SpinnerColumn(style="bold cyan"),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(bar_width=26, complete_style="cyan", finished_style="green"),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            ptask = progress.add_task(
                t("正在扫描安全域...", "Scanning security domains..."),
                total=len(tasks),
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as pool:
                futures = {
                    pool.submit(fn): label for label, fn in tasks
                }
                for future in concurrent.futures.as_completed(futures):
                    label = futures[future]
                    try:
                        findings_map[label] = future.result()
                    except Exception:
                        findings_map[label] = []
                    progress.update(
                        ptask,
                        advance=1,
                        description=t(
                            f"已完成 {label}",
                            f"Completed {label}",
                        ),
                    )
    else:
        # Non-interactive text mode and non-text formats run silently.
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures = {
                pool.submit(fn): label for label, fn in tasks
            }
            for future in concurrent.futures.as_completed(futures):
                label = futures[future]
                try:
                    findings_map[label] = future.result()
                except Exception:
                    findings_map[label] = []

    # Ensure consistent ordering in findings_map
    ordered_map = {}
    for label, _ in tasks:
        ordered_map[label] = findings_map.get(label, [])
    findings_map = ordered_map

    # Step 8: Red team (conditional, sequential)
    redteam_f = []
    if not no_redteam and endpoint:
        if rich_text:
            console.print(f"[bold cyan]{t('正在执行红队测试...', 'Running red team...')}[/bold cyan]")
        from .integrations.promptfoo import run_redteam
        redteam_f = run_redteam(endpoint, deep=deep)
    if redteam_f:
        findings_map[t("红队测试", "Red Team")] = redteam_f

    if rich_text:
        console.print()
    render_scan_report(spec.display, ver, findings_map, output_format, output)

    all_f = [f for fs in findings_map.values() for f in fs]
    if mode == "enforce" and any(f.level in (CRIT, HIGH) for f in all_f):
        raise typer.Exit(code=1)


@app.command(help=t("发现本地 Claw 安装", "Discover local Claw installations."))
def discover():
    """Discover local Claw installations."""
    findings = discover_installations()
    for f in findings:
        console.print(f"  {_tag(f.level)} [bold]{f.title}[/bold]")
        if f.detail:
            console.print(f"     [dim]{f.detail}[/dim]")


@app.command(help=t("审计单个 Skill", "Audit one skill."))
def skill(
    path: Annotated[str, typer.Argument(help=t("Skill 目录或 SKILL.md 路径", "Skill directory or SKILL.md path"))],
    adapter: A = "auto",
    check_cloud: Annotated[
        bool, typer.Option("--cloud/--no-cloud", help=t("在可用时检查云端情报", "Check cloud intel if available"))
    ] = True,
    output_format: F = "text",
):
    """Audit one skill."""
    p = Path(path).expanduser()
    if not p.exists():
        console.print(f"[red]{t('路径不存在', 'Path not found')}: {p}[/red]")
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
    render_focus_report(
        title=t("Skill 单体审计", "Skill Audit"),
        subject=f"{skill_name} · {p}",
        findings=findings,
        ok_message=t(
            "当前静态检查范围内未发现高风险问题，可继续结合来源与权限范围评估。",
            "Within the current static checks, no high-risk issues were found. Continue evaluating the source and permission scope.",
        ),
        review_message=t(
            "发现需要确认的行为，建议在核实来源可信且权限合理后再使用。",
            "Review-worthy behavior was found. Use it only after confirming the source is trusted and the permissions make sense.",
        ),
        risk_message=t(
            "发现明确风险，建议暂缓安装并优先核对来源、权限声明与实际行为。",
            "Risk was found. Pause installation and verify the source, declared permissions, and actual behavior first.",
        ),
    )
    if crits:
        raise typer.Exit(1)


@app.command(help=t("在导入前预检新的 Skill", "Precheck a new skill before import."))
def precheck(path: Annotated[str, typer.Argument(help=t("新的 SKILL.md 文件路径", "Path to a new SKILL.md file"))]):
    """Precheck a new skill before import."""
    p = Path(path).expanduser()
    if not p.exists():
        console.print(f"[red]{t('文件不存在', 'File not found')}: {p}[/red]")
        raise typer.Exit(1)
    findings, is_safe = precheck_skill_md(p)
    name = p.parent.name if p.name == "SKILL.md" else p.stem
    render_focus_report(
        title=t("Skill 导入预检", "Skill Precheck"),
        subject=f"{name} · {p}",
        findings=findings,
        ok_message=t(
            "预检通过。仍建议在安装前再跑一次完整的 skill 审计。",
            "Pre-check passed. It is still worth running the full skill audit before installation.",
        ),
        review_message=t(
            "发现需要人工确认的内容，建议核实用途、来源与权限声明后再导入。",
            "Some items need human review. Confirm purpose, source, and declared permissions before importing.",
        ),
        risk_message=t(
            "发现高风险信号，当前不建议直接导入。",
            "High-risk signals were found. Import is not recommended right now.",
        ),
    )
    if not is_safe:
        raise typer.Exit(1)


@app.command(help=t("检查提示词与记忆漂移", "Check prompt and memory drift."))
def soul(
    path: Annotated[Optional[str], typer.Argument(help=t("SOUL.md 路径", "SOUL.md path"))] = None,
    adapter: A = "auto",
    update_baseline: Annotated[
        bool, typer.Option("--update-baseline", help=t("保存新的基线哈希", "Save a new baseline hash"))
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
        console.print(
            Text(
                t(
                    f"提示词基线已更新：{found.name}",
                    f"Prompt baseline updated: {found.name}",
                ),
                style="green",
            )
        )
        return
    if not found and not mem_findings:
        console.print(
            Text(
                t(
                    "未找到 SOUL.md 或 MEMORY.md。",
                    "No SOUL.md or MEMORY.md was found.",
                ),
                style="yellow",
            )
        )
        return
    render_focus_report(
        title=t("提示词与记忆检查", "Prompt & Memory Check"),
        subject=str(found or spec.display),
        findings=all_f,
        ok_message=t(
            "未发现注入或漂移问题。",
            "No injection or drift issue was found.",
        ),
        review_message=t(
            "发现需要关注的改动，请确认是否符合预期。",
            "Changes worth reviewing were found. Confirm that they are expected.",
        ),
        risk_message=t(
            "发现高风险提示词问题，建议优先核查相关文件。",
            "High-risk prompt issues were found. Review the related files first.",
        ),
    )


@app.command(help=t("运行交互式安全加固向导", "Run the interactive hardening wizard."))
def harden(
    adapter: A = "auto",
    auto: Annotated[bool, typer.Option("--auto")] = False,
    auto_fix: Annotated[
        bool,
        typer.Option(
            "--auto-fix", help=t("自动应用安全修复，例如文件权限", "Auto-apply safe fixes such as file permissions")
        ),
    ] = False,
):
    """Run the interactive hardening wizard."""
    run_hardening(get_adapter(adapter).name, auto=auto, auto_fix=auto_fix)


@app.command(help=t("运行 promptfoo 红队测试", "Run promptfoo red-team tests."))
def redteam(
    endpoint: Annotated[str, typer.Argument(help=t("LLM API 接口地址", "LLM API endpoint URL"))],
    purpose: Annotated[
        str, typer.Option("--purpose", help=t("目标系统用途", "Target system purpose"))
    ] = t("Claw 系 AI Agent", "Claw-family AI agent"),
    num_tests: Annotated[
        int, typer.Option("--num-tests", "-n", help=t("测试数量", "Number of tests"))
    ] = 10,
    deep: Annotated[bool, typer.Option("--deep", help=t("使用更深入的测试集", "Use a deeper test set"))] = False,
    save_config: Annotated[
        Optional[str], typer.Option("--save-config", help=t("仅保存配置文件", "Save config only"))
    ] = None,
):
    """Run promptfoo red-team tests."""
    from .integrations.promptfoo import generate_redteam_config_file, run_redteam

    if save_config:
        generate_redteam_config_file(
            Path(save_config), endpoint, purpose, num_tests, deep
        )
        console.print(f"[green]{t('配置已保存', 'Config saved')}: {save_config}[/green]")
        return
    findings = run_redteam(endpoint, purpose=purpose, num_tests=num_tests, deep=deep)
    render_focus_report(
        title=t("红队测试", "Red Team"),
        subject=f"{endpoint} · {purpose}",
        findings=findings,
        ok_message=t(
            "当前测试集中未命中高风险问题。",
            "No high-risk issue was triggered in the current test set.",
        ),
        review_message=t(
            "测试中触发了需要关注的行为，建议结合业务上下文继续复核。",
            "The test run surfaced review-worthy behavior. Inspect it with the system context in mind.",
        ),
        risk_message=t(
            "红队测试已触发高风险行为，建议在继续暴露接口前先修复。",
            "Red-team tests triggered high-risk behavior. Fix it before exposing the endpoint further.",
        ),
    )


@app.command(name="mcp-scan", help=t("深度扫描 MCP 服务端源码", "Deep-scan MCP server source code."))
def mcp_scan(
    code_path: Annotated[str, typer.Argument(help=t("MCP 服务端源码路径", "MCP server source path"))],
    model: Annotated[
        str, typer.Option("--model", help=t("ai-infra-guard 使用的 LLM 模型", "LLM model for ai-infra-guard"))
    ] = "",
    token: Annotated[
        str,
        typer.Option(
            "--token", envvar="OPENAI_API_KEY", help=t("ai-infra-guard 的 API Key", "API key for ai-infra-guard")
        ),
    ] = "",
    base_url: Annotated[
        str, typer.Option("--base-url", help=t("自定义 API Base URL", "Custom API base URL"))
    ] = "",
):
    """Deep-scan MCP server source code."""
    from .integrations import run_mcp_deep_scan

    p = Path(code_path).expanduser()
    console.print(f"[cyan]{t('MCP 深度扫描', 'MCP Deep Scan')}[/cyan]  path={p}")
    findings = run_mcp_deep_scan(p, model, token, base_url)
    for f in findings:
        console.print(f"  {_tag(f.level)} {f.title}")
        if f.detail:
            console.print(f"     [dim]{f.detail}[/dim]")
        if f.location:
            console.print(f"     {t('位置', 'Location')}: {f.location}")
        if f.remediation:
            console.print(f"     {t('修复', 'Fix')}: {f.remediation}")
    if any(f.level in (CRIT, HIGH) for f in findings):
        raise typer.Exit(1)


@app.command(name="agent-scan", help=t("运行 OWASP ASI Agent 扫描", "Run the OWASP ASI agent scan."))
def agent_scan(
    code: Annotated[
        Optional[str], typer.Option("--code", help=t("Agent 源码路径", "Agent source path"))
    ] = None,
    config_file: Annotated[
        Optional[str], typer.Option("--config", help=t("Agent 配置文件路径", "Agent config file path"))
    ] = None,
    model: Annotated[str, typer.Option("--model", help=t("LLM 模型名", "LLM model name"))] = "",
    token: Annotated[
        str, typer.Option("--token", envvar="ANTHROPIC_API_KEY", help=t("LLM API Key", "LLM API key"))
    ] = "",
    base_url: Annotated[
        str, typer.Option("--base-url", help=t("自定义 API Base URL", "Custom API base URL"))
    ] = "",
    llm: Annotated[
        bool,
        typer.Option("--llm/--no-llm", help=t("启用 LLM 辅助语义分析", "Enable LLM-assisted semantic analysis")),
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
        layers.append(t("配置", "Config"))
    if code:
        layers.append(t("代码", "Code"))
    if llm:
        layers.append("LLM")
    console.print(f"[cyan]{t('Agent 扫描 (OWASP ASI 14)', 'Agent-Scan (OWASP ASI 14)')}[/cyan]")
    console.print(
        f"  {t('分析层', 'Layers')}: "
        f"{' + '.join(layers) if layers else t('配置', 'Config')}"
    )

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
            console.print(f"     {t('位置', 'Location')}: {f.location}")
        if f.remediation:
            console.print(f"     {t('修复', 'Fix')}: {f.remediation}")
    if any(f.level in (CRIT, HIGH) for f in findings):
        raise typer.Exit(1)


@app.command(help=t("查看最近的扫描历史", "Show recent scan history."))
def history(
    limit: Annotated[
        int, typer.Option("--limit", "-n", help=t("显示最近 N 条记录", "Show the last N records"))
    ] = 20,
):
    """Show recent scan history."""
    from rich.table import Table

    from .utils import get_scan_history

    records = get_scan_history(limit)
    if not records:
        console.print(
            f"[yellow]{t('暂无扫描历史，请先运行 `clawlock scan`。', 'No scan history yet. Run `clawlock scan` first.')}[/yellow]"
        )
        return
    tbl = Table(title=t("ClawLock 历史记录", "ClawLock History"), show_header=True, header_style="bold cyan")
    tbl.add_column(t("时间", "Time"), min_width=20)
    tbl.add_column(t("适配器", "Adapter"), min_width=10)
    tbl.add_column(t("评分", "Score"), min_width=6, justify="center")
    tbl.add_column(t("高危", "High"), min_width=6, justify="center")
    tbl.add_column(t("警告", "Warn"), min_width=6, justify="center")
    tbl.add_column(t("设备", "Device"), min_width=14)
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
            console.print(f"  [green]{t('评分上升', 'Score up')} {prev} -> {curr}[/green]")
        elif curr < prev:
            console.print(f"  [red]{t('评分下降', 'Score down')} {prev} -> {curr}[/red]")
        else:
            console.print(f"  [dim]-> {t('评分不变', 'Score unchanged')} {curr}[/dim]")


@app.command(help=t("持续监控关键检查项变化", "Watch key checks for changes."))
def watch(
    adapter: A = "auto",
    interval: Annotated[
        int, typer.Option("--interval", "-i", help=t("扫描间隔秒数", "Scan interval in seconds"))
    ] = 300,
    count: Annotated[
        int, typer.Option("--count", "-c", help=t("执行次数（0 表示无限）", "Number of runs (0 = unlimited)"))
    ] = 0,
):
    """Watch key checks for changes."""
    import time

    spec = get_adapter(adapter)
    console.print(
        f"[cyan]{t('ClawLock 监控', 'ClawLock Watch')}[/cyan]  interval={interval}s  adapter={spec.display}"
    )
    console.print(f"[dim]{t('按 Ctrl+C 停止', 'Press Ctrl+C to stop')}[/dim]\n")
    iteration = 0
    try:
        while count == 0 or iteration < count:
            iteration += 1
            now_str = time.strftime("%H:%M:%S")
            console.print(
                f"[bold cyan]"
                f"{t(f'-- 第 {iteration} 轮 ({now_str}) --', f'-- Run {iteration} ({now_str}) --')}"
                f"[/bold cyan]"
            )
            cfg_f, _ = scan_config(spec)
            soul_f, _ = scan_soul(spec)
            mem_f = scan_memory_files(spec)
            proc_f = scan_processes(spec)
            all_f = cfg_f + soul_f + mem_f + proc_f
            crits = [f for f in all_f if f.level in ("critical", "high")]
            warns = [f for f in all_f if f.level == "medium"]
            if crits:
                console.print(
                    f"  [bold red]{len(crits)} {t('项高危变化', 'high-severity change(s) found')}[/bold red]"
                )
                for f in crits[:3]:
                    console.print(f"    {_tag(f.level)} {f.title}: {f.detail[:60]}")
            elif warns:
                console.print(f"  [yellow]{len(warns)} {t('项警告', 'warning(s)')}[/yellow]")
            else:
                console.print(f"  [green]{t('未检测到变化', 'No change detected')}[/green]")
            if count == 0 or iteration < count:
                console.print(f"  [dim]{t('下次运行将在', 'Next run in')} {interval}s[/dim]\n")
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print(f"\n[dim]{t('监控已停止，共执行', 'Watch stopped after')} {iteration} {t('轮。', 'run(s).')}[/dim]")


@app.command(help=t("显示版本信息", "Show version info."))
def version():
    """Show version info."""
    from .integrations import _ext_version
    from .utils import platform_label

    console.print(f"ClawLock v[bold]{__version__}[/bold]")
    console.print("[dim]https://github.com/g1at/clawlock[/dim]")
    console.print(f"[dim]{t('平台', 'Platform')}: {platform_label()}[/dim]")
    console.print(f"[dim]{t('外部扫描器', 'External scanner')}: {_ext_version()}[/dim]")


if __name__ == "__main__":
    app()
