"""ClawLock v2.6.0 CLI - 16 commands."""

import asyncio
import concurrent.futures
import json
import re
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.align import Align
from rich.cells import cell_len
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
from .hardening import run_hardening, rollback_last
from .i18n import t
from .reporters import console, render_focus_report, render_scan_report
from .scanners import (
    CRIT,
    HIGH,
    INFO,
    WARN,
    Finding,
    _scanner_error_finding,
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
        "ClawLock v2.6.0 - 面向 Claw 平台的安全扫描与加固工具",
        "ClawLock v2.6.0 - security scan and hardening for Claw platforms",
    ),
    rich_markup_mode="rich",
    no_args_is_help=False,
)
LOGO = """   ██████╗██╗      █████╗ ██╗    ██╗██╗      ██████╗  ██████╗██╗  ██╗
  ██╔════╝██║     ██╔══██╗██║    ██║██║     ██╔═══██╗██╔════╝██║ ██╔╝
  ██║     ██║     ███████║██║ █╗ ██║██║     ██║   ██║██║     █████╔╝ 
  ██║     ██║     ██╔══██║██║███╗██║██║     ██║   ██║██║     ██╔═██╗ 
  ╚██████╗███████╗██║  ██║╚███╔███╔╝███████╗╚██████╔╝╚██████╗██║  ██╗
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝"""
TAGLINE = ">> Agent Security Enforcement <<"
AUTHOR_ID = "g0at"


def _pad_center(line: str, width: int) -> str:
    diff = max(0, width - cell_len(line))
    left = diff // 2
    right = diff - left
    return (" " * left) + line + (" " * right)


def _footer_block_text() -> Text:
    version_line = f"v{__version__} | by {AUTHOR_ID}"
    width = max(cell_len(TAGLINE), cell_len(version_line))
    text = Text()
    text.append(_pad_center(TAGLINE, width), style="bold cyan")
    text.append("\n")
    text.append(_pad_center(version_line, width), style="dim")
    return text


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

_ADAPTER_CHOICES = ("auto", "openclaw", "zeroclaw", "claude-code", "generic")
_SCAN_FORMAT_CHOICES = ("text", "json", "html")
_FOCUS_FORMAT_CHOICES = ("text", "json")
_MODE_CHOICES = ("monitor", "enforce")


def _validated_choice(value: str, choices: tuple[str, ...], param_hint: str) -> str:
    """Reject misspelled CLI values instead of silently changing behavior."""
    if value not in choices:
        allowed = ", ".join(choices)
        raise typer.BadParameter(
            t(
                f"不支持的值 {value!r}；可选值：{allowed}",
                f"Unsupported value {value!r}; choose one of: {allowed}",
            ),
            param_hint=param_hint,
        )
    return value


def _validated_adapter(value: str) -> str:
    return _validated_choice(value, _ADAPTER_CHOICES, "--adapter")


def _validated_format(value: str, choices: tuple[str, ...] = _SCAN_FORMAT_CHOICES) -> str:
    return _validated_choice(value, choices, "--format")


def _validated_mode(value: str) -> str:
    return _validated_choice(value, _MODE_CHOICES, "--mode")


def _is_scan_error(finding: Finding) -> bool:
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    status = metadata.get("scan_status")
    explicitly_requested_skip = status == "skipped" and metadata.get("requested") is True
    return (
        finding.scanner == "internal"
        or status == "error"
        or explicitly_requested_skip
    )


def _existing_path(
    value: str,
    *,
    param_hint: str,
    file_only: bool = False,
    directory_only: bool = False,
) -> Path:
    """Resolve an explicit input path and fail with Click's usage exit code."""
    path = Path(value).expanduser()
    if not path.exists():
        raise typer.BadParameter(
            t(f"路径不存在：{path}", f"Path does not exist: {path}"),
            param_hint=param_hint,
        )
    if file_only and not path.is_file():
        raise typer.BadParameter(
            t(f"需要文件路径：{path}", f"Expected a file path: {path}"),
            param_hint=param_hint,
        )
    if directory_only and not path.is_dir():
        raise typer.BadParameter(
            t(f"需要目录路径：{path}", f"Expected a directory path: {path}"),
            param_hint=param_hint,
        )
    return path


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
SF = Annotated[
    str,
    typer.Option(
        "--format",
        "-f",
        help=t(
            "输出格式：text 适合终端阅读，json 适合自动化与完整证据保留",
            "Output format: text for terminal review, json for automation and complete evidence",
        ),
    ),
]

BANNER = "[bold cyan]ClawLock[/bold cyan] [dim]v{ver} | github.com/g1at/clawlock[/dim]"


def _tag(level: str) -> str:
    if level in (CRIT, HIGH):
        return t("高危", "HIGH")
    if level == WARN:
        return t("警告", "WARN")
    return t("信息", "INFO")


def _finding_fingerprint(finding: Finding) -> tuple[str, ...]:
    """Stable identity for comparing findings across watch iterations."""
    return (
        finding.scanner,
        finding.level,
        finding.title,
        finding.detail,
        finding.location,
        finding.remediation,
    )


def _diff_findings(
    previous: list[Finding], current: list[Finding]
) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """Return (new, persistent, resolved) findings in stable display order."""
    previous_by_id = {_finding_fingerprint(finding): finding for finding in previous}
    current_by_id = {_finding_fingerprint(finding): finding for finding in current}
    new = [
        finding
        for identity, finding in current_by_id.items()
        if identity not in previous_by_id
    ]
    persistent = [
        finding
        for identity, finding in current_by_id.items()
        if identity in previous_by_id
    ]
    resolved = [
        finding
        for identity, finding in previous_by_id.items()
        if identity not in current_by_id
    ]
    return new, persistent, resolved


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Render the brand logo when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        console.print(Align.center(Text(LOGO, style="bold cyan")))
        console.print()
        console.print(Align.center(_footer_block_text()))


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
    ] = "monitor",
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
    adapter = _validated_adapter(adapter)
    mode = _validated_mode(mode)
    output_format = _validated_format(output_format)
    if skills_dir is not None:
        skills_dir = str(
            _existing_path(
                skills_dir,
                param_hint="--skills-dir",
                directory_only=True,
            )
        )
    if soul_path is not None:
        soul_path = str(
            _existing_path(soul_path, param_hint="--soul", file_only=True)
        )
    if mcp_config is not None:
        mcp_config = str(
            _existing_path(
                mcp_config,
                param_hint="--mcp-config",
                file_only=True,
            )
        )
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

    def _scan_agent_security():
        from .adapters import load_config
        from .integrations import run_agent_scan

        agent_config, _ = load_config(spec)
        return run_agent_scan(
            config=agent_config or None,
            enable_llm=False,
            adapter_name=spec.name,
        )

    # Step labels for progress display, mapped to their scan functions
    tasks = [
        (t("配置审计", "Config"), _scan_config),
        (t("进程暴露", "Processes"), lambda: scan_processes(spec)),
        (t("凭证审计", "Credentials"), lambda: scan_credential_dirs(spec)),
        (t("Skill 供应链", "Skills"), _scan_skills),
        (t("提示词与记忆", "Prompt & Memory"), _scan_soul_mem),
        (t("MCP", "MCP"), lambda: scan_mcp(spec, extra_mcp=mcp_config)),
        (t("CVE", "CVEs"), _scan_cve),
        (t("Agent 安全", "Agent Security"), _scan_agent_security),
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
                    except Exception as exc:
                        findings_map[label] = [_scanner_error_finding(label, exc)]
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
                except Exception as exc:
                    findings_map[label] = [_scanner_error_finding(label, exc)]

    # Ensure consistent ordering in findings_map
    ordered_map = {}
    for label, _ in tasks:
        ordered_map[label] = findings_map.get(label, [])
    findings_map = ordered_map

    # Optional red-team stage after the core scan domains
    redteam_f = []
    if not no_redteam and endpoint:
        if rich_text:
            console.print(f"[bold cyan]{t('正在执行红队测试...', 'Running red team...')}[/bold cyan]")
        from .integrations.promptfoo import run_redteam
        try:
            redteam_f = run_redteam(endpoint, deep=deep)
        except Exception as exc:
            redteam_f = [
                _scanner_error_finding(t("红队测试", "Red Team"), exc)
            ]
    if redteam_f:
        findings_map[t("红队测试", "Red Team")] = redteam_f

    if rich_text:
        console.print()
    render_scan_report(spec.display, ver, findings_map, output_format, output)

    all_f = [f for fs in findings_map.values() for f in fs]
    if mode == "enforce":
        if any(_is_scan_error(f) for f in all_f):
            raise typer.Exit(code=2)
        if any(f.level in (CRIT, HIGH) for f in all_f):
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
    output_format: SF = "text",
):
    """Audit one skill."""
    _validated_adapter(adapter)
    output_format = _validated_format(output_format, _FOCUS_FORMAT_CHOICES)
    p = _existing_path(path, param_hint="PATH")
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
                    {
                        "scanner": f.scanner,
                        "level": f.level,
                        "title": f.title,
                        "detail": f.detail,
                        "location": f.location,
                        "snippet": f.snippet,
                        "remediation": f.remediation,
                        "metadata": f.metadata or {},
                    }
                    for f in findings
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
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
    # A standalone skill audit must not report success when the scanner could
    # only inspect part of the package (for example, because a file was
    # unreadable or a traversal budget was exhausted).
    if any(_is_scan_error(f) for f in findings):
        raise typer.Exit(2)
    crits = [f for f in findings if f.level in (CRIT, HIGH)]
    if crits:
        raise typer.Exit(1)


@app.command(help=t("在导入前预检新的 Skill", "Precheck a new skill before import."))
def precheck(path: Annotated[str, typer.Argument(help=t("新的 SKILL.md 文件路径", "Path to a new SKILL.md file"))]):
    """Precheck a new skill before import."""
    p = _existing_path(path, param_hint="PATH", file_only=True)
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
    adapter = _validated_adapter(adapter)
    if path is not None:
        path = str(_existing_path(path, param_hint="PATH", file_only=True))
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
    from_scan: Annotated[
        bool,
        typer.Option(
            "--from-scan", help=t("仅展示与最近扫描发现相关的加固措施", "Show only measures relevant to the latest scan findings")
        ),
    ] = False,
    verify: Annotated[
        bool,
        typer.Option(
            "--verify", help=t("修复后自动验证", "Run verification scan after fixes")
        ),
    ] = False,
    do_rollback: Annotated[
        bool,
        typer.Option(
            "--rollback", help=t("回滚上一次自动修复", "Rollback the last auto-fix action")
        ),
    ] = False,
):
    """Run the interactive hardening wizard."""
    adapter = _validated_adapter(adapter)
    if do_rollback:
        n = rollback_last(1)
        if n:
            console.print(f"[green]{t('已还原', 'Restored')} {n} {t('个文件', 'file(s)')}[/green]")
        else:
            console.print(f"[yellow]{t('没有可回滚的操作。', 'No actions to rollback.')}[/yellow]")
        return
    scan_findings = None
    if from_scan:
        from .utils import get_scan_history
        history = get_scan_history(1)
        if history and "findings" in history[-1]:
            scan_findings = history[-1]["findings"]
        else:
            scan_findings = []
    run_hardening(
        get_adapter(adapter).name,
        auto=auto,
        auto_fix=auto_fix,
        from_scan=scan_findings if from_scan else None,
        verify=verify,
    )


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

    if num_tests <= 0:
        raise typer.BadParameter(
            t("测试数量必须大于 0", "Number of tests must be greater than 0"),
            param_hint="--num-tests",
        )
    if save_config:
        generate_redteam_config_file(
            Path(save_config), endpoint, purpose, num_tests, deep
        )
        console.print(f"[green]{t('配置已保存', 'Config saved')}: {save_config}[/green]")
        return
    findings = run_redteam(endpoint, purpose=purpose, num_tests=num_tests, deep=deep)
    incomplete = any(_is_scan_error(f) for f in findings)
    render_focus_report(
        title=t("红队测试", "Red Team"),
        subject=f"{endpoint} · {purpose}",
        findings=findings,
        ok_message=t(
            "当前测试集中未命中高风险问题。",
            "No high-risk issue was triggered in the current test set.",
        ),
        review_message=(
            t(
                "红队测试未完整执行，当前结果不能用于判断目标是否通过。请先处理报告中的诊断信息后重试。",
                "The red-team run did not complete, so this result cannot establish that the target passed. Resolve the reported diagnostic and retry.",
            )
            if incomplete
            else t(
                "测试中触发了需要关注的行为，建议结合业务上下文继续复核。",
                "The test run surfaced review-worthy behavior. Inspect it with the system context in mind.",
            )
        ),
        risk_message=t(
            "红队测试已触发高风险行为，建议在继续暴露接口前先修复。",
            "Red-team tests triggered high-risk behavior. Fix it before exposing the endpoint further.",
        ),
    )
    if incomplete:
        raise typer.Exit(2)


@app.command(name="mcp-scan", help=t("深度扫描 MCP 服务端源码", "Deep-scan MCP server source code."))
def mcp_scan(
    code_path: Annotated[str, typer.Argument(help=t("MCP 服务端源码路径", "MCP server source path"))],
    no_pkg_check: Annotated[
        bool,
        typer.Option(
            "--no-pkg-check",
            help=t(
                "跳过包名存在性检查（npm / PyPI 注册表探测）",
                "Skip the npm / PyPI registry existence probe",
            ),
        ),
    ] = False,
):
    """Deep-scan MCP server source code."""
    from .integrations import run_mcp_deep_scan
    import os as _os

    p = _existing_path(code_path, param_hint="CODE_PATH")
    if no_pkg_check:
        _os.environ["CLAWLOCK_NO_PKG_CHECK"] = "1"
    console.print(f"[cyan]{t('MCP 深度扫描', 'MCP Deep Scan')}[/cyan]  path={p}")
    try:
        findings = run_mcp_deep_scan(p)
    except Exception as exc:
        findings = [_scanner_error_finding(t("MCP 深度扫描", "MCP Deep Scan"), exc)]
    for f in findings:
        console.print(f"  {_tag(f.level)} {f.title}")
        if f.detail:
            console.print(f"     [dim]{f.detail}[/dim]")
        if f.location:
            console.print(f"     {t('位置', 'Location')}: {f.location}")
        if f.remediation:
            console.print(f"     {t('修复', 'Fix')}: {f.remediation}")
    if any(_is_scan_error(f) for f in findings):
        raise typer.Exit(2)
    if any(f.level in (CRIT, HIGH) for f in findings):
        raise typer.Exit(1)


@app.command(
    name="mcp-live",
    help=t(
        "经明确授权连接 MCP，采集真实工具清单并检测 rug-pull 漂移",
        "Collect a consented live MCP inventory and detect rug-pull drift.",
    ),
)
def mcp_live(
    config_path: Annotated[
        str,
        typer.Argument(help=t("MCP JSON 配置路径", "Path to an MCP JSON config")),
    ],
    server_name: Annotated[
        Optional[str],
        typer.Option("--server", help=t("要探测的 Server 名称", "Server name to probe")),
    ] = None,
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help=t(
                "允许启动配置中的本地 stdio Server",
                "Explicitly allow starting the configured local stdio server",
            ),
        ),
    ] = False,
    allow_remote: Annotated[
        bool,
        typer.Option(
            "--allow-remote",
            help=t(
                "允许向非本机 HTTP(S) Server 发起 live 探测",
                "Explicitly allow probing a non-loopback HTTP(S) server",
            ),
        ),
    ] = False,
    allow_unpinned: Annotated[
        bool,
        typer.Option(
            "--allow-unpinned",
            help=t(
                "即使启动包未固定版本也允许执行（高风险）",
                "Allow execution even when the launch package is unpinned (high risk)",
            ),
        ),
    ] = False,
    snapshot: Annotated[
        Optional[str],
        typer.Option(
            "--snapshot",
            help=t(
                "可信清单快照路径；已有快照会用于漂移对比",
                "Trusted inventory snapshot path; existing snapshots are compared",
            ),
        ),
    ] = None,
    trust_snapshot: Annotated[
        bool,
        typer.Option(
            "--trust-snapshot",
            help=t(
                "经人工审查后显式写入/更新可信快照",
                "Explicitly write/update the trusted snapshot after human review",
            ),
        ),
    ] = False,
    output_format: SF = "text",
):
    """Probe one MCP server without auto-installing or invoking its tools."""
    import os as _os

    from .scanners.mcp_runtime import (
        RuntimeIssue,
        audit_server_config,
        diff_inventory,
        load_trusted_snapshot,
        probe_http_server,
        probe_stdio_server,
        save_trusted_snapshot,
    )

    output_format = _validated_format(output_format, _FOCUS_FORMAT_CHOICES)
    cfg_path = _existing_path(config_path, param_hint="CONFIG_PATH", file_only=True)
    try:
        config = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(
            t(f"无法读取有效的 MCP JSON：{exc}", f"Could not read valid MCP JSON: {exc}"),
            param_hint="CONFIG_PATH",
        ) from exc
    if not isinstance(config, dict):
        raise typer.BadParameter(
            t("MCP 配置顶层必须是对象", "MCP config must contain a top-level object"),
            param_hint="CONFIG_PATH",
        )
    servers = config.get("mcpServers", config.get("servers", {}))
    if not isinstance(servers, dict) or not servers:
        raise typer.BadParameter(
            t("配置中没有有效的 mcpServers", "Config has no valid mcpServers object"),
            param_hint="CONFIG_PATH",
        )
    if server_name is None:
        if len(servers) != 1:
            raise typer.BadParameter(
                t(
                    "配置包含多个 Server，请用 --server 明确选择",
                    "Config contains multiple servers; select one with --server",
                ),
                param_hint="--server",
            )
        server_name = str(next(iter(servers)))
    if server_name not in servers:
        raise typer.BadParameter(
            t(f"找不到 MCP Server：{server_name}", f"MCP server not found: {server_name}"),
            param_hint="--server",
        )
    server = servers[server_name]
    if not isinstance(server, dict):
        raise typer.BadParameter(
            t("所选 Server 配置必须是对象", "Selected server entry must be an object"),
            param_hint="--server",
        )

    def to_finding(issue: RuntimeIssue) -> Finding:
        metadata = {
            "rule_id": issue.rule_id,
            "component": "mcp_live",
            "server": server_name,
            "evidence": issue.evidence,
        }
        if isinstance(issue.evidence, dict) and issue.evidence.get("scan_status"):
            metadata["scan_status"] = issue.evidence["scan_status"]
        return Finding(
            "mcp_live",
            issue.level,
            f"[{issue.rule_id}] {issue.title}",
            issue.detail,
            issue.location,
            remediation=issue.remediation,
            metadata=metadata,
        )

    static_issues = audit_server_config(
        server_name,
        server,
        location=f"{cfg_path.name}:mcpServers",
    )
    url = server.get("url") or server.get("endpoint")
    if isinstance(url, str) and url:
        raw_headers = server.get("headers", {})
        headers = {}
        missing_env = []
        if isinstance(raw_headers, dict):
            env_pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
            for key, value in raw_headers.items():
                value_text = str(value)

                def replace_env(match):
                    name = match.group(1)
                    resolved = _os.environ.get(name)
                    if resolved is None:
                        missing_env.append(name)
                        return match.group(0)
                    return resolved

                headers[str(key)] = env_pattern.sub(replace_env, value_text)
        probe = asyncio.run(
            probe_http_server(
                server_name,
                url,
                headers=headers,
                allow_remote=allow_remote,
            )
        )
        for name in sorted(set(missing_env)):
            static_issues.append(
                RuntimeIssue(
                    "MCP-LIVE-ENV-MISSING",
                    WARN,
                    t("MCP live 授权变量缺失", "MCP live authorization variable is missing"),
                    t(f"环境变量 {name} 未设置。", f"Environment variable {name} is not set."),
                    f"{cfg_path.name}:mcpServers.{server_name}.headers",
                    evidence={"scan_status": "incomplete"},
                )
            )
            probe.status = "incomplete"
    else:
        command = server.get("command", "")
        args = server.get("args", [])
        env = server.get("env", {})
        probe = asyncio.run(
            probe_stdio_server(
                server_name,
                str(command),
                [str(value) for value in args] if isinstance(args, list) else [],
                env=env if isinstance(env, dict) else {},
                allow_execute=execute,
                allow_unpinned=allow_unpinned,
            )
        )

    runtime_issues = [*static_issues, *probe.issues]
    snapshot_path = Path(snapshot).expanduser() if snapshot else None
    signing_value = _os.environ.get("CLAWLOCK_SNAPSHOT_KEY", "")
    signing_key = signing_value.encode("utf-8") if signing_value else None
    if snapshot_path is not None and signing_key is None:
        runtime_issues.append(
            RuntimeIssue(
                "MCP-SNAPSHOT-UNSIGNED",
                WARN,
                t("MCP 快照未绑定独立签名密钥", "MCP snapshot has no independent signing key"),
                t(
                    "文件权限和内部指纹只能发现意外损坏，不能抵抗同权限篡改。可设置 CLAWLOCK_SNAPSHOT_KEY 启用 HMAC。",
                    "File permissions and the internal fingerprint detect accidental corruption, not same-user tampering. Set CLAWLOCK_SNAPSHOT_KEY to enable HMAC.",
                ),
                str(snapshot_path),
            )
        )
    if snapshot_path is not None and probe.inventory is not None:
        if snapshot_path.exists() and not trust_snapshot:
            try:
                trusted = load_trusted_snapshot(snapshot_path, signing_key=signing_key)
                runtime_issues.extend(diff_inventory(trusted, probe.inventory))
            except Exception as exc:
                runtime_issues.append(
                    RuntimeIssue(
                        "MCP-SNAPSHOT-INVALID",
                        WARN,
                        t("MCP 可信快照无效", "MCP trusted snapshot is invalid"),
                        f"{type(exc).__name__}: {exc}",
                        str(snapshot_path),
                        evidence={"scan_status": "error"},
                    )
                )
                probe.status = "incomplete"
        elif trust_snapshot:
            save_trusted_snapshot(
                probe.inventory,
                snapshot_path,
                trust=True,
                signing_key=signing_key,
            )
            runtime_issues.append(
                RuntimeIssue(
                    "MCP-SNAPSHOT-TRUSTED",
                    INFO,
                    t("MCP 可信快照已写入", "MCP trusted snapshot saved"),
                    t(
                        "该清单由显式信任操作写入；后续扫描将检测变化。",
                        "The inventory was explicitly trusted; later scans can detect drift.",
                    ),
                    str(snapshot_path),
                )
            )
        else:
            runtime_issues.append(
                RuntimeIssue(
                    "MCP-SNAPSHOT-MISSING",
                    WARN,
                    t("尚无 MCP 可信快照", "No trusted MCP snapshot exists"),
                    t(
                        "当前清单可以审查，但尚不能检测安装后的 rug-pull 变化。",
                        "The current inventory can be reviewed, but post-install rug-pull drift cannot yet be detected.",
                    ),
                    str(snapshot_path),
                    evidence={"scan_status": "incomplete"},
                )
            )
            probe.status = "incomplete"

    findings = [to_finding(issue) for issue in runtime_issues]
    if probe.inventory is not None:
        findings.insert(
            0,
            Finding(
                "mcp_live",
                INFO,
                t(
                    f"MCP live 清单：{len(probe.inventory.tools)} tools / "
                    f"{len(probe.inventory.prompts)} prompts / {len(probe.inventory.resources)} resources",
                    f"MCP live inventory: {len(probe.inventory.tools)} tools / "
                    f"{len(probe.inventory.prompts)} prompts / {len(probe.inventory.resources)} resources",
                ),
                t(
                    f"协议 {probe.inventory.protocol_version}，指纹 {probe.inventory.fingerprint[:16]}…",
                    f"Protocol {probe.inventory.protocol_version}; fingerprint {probe.inventory.fingerprint[:16]}…",
                ),
                metadata={
                    "component": "mcp_live",
                    "server": server_name,
                    "inventory_fingerprint": probe.inventory.fingerprint,
                    "tools": [tool.name for tool in probe.inventory.tools],
                },
            ),
        )
    if probe.status != "complete":
        findings.append(
            Finding(
                "internal",
                WARN,
                t("MCP live 扫描不完整", "MCP live scan incomplete"),
                probe.error or t("部分协议面未完成采集。", "Part of the protocol surface was not collected."),
                str(cfg_path),
                metadata={
                    "scan_status": "error",
                    "component": "mcp_live",
                    "probe_status": probe.status,
                },
            )
        )

    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "status": probe.status,
                    "inventory": probe.inventory.canonical() if probe.inventory else None,
                    "fingerprint": probe.inventory.fingerprint if probe.inventory else None,
                    "findings": [
                        {
                            "scanner": finding.scanner,
                            "level": finding.level,
                            "title": finding.title,
                            "detail": finding.detail,
                            "location": finding.location,
                            "remediation": finding.remediation,
                            "metadata": finding.metadata,
                        }
                        for finding in findings
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        render_focus_report(
            title=t("MCP Live 审计", "MCP Live Audit"),
            subject=f"{server_name} · {cfg_path}",
            findings=findings,
            ok_message=t("实时清单采集完成，未发现高风险变化。", "Live inventory completed with no high-risk drift."),
            review_message=t("实时清单中有需要复核的配置或协议信号。", "The live inventory contains configuration or protocol signals to review."),
            risk_message=t("实时 MCP 清单中发现高风险启动、投毒或漂移。", "The live MCP inventory contains high-risk launch, poisoning, or drift findings."),
        )
    if probe.status != "complete" or any(_is_scan_error(finding) for finding in findings):
        raise typer.Exit(2)
    if any(finding.level in (CRIT, HIGH) for finding in findings):
        raise typer.Exit(1)


@app.command(
    name="supply-chain",
    help=t(
        "结构化审计依赖、安装脚本、SBOM、外部指令和 SLSA 来源证明",
        "Audit dependencies, install scripts, SBOMs, external instructions, and SLSA provenance.",
    ),
)
def supply_chain(
    path: Annotated[str, typer.Argument(help=t("包或项目路径", "Package or project path"))],
    osv: Annotated[
        bool,
        typer.Option(
            "--osv",
            help=t(
                "调用已安装的 OSV-Scanner；不会自动下载",
                "Run an installed OSV-Scanner; never auto-download it",
            ),
        ),
    ] = False,
    gitleaks: Annotated[
        bool,
        typer.Option(
            "--gitleaks",
            help=t(
                "调用已安装的 Gitleaks；不会自动下载",
                "Run an installed Gitleaks; never auto-download it",
            ),
        ),
    ] = False,
    provenance: Annotated[
        Optional[str],
        typer.Option(
            "--provenance",
            help=t("in-toto/SLSA JSON 或 DSSE 文件", "in-toto/SLSA JSON or DSSE file"),
        ),
    ] = None,
    expected_digest: Annotated[
        str,
        typer.Option("--expected-digest", help=t("预期制品 SHA-256", "Expected artifact SHA-256")),
    ] = "",
    expected_builder: Annotated[
        str,
        typer.Option("--expected-builder", help=t("预期 builder.id", "Expected builder.id")),
    ] = "",
    expected_source: Annotated[
        str,
        typer.Option("--expected-source", help=t("预期源码 URI", "Expected source URI")),
    ] = "",
    expected_subject: Annotated[
        str,
        typer.Option("--expected-subject", help=t("预期 subject 名称", "Expected subject name")),
    ] = "",
    output_format: SF = "text",
):
    """Run the offline inventory and explicitly requested external adapters."""
    from .scanners.supply_chain import (
        run_gitleaks,
        run_osv_scanner,
        scan_supply_chain,
        validate_slsa_provenance,
    )

    output_format = _validated_format(output_format, _FOCUS_FORMAT_CHOICES)
    target = _existing_path(path, param_hint="PATH")
    if provenance is not None:
        provenance_path = _existing_path(
            provenance, param_hint="--provenance", file_only=True
        )
    else:
        provenance_path = None

    report = scan_supply_chain(target)
    findings: list[Finding] = []
    for issue in report.issues:
        findings.append(
            Finding(
                "supply_chain",
                issue.severity,
                f"[{issue.rule_id}] {issue.title}",
                issue.detail,
                issue.location,
                issue.evidence,
                remediation=t(
                    "固定版本/摘要并审查安装期执行。",
                    "Pin versions/digests and review install-time execution.",
                ),
                metadata={
                    "rule_id": issue.rule_id,
                    "component": "supply_chain",
                    "confidence_score": issue.confidence,
                    **dict(issue.metadata),
                },
            )
        )
    if not report.complete:
        findings.append(
            Finding(
                "internal",
                WARN,
                t("供应链清单不完整", "Supply-chain inventory incomplete"),
                "; ".join(report.diagnostics[:20]),
                str(target),
                metadata={"scan_status": "error", "component": "supply_chain"},
            )
        )

    external_results = []
    if osv:
        external_results.append(run_osv_scanner(target))
    if gitleaks:
        external_results.append(run_gitleaks(target))
    for external in external_results:
        for item in external.findings:
            findings.append(
                Finding(
                    external.tool,
                    item.severity,
                    f"[{item.rule_id}] {item.title}",
                    item.detail,
                    item.location,
                    metadata={
                        "rule_id": item.rule_id,
                        "component": external.tool,
                        **dict(item.metadata),
                    },
                )
            )
        if not external.complete:
            findings.append(
                Finding(
                    "internal",
                    WARN,
                    t(
                        f"{external.tool} 检查未完成",
                        f"{external.tool} check did not complete",
                    ),
                    "; ".join(external.diagnostics[:10]),
                    str(target),
                    metadata={
                        "scan_status": "skipped" if not external.available else "error",
                        "requested": True,
                        "component": external.tool,
                        "tool_status": external.status,
                    },
                )
            )

    provenance_result = None
    if provenance_path is not None:
        provenance_result = validate_slsa_provenance(
            provenance_path,
            expected_digest=expected_digest,
            expected_builder=expected_builder,
            expected_source=expected_source,
            expected_subject=expected_subject,
        )
        for issue in provenance_result.issues:
            level = HIGH if issue.severity == "error" else WARN
            findings.append(
                Finding(
                    "slsa",
                    level,
                    f"[{issue.code}] "
                    + t("SLSA 来源证明检查", "SLSA provenance check"),
                    issue.detail,
                    str(provenance_path),
                    remediation=t(
                        "核对 subject 摘要、builder、源码，并使用可信密钥策略验证 DSSE 签名。",
                        "Verify subject digest, builder, source, and DSSE signatures against a trusted key policy.",
                    ),
                    metadata={
                        "rule_id": issue.code,
                        "component": "slsa",
                        "signature_present": provenance_result.signature_present,
                        "signature_verified": provenance_result.signature_verified,
                        "trusted": provenance_result.trusted,
                    },
                )
            )
        if not provenance_result.complete:
            findings.append(
                Finding(
                    "internal",
                    WARN,
                    t("SLSA 来源证明分析不完整", "SLSA provenance analysis incomplete"),
                    t("来源证明无法完整解析。", "The provenance statement could not be fully parsed."),
                    str(provenance_path),
                    metadata={"scan_status": "error", "component": "slsa"},
                )
            )

    summary = Finding(
        "supply_chain",
        INFO,
        t(
            f"供应链清单：{len(report.dependencies)} 依赖 / {len(report.lockfiles)} lockfiles / {len(report.sboms)} SBOM",
            f"Supply-chain inventory: {len(report.dependencies)} dependencies / {len(report.lockfiles)} lockfiles / {len(report.sboms)} SBOMs",
        ),
        t(
            f"发现 {len(report.scripts)} 个脚本和 {len(report.build_backends)} 个构建后端。",
            f"Found {len(report.scripts)} scripts and {len(report.build_backends)} build backends.",
        ),
        str(target),
        metadata={
            "component": "supply_chain",
            "manifests": report.manifests,
            "lockfiles": report.lockfiles,
            "sboms": report.sboms,
        },
    )
    findings.insert(0, summary)

    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "complete": not any(_is_scan_error(finding) for finding in findings),
                    "inventory": {
                        "dependencies": [
                            {
                                "ecosystem": dep.ecosystem,
                                "name": dep.name,
                                "spec": dep.spec,
                                "source": dep.source,
                                "kind": dep.kind,
                                "pinned": dep.pinned,
                                "mutable": dep.mutable,
                                "hashes": list(dep.hashes),
                            }
                            for dep in report.dependencies
                        ],
                        "lockfiles": report.lockfiles,
                        "sboms": report.sboms,
                    },
                    "provenance": (
                        {
                            "valid": provenance_result.valid,
                            "complete": provenance_result.complete,
                            "trusted": provenance_result.trusted,
                            "signature_present": provenance_result.signature_present,
                            "signature_verified": provenance_result.signature_verified,
                            "matched": dict(provenance_result.matched),
                        }
                        if provenance_result
                        else None
                    ),
                    "findings": [
                        {
                            "scanner": finding.scanner,
                            "level": finding.level,
                            "title": finding.title,
                            "detail": finding.detail,
                            "location": finding.location,
                            "remediation": finding.remediation,
                            "metadata": finding.metadata,
                        }
                        for finding in findings
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        render_focus_report(
            title=t("供应链与来源证明", "Supply Chain & Provenance"),
            subject=str(target),
            findings=findings,
            ok_message=t("供应链结构化检查完成。", "Structured supply-chain checks completed."),
            review_message=t("发现需要复核的依赖、脚本或来源证明。", "Dependencies, scripts, or provenance need review."),
            risk_message=t("发现高风险供应链或来源证明不匹配。", "High-risk supply-chain or provenance mismatches were found."),
        )
    if any(_is_scan_error(finding) for finding in findings):
        raise typer.Exit(2)
    if any(finding.level in (CRIT, HIGH) for finding in findings):
        raise typer.Exit(1)


@app.command(
    name="runtime-scan",
    help=t(
        "审计 Dockerfile、Compose 与 Kubernetes 运行时隔离",
        "Audit Dockerfile, Compose, and Kubernetes runtime isolation.",
    ),
)
def runtime_scan(
    path: Annotated[
        str,
        typer.Argument(help=t("部署文件或项目目录", "Deployment file or project directory")),
    ],
    output_format: SF = "text",
):
    """Run a bounded, fail-closed static audit of deployment manifests."""
    from .scanners.runtime_security import audit_runtime_security

    output_format = _validated_format(output_format, _FOCUS_FORMAT_CHOICES)
    target = _existing_path(path, param_hint="PATH")
    try:
        report = audit_runtime_security(target, require_candidates=True)
        findings = []
        for issue in report.issues:
            kwargs = issue.as_finding_kwargs()
            kwargs["title"] = f"[{issue.rule_id}] {issue.title}"
            findings.append(Finding(**kwargs))
    except Exception as exc:
        report = None
        findings = [
            _scanner_error_finding(
                t("运行时部署审计", "Runtime deployment audit"), exc
            )
        ]

    findings.insert(
        0,
        Finding(
            "runtime_security",
            INFO,
            t(
                f"已检查 {len(report.inspected_files) if report else 0} 个运行时文件",
                f"Inspected {len(report.inspected_files) if report else 0} runtime files",
            ),
            t(
                f"状态：{report.status if report else 'INCOMPLETE'}",
                f"Status: {report.status if report else 'INCOMPLETE'}",
            ),
            str(target),
            metadata={
                "component": "runtime_security",
                "status": report.status if report else "INCOMPLETE",
                "inspected_files": report.inspected_files if report else [],
                "documents": report.documents if report else 0,
                "bytes_read": report.bytes_read if report else 0,
            },
        ),
    )
    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "status": report.status if report else "INCOMPLETE",
                    "inspected_files": report.inspected_files if report else [],
                    "documents": report.documents if report else 0,
                    "bytes_read": report.bytes_read if report else 0,
                    "diagnostics": report.diagnostics if report else [],
                    "findings": [
                        {
                            "scanner": finding.scanner,
                            "level": finding.level,
                            "title": finding.title,
                            "detail": finding.detail,
                            "location": finding.location,
                            "snippet": finding.snippet,
                            "metadata": finding.metadata,
                        }
                        for finding in findings
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        render_focus_report(
            title=t("运行时部署安全审计", "Runtime Deployment Security Audit"),
            subject=str(target),
            findings=findings,
            ok_message=t(
                "运行时配置未发现高风险隔离绕过。",
                "No high-risk runtime isolation bypass was found.",
            ),
            review_message=t(
                "运行时配置存在需要复核或加固的项目。",
                "Runtime configuration has review or hardening items.",
            ),
            risk_message=t(
                "发现高风险运行时隔离绕过。",
                "High-risk runtime isolation bypasses were found.",
            ),
        )
    if report is None or not report.complete or any(
        _is_scan_error(finding) for finding in findings
    ):
        raise typer.Exit(2)
    if any(finding.level in (CRIT, HIGH) for finding in findings):
        raise typer.Exit(1)


@app.command(
    name="dynamic-scan",
    help=t(
        "在固定镜像的只读容器中执行隔离行为分析",
        "Run isolated behavioral analysis in a pinned, read-only container.",
    ),
)
def dynamic_scan(
    path: Annotated[str, typer.Argument(help=t("待分析 Skill/源码路径", "Skill/source path to analyze"))],
    image: Annotated[
        str,
        typer.Option(
            "--image",
            help=t(
                "分析器镜像，必须固定为 name@sha256:<digest>",
                "Analyzer image pinned as name@sha256:<digest>",
            ),
        ),
    ],
    entrypoint_json: Annotated[
        str,
        typer.Option(
            "--entrypoint-json",
            help=t(
                "容器内分析命令的 JSON argv 数组",
                "JSON argv array for the analyzer command inside the container",
            ),
        ),
    ],
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help=t("明确允许隔离动态执行", "Explicitly allow isolated dynamic execution"),
        ),
    ] = False,
    engine: Annotated[
        str,
        typer.Option("--engine", help=t("docker 或 podman", "docker or podman")),
    ] = "",
    network: Annotated[
        str,
        typer.Option(
            "--network",
            help=t(
                "none 或预先创建的隔离网络名；禁止 host",
                "none or a pre-created isolated network; host is forbidden",
            ),
        ),
    ] = "none",
    timeout: Annotated[
        float,
        typer.Option("--timeout", help=t("最大执行秒数", "Maximum execution seconds")),
    ] = 30.0,
    output_format: SF = "text",
):
    """Execute only through Docker/Podman; there is no host fallback."""
    from .scanners.dynamic import SandboxPolicy, run_dynamic_analysis

    output_format = _validated_format(output_format, _FOCUS_FORMAT_CHOICES)
    target = _existing_path(path, param_hint="PATH")
    try:
        entrypoint = json.loads(entrypoint_json)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(
            t(f"entrypoint JSON 无效：{exc}", f"Invalid entrypoint JSON: {exc}"),
            param_hint="--entrypoint-json",
        ) from exc
    if not isinstance(entrypoint, list) or not entrypoint or not all(
        isinstance(value, str) and value for value in entrypoint
    ):
        raise typer.BadParameter(
            t("entrypoint 必须是非空字符串数组", "Entrypoint must be a non-empty string array"),
            param_hint="--entrypoint-json",
        )
    try:
        policy = SandboxPolicy(timeout_seconds=timeout, network=network)
        result = run_dynamic_analysis(
            target,
            image,
            entrypoint,
            policy=policy,
            engine=engine,
            allow_execute=execute,
        )
    except Exception as exc:
        result = None
        findings = [_scanner_error_finding(t("动态隔离分析", "Dynamic sandbox analysis"), exc)]
    else:
        findings = [
            Finding(
                "dynamic",
                issue.level,
                f"[{issue.rule_id}] {issue.title}",
                issue.detail,
                issue.location,
                remediation=issue.remediation,
                metadata={
                    "rule_id": issue.rule_id,
                    "component": "dynamic",
                    "evidence": issue.evidence,
                    **(
                        {"scan_status": issue.evidence["scan_status"]}
                        if issue.evidence.get("scan_status")
                        else {}
                    ),
                },
            )
            for issue in result.issues
        ]
        findings.insert(
            0,
            Finding(
                "dynamic",
                INFO,
                t(
                    f"动态事件：{len(result.events)}，状态：{result.status}",
                    f"Dynamic events: {len(result.events)}; status: {result.status}",
                ),
                t(
                    f"隔离后端：{result.backend or 'unavailable'}",
                    f"Sandbox backend: {result.backend or 'unavailable'}",
                ),
                metadata={
                    "component": "dynamic",
                    "status": result.status,
                    "event_count": len(result.events),
                    "exit_code": result.exit_code,
                    "command_preview": result.command_preview,
                },
            ),
        )
        if result.status != "complete":
            findings.append(
                Finding(
                    "internal",
                    WARN,
                    t("动态行为分析不完整", "Dynamic behavior analysis incomplete"),
                    result.error or t("行为事件覆盖不足。", "Behavioral event coverage was incomplete."),
                    str(target),
                    metadata={"scan_status": "error", "component": "dynamic"},
                )
            )
    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "status": result.status if result else "error",
                    "events": [
                        {
                            "kind": event.kind,
                            "operation": event.operation,
                            "target": event.target,
                            "process": event.process,
                            "pid": event.pid,
                            "parent_pid": event.parent_pid,
                            "timestamp": event.timestamp,
                            "labels": list(event.labels),
                            "metadata": event.metadata,
                        }
                        for event in (result.events if result else [])
                    ],
                    "findings": [
                        {
                            "scanner": finding.scanner,
                            "level": finding.level,
                            "title": finding.title,
                            "detail": finding.detail,
                            "location": finding.location,
                            "remediation": finding.remediation,
                            "metadata": finding.metadata,
                        }
                        for finding in findings
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        render_focus_report(
            title=t("隔离动态分析", "Isolated Dynamic Analysis"),
            subject=str(target),
            findings=findings,
            ok_message=t("隔离执行完成，未形成高风险行为链。", "Sandbox execution completed without a high-risk behavior chain."),
            review_message=t("动态分析中有需要复核的行为或覆盖缺口。", "Dynamic analysis found behavior or coverage gaps to review."),
            risk_message=t("隔离执行触发了高风险行为链。", "Sandbox execution triggered a high-risk behavior chain."),
        )
    if result is None or result.status != "complete" or any(_is_scan_error(finding) for finding in findings):
        raise typer.Exit(2)
    if any(finding.level in (CRIT, HIGH) for finding in findings):
        raise typer.Exit(1)


@app.command(
    name="agent-scan",
    help=t(
        "运行 ClawLock ASI 14 兼容规则集扫描",
        "Run the ClawLock ASI 14 compatibility profile.",
    ),
)
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
    no_pkg_check: Annotated[
        bool,
        typer.Option(
            "--no-pkg-check",
            help=t(
                "跳过包名存在性检查（npm / PyPI 注册表探测）",
                "Skip the npm / PyPI registry existence probe",
            ),
        ),
    ] = False,
    adapter: A = "auto",
):
    """Run the ClawLock ASI 14 compatibility profile."""
    from .adapters import get_adapter, load_config
    from .integrations import run_agent_scan
    import os as _os

    adapter = _validated_adapter(adapter)
    code_path = (
        _existing_path(code, param_hint="--code") if code is not None else None
    )
    config_path = (
        _existing_path(config_file, param_hint="--config", file_only=True)
        if config_file
        else None
    )
    if no_pkg_check:
        _os.environ["CLAWLOCK_NO_PKG_CHECK"] = "1"

    spec = get_adapter(adapter)
    config = None
    diagnostics: list[Finding] = []
    if config_path is not None:
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise typer.BadParameter(
                t(
                    f"无法读取有效的 JSON 配置：{exc}",
                    f"Could not read valid JSON config: {exc}",
                ),
                param_hint="--config",
            ) from exc
        if not isinstance(config, dict):
            raise typer.BadParameter(
                t("配置顶层必须是 JSON 对象", "Config must contain a JSON object at the top level"),
                param_hint="--config",
            )
    else:
        try:
            config, _ = load_config(spec, strict=True)
        except Exception as exc:
            diagnostics.append(
                _scanner_error_finding(t("Agent 配置", "Agent Config"), exc)
            )

    layers = []
    if config:
        layers.append(t("配置", "Config"))
    if code:
        layers.append(t("代码", "Code"))
    if llm:
        layers.append("LLM")
    console.print(
        f"[cyan]{t('ClawLock ASI 14 兼容规则集', 'ClawLock ASI 14 compatibility profile')}[/cyan]"
    )
    console.print(
        f"  {t('分析层', 'Layers')}: "
        f"{' + '.join(layers) if layers else t('配置', 'Config')}"
    )

    try:
        findings = diagnostics + run_agent_scan(
            model=model,
            token=token,
            base_url=base_url,
            config=config,
            code_path=code_path,
            enable_llm=llm,
            adapter_name=spec.name,
        )
    except Exception as exc:
        findings = diagnostics + [
            _scanner_error_finding(t("Agent 扫描", "Agent Scan"), exc)
        ]

    if diagnostics:
        for finding in findings:
            metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
            if finding.scanner != "agent_scan" or metadata.get("profile") != "clawlock-asi14":
                continue
            security_count = int(metadata.get("security_finding_count", 0))
            diagnostic_count = int(metadata.get("diagnostic_count", 0)) + len(diagnostics)
            finding.title = t(
                f"Agent-Scan 不完整: {security_count} 项安全发现, {diagnostic_count} 项诊断",
                f"Agent-Scan INCOMPLETE: {security_count} security findings, {diagnostic_count} diagnostic(s)",
            )
            finding.detail = (
                finding.detail
                + " "
                + t(
                    "自动发现的配置无法读取；仅完成了其余可用分析层。",
                    "The auto-discovered config could not be read; only the remaining available layers completed.",
                )
            )
            metadata.update(
                {
                    "complete": False,
                    "scan_status": "incomplete",
                    "diagnostic_count": diagnostic_count,
                }
            )
            finding.metadata = metadata

    for f in findings:
        console.print(f"  {_tag(f.level)} [bold]{f.title}[/bold]")
        if f.detail:
            console.print(f"     [dim]{f.detail}[/dim]")
        if f.location:
            console.print(f"     {t('位置', 'Location')}: {f.location}")
        if f.remediation:
            console.print(f"     {t('修复', 'Fix')}: {f.remediation}")
    if any(_is_scan_error(f) for f in findings):
        raise typer.Exit(2)
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

    def _completed_score(record: dict) -> Optional[int]:
        complete = record.get("complete")
        if complete is None:
            complete = record.get("status", "complete") == "complete"
        score = record.get("score")
        if not complete or not isinstance(score, (int, float)) or isinstance(score, bool):
            return None
        return int(score)

    records = get_scan_history(limit)
    if not records:
        console.print(
            f"[yellow]{t('暂无扫描历史，请先运行 `clawlock scan`。', 'No scan history yet. Run `clawlock scan` first.')}[/yellow]"
        )
        return
    tbl = Table(title=t("ClawLock 历史记录", "ClawLock History"), show_header=True, header_style="bold cyan")
    tbl.add_column(t("时间", "Time"), min_width=20)
    tbl.add_column(t("适配器", "Adapter"), min_width=10)
    tbl.add_column(t("评分", "Score"), min_width=10, justify="center")
    tbl.add_column(t("高危", "High"), min_width=6, justify="center")
    tbl.add_column(t("警告", "Warn"), min_width=6, justify="center")
    tbl.add_column(t("设备", "Device"), min_width=14)
    for r in records:
        sc = _completed_score(r)
        if sc is None:
            score_cell = f"[yellow]{t('不完整', 'INCOMPLETE')}[/yellow]"
        else:
            sc_style = "red" if sc < 60 else ("yellow" if sc < 80 else "green")
            score_cell = f"[{sc_style}]{sc}[/{sc_style}]"
        tbl.add_row(
            r.get("time", "")[:19],
            r.get("adapter", ""),
            score_cell,
            str(r.get("critical", 0)),
            str(r.get("warning", 0)),
            r.get("device", ""),
        )
    console.print(tbl)
    completed_scores = [
        score for record in records if (score := _completed_score(record)) is not None
    ]
    if len(completed_scores) >= 2:
        prev, curr = completed_scores[-2:]
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

    adapter = _validated_adapter(adapter)
    if interval <= 0:
        raise typer.BadParameter(
            t("扫描间隔必须大于 0 秒", "Scan interval must be greater than 0 seconds"),
            param_hint="--interval",
        )
    if count < 0:
        raise typer.BadParameter(
            t("执行次数不能小于 0", "Number of runs cannot be negative"),
            param_hint="--count",
        )
    spec = get_adapter(adapter)
    console.print(
        f"[cyan]{t('ClawLock 监控', 'ClawLock Watch')}[/cyan]  interval={interval}s  adapter={spec.display}"
    )
    console.print(f"[dim]{t('按 Ctrl+C 停止', 'Press Ctrl+C to stop')}[/dim]\n")
    iteration = 0
    previous_by_check: dict[str, list[Finding]] = {}

    def _print_group(
        label: str,
        findings: list[tuple[str, Finding]],
        *,
        style: str,
    ) -> None:
        if not findings:
            return
        console.print(f"  [{style}]{label}: {len(findings)}[/{style}]")
        for check, finding in findings[:5]:
            console.print(
                f"    {_tag(finding.level)} [{check}] {finding.title}: "
                f"{finding.detail[:80]}"
            )
        if len(findings) > 5:
            console.print(
                f"    [dim]{t('其余', 'Additional')} {len(findings) - 5}"
                f" {t('项已省略', 'item(s) omitted')}[/dim]"
            )

    try:
        while count == 0 or iteration < count:
            iteration += 1
            now_str = time.strftime("%H:%M:%S")
            console.print(
                f"[bold cyan]"
                f"{t(f'-- 第 {iteration} 轮 ({now_str}) --', f'-- Run {iteration} ({now_str}) --')}"
                f"[/bold cyan]"
            )
            jobs = [
                (t("配置", "Config"), lambda: scan_config(spec)[0]),
                (t("提示词", "Prompt"), lambda: scan_soul(spec)[0]),
                (t("记忆", "Memory"), lambda: scan_memory_files(spec)),
                (t("进程", "Processes"), lambda: scan_processes(spec)),
            ]
            new_findings: list[tuple[str, Finding]] = []
            persistent_findings: list[tuple[str, Finding]] = []
            resolved_findings: list[tuple[str, Finding]] = []
            diagnostics: list[tuple[str, Finding]] = []

            for check, run_check in jobs:
                try:
                    findings = run_check()
                except Exception as exc:
                    diagnostics.append((check, _scanner_error_finding(check, exc)))
                    # Preserve the last trusted state for a failed check so its
                    # prior findings are not falsely reported as resolved.
                    continue

                check_diagnostics = [
                    finding for finding in findings if _is_scan_error(finding)
                ]
                if check_diagnostics:
                    diagnostics.extend(
                        (check, finding) for finding in check_diagnostics
                    )
                    continue

                actionable = [
                    finding
                    for finding in findings
                    if finding.level in (CRIT, HIGH, WARN)
                    and not _is_scan_error(finding)
                ]
                new, persistent, resolved = _diff_findings(
                    previous_by_check.get(check, []), actionable
                )
                new_findings.extend((check, finding) for finding in new)
                persistent_findings.extend(
                    (check, finding) for finding in persistent
                )
                resolved_findings.extend((check, finding) for finding in resolved)
                previous_by_check[check] = actionable

            if diagnostics:
                console.print(
                    f"  [bold yellow]{t('本轮扫描不完整', 'Watch iteration incomplete')}: "
                    f"{len(diagnostics)} {t('项检查失败', 'check(s) failed')}[/bold yellow]"
                )
                for check, diagnostic in diagnostics:
                    console.print(
                        f"    [yellow][{check}] {diagnostic.title}: "
                        f"{diagnostic.detail[:120]}[/yellow]"
                    )

            _print_group(
                t("新增", "New"),
                new_findings,
                style="bold red"
                if any(f.level in (CRIT, HIGH) for _, f in new_findings)
                else "yellow",
            )
            _print_group(
                t("持续存在", "Persistent"),
                persistent_findings,
                style="yellow",
            )
            _print_group(
                t("已解决", "Resolved"),
                resolved_findings,
                style="green",
            )
            if not diagnostics and not (
                new_findings or persistent_findings or resolved_findings
            ):
                console.print(f"  [green]{t('未检测到变化', 'No change detected')}[/green]")
            if count == 0 or iteration < count:
                console.print(f"  [dim]{t('下次运行将在', 'Next run in')} {interval}s[/dim]\n")
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print(f"\n[dim]{t('监控已停止，共执行', 'Watch stopped after')} {iteration} {t('轮。', 'run(s).')}[/dim]")


@app.command(help=t("显示版本信息", "Show version info."))
def version(
    check_update: Annotated[
        bool,
        typer.Option(
            "--check-update",
            help=t(
                "检查 PyPI 更新与本地 skill 版本同步状态",
                "Check PyPI updates and local skill version sync",
            ),
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help=t("以 JSON 输出版本与更新信息", "Output version and update info as JSON"),
        ),
    ] = False,
    skill_path: Annotated[
        Optional[str],
        typer.Option(
            "--skill-path",
            help=t(
                "本地 SKILL.md 路径，用于检查 skill 版本同步状态",
                "Local SKILL.md path for skill version sync checks",
            ),
        ),
    ] = None,
):
    """Show version info."""
    from .updates import build_update_report, render_update_report_json, render_update_report_text
    from .utils import platform_label

    resolved_skill_path = Path(skill_path) if skill_path else None
    if resolved_skill_path is not None and not resolved_skill_path.exists():
        raise typer.BadParameter(t("SKILL.md 路径不存在", "SKILL.md path does not exist"))

    if check_update:
        report = build_update_report(resolved_skill_path)
        if json_output:
            typer.echo(render_update_report_json(report))
        else:
            console.print(render_update_report_text(report))
        return

    console.print(f"ClawLock v[bold]{__version__}[/bold]")
    console.print("[dim]https://github.com/g1at/clawlock[/dim]")
    console.print(f"[dim]{t('平台', 'Platform')}: {platform_label()}[/dim]")


if __name__ == "__main__":
    app()
