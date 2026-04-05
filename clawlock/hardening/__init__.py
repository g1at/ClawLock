from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Union

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from ..i18n import t
from ..utils import IS_ANDROID, IS_MACOS, IS_WINDOWS, platform_label

console = Console()
TextValue = Union[str, Callable[[], str]]


@dataclass
class HardenMeasure:
    id: str
    title: TextValue
    desc: TextValue
    ux_impact: TextValue
    apply: Callable[[], bool]
    adapters: List[str]
    platforms: List[str] = field(default_factory=list)
    auto_fixable: bool = False
    guidance_only: bool = True


def _text(value: TextValue) -> str:
    return value() if callable(value) else value


def _tr(zh: str, en: str) -> Callable[[], str]:
    return lambda: t(zh, en)


def _g(msg: str):
    console.print(f"  [dim]{msg}[/dim]")


def _guide(*steps: TextValue) -> bool:
    shown = False
    for step in steps:
        text = _text(step)
        if not text:
            continue
        _g(text)
        shown = True
    return shown


def _current_platform_tags() -> set[str]:
    if IS_WINDOWS:
        return {"windows"}
    if IS_MACOS:
        return {"macos"}
    if IS_ANDROID:
        return {"android", "android-termux", "linux"}
    return {"linux"}


def _platform_matches(measure: HardenMeasure) -> bool:
    if not measure.platforms:
        return True
    return bool(_current_platform_tags().intersection(measure.platforms))


def _persistence_guidance() -> bool:
    if IS_WINDOWS:
        return _guide(
            _tr(
                "检查 schtasks 与 Run/RunOnce 注册表键中的异常持久化项。",
                "Review schtasks and Run/RunOnce registry keys for unexpected persistence.",
            ),
            _tr(
                "删除未使用的计划任务和自启动注册表项，只保留有文档说明的自动化。",
                "Delete unused scheduled tasks and autoruns; keep only documented automation.",
            ),
            _tr(
                "在重新创建后台任务前要求人工审批。",
                "Require manual approval before recreating background tasks.",
            ),
        )
    if IS_MACOS:
        return _guide(
            _tr(
                "检查 ~/Library/LaunchAgents、/Library/LaunchAgents 与 launchctl 列表中的异常条目。",
                "Review ~/Library/LaunchAgents, /Library/LaunchAgents, and launchctl output for unexpected entries.",
            ),
            _tr(
                "移除未使用的 LaunchAgent，只保留明确记录用途的后台任务。",
                "Remove unused LaunchAgents and keep only documented background jobs.",
            ),
            _tr(
                "在从 skill 或 prompt 重新建立持久化任务前要求人工审批。",
                "Require manual approval before rebuilding persistence from skills or prompts.",
            ),
        )
    if IS_ANDROID:
        return _guide(
            _tr(
                "检查 ~/.termux/boot 与 termux-job-scheduler 任务中是否存在异常启动脚本。",
                "Review ~/.termux/boot and termux-job-scheduler jobs for unexpected startup scripts.",
            ),
            _tr(
                "删除未使用的 Termux 启动脚本和后台任务，只保留明确记录用途的自动化。",
                "Delete unused Termux boot scripts and background jobs; keep only documented automation.",
            ),
            _tr(
                "在重新创建 Termux 持久化任务前要求人工审批。",
                "Require manual approval before recreating Termux persistence.",
            ),
        )
    return _guide(
        _tr(
            "检查 ~/.config/systemd/user、systemctl --user 与 crontab 中的异常持久化项。",
            "Review ~/.config/systemd/user, systemctl --user, and crontab for unexpected persistence.",
        ),
        _tr(
            "删除未使用的 systemd 用户级单元和 cron 任务，只保留有文档说明的自动化。",
            "Delete unused user-level systemd units and cron jobs; keep only documented automation.",
        ),
        _tr(
            "在从 skill 或 prompt 重新创建后台任务前要求人工审批。",
            "Require manual approval before re-creating background tasks from skills or prompts.",
        ),
    )


def _fix_cred_perms():
    from ..utils import fix_file_permission

    fixed = 0
    for d in [
        Path.home() / ".openclaw",
        Path.home() / ".zeroclaw",
        Path.home() / ".claude",
        Path.home() / ".config" / "openclaw",
        Path.home() / ".config" / "zeroclaw",
        Path.home() / ".config" / "claude",
    ]:
        if d.exists():
            if fix_file_permission(d, private=True):
                fixed += 1
                _g(f"{t('已收紧', 'Tightened')}: {d}")
            for f in d.iterdir():
                if f.is_file() and f.suffix in (
                    ".json",
                    ".key",
                    ".pem",
                    ".token",
                    ".env",
                    ".rc",
                ):
                    fix_file_permission(f, private=True)
                    _g(f"{t('已收紧', 'Tightened')}: {f}")
    for f in [
        Path.home() / ".npmrc",
        Path.home() / ".pypirc",
        Path.home() / ".netrc",
    ]:
        if f.exists() and fix_file_permission(f, private=True):
            fixed += 1
            _g(f"{t('已收紧', 'Tightened')}: {f}")
    return fixed > 0


MEASURES: List[HardenMeasure] = [
    HardenMeasure(
        "H001",
        _tr("将文件访问限制在工作区内", "Restrict file access to the workspace"),
        _tr(
            "将 allowedDirectories / allowedPaths 收紧到项目路径内。",
            "Tighten allowedDirectories / allowedPaths to project paths only.",
        ),
        _tr(
            "可能会阻止需要跨目录访问的 skills。",
            "May block skills that need cross-directory access.",
        ),
        lambda: _guide('"allowedDirectories": ["~/projects"]'),
        ["openclaw", "zeroclaw", "claude-code"],
    ),
    HardenMeasure(
        "H002",
        _tr("启用 gateway / API 鉴权", "Enable gateway / API auth"),
        _tr("为 gateway 访问设置令牌。", "Require a token for gateway access."),
        _tr("外部工具可能需要新的令牌。", "External tools may need a new token."),
        lambda: _guide('"gatewayAuth": true + "gatewayToken": "<your-token>"'),
        ["openclaw", "zeroclaw"],
    ),
    HardenMeasure(
        "H003",
        _tr("缩短会话保留期", "Shorten session retention"),
        _tr(
            "将会话日志保留期控制在 7 天以内。",
            "Keep session logs for 7 days or less.",
        ),
        _tr(
            "更早的会话历史将不再可用。",
            "Older session history will no longer be available.",
        ),
        lambda: _guide('"sessionRetentionDays": 7, "logLevel": "warn"'),
        [],
    ),
    HardenMeasure(
        "H004",
        _tr("关闭浏览器控制", "Disable browser control"),
        _tr("关闭 enableBrowserControl。", "Turn off enableBrowserControl."),
        _tr(
            "依赖浏览器的 skills 可能会停止工作。",
            "Browser-driven skills may stop working.",
        ),
        lambda: _guide('"enableBrowserControl": false'),
        ["openclaw"],
    ),
    HardenMeasure(
        "H005",
        _tr("设置出站白名单", "Set an outbound allowlist"),
        _tr("仅允许 skills 访问经过批准的域名。", "Limit skills to approved domains only."),
        "",
        lambda: _guide('"allowedNetworkDomains": ["api.anthropic.com"]'),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H006",
        _tr("审查 MCP 服务配置", "Review MCP server config"),
        _tr("检查绑定地址和远程端点。", "Check bind addresses and remote endpoints."),
        "",
        lambda: _guide(
            _tr("将 0.0.0.0 改为 127.0.0.1。", "Change 0.0.0.0 to 127.0.0.1."),
            _tr("移除未使用的远程 MCP 服务。", "Remove unused remote MCP servers."),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H007",
        _tr("建立提示词基线", "Create a prompt baseline"),
        _tr(
            "为 SOUL.md / CLAUDE.md / MEMORY.md 记录 SHA-256 基线。",
            "Record a SHA-256 baseline for SOUL.md / CLAUDE.md / MEMORY.md.",
        ),
        "",
        lambda: _guide(
            _tr(
                "运行 `clawlock soul --update-baseline` 保存基线。",
                "Run `clawlock soul --update-baseline` to save a baseline.",
            )
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H008",
        _tr("启用审批模式", "Enable approval mode"),
        _tr(
            "在高风险操作前要求确认。",
            "Require confirmation before high-risk actions.",
        ),
        _tr(
            "高风险操作会暂停等待确认。",
            "High-risk actions will pause for confirmation.",
        ),
        lambda: _guide('"approvalMode": "always"'),
        ["openclaw", "zeroclaw"],
    ),
    HardenMeasure(
        "H009",
        _tr("收紧凭证权限", "Tighten credential permissions"),
        _tr(
            "将配置和凭证路径限制为仅当前用户可访问。",
            "Limit config and credential paths to the current user.",
        ),
        "",
        _fix_cred_perms,
        [],
        auto_fixable=True,
        guidance_only=False,
    ),
    HardenMeasure(
        "H010",
        _tr("设置速率限制", "Set rate limits"),
        _tr(
            "添加请求速率限制以降低暴力尝试和 API 滥用风险。",
            "Add request limits to reduce brute force and API abuse.",
        ),
        "",
        lambda: _guide('"rateLimit": {"enabled": true, "maxRequestsPerMinute": 60}'),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H011",
        _tr(
            "阻止下载即执行和远程运行时安装",
            "Block download-and-execute and remote runtime installs",
        ),
        _tr(
            "从 skills 和安装脚本中移除 pipe-to-shell 启动方式与运行时依赖拉取。",
            "Remove pipe-to-shell bootstraps and runtime dependency fetch from skills and setup scripts.",
        ),
        _tr(
            "引导安装脚本和一次性依赖拉取可能会停止工作。",
            "Bootstrap installers and one-shot dependency fetches may stop working.",
        ),
        lambda: _guide(
            _tr(
                '移除 "curl | bash"、"wget | sh"、"Invoke-WebRequest | iex" 这类模式。',
                'Remove patterns like "curl | bash", "wget | sh", and "Invoke-WebRequest | iex".',
            ),
            _tr(
                '将 "npx"、"uvx"、"pipx run"、"npm exec"、"pip install git+..." 这类运行时拉取方式替换为固定的本地依赖。',
                'Replace runtime fetchers such as "npx", "uvx", "pipx run", "npm exec", and "pip install git+..." with pinned local dependencies.',
            ),
            _tr(
                "在执行前把依赖 vendoring 或固定到包清单里。",
                "Vendor or pin dependencies in package manifests before execution.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H012",
        _tr("禁用 Windows LOLBins 和脚本宿主", "Deny Windows LOLBins and script hosts"),
        _tr(
            "阻止常被滥用于代码执行的 Windows 内置执行器。",
            "Block built-in Windows executors that are commonly abused for code execution.",
        ),
        _tr(
            "依赖 LOLBins 的 Windows 管理脚本可能会停止工作。",
            "Windows admin scripts that rely on LOLBins may stop working.",
        ),
        lambda: _guide(
            _tr(
                "把 mshta、regsvr32、rundll32、certutil、bitsadmin、wmic 加入拒绝列表或仅审批后可执行的命令集合。",
                "Add mshta, regsvr32, rundll32, certutil, bitsadmin, and wmic to your denylist or approval-only command set.",
            ),
            _tr(
                "优先使用签名应用程序或已审查的 PowerShell 脚本，而不是传统脚本宿主。",
                "Prefer signed application binaries or reviewed PowerShell scripts over legacy script hosts.",
            ),
            _tr(
                "审查所有通过 Windows 内置加载器调用 shell 的 skill 或自动化。",
                "Review any skill or automation that shells out through built-in Windows loaders.",
            ),
        ),
        [],
        platforms=["windows"],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H013",
        _tr("清理持久化落点", "Remove persistence footholds"),
        _tr(
            "审查计划任务、autoruns、LaunchAgents 和用户级 systemd 单元中的持久化项。",
            "Audit scheduled tasks, autoruns, LaunchAgents, and user-level systemd units for persistence.",
        ),
        _tr(
            "合法的后台任务在重新批准前可能会停止工作。",
            "Legitimate background jobs may stop working until re-approved.",
        ),
        _persistence_guidance,
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H014",
        _tr("阻止隧道和反向代理", "Block tunnels and reverse proxies"),
        _tr(
            "阻止反向 SSH 和隧道客户端等隐蔽出站通道。",
            "Prevent covert outbound channels such as reverse SSH and tunneling clients.",
        ),
        _tr(
            "远程调试隧道和临时共享工具可能会停止工作。",
            "Remote debugging tunnels and ad-hoc sharing tools may stop working.",
        ),
        lambda: _guide(
            _tr(
                "对 ssh -R、ngrok、cloudflared tunnel、frpc 设置拒绝或显式审批。",
                "Deny or require explicit approval for ssh -R, ngrok, cloudflared tunnel, and frpc.",
            ),
            _tr(
                "把出站域名限制在白名单内，并从 PATH 中移除未使用的隧道工具。",
                "Keep outbound domains on an allowlist and remove unused tunnel binaries from PATH.",
            ),
            _tr(
                "优先使用已审计的 VPN 或堡垒机，而不是临时反向隧道。",
                "Use audited VPN or bastion access instead of ad-hoc reverse tunnels.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H015",
        _tr("收紧 MCP 鉴权、绑定和 CORS", "Tighten MCP auth, bind, and CORS"),
        _tr(
            "为 MCP 路由启用鉴权、回环地址绑定和严格来源限制。",
            "Require authentication, loopback bind, and restrictive origins for MCP routes.",
        ),
        _tr(
            "外部仪表盘或工具可能需要更新令牌和来源配置。",
            "External dashboards or tools may need token and origin updates.",
        ),
        lambda: _guide(
            _tr(
                "对 /invoke、/tools、/call 等 MCP 端点要求鉴权。",
                "Require auth on /invoke, /tools, /call, and similar MCP endpoints.",
            ),
            _tr(
                '将 MCP 服务绑定到 127.0.0.1，并移除 "Access-Control-Allow-Origin: *"。',
                'Bind MCP services to 127.0.0.1 and remove "Access-Control-Allow-Origin: *".',
            ),
            _tr(
                "只允许显式列出的来源，避免在启用凭证时使用通配符来源。",
                "Only allow explicit origins and avoid wildcard origins with credentials enabled.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H016",
        _tr(
            "禁用用户可控的动态模块加载",
            "Disable user-controlled dynamic module loading",
        ),
        _tr(
            "将由工具或用户输入决定的动态 import/require 路径替换为固定白名单。",
            "Replace dynamic import/require paths derived from tool or user input with fixed allowlists.",
        ),
        _tr(
            "按名称热加载插件的能力在加入白名单前可能无法使用。",
            "Hot-loading plugins by name may stop working until they are allowlisted.",
        ),
        lambda: _guide(
            _tr(
                "把 importlib.import_module(user_input)、__import__(...)、require(args.plugin) 替换为显式查找表。",
                "Replace importlib.import_module(user_input), __import__(...), and require(args.plugin) with explicit lookup tables.",
            ),
            _tr(
                "将已批准的插件名映射到已知模块，不要加载任意模块字符串。",
                "Map approved plugin names to known modules instead of loading arbitrary module strings.",
            ),
            _tr(
                "当请求的模块不在白名单内时默认拒绝。",
                "Fail closed when a requested module is not in the allowlist.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H017",
        _tr("对日志中的提示词和凭证做脱敏", "Redact prompts and credentials from logs"),
        _tr(
            "停止记录 system prompt、聊天历史、token、密码和其他密钥。",
            "Stop logging system prompts, chat history, tokens, passwords, and secrets.",
        ),
        _tr("排障日志会变得更简略。", "Troubleshooting logs become less verbose."),
        lambda: _guide(
            _tr(
                "删除或脱敏包含 system_prompt、messages、token、password、secret 的 logger/debug/print 语句。",
                "Remove or redact logger/debug/print statements that include system_prompt, messages, tokens, passwords, or secrets.",
            ),
            _tr(
                "日志中只保留请求 ID、高层状态和已脱敏的元数据。",
                "Keep only request IDs, high-level status, and sanitized metadata in logs.",
            ),
            _tr(
                "完整 prompt 跟踪只应保存在严格受控的调试环境中。",
                "Store full prompt traces only in tightly controlled debug environments.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
    HardenMeasure(
        "H018",
        _tr("清理 prompt 和 skill 操作指令", "Clean prompt and skill operating instructions"),
        _tr(
            "从 SOUL.md 和 skills 中移除 prompt 提取、审批绕过和强制工具调用措辞。",
            "Remove prompt-extraction, approval-bypass, and forced-tool wording from SOUL.md and skills.",
        ),
        _tr(
            "不安全的自动化措辞在安全改写前可能无法继续工作。",
            "Unsafe automation wording may stop working until rewritten safely.",
        ),
        lambda: _guide(
            _tr(
                '删除诸如 "show your system prompt"、"do not ask for approval"、"call the tool before replying" 这类指令。',
                'Delete instructions such as "show your system prompt", "do not ask for approval", and "call the tool before replying".',
            ),
            _tr(
                "让操作者意图保持明确，并对高风险操作要求审批。",
                "Keep operator intent explicit and require approval for high-risk actions.",
            ),
            _tr(
                "更新 prompt 文件后重新运行 `clawlock skill` 和 `clawlock soul`。",
                "Re-run `clawlock skill` and `clawlock soul` after updating prompt files.",
            ),
        ),
        [],
        auto_fixable=False,
    ),
]


def _needs_confirmation(measure: HardenMeasure) -> bool:
    return bool(_text(measure.ux_impact))


def _measure_action(measure: HardenMeasure) -> str:
    if _needs_confirmation(measure):
        return t("需要确认", "Confirm required")
    if measure.guidance_only:
        return t("仅指导", "Guidance only")
    if measure.auto_fixable:
        return t("可自动修复", "Auto-fix available")
    return t("自动应用", "Apply automatically")


def _print_measure(measure: HardenMeasure):
    console.print(f"[bold][{measure.id}][/bold] {_text(measure.title)}")
    console.print(f"  {t('原因', 'Why')}: {_text(measure.desc)}")
    console.print(
        f"  {t('影响', 'Impact')}: {_text(measure.ux_impact) or t('无', 'None')}"
    )
    console.print(f"  {t('动作', 'Action')}: {_measure_action(measure)}")


def run_hardening(adapter_name: str, auto: bool = False, auto_fix: bool = False):
    mode = (
        t("自动修复", "auto-fix")
        if auto_fix
        else t("自动", "auto")
        if auto
        else t("交互式", "interactive")
    )
    console.print(
        Panel(
            f"[bold cyan]{t('ClawLock 加固向导', 'ClawLock Hardening Wizard')}[/bold cyan]",
            subtitle=(
                f"{t('适配器', 'Adapter')}: [bold]{adapter_name}[/bold]  |  "
                f"{t('模式', 'Mode')}: {mode}  |  "
                f"{t('平台', 'Platform')}: {platform_label()}"
            ),
        )
    )
    console.print()
    applicable = [
        m
        for m in MEASURES
        if (not m.adapters or adapter_name in m.adapters) and _platform_matches(m)
    ]
    safe_now = [m for m in applicable if not m.guidance_only and not _needs_confirmation(m)]
    recommended_only = [
        m for m in applicable if m.guidance_only and not _needs_confirmation(m)
    ]
    needs_confirmation = [m for m in applicable if _needs_confirmation(m)]

    console.print(f"[bold]{t('执行摘要', 'Execution Summary')}[/bold]")
    console.print(f"  {t('现在可安全应用', 'Safe to apply now')}: {len(safe_now)}")
    console.print(f"  {t('仅建议', 'Recommended only')}: {len(recommended_only)}")
    console.print(f"  {t('需要确认', 'Needs confirmation')}: {len(needs_confirmation)}")
    console.print()

    applied = 0
    recommended = 0
    skipped = 0
    failed = 0

    sections = [
        (t("现在可安全应用", "Safe to Apply Now"), safe_now),
        (t("仅建议", "Recommended Only"), recommended_only),
        (t("需要确认", "Needs Confirmation"), needs_confirmation),
    ]

    for title, measures in sections:
        if not measures:
            continue
        console.print(f"[bold]{title}[/bold]")
        console.print()
        for m in measures:
            _print_measure(m)
            if m.guidance_only:
                if _needs_confirmation(m):
                    if auto or auto_fix:
                        skipped += 1
                        console.print(
                            f"  [dim]{t('需要确认：非交互模式下已跳过', 'Requires confirmation: skipped in non-interactive mode')}[/dim]\n"
                        )
                        continue
                    if not Confirm.ask(
                        f"  {t('查看建议', 'Review recommendation')} [{m.id}]?",
                        default=False,
                    ):
                        skipped += 1
                        console.print(
                            f"  [dim]{t('已跳过', 'Skipped')} {m.id}[/dim]\n"
                        )
                        continue
                    recommended += 1
                    console.print(
                        f"  [cyan]{t('需要手动修改：请按上方建议处理', 'Manual change required: follow the recommendation above')}[/cyan]\n"
                    )
                    continue

                recommended += 1
                console.print(
                    f"  [dim]{t('仅提供建议：未执行自动修改', 'Recommendation only: no automatic change was made')}[/dim]\n"
                )
                continue

            if auto_fix and not m.auto_fixable:
                skipped += 1
                console.print(
                    f"  [dim]{t('安全项已跳过：不适用于自动修复模式', 'Safe item skipped: not eligible for auto-fix mode')}[/dim]\n"
                )
                continue

            if not auto and not auto_fix and not Confirm.ask(
                f"  {t('应用加固项', 'Apply hardening')} [{m.id}]?",
                default=True,
            ):
                skipped += 1
                console.print(f"  [dim]{t('已跳过', 'Skipped')} {m.id}[/dim]\n")
                continue

            if auto_fix and m.auto_fixable:
                console.print(
                    f"  [green]{t('自动修复：正在应用', 'Auto-fix: applying now')}[/green]"
                )

            if m.apply():
                applied += 1
                console.print(f"  [green]{m.id} {t('已应用', 'applied')}[/green]\n")
            else:
                failed += 1
                console.print(f"  [red]{m.id} {t('失败', 'failed')}[/red]\n")

    console.print(f"[bold]{t('结果', 'Result')}[/bold]")
    console.print(f"  {t('已自动应用', 'Applied automatically')}: {applied}")
    console.print(f"  {t('仅建议', 'Recommended only')}: {recommended}")
    console.print(f"  {t('待确认前已跳过', 'Skipped until confirmed')}: {skipped}")
    if failed:
        console.print(f"  {t('失败', 'Failed')}: {failed}")
    console.print(
        f"[bold green]{t('加固完成', 'Hardening complete')}[/bold green]: "
        f"{applied} {t('项已应用', 'applied')}, "
        f"{recommended} {t('项仅建议', 'recommended')}, "
        f"{skipped} {t('项已跳过', 'skipped')}."
    )
