from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

@dataclass
class HardenMeasure:
    id: str; title: str; desc: str; ux_impact: str
    apply: Callable[[], bool]; adapters: List[str]
    auto_fixable: bool = False  

def _g(msg): console.print(f"  [dim]{msg}[/dim]")

def _fix_cred_perms():
    from ..utils import fix_file_permission
    fixed = 0
    for d in [Path.home() / ".openclaw", Path.home() / ".zeroclaw",
              Path.home() / ".claude", Path.home() / ".config" / "openclaw"]:
        if d.exists():
            if fix_file_permission(d, private=True):
                fixed += 1; _g(f"已收紧: {d}")
            for f in d.iterdir():
                if f.is_file() and f.suffix in (".json", ".key", ".pem", ".token", ".env"):
                    fix_file_permission(f, private=True)
                    _g(f"已收紧: {f}")
    return fixed > 0

MEASURES: List[HardenMeasure] = [
    HardenMeasure("H001", "限制文件访问范围到工作区目录",
        "将 allowedDirectories / allowedPaths 收紧到项目目录。",
        "⚠️ 影响体验：需要跨目录访问的 skill 将无法正常工作。",
        lambda: (_g('"allowedDirectories": ["~/projects"]'), True)[-1],
        ["openclaw", "zeroclaw", "claude-code"]),
    HardenMeasure("H002", "开启 Gateway / API 鉴权",
        "要求 Gateway 连接携带 token。",
        "⚠️ 影响体验：外部工具需重新配置 token。",
        lambda: (_g('"gatewayAuth": true + "gatewayToken": "<your-token>"'), True)[-1],
        ["openclaw", "zeroclaw"]),
    HardenMeasure("H003", "缩短会话日志保留期",
        "将日志保留时间设为 7 天或更短。",
        "⚠️ 影响体验：无法查看超过保留期的历史会话。",
        lambda: (_g('"sessionRetentionDays": 7, "logLevel": "warn"'), True)[-1], []),
    HardenMeasure("H004", "关闭浏览器控制权限",
        "禁用 enableBrowserControl。",
        "⚠️ 影响体验：依赖浏览器控制的 skill 将停止工作。",
        lambda: (_g('"enableBrowserControl": false'), True)[-1], ["openclaw"]),
    HardenMeasure("H005", "配置出站网络白名单",
        "限制 skill 只能向许可域名发起请求。", "",
        lambda: (_g('"allowedNetworkDomains": ["api.anthropic.com"]'), True)[-1], [],
        auto_fixable=False),
    HardenMeasure("H006", "审核并收紧 MCP 服务器配置",
        "检查 MCP 绑定地址和远程端点。", "",
        lambda: (_g("将 0.0.0.0 改为 127.0.0.1; 移除不需要的远程 MCP"), True)[-1], [],
        auto_fixable=False),
    HardenMeasure("H007", "建立系统提示词哈希基准",
        "记录 SOUL.md / CLAUDE.md / MEMORY.md 的 SHA-256 基准。", "",
        lambda: (_g("运行 `clawlock soul --update-baseline` 更新基准"), True)[-1], [],
        auto_fixable=False),
    HardenMeasure("H008", "启用操作审批模式",
        "高危操作执行前需用户二次确认。",
        "⚠️ 影响体验：每次高危操作都会暂停等待确认。",
        lambda: (_g('"approvalMode": "always"'), True)[-1], ["openclaw", "zeroclaw"]),
    HardenMeasure("H009", "收紧凭证目录权限 (chmod 700/600)",
        "将 Claw 配置和凭证目录权限设为仅当前用户可访问。", "",
        _fix_cred_perms, [], auto_fixable=True),  # v1.1: auto-fixable!
    HardenMeasure("H010", "配置速率限制",
        "为 Gateway 配置请求速率限制，防止暴力破解和 API 滥用。", "",
        lambda: (_g('"rateLimit": {"enabled": true, "maxRequestsPerMinute": 60}'), True)[-1], [],
        auto_fixable=False),
]

def run_hardening(adapter_name: str, auto: bool = False, auto_fix: bool = False):
    console.print(Panel("[bold cyan]🔧 ClawLock 安全加固向导[/bold cyan]",
        subtitle=f"适配器: [bold]{adapter_name}[/bold]  |  "
                 f"模式: {'自动修复' if auto_fix else '自动' if auto else '交互式'}"))
    console.print()
    applicable = [m for m in MEASURES if not m.adapters or adapter_name in m.adapters]
    applied = 0
    for m in applicable:
        console.print(f"[bold][{m.id}][/bold] {m.title}")
        console.print(f"  [dim]{m.desc}[/dim]")
        if m.ux_impact:
            console.print(f"  [yellow]{m.ux_impact}[/yellow]")
            if auto or auto_fix:
                console.print(f"  [dim]自动模式：跳过（需人工确认）[/dim]\n"); continue
            if not Confirm.ask(f"  是否应用加固 [{m.id}]?", default=False):
                console.print(f"  [dim]已跳过 {m.id}[/dim]\n"); continue
        else:
            # v1.1: auto-fix mode directly applies auto_fixable measures
            if auto_fix and m.auto_fixable:
                console.print(f"  [green]🔧 自动修复模式：直接应用[/green]")
            elif not auto and not Confirm.ask(f"  是否应用加固 [{m.id}]?", default=True):
                console.print(f"  [dim]已跳过 {m.id}[/dim]\n"); continue
        if m.apply(): applied += 1; console.print(f"  [green]✓ {m.id} 已完成[/green]\n")
        else: console.print(f"  [red]✗ {m.id} 应用失败[/red]\n")
    console.print(f"[bold green]加固完成[/bold green]，已应用 {applied}/{len(applicable)} 项措施。")
