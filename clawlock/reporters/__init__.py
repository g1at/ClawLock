"""ClawLock v1.0.1 report renderer — Rich terminal + JSON + HTML output."""
from __future__ import annotations
import json, html as html_mod
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from ..scanners import Finding, CRIT, HIGH, WARN, INFO

console = Console()

def _level_badge(level):
    if level in (CRIT, HIGH): return Text("🔴 高危", style="bold red")
    if level == WARN: return Text("⚠️  需关注", style="bold yellow")
    return Text("ℹ️  提示", style="dim")

def _status_icon(findings):
    if any(f.level in (CRIT, HIGH) for f in findings): return "🔴 风险"
    if any(f.level == WARN for f in findings): return "⚠️  需关注"
    return "✅ 通过"

def _ss(s):
    if "🔴" in s: return "bold red"
    if "⚠️" in s: return "bold yellow"
    return "bold green"


def render_scan_report(adapter_name, adapter_version, all_findings_map: dict,
                       output_format="text", output_path: Optional[str] = None):
    """
    all_findings_map: dict of {label: List[Finding]}
    """
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_f = [f for fs in all_findings_map.values() for f in fs]
    nc = sum(1 for f in all_f if f.level in (CRIT, HIGH))
    nw = sum(1 for f in all_f if f.level == WARN)
    score = max(0, 100 - nc * 20 - nw * 5)

    # v1.0: Auto-record scan to persistent history
    from ..utils import device_fingerprint, record_scan
    dev_fp = device_fingerprint()
    record_scan(adapter_name, score, nc, nw, len(all_f))

    if output_format == "json":
        out = {"tool": "ClawLock", "version": "1.0.1", "time": t,
            "adapter": adapter_name, "device": dev_fp, "score": score,
            "findings": [{"scanner": f.scanner, "level": f.level, "title": f.title,
                "detail": f.detail, "location": f.location, "remediation": f.remediation}
                for f in all_f]}
        text = json.dumps(out, ensure_ascii=False, indent=2)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
            console.print(f"[green]📄 JSON 报告已保存: {output_path}[/green]")
        else:
            console.print_json(text)
        return

    if output_format == "html":
        _render_html(adapter_name, adapter_version, t, score, nc, nw, all_findings_map, output_path)
        return

    # Terminal Rich output
    console.print()
    console.print(Panel("[bold]🏥 ClawLock 安全扫描报告[/bold]",
        subtitle=f"📅 {t}  |  🔧 {adapter_name} {adapter_version}  |  🖥️ {dev_fp}", border_style="cyan"))
    sc = "red" if score < 60 else ("yellow" if score < 80 else "green")
    console.print(f"  安全评分  [bold {sc}]{score}/100[/bold {sc}]  │  [red]高危 {nc}[/red]  [yellow]需关注 {nw}[/yellow]")
    console.print()
    summary = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    summary.add_column("检查项", min_width=14); summary.add_column("状态", min_width=12); summary.add_column("详情", min_width=40)
    for label, fs in all_findings_map.items():
        st = _status_icon(fs) if fs else "✅ 通过"
        n = len([f for f in fs if f.level in (CRIT, HIGH)])
        summary.add_row(label, Text(st, style=_ss(st)),
            f"{n} 高危, {len([f for f in fs if f.level==WARN])} 需关注" if fs else "未发现风险")
    console.print(summary); console.print()
    step = 0
    for label, fs in all_findings_map.items():
        step += 1
        if not fs: continue
        console.print(f"[bold cyan]Step {step}: {label}[/bold cyan]")
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        tbl.add_column("等级", min_width=10); tbl.add_column("发现", min_width=30); tbl.add_column("说明", min_width=40)
        for f in fs: tbl.add_row(_level_badge(f.level), f.title[:60], f.detail[:80])
        console.print(tbl)
        for f in fs[:3]:
            if f.remediation: console.print(f"  [dim]→ {f.remediation}[/dim]")
        console.print()
    console.print(Panel("[dim]本报告由 ClawLock v1.0.1 生成。静态分析结论仅反映当前可见代码。[/dim]", border_style="dim"))


def _render_html(adapter_name, adapter_version, t, score, nc, nw, all_findings_map, output_path):
    """v1.0.1: Generate standalone HTML report (inspired by ClawLens)."""
    sc = "#e24b4a" if score < 60 else ("#ef9f27" if score < 80 else "#1d9e75")
    rows = ""
    for label, fs in all_findings_map.items():
        if not fs: continue
        for f in fs:
            lv_color = "#e24b4a" if f.level in (CRIT, HIGH) else ("#ef9f27" if f.level == WARN else "#888")
            lv_text = "高危" if f.level in (CRIT, HIGH) else ("需关注" if f.level == WARN else "提示")
            rows += f"""<tr>
<td style="text-align:center"><span style="background:{lv_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{lv_text}</span></td>
<td>{html_mod.escape(label)}</td>
<td><b>{html_mod.escape(f.title[:80])}</b><br><span style="color:#666;font-size:13px">{html_mod.escape(f.detail[:120])}</span></td>
<td style="font-size:13px">{html_mod.escape(f.remediation[:100])}</td></tr>\n"""
    html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>ClawLock 安全报告</title>
<style>body{{font-family:-apple-system,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#333;background:#fafaf8}}
h1{{color:#222;border-bottom:2px solid #ddd;padding-bottom:12px}}
.score{{display:inline-block;font-size:36px;font-weight:700;color:{sc};margin:8px 0}}
.meta{{color:#888;font-size:14px}}
table{{width:100%;border-collapse:collapse;margin:20px 0}}
th{{background:#f5f5f0;text-align:left;padding:10px;border-bottom:2px solid #ddd;font-size:13px}}
td{{padding:10px;border-bottom:1px solid #eee;vertical-align:top}}
tr:hover{{background:#f9f9f4}}
.footer{{margin-top:40px;padding:16px;background:#f5f5f0;border-radius:8px;font-size:13px;color:#888;text-align:center}}
</style></head><body>
<h1>🏥 ClawLock 安全扫描报告</h1>
<p class="meta">📅 {t} &nbsp; 🔧 {adapter_name} {adapter_version}</p>
<p>安全评分 <span class="score">{score}/100</span> &nbsp; 🔴 高危 {nc} &nbsp; ⚠️ 需关注 {nw}</p>
<table><thead><tr><th style="width:80px">等级</th><th style="width:120px">检查项</th><th>发现</th><th style="width:200px">建议</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="footer">本报告由 ClawLock v1.0.1 生成 · <a href="https://github.com/g1at/clawlock">github.com/g1at/clawlock</a><br>
静态分析结论仅反映当前可见代码，不覆盖运行时风险。</div></body></html>"""
    out = Path(output_path or "clawlock-report.html")
    out.write_text(html_content, encoding="utf-8")
    console.print(f"[green]📄 HTML 报告已保存: {out.absolute()}[/green]")
    # Try to open in browser
    import webbrowser
    try: webbrowser.open(f"file://{out.absolute()}")
    except Exception: pass
