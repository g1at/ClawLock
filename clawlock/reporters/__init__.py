"""ClawLock v1.1.0 report renderer - Rich terminal + JSON + HTML output."""

from __future__ import annotations

import html as html_mod
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..scanners import CRIT, HIGH, WARN, Finding

console = Console()

# ---------------------------------------------------------------------------
# Security scoring system — multi-domain grades (S / A / B / C / D)
# ---------------------------------------------------------------------------

# Map scanner names → security domains for domain-level grading.
_SCANNER_TO_DOMAIN: Dict[str, str] = {
    "config": "配置安全",
    "process": "运行时安全",
    "credential": "凭据安全",
    "skill": "供应链安全",
    "skill_precheck": "供应链安全",
    "soul": "提示词完整性",
    "memory": "提示词完整性",
    "mcp": "MCP 安全",
    "mcp_itp": "MCP 安全",
    "mcp_deep": "MCP 安全",
    "cve": "漏洞管理",
    "cost": "成本控制",
    "agent_scan": "Agent 安全",
}

# All possible domains in display order.
_ALL_DOMAINS = [
    "配置安全",
    "凭据安全",
    "供应链安全",
    "提示词完整性",
    "MCP 安全",
    "运行时安全",
    "漏洞管理",
    "Agent 安全",
    "成本控制",
]

_GRADE_STYLES = {
    "S": "bold bright_green",
    "A": "bold green",
    "B": "bold yellow",
    "C": "bold rgb(255,165,0)",  # orange
    "D": "bold red",
}

_GRADE_HTML_COLORS = {
    "S": "#00c853",
    "A": "#1d9e75",
    "B": "#ef9f27",
    "C": "#e67e22",
    "D": "#e24b4a",
}


def _compute_domain_grade(findings: List[Finding]) -> str:
    """Compute a letter grade for a security domain based on its findings."""
    nc = sum(1 for f in findings if f.level in (CRIT, HIGH))
    nw = sum(1 for f in findings if f.level == WARN)
    if nc == 0 and nw == 0:
        return "S"
    if nc == 0 and nw <= 2:
        return "A"
    if nc <= 1 and nw <= 3:
        return "B"
    if nc <= 2:
        return "C"
    return "D"


def _compute_overall_grade(domain_grades: Dict[str, str]) -> str:
    """Overall grade = worst domain grade (short-board principle)."""
    order = ["S", "A", "B", "C", "D"]
    worst = 0
    for g in domain_grades.values():
        idx = order.index(g) if g in order else 4
        worst = max(worst, idx)
    return order[worst]


def _build_domain_report(
    all_findings: List[Finding],
) -> Tuple[Dict[str, str], Dict[str, List[Finding]], str]:
    """Classify findings into domains, compute per-domain grades and overall grade.

    Returns (domain_grades, domain_findings, overall_grade).
    """
    domain_findings: Dict[str, List[Finding]] = {d: [] for d in _ALL_DOMAINS}
    for f in all_findings:
        domain = _SCANNER_TO_DOMAIN.get(f.scanner, "配置安全")
        if domain in domain_findings:
            domain_findings[domain].append(f)

    # Only grade domains that are active (have findings or were scanned).
    # Domains with no findings get grade S.
    domain_grades: Dict[str, str] = {}
    for domain in _ALL_DOMAINS:
        domain_grades[domain] = _compute_domain_grade(domain_findings[domain])

    overall = _compute_overall_grade(domain_grades)
    return domain_grades, domain_findings, overall


def _level_badge(level: str) -> Text:
    if level in (CRIT, HIGH):
        return Text("High", style="bold red")
    if level == WARN:
        return Text("Warn", style="bold yellow")
    return Text("Info", style="dim")


def _status_icon(findings) -> str:
    if any(f.level in (CRIT, HIGH) for f in findings):
        return "Risk"
    if any(f.level == WARN for f in findings):
        return "Review"
    return "Pass"


def _status_style(status: str) -> str:
    if status == "Risk":
        return "bold red"
    if status == "Review":
        return "bold yellow"
    return "bold green"


def render_scan_report(
    adapter_name,
    adapter_version,
    all_findings_map: dict,
    output_format="text",
    output_path: Optional[str] = None,
):
    """Render scan results in text, JSON, or HTML."""
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_f = [f for fs in all_findings_map.values() for f in fs]
    nc = sum(1 for f in all_f if f.level in (CRIT, HIGH))
    nw = sum(1 for f in all_f if f.level == WARN)
    score = max(0, 100 - nc * 20 - nw * 5)

    from ..utils import device_fingerprint, record_scan

    dev_fp = device_fingerprint()
    record_scan(adapter_name, score, nc, nw, len(all_f))

    if output_format == "json":
        domain_grades, _df, overall_grade = _build_domain_report(all_f)
        out = {
            "tool": "ClawLock",
            "version": "1.1.0",
            "time": t,
            "adapter": adapter_name,
            "device": dev_fp,
            "score": score,
            "grade": overall_grade,
            "domain_grades": domain_grades,
            "findings": [
                {
                    "scanner": f.scanner,
                    "level": f.level,
                    "title": f.title,
                    "detail": f.detail,
                    "location": f.location,
                    "remediation": f.remediation,
                }
                for f in all_f
            ],
        }
        text = json.dumps(out, ensure_ascii=False, indent=2)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
            console.print(f"[green]Saved JSON report: {output_path}[/green]")
        else:
            console.print_json(text)
        return

    if output_format == "html":
        _render_html(
            adapter_name,
            adapter_version,
            t,
            score,
            nc,
            nw,
            all_findings_map,
            output_path,
        )
        return

    # --- Domain-level security grading ---
    domain_grades, domain_findings, overall_grade = _build_domain_report(all_f)

    console.print()
    console.print(
        Panel(
            "[bold]ClawLock Security Report[/bold]",
            subtitle=f"Time {t}  |  Adapter {adapter_name} {adapter_version}  |  Device {dev_fp}",
            border_style="cyan",
        )
    )
    sc = "red" if score < 60 else ("yellow" if score < 80 else "green")
    og_style = _GRADE_STYLES.get(overall_grade, "bold red")
    console.print(
        f"  Score [bold {sc}]{score}/100[/bold {sc}]"
        f"  |  Grade [{og_style}]{overall_grade}[/{og_style}]"
        f"  |  [red]High {nc}[/red]"
        f"  |  [yellow]Warn {nw}[/yellow]"
    )
    console.print()

    # Domain grading table
    grade_tbl = Table(
        box=box.ROUNDED, show_header=True, header_style="bold cyan", title="Security Domains"
    )
    grade_tbl.add_column("Domain", min_width=16)
    grade_tbl.add_column("Grade", min_width=8, justify="center")
    grade_tbl.add_column("High", min_width=6, justify="center")
    grade_tbl.add_column("Warn", min_width=6, justify="center")
    for domain in _ALL_DOMAINS:
        g = domain_grades[domain]
        dfs = domain_findings[domain]
        if not dfs and g == "S":
            # Skip domains with no findings and no scan coverage
            # But show them if they were part of the scan
            has_scanner = any(
                _SCANNER_TO_DOMAIN.get(f.scanner) == domain for f in all_f
            )
            if not has_scanner and not dfs:
                continue
        g_style = _GRADE_STYLES.get(g, "dim")
        dh = sum(1 for f in dfs if f.level in (CRIT, HIGH))
        dw = sum(1 for f in dfs if f.level == WARN)
        grade_tbl.add_row(
            domain,
            Text(g, style=g_style),
            str(dh) if dh else "-",
            str(dw) if dw else "-",
        )
    console.print(grade_tbl)
    console.print()

    # Per-check summary table
    summary = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    summary.add_column("Check", min_width=14)
    summary.add_column("Status", min_width=12)
    summary.add_column("Summary", min_width=40)
    for label, fs in all_findings_map.items():
        status = _status_icon(fs) if fs else "Pass"
        high_count = len([f for f in fs if f.level in (CRIT, HIGH)])
        warn_count = len([f for f in fs if f.level == WARN])
        summary.add_row(
            label,
            Text(status, style=_status_style(status)),
            f"{high_count} high, {warn_count} warn" if fs else "no issue found",
        )
    console.print(summary)
    console.print()

    step = 0
    for label, fs in all_findings_map.items():
        step += 1
        if not fs:
            continue
        console.print(f"[bold cyan]Step {step}: {label}[/bold cyan]")
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        tbl.add_column("Level", min_width=10)
        tbl.add_column("Finding", min_width=30)
        tbl.add_column("Detail", min_width=40)
        for f in fs:
            tbl.add_row(_level_badge(f.level), f.title[:60], f.detail[:80])
        console.print(tbl)
        for f in fs[:3]:
            if f.remediation:
                console.print(f"  [dim]Fix: {f.remediation}[/dim]")
        console.print()

    console.print(
        Panel(
            "[dim]Generated by ClawLock v1.1.0. Static analysis reflects the currently visible code and config only.[/dim]",
            border_style="dim",
        )
    )


def _render_html(
    adapter_name, adapter_version, t, score, nc, nw, all_findings_map, output_path
):
    """Generate a standalone HTML report."""
    all_f = [f for fs in all_findings_map.values() for f in fs]
    domain_grades, domain_findings, overall_grade = _build_domain_report(all_f)

    sc = "#e24b4a" if score < 60 else ("#ef9f27" if score < 80 else "#1d9e75")
    og_color = _GRADE_HTML_COLORS.get(overall_grade, "#e24b4a")

    # Build domain grading HTML rows
    domain_rows = ""
    for domain in _ALL_DOMAINS:
        g = domain_grades[domain]
        dfs = domain_findings[domain]
        if not dfs and g == "S":
            has_scanner = any(
                _SCANNER_TO_DOMAIN.get(f.scanner) == domain for f in all_f
            )
            if not has_scanner:
                continue
        g_color = _GRADE_HTML_COLORS.get(g, "#888")
        dh = sum(1 for f in dfs if f.level in (CRIT, HIGH))
        dw = sum(1 for f in dfs if f.level == WARN)
        domain_rows += (
            f'<tr><td>{html_mod.escape(domain)}</td>'
            f'<td style="text-align:center"><span style="background:{g_color};color:#fff;'
            f'padding:2px 12px;border-radius:4px;font-weight:700;font-size:14px">{g}</span></td>'
            f'<td style="text-align:center">{dh or "-"}</td>'
            f'<td style="text-align:center">{dw or "-"}</td></tr>\n'
        )

    rows = ""
    for label, fs in all_findings_map.items():
        if not fs:
            continue
        for f in fs:
            lv_color = (
                "#e24b4a"
                if f.level in (CRIT, HIGH)
                else ("#ef9f27" if f.level == WARN else "#888")
            )
            lv_text = (
                "High"
                if f.level in (CRIT, HIGH)
                else ("Warn" if f.level == WARN else "Info")
            )
            rows += (
                "<tr>"
                f'<td style="text-align:center"><span style="background:{lv_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{lv_text}</span></td>'
                f"<td>{html_mod.escape(label)}</td>"
                f'<td><b>{html_mod.escape(f.title[:80])}</b><br><span style="color:#666;font-size:13px">{html_mod.escape(f.detail[:120])}</span></td>'
                f'<td style="font-size:13px">{html_mod.escape(f.remediation[:100])}</td></tr>\n'
            )
    html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>ClawLock Security Report</title>
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
<h1>ClawLock Security Report</h1>
<p class="meta">Time {t} &nbsp; Adapter {adapter_name} {adapter_version}</p>
<p>Score <span class="score">{score}/100</span> &nbsp;
Grade <span style="display:inline-block;font-size:36px;font-weight:700;color:{og_color}">{overall_grade}</span> &nbsp;
High {nc} &nbsp; Warn {nw}</p>
<h2 style="margin-top:32px">Security Domains</h2>
<table><thead><tr><th>Domain</th><th style="width:80px;text-align:center">Grade</th><th style="width:60px;text-align:center">High</th><th style="width:60px;text-align:center">Warn</th></tr></thead>
<tbody>{domain_rows}</tbody></table>
<h2 style="margin-top:32px">Findings</h2>
<table><thead><tr><th style="width:80px">Level</th><th style="width:120px">Check</th><th>Finding</th><th style="width:200px">Fix</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="footer">Generated by ClawLock v1.1.0 | <a href="https://github.com/g1at/clawlock">github.com/g1at/clawlock</a><br>
Static analysis reflects the currently visible code and config only.</div></body></html>"""
    out = Path(output_path or "clawlock-report.html")
    out.write_text(html_content, encoding="utf-8")
    console.print(f"[green]Saved HTML report: {out.absolute()}[/green]")
    import webbrowser

    try:
        webbrowser.open(f"file://{out.absolute()}")
    except Exception:
        pass
