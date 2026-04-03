"""ClawLock v1.4.0 report renderer - Rich terminal + JSON + HTML output."""

from __future__ import annotations

import html as html_mod
import json
import math
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..i18n import t
from ..scanners import CRIT, HIGH, WARN, Finding

console = Console()

# ---------------------------------------------------------------------------
# Security scoring system — domain-weighted exponential decay + S/A/B/C/D
# ---------------------------------------------------------------------------

# Map scanner names → security domains for domain-level grading.
_SCANNER_TO_DOMAIN: Dict[str, str] = {
    "config": t("配置安全", "Config Security"),
    "process": t("运行时安全", "Runtime Security"),
    "credential": t("凭据安全", "Credential Security"),
    "skill": t("供应链安全", "Supply Chain Security"),
    "skill_precheck": t("供应链安全", "Supply Chain Security"),
    "soul": t("提示词完整性", "Prompt Integrity"),
    "memory": t("提示词完整性", "Prompt Integrity"),
    "mcp": t("MCP 安全", "MCP Security"),
    "mcp_itp": t("MCP 安全", "MCP Security"),
    "mcp_deep": t("MCP 安全", "MCP Security"),
    "cve": t("漏洞管理", "Vulnerability Mgmt"),
    "cost": t("成本控制", "Cost Control"),
    "agent_scan": t("Agent 安全", "Agent Security"),
}

# All possible domains in display order, with weights.
_DOMAIN_WEIGHTS: Dict[str, int] = {
    t("供应链安全", "Supply Chain Security"): 24,
    t("MCP 安全", "MCP Security"): 18,
    t("漏洞管理", "Vulnerability Mgmt"): 18,
    t("配置安全", "Config Security"): 17,
    t("凭据安全", "Credential Security"): 8,
    t("提示词完整性", "Prompt Integrity"): 5,
    t("Agent 安全", "Agent Security"): 5,
    t("运行时安全", "Runtime Security"): 5,
    t("成本控制", "Cost Control"): 0,
}

_ALL_DOMAINS = list(_DOMAIN_WEIGHTS.keys())

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


# Per-CVE severity penalty for the CVE domain scoring.
# Maps metadata["severity"] → equivalent (high_count, warn_count) contribution.
_CVE_SEVERITY_PENALTY: Dict[str, Tuple[float, float]] = {
    "critical": (1.5, 0.0),   # 比普通 high 更重
    "high":     (1.0, 0.0),
    "medium":   (0.0, 1.5),
    "low":      (0.0, 0.6),
}


# Exponential decay coefficients — steeper than typical so that
# 3 warns ≈ 85, 1 high < 80 at the overall score level.
_HIGH_DECAY = 0.75   # per high/critical finding
_WARN_DECAY = 0.15   # per warn finding

# Per-finding baseline deduction applied to overall score so that
# different finding counts never collapse into the same integer.
_HIGH_DEDUCTION = 8.0
_WARN_DEDUCTION = 2.0


def _domain_score(findings: List[Finding], *, domain: str = "") -> int:
    """Compute a 0-100 score for a single domain.

    Hard rules applied first:
      - Any CRIT finding → domain score = 0
      - Any HIGH finding → domain score capped at 50
    Then exponential decay on remaining WARN findings.

    For CVE domain: maps CVE severity to equivalent levels before applying rules.
    """
    if not findings:
        return 100

    # Only INFO-level findings (e.g. "skipped", "timeout") → no real issue.
    if all(f.level not in (CRIT, HIGH, WARN) for f in findings):
        return 100

    if domain == t("漏洞管理", "Vulnerability Mgmt"):
        # CVE domain: determine effective severity from metadata.
        has_crit = any(
            (f.metadata.get("severity") if f.metadata else "") in ("critical",)
            for f in findings
        )
        has_high = any(
            (f.metadata.get("severity") if f.metadata else "") in ("high",)
            for f in findings
        )
        if has_crit:
            return 0
        # Count medium/low as warn-equivalent for decay.
        weighted_w = 0.0
        for f in findings:
            sev = f.metadata.get("severity", "medium") if f.metadata else "medium"
            _, w_pen = _CVE_SEVERITY_PENALTY.get(sev, (0.0, 1.0))
            weighted_w += w_pen
        cap = 50 if has_high else 99
        raw = 100.0 * math.exp(-_WARN_DECAY * weighted_w)
        return max(0, min(cap, int(round(raw))))

    # General domains: hard caps by severity level.
    has_crit = any(f.level == CRIT for f in findings)
    has_high = any(f.level == HIGH for f in findings)

    if has_crit:
        return 0
    if has_high:
        cap = 50
    else:
        cap = 99

    nw = sum(1 for f in findings if f.level == WARN)
    raw = 100.0 * math.exp(-_WARN_DECAY * nw)
    return max(0, min(cap, int(round(raw))))


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


def _score_to_grade(score: int) -> str:
    """Overall grade derived from score range."""
    if score >= 95:
        return "S"
    if score >= 80:
        return "A"
    if score >= 60:
        return "B"
    if score >= 30:
        return "C"
    return "D"


def _build_domain_report(
    all_findings: List[Finding],
) -> Tuple[Dict[str, str], Dict[str, List[Finding]], Dict[str, int], str, int]:
    """Classify findings into domains, compute per-domain grades/scores and overall.

    Returns (domain_grades, domain_findings, domain_scores, overall_grade, overall_score).
    """
    domain_findings: Dict[str, List[Finding]] = {d: [] for d in _ALL_DOMAINS}
    for f in all_findings:
        domain = _SCANNER_TO_DOMAIN.get(f.scanner, t("配置安全", "Config Security"))
        if domain in domain_findings:
            domain_findings[domain].append(f)

    domain_grades: Dict[str, str] = {}
    domain_scores: Dict[str, int] = {}
    for domain in _ALL_DOMAINS:
        domain_grades[domain] = _compute_domain_grade(domain_findings[domain])
        domain_scores[domain] = _domain_score(domain_findings[domain], domain=domain)

    # Weighted average score across domains.
    total_weight = sum(_DOMAIN_WEIGHTS.values())
    weighted_sum = sum(
        domain_scores[d] * _DOMAIN_WEIGHTS[d] for d in _ALL_DOMAINS
    )
    raw_score = weighted_sum / total_weight

    # Per-finding baseline deduction by severity, so that different
    # finding counts and severities never collapse into the same integer.
    for f in all_findings:
        if f.level in (CRIT, HIGH):
            raw_score -= _HIGH_DEDUCTION
        elif f.level == WARN:
            raw_score -= _WARN_DEDUCTION

    overall_score = max(0, min(100, int(round(raw_score))))

    # 100 is reserved for zero real findings (INFO-only is fine).
    has_real_findings = any(f.level in (CRIT, HIGH, WARN) for f in all_findings)
    if has_real_findings and overall_score >= 100:
        overall_score = 99

    # Overall grade derived from final score.
    overall_grade = _score_to_grade(overall_score)

    return domain_grades, domain_findings, domain_scores, overall_grade, overall_score


def _level_badge(level: str) -> Text:
    if level in (CRIT, HIGH):
        return Text(t("高危", "High"), style="bold red")
    if level == WARN:
        return Text(t("警告", "Warn"), style="bold yellow")
    return Text(t("信息", "Info"), style="dim")


def _status_icon(findings) -> str:
    if any(f.level in (CRIT, HIGH) for f in findings):
        return t("风险", "Risk")
    if any(f.level == WARN for f in findings):
        return t("待查", "Review")
    return t("通过", "Pass")


def _status_style(status: str) -> str:
    if status == t("风险", "Risk"):
        return "bold red"
    if status == t("待查", "Review"):
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
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_f = [f for fs in all_findings_map.values() for f in fs]
    nc = sum(1 for f in all_f if f.level in (CRIT, HIGH))
    nw = sum(1 for f in all_f if f.level == WARN)

    domain_grades, domain_findings, domain_scores, overall_grade, score = (
        _build_domain_report(all_f)
    )

    from ..utils import device_fingerprint, record_scan

    dev_fp = device_fingerprint()
    record_scan(adapter_name, score, nc, nw, len(all_f))

    if output_format == "json":
        out = {
            "tool": "ClawLock",
            "version": "1.4.0",
            "time": scan_time,
            "adapter": adapter_name,
            "device": dev_fp,
            "score": score,
            "grade": overall_grade,
            "domain_grades": domain_grades,
            "domain_scores": domain_scores,
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
            console.print(f"[green]{t('JSON 报告已保存', 'Saved JSON report')}: {output_path}[/green]")
        else:
            console.print_json(text)
        return

    if output_format == "html":
        _render_html(
            adapter_name,
            adapter_version,
            scan_time,
            all_findings_map,
            output_path,
        )
        return

    console.print()
    console.print(
        Panel(
            f"[bold]{t('ClawLock 安全报告', 'ClawLock Security Report')}[/bold]",
            subtitle=f"{t('时间', 'Time')} {scan_time}  |  {t('适配器', 'Adapter')} {adapter_name} {adapter_version}  |  {t('设备', 'Device')} {dev_fp}",
            border_style="cyan",
        )
    )
    sc = "red" if score < 60 else ("yellow" if score < 80 else "green")
    og_style = _GRADE_STYLES.get(overall_grade, "bold red")
    console.print(
        f"  {t('分数', 'Score')} [bold {sc}]{score}/100[/bold {sc}]"
        f"  |  {t('等级', 'Grade')} [{og_style}]{overall_grade}[/{og_style}]"
        f"  |  [red]{t('高危', 'High')} {nc}[/red]"
        f"  |  [yellow]{t('警告', 'Warn')} {nw}[/yellow]"
    )
    console.print()

    # Domain grading table
    grade_tbl = Table(
        box=box.ROUNDED, show_header=True, header_style="bold cyan", title=t("安全域", "Security Domains")
    )
    grade_tbl.add_column(t("域", "Domain"), min_width=16)
    grade_tbl.add_column(t("等级", "Grade"), min_width=8, justify="center")
    grade_tbl.add_column(t("分数", "Score"), min_width=8, justify="center")
    grade_tbl.add_column(t("高危", "High"), min_width=6, justify="center")
    grade_tbl.add_column(t("警告", "Warn"), min_width=6, justify="center")
    for domain in _ALL_DOMAINS:
        g = domain_grades[domain]
        dfs = domain_findings[domain]
        ds = domain_scores[domain]
        if not dfs and g == "S":
            has_scanner = any(
                _SCANNER_TO_DOMAIN.get(f.scanner) == domain for f in all_f
            )
            if not has_scanner and not dfs:
                continue
        g_style = _GRADE_STYLES.get(g, "dim")
        ds_style = "red" if ds < 60 else ("yellow" if ds < 80 else "green")
        dh = sum(1 for f in dfs if f.level in (CRIT, HIGH))
        dw = sum(1 for f in dfs if f.level == WARN)
        grade_tbl.add_row(
            domain,
            Text(g, style=g_style),
            Text(str(ds), style=ds_style),
            str(dh) if dh else "-",
            str(dw) if dw else "-",
        )
    console.print(grade_tbl)
    console.print()

    # Per-check summary table
    summary = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    summary.add_column(t("检查项", "Check"), min_width=14)
    summary.add_column(t("状态", "Status"), min_width=12)
    summary.add_column(t("摘要", "Summary"), min_width=40)
    for label, fs in all_findings_map.items():
        status = _status_icon(fs) if fs else t("通过", "Pass")
        high_count = len([f for f in fs if f.level in (CRIT, HIGH)])
        warn_count = len([f for f in fs if f.level == WARN])
        summary.add_row(
            label,
            Text(status, style=_status_style(status)),
            t(f"{high_count} 高危, {warn_count} 警告", f"{high_count} high, {warn_count} warn") if fs else t("未发现问题", "no issue found"),
        )
    console.print(summary)
    console.print()

    step = 0
    for label, fs in all_findings_map.items():
        step += 1
        if not fs:
            continue
        console.print(f"[bold cyan]{t('步骤', 'Step')} {step}: {label}[/bold cyan]")
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        tbl.add_column(t("级别", "Level"), min_width=10)
        tbl.add_column(t("发现", "Finding"), min_width=30)
        tbl.add_column(t("详情", "Detail"), min_width=40)
        for f in fs:
            tbl.add_row(_level_badge(f.level), f.title[:60], f.detail[:80])
        console.print(tbl)
        for f in fs[:3]:
            if f.remediation:
                console.print(f"  [dim]{t('修复', 'Fix')}: {f.remediation}[/dim]")
        console.print()

    console.print(
        Panel(
            f"[dim]{t('由 ClawLock v1.4.0 生成。静态分析仅反映当前可见的代码和配置。', 'Generated by ClawLock v1.4.0. Static analysis reflects the currently visible code and config only.')}[/dim]",
            border_style="dim",
        )
    )


def _render_html(
    adapter_name, adapter_version, scan_time, all_findings_map, output_path
):
    """Generate a standalone HTML report."""
    all_f = [f for fs in all_findings_map.values() for f in fs]
    domain_grades, domain_findings, domain_scores, overall_grade, score = (
        _build_domain_report(all_f)
    )
    nc = sum(1 for f in all_f if f.level in (CRIT, HIGH))
    nw = sum(1 for f in all_f if f.level == WARN)

    sc = "#e24b4a" if score < 60 else ("#ef9f27" if score < 80 else "#1d9e75")
    og_color = _GRADE_HTML_COLORS.get(overall_grade, "#e24b4a")
    cap_notice = ""

    # Build domain grading HTML rows
    domain_rows = ""
    for domain in _ALL_DOMAINS:
        g = domain_grades[domain]
        dfs = domain_findings[domain]
        ds = domain_scores[domain]
        if not dfs and g == "S":
            has_scanner = any(
                _SCANNER_TO_DOMAIN.get(f.scanner) == domain for f in all_f
            )
            if not has_scanner:
                continue
        g_color = _GRADE_HTML_COLORS.get(g, "#888")
        ds_color = "#e24b4a" if ds < 60 else ("#ef9f27" if ds < 80 else "#1d9e75")
        dh = sum(1 for f in dfs if f.level in (CRIT, HIGH))
        dw = sum(1 for f in dfs if f.level == WARN)
        domain_rows += (
            f'<tr><td>{html_mod.escape(domain)}</td>'
            f'<td style="text-align:center"><span style="background:{g_color};color:#fff;'
            f'padding:2px 12px;border-radius:4px;font-weight:700;font-size:14px">{g}</span></td>'
            f'<td style="text-align:center;color:{ds_color};font-weight:600">{ds}</td>'
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
                t("高危", "High")
                if f.level in (CRIT, HIGH)
                else (t("警告", "Warn") if f.level == WARN else t("信息", "Info"))
            )
            rows += (
                "<tr>"
                f'<td style="text-align:center"><span style="background:{lv_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{lv_text}</span></td>'
                f"<td>{html_mod.escape(label)}</td>"
                f'<td><b>{html_mod.escape(f.title[:80])}</b><br><span style="color:#666;font-size:13px">{html_mod.escape(f.detail[:120])}</span></td>'
                f'<td style="font-size:13px">{html_mod.escape(f.remediation[:100])}</td></tr>\n'
            )
    _title = t("ClawLock 安全报告", "ClawLock Security Report")
    _lbl_time = t("时间", "Time")
    _lbl_adapter = t("适配器", "Adapter")
    _lbl_score = t("分数", "Score")
    _lbl_grade = t("等级", "Grade")
    _lbl_high = t("高危", "High")
    _lbl_warn = t("警告", "Warn")
    _lbl_domains = t("安全域", "Security Domains")
    _lbl_domain = t("域", "Domain")
    _lbl_findings = t("发现", "Findings")
    _lbl_level = t("级别", "Level")
    _lbl_check = t("检查项", "Check")
    _lbl_finding = t("发现", "Finding")
    _lbl_fix = t("修复", "Fix")
    _footer1 = t("由 ClawLock v1.4.0 生成", "Generated by ClawLock v1.4.0")
    _footer2 = t("静态分析仅反映当前可见的代码和配置。", "Static analysis reflects the currently visible code and config only.")
    html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{_title}</title>
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
<h1>{_title}</h1>
<p class="meta">{_lbl_time} {scan_time} &nbsp; {_lbl_adapter} {adapter_name} {adapter_version}</p>
<p>{_lbl_score} <span class="score">{score}/100</span> &nbsp;
{_lbl_grade} <span style="display:inline-block;font-size:36px;font-weight:700;color:{og_color}">{overall_grade}</span> &nbsp;
{_lbl_high} {nc} &nbsp; {_lbl_warn} {nw}</p>
{cap_notice}
<h2 style="margin-top:32px">{_lbl_domains}</h2>
<table><thead><tr><th>{_lbl_domain}</th><th style="width:80px;text-align:center">{_lbl_grade}</th><th style="width:80px;text-align:center">{_lbl_score}</th><th style="width:60px;text-align:center">{_lbl_high}</th><th style="width:60px;text-align:center">{_lbl_warn}</th></tr></thead>
<tbody>{domain_rows}</tbody></table>
<h2 style="margin-top:32px">{_lbl_findings}</h2>
<table><thead><tr><th style="width:80px">{_lbl_level}</th><th style="width:120px">{_lbl_check}</th><th>{_lbl_finding}</th><th style="width:200px">{_lbl_fix}</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="footer">{_footer1} | <a href="https://github.com/g1at/clawlock">github.com/g1at/clawlock</a><br>
{_footer2}</div></body></html>"""
    out = Path(output_path or "clawlock-report.html")
    out.write_text(html_content, encoding="utf-8")
    console.print(f"[green]{t('HTML 报告已保存', 'Saved HTML report')}: {out.absolute()}[/green]")
    import webbrowser

    try:
        webbrowser.open(f"file://{out.absolute()}")
    except Exception:
        pass
