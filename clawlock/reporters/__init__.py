"""ClawLock v2.2.2 report renderer - Rich terminal + JSON + HTML output."""

from __future__ import annotations

import html as html_mod
import json
import math
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from rich.console import Console
from rich.text import Text

from ..i18n import current_lang, t
from ..scanners import CRIT, HIGH, INFO, WARN, Finding

import sys as _sys
if _sys.platform == "win32":
    import os as _os
    _os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:
        pass

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
}

_ALL_DOMAINS = list(_DOMAIN_WEIGHTS.keys())

_CHECK_LABEL_TO_DOMAIN: Dict[str, str] = {
    t("配置审计", "Config"): t("配置安全", "Config Security"),
    t("进程暴露", "Processes"): t("运行时安全", "Runtime Security"),
    t("凭证审计", "Credentials"): t("凭据安全", "Credential Security"),
    t("Skill 供应链", "Skills"): t("供应链安全", "Supply Chain Security"),
    t("提示词与记忆", "Prompt & Memory"): t("提示词完整性", "Prompt Integrity"),
    t("MCP", "MCP"): t("MCP 安全", "MCP Security"),
    t("CVE", "CVEs"): t("漏洞管理", "Vulnerability Mgmt"),
    t("Agent 安全", "Agent Security"): t("Agent 安全", "Agent Security"),
}

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

_LEVEL_ORDER = {
    CRIT: 0,
    HIGH: 1,
    WARN: 2,
    "medium": 2,
    "warn": 2,
    "warning": 2,
    "review": 2,
    INFO: 3,
}

_LEVEL_PANEL_COLORS = {
    CRIT: "bright_red",
    HIGH: "red",
    WARN: "yellow",
    INFO: "cyan",
}

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

    Uses the final normalized finding levels produced by the scanners.
    """
    if not findings:
        return 100

    # Only INFO-level findings (e.g. "skipped", "timeout") → no real issue.
    if all(f.level not in (CRIT, HIGH, WARN) for f in findings):
        return 100

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


def _active_domains_from_findings_map(
    all_findings_map: Dict[str, List[Finding]]
) -> Set[str]:
    active_domains: Set[str] = set()
    for label, findings in all_findings_map.items():
        domain = _CHECK_LABEL_TO_DOMAIN.get(label)
        if domain:
            active_domains.add(domain)
        for finding in findings:
            mapped = _SCANNER_TO_DOMAIN.get(finding.scanner)
            if mapped:
                active_domains.add(mapped)
    return active_domains


def _build_domain_report(
    all_findings: List[Finding],
    *,
    active_domains: Optional[Set[str]] = None,
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
        domain_scores[domain] = _domain_score(domain_findings[domain], domain=domain)
        domain_grades[domain] = _compute_domain_grade(domain_findings[domain])

    weighted_domains = [d for d in _ALL_DOMAINS if not active_domains or d in active_domains]
    if not weighted_domains:
        weighted_domains = list(_ALL_DOMAINS)

    # Weighted average score across executed domains.
    total_weight = sum(_DOMAIN_WEIGHTS[d] for d in weighted_domains)
    weighted_sum = sum(
        domain_scores[d] * _DOMAIN_WEIGHTS[d] for d in weighted_domains
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


def _score_bar(score: int, width: int = 30) -> Text:
    """Render a visual score bar with block characters."""
    filled = int(score / 100 * width)
    color = "red" if score < 60 else ("yellow" if score < 80 else "green")
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="dim")
    return bar


def _level_sort_key(level: str) -> int:
    return _LEVEL_ORDER.get(level, _LEVEL_ORDER[INFO])


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (_level_sort_key(f.level), f.title.lower(), f.detail.lower()),
    )


def _severity_counts(findings: List[Finding]) -> Tuple[int, int, int, int]:
    ordered = list(findings)
    return (
        sum(1 for f in ordered if f.level == CRIT),
        sum(1 for f in ordered if f.level == HIGH),
        sum(1 for f in ordered if f.level == WARN),
        sum(1 for f in ordered if f.level not in (CRIT, HIGH, WARN)),
    )


def _finding_level_style(level: str) -> str:
    return _LEVEL_PANEL_COLORS.get(level, _LEVEL_PANEL_COLORS[INFO])


def _findings_tone(findings: List[Finding]) -> str:
    if any(f.level in (CRIT, HIGH) for f in findings):
        return "risk"
    if any(f.level == WARN for f in findings):
        return "review"
    return "pass"


def _tone_message_style(tone: str) -> str:
    if tone == "risk":
        return "bold red"
    if tone == "review":
        return "bold yellow"
    return "bold green"


def _status_token(findings: List[Finding]) -> Tuple[str, str]:
    tone = _findings_tone(findings)
    if tone == "risk":
        return (t("风险", "RISK"), "red")
    if tone == "review":
        return (t("待查", "REVIEW"), "yellow")
    return (t("通过", "PASS"), "green")


def _print_section(title: str) -> None:
    console.print()
    console.print(Text(title, style="bold cyan"))


def _print_finding_block(
    finding: Finding,
    *,
    index: Optional[int] = None,
) -> None:
    prefix = f"{index}. " if index is not None else "- "
    header = Text()
    header.append(prefix, style="dim")
    header.append(f"[{_plain_level_label(finding.level)}] ", style=f"bold {_finding_level_style(finding.level)}")
    header.append(finding.title, style="bold")
    console.print(header)
    console.print(f"   {t('详情', 'Detail')}: {finding.detail}")
    if finding.location:
        console.print(f"   {t('位置', 'Location')}: {finding.location}")
    if finding.remediation:
        console.print(f"   {t('修复', 'Fix')}: {finding.remediation}", style="dim")


def _plain_level_label(level: str) -> str:
    if level == CRIT:
        return t("严重", "CRIT")
    if level == HIGH:
        return t("高危", "HIGH")
    if level == WARN:
        return t("警告", "WARN")
    return t("信息", "INFO")


def _plain_check_summary(findings: List[Finding]) -> str:
    crit_count, high_count, warn_count, info_count = _severity_counts(findings)
    parts = []
    if crit_count:
        parts.append(t(f"{crit_count} 严重", f"{crit_count} crit"))
    if high_count:
        parts.append(t(f"{high_count} 高危", f"{high_count} high"))
    if warn_count:
        parts.append(t(f"{warn_count} 警告", f"{warn_count} warn"))
    if info_count and not parts:
        parts.append(t(f"{info_count} 信息", f"{info_count} info"))
    return ", ".join(parts) if parts else t("未发现问题", "no issue found")


def render_focus_report(
    title: str,
    subject: str,
    findings: List[Finding],
    *,
    ok_message: str,
    review_message: str,
    risk_message: str,
    limit: int = 5,
) -> None:
    ordered = _sorted_findings(findings)
    crit_count, high_count, warn_count, info_count = _severity_counts(ordered)
    tone = _findings_tone(ordered)
    message = ok_message
    if tone == "risk":
        message = risk_message
    elif tone == "review":
        message = review_message

    _print_section(f"## {title}")
    console.print(f"{t('对象', 'Target')}: [bold]{subject}[/bold]")
    console.print(Text(message, style=_tone_message_style(tone)))
    console.print(
        Text.from_markup(
            f"[bold]{t('摘要', 'Summary')}:[/bold] "
            f"{t('高危', 'High Risk')} {crit_count + high_count} | "
            f"{t('待关注', 'Needs Review')} {warn_count} | "
            f"{t('信息项', 'Info')} {info_count} | "
            f"{t('总发现', 'Total')} {len(ordered)}"
        )
    )

    if ordered:
        _print_section(f"### {t('重点发现', 'Key Findings')}")
        for idx, finding in enumerate(ordered[:limit], start=1):
            _print_finding_block(finding, index=idx)
        if len(ordered) > limit:
            console.print(
                Text(
                    t(
                        f"其余 {len(ordered) - limit} 项已省略。",
                        f"{len(ordered) - limit} additional item(s) omitted.",
                    ),
                    style="dim",
                )
            )
    else:
        console.print(
            Text(
                t("当前未发现需要优先处理的问题。", "No issues require immediate attention."),
                style="green",
            )
        )


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
    active_domains = _active_domains_from_findings_map(all_findings_map)
    n_crit = sum(1 for f in all_f if f.level == CRIT)
    n_high = sum(1 for f in all_f if f.level == HIGH)
    nc = n_crit + n_high  # combined for scoring compatibility
    nw = sum(1 for f in all_f if f.level == WARN)

    domain_grades, domain_findings, domain_scores, overall_grade, score = (
        _build_domain_report(all_f, active_domains=active_domains)
    )

    from ..utils import device_fingerprint, record_scan

    dev_fp = device_fingerprint()
    record_scan(adapter_name, score, nc, nw, len(all_f))

    if output_format == "json":
        out = {
            "tool": "ClawLock",
            "version": "2.2.2",
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

    grade_style = _GRADE_STYLES.get(overall_grade, "bold red")
    sc_color = "red" if score < 60 else ("yellow" if score < 80 else "green")

    _print_section(f"# {t('ClawLock 安全报告', 'ClawLock Security Report')}")
    console.print(
        Text.from_markup(
            f"[bold]{t('时间', 'Time')}:[/bold] {scan_time}   "
            f"[bold]{t('适配器', 'Adapter')}:[/bold] {adapter_name} {adapter_version}   "
            f"[bold]{t('设备', 'Device')}:[/bold] {dev_fp}"
        )
    )
    score_line = Text()
    score_line.append(f"{t('评分', 'Score')}: ", style="bold")
    score_line.append(f"{score}/100", style=f"bold {sc_color}")
    score_line.append("   ")
    score_line.append(f"{t('等级', 'Grade')}: ", style="bold")
    score_line.append(overall_grade, style=grade_style)
    score_line.append("   ")
    score_line.append(f"{t('严重', 'Crit')}: ", style="bold")
    score_line.append(str(n_crit), style="bold bright_red")
    score_line.append("   ")
    score_line.append(f"{t('高危', 'High')}: ", style="bold")
    score_line.append(str(n_high), style="bold red")
    score_line.append("   ")
    score_line.append(f"{t('警告', 'Warn')}: ", style="bold")
    score_line.append(str(nw), style="bold yellow")
    console.print(score_line)
    console.print(f"{t('评分条', 'Score Bar')}: ", end="")
    console.print(_score_bar(score))

    _print_section(f"## {t('安全域评级', 'Security Domain Grades')}")
    for domain in _ALL_DOMAINS:
        if active_domains and domain not in active_domains:
            continue
        findings = domain_findings[domain]
        grade = domain_grades[domain]
        crit_count, high_count, warn_count, _ = _severity_counts(findings)
        line = Text()
        line.append(f"- {domain}: ", style="default")
        line.append(grade, style=_GRADE_STYLES.get(grade, "dim"))
        line.append(f"  {domain_scores[domain]}/100", style="bold")
        if crit_count:
            line.append(f"  {t('严重', 'Crit')} {crit_count}", style="bright_red")
        if high_count:
            line.append(f"  {t('高危', 'High')} {high_count}", style="red")
        if warn_count:
            line.append(f"  {t('警告', 'Warn')} {warn_count}", style="yellow")
        console.print(line)

    _print_section(f"## {t('检查摘要', 'Check Summary')}")
    for label, findings in all_findings_map.items():
        token, color = _status_token(findings)
        summary_line = Text()
        summary_line.append(f"- {label}: ", style="default")
        summary_line.append(token, style=f"bold {color}")
        summary_line.append(f"  {_plain_check_summary(findings)}", style="default")
        console.print(summary_line)

    _print_section(f"## {t('优先处理', 'Priority Queue')}")
    priority_findings = [f for f in all_f if f.level in (CRIT, HIGH, WARN)]
    if priority_findings:
        for idx, finding in enumerate(_sorted_findings(priority_findings)[:5], start=1):
            _print_finding_block(finding, index=idx)
        if len(priority_findings) > 5:
            console.print(
                Text(
                    t(
                        f"其余 {len(priority_findings) - 5} 项请查看下方详细发现。",
                        f"{len(priority_findings) - 5} more item(s) appear in the detailed findings below.",
                    ),
                    style="dim",
                )
            )
    else:
        console.print(Text(t("当前未发现需要优先处理的问题。", "No issues require immediate attention."), style="green"))

    for domain in _ALL_DOMAINS:
        dfs = domain_findings[domain]
        if not dfs:
            continue
        g = domain_grades[domain]
        ds = domain_scores[domain]
        _print_section(f"### {domain} · {t('等级', 'Grade')} {g} · {t('分数', 'Score')} {ds}/100")
        for finding in _sorted_findings(dfs):
            _print_finding_block(finding)

    console.print()
    console.print(
        Text(
            t(
                "注：静态分析仅反映当前可见的代码和配置。",
                "Note: static analysis reflects the currently visible code and config only.",
            ),
            style="dim",
        )
    )


def _render_html(
    adapter_name, adapter_version, scan_time, all_findings_map, output_path
):
    """Generate a modern standalone HTML report with dark mode support."""
    all_f = [f for fs in all_findings_map.values() for f in fs]
    active_domains = _active_domains_from_findings_map(all_findings_map)
    domain_grades, domain_findings, domain_scores, overall_grade, score = (
        _build_domain_report(all_f, active_domains=active_domains)
    )
    n_crit = sum(1 for f in all_f if f.level == CRIT)
    n_high = sum(1 for f in all_f if f.level == HIGH)
    nw = sum(1 for f in all_f if f.level == WARN)

    sc = _GRADE_HTML_COLORS.get(overall_grade, "#e24b4a")
    angle = int(score * 3.6)

    # Build domain cards
    domain_cards: List[str] = []
    for domain in _ALL_DOMAINS:
        if active_domains and domain not in active_domains:
            continue
        g = domain_grades[domain]
        dfs = domain_findings[domain]
        ds = domain_scores[domain]
        g_color = _GRADE_HTML_COLORS.get(g, "#888")
        dc = sum(1 for f in dfs if f.level == CRIT)
        dh = sum(1 for f in dfs if f.level == HIGH)
        dw = sum(1 for f in dfs if f.level == WARN)
        stats_parts = []
        if dc:
            stats_parts.append(f'{dc} {t("严重", "crit")}')
        if dh:
            stats_parts.append(f'{dh} {t("高危", "high")}')
        stats_parts.append(f'{dw} {t("警告", "warn")}')
        domain_cards.append(
            f'<div class="domain-card" style="border-left:4px solid {g_color}">'
            f'<div class="domain-header">'
            f'<span class="domain-name">{html_mod.escape(domain)}</span>'
            f'<span class="domain-grade" style="color:{g_color}">{g}</span>'
            f'</div>'
            f'<div class="domain-score" style="color:{g_color}">{ds}/100</div>'
            f'<div class="domain-stats">{" · ".join(stats_parts)}</div>'
            f'</div>'
        )
    domain_html = "\n".join(domain_cards)

    # Build finding sections grouped by check label
    findings_parts: List[str] = []
    for label, fs in all_findings_map.items():
        if not fs:
            continue
        items: List[str] = []
        for f in fs:
            if f.level == CRIT:
                badge_cls, badge_text = "badge-crit", t("严重", "Crit")
            elif f.level == HIGH:
                badge_cls, badge_text = "badge-high", t("高危", "High")
            elif f.level == WARN:
                badge_cls, badge_text = "badge-warn", t("警告", "Warn")
            else:
                badge_cls, badge_text = "badge-info", t("信息", "Info")
            fix_html = (
                f'<p class="fix">💡 {t("修复", "Fix")}: {html_mod.escape(f.remediation)}</p>'
                if f.remediation else ""
            )
            loc_html = (
                f'<p class="loc">📍 {html_mod.escape(f.location)}</p>'
                if f.location else ""
            )
            items.append(
                f'<details class="finding">'
                f'<summary><span class="badge {badge_cls}">{badge_text}</span> '
                f'{html_mod.escape(f.title)}</summary>'
                f'<div class="finding-body">'
                f'<p>{html_mod.escape(f.detail)}</p>'
                f'{fix_html}{loc_html}'
                f'</div></details>'
            )
        findings_parts.append(
            f'<h3>{html_mod.escape(label)}</h3>\n' + "\n".join(items)
        )
    findings_html = "\n".join(findings_parts)

    _title = t("ClawLock 安全报告", "ClawLock Security Report")
    _lbl_domains = t("安全域评级", "Security Domains")
    _lbl_findings = t("详细发现", "Detailed Findings")
    _footer1 = t("由 ClawLock v2.2.2 生成", "Generated by ClawLock v2.2.2")
    _footer2 = t("静态分析仅反映当前可见的代码和配置。",
                  "Static analysis reflects the currently visible code and config only.")

    html_lang = "zh" if current_lang() == "zh" else "en"

    html_content = f"""<!DOCTYPE html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_title}</title>
<style>
:root {{
  --bg: #fafaf8; --text: #333; --text-dim: #888;
  --card-bg: #fff; --card-shadow: 0 2px 8px rgba(0,0,0,0.06);
  --border: #e8e8e0; --hover-bg: #f5f5ef;
  --header-bg: linear-gradient(135deg, #0d7377 0%, #14919b 100%);
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #1a1a2e; --text: #e0e0e0; --text-dim: #999;
    --card-bg: #252540; --card-shadow: 0 2px 8px rgba(0,0,0,0.3);
    --border: #333350; --hover-bg: #2a2a4a;
    --header-bg: linear-gradient(135deg, #0d4a4d 0%, #0e6b73 100%);
  }}
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 1000px; margin: 0 auto; padding: 24px;
       background: var(--bg); color: var(--text); line-height: 1.6; }}
.header {{ background: var(--header-bg); color: #fff; border-radius: 16px;
           padding: 32px; margin-bottom: 24px; display: flex;
           align-items: center; gap: 32px; flex-wrap: wrap; }}
.header h1 {{ font-size: 24px; font-weight: 700; }}
.header .meta {{ font-size: 13px; opacity: 0.85; margin-top: 4px; }}
.score-circle {{ width: 110px; height: 110px; border-radius: 50%; flex-shrink: 0;
  background: conic-gradient({sc} 0deg {angle}deg, rgba(255,255,255,0.2) {angle}deg 360deg);
  display: flex; align-items: center; justify-content: center; }}
.score-inner {{ width: 82px; height: 82px; border-radius: 50%;
  background: rgba(0,0,0,0.25); display: flex; flex-direction: column;
  align-items: center; justify-content: center; }}
.score-num {{ font-size: 28px; font-weight: 800; color: #fff; }}
.score-grade {{ font-size: 14px; font-weight: 600; opacity: 0.9; color: #fff; }}
.stats {{ display: flex; gap: 16px; margin-top: 8px; }}
.stat {{ font-size: 14px; opacity: 0.9; }}
h2 {{ font-size: 18px; font-weight: 700; margin: 28px 0 16px; }}
.domain-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
               gap: 12px; margin-bottom: 24px; }}
.domain-card {{ background: var(--card-bg); border-radius: 10px; padding: 16px;
               box-shadow: var(--card-shadow); transition: transform 0.15s; }}
.domain-card:hover {{ transform: translateY(-2px); }}
.domain-header {{ display: flex; justify-content: space-between; align-items: center; }}
.domain-name {{ font-size: 13px; font-weight: 600; }}
.domain-grade {{ font-size: 22px; font-weight: 800; }}
.domain-score {{ font-size: 20px; font-weight: 700; margin: 4px 0; }}
.domain-stats {{ font-size: 12px; color: var(--text-dim); }}
h3 {{ font-size: 15px; font-weight: 600; margin: 20px 0 8px;
     padding-bottom: 6px; border-bottom: 2px solid var(--border); }}
.finding {{ background: var(--card-bg); border-radius: 8px; margin-bottom: 6px;
           box-shadow: var(--card-shadow); }}
.finding summary {{ padding: 12px 16px; cursor: pointer; font-size: 14px;
                   list-style: none; display: flex; align-items: center; gap: 8px; }}
.finding summary::-webkit-details-marker {{ display: none; }}
.finding summary::before {{ content: "\\25B8"; font-size: 12px; color: var(--text-dim);
                           transition: transform 0.2s; }}
.finding[open] summary::before {{ transform: rotate(90deg); }}
.finding-body {{ padding: 0 16px 14px 36px; font-size: 13px; color: var(--text-dim); }}
.finding-body p {{ margin: 4px 0; }}
.fix {{ color: #14919b; }}
.loc {{ font-family: monospace; font-size: 12px; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px;
         font-size: 11px; font-weight: 600; color: #fff; }}
.badge-crit {{ background: #c0392b; }}
.badge-high {{ background: #e24b4a; }}
.badge-warn {{ background: #ef9f27; }}
.badge-info {{ background: #888; }}
.footer {{ margin-top: 40px; padding: 20px; background: var(--card-bg); border-radius: 12px;
          font-size: 13px; color: var(--text-dim); text-align: center;
          box-shadow: var(--card-shadow); }}
.footer a {{ color: #14919b; text-decoration: none; }}
.footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="header">
  <div class="score-circle">
    <div class="score-inner">
      <span class="score-num">{score}</span>
      <span class="score-grade">{overall_grade}</span>
    </div>
  </div>
  <div>
    <h1>{_title}</h1>
    <div class="meta">{scan_time} · {adapter_name} {adapter_version}</div>
    <div class="stats">
      <span class="stat">{t('🔴 严重', '🔴 Crit')} {n_crit}</span>
      <span class="stat">{t('🟠 高危', '🟠 High')} {n_high}</span>
      <span class="stat">{t('🟡 警告', '🟡 Warn')} {nw}</span>
    </div>
  </div>
</div>

<h2>{t('📊', '📊')} {_lbl_domains}</h2>
<div class="domain-grid">
{domain_html}
</div>

<h2>{t('🔍', '🔍')} {_lbl_findings}</h2>
{findings_html}

<div class="footer">
  {_footer1} · <a href="https://github.com/g1at/clawlock">github.com/g1at/clawlock</a><br>
  {_footer2}
</div>
</body>
</html>"""

    out = Path(output_path or "clawlock-report.html").expanduser().resolve()
    out.write_text(html_content, encoding="utf-8")
    console.print(f"[green]{t('HTML 报告已保存', 'Saved HTML report')}: {out}[/green]")
    import webbrowser

    opened = False
    try:
        opened = bool(webbrowser.open(out.as_uri()))
    except Exception:
        opened = False

    if not opened:
        console.print(
            f"[yellow]{t('未能自动打开浏览器，请手动打开该文件', 'Could not open a browser automatically. Open this file manually')}: {out}[/yellow]"
        )

