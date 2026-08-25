"""Render capability-graph composites as ordinary ClawLock findings."""

from __future__ import annotations

from typing import Iterable, List

from ..i18n import t
from . import WARN, Finding
from .capabilities import CapabilityAnalysis, analyze_capabilities


def findings_from_capabilities(
    analysis: CapabilityAnalysis,
    *,
    subject: str,
    scanner: str = "capability_graph",
) -> List[Finding]:
    findings: List[Finding] = []
    if not analysis.graph.complete:
        findings.append(
            Finding(
                "internal",
                WARN,
                t("能力链分析不完整", "Capability-chain analysis incomplete"),
                "; ".join(analysis.graph.diagnostics[:20]),
                subject,
                metadata={"scan_status": "error", "component": "capability_graph"},
            )
        )
    for detection in (*analysis.detections, *analysis.mismatches):
        evidence = [event.to_dict() for event in detection.evidence_path]
        final = detection.evidence_path[-1] if detection.evidence_path else None
        location = (
            f"{final.location}:{final.line}"
            if final is not None and final.line is not None
            else final.location
            if final is not None
            else subject
        )
        findings.append(
            Finding(
                scanner,
                detection.severity,
                f"[{detection.rule_id}] {detection.title}",
                detection.detail,
                location,
                " -> ".join(event.evidence[:100] for event in detection.evidence_path)[:500],
                remediation=t(
                    "拆断能力链，限制敏感数据、外部目的地、持久化或执行权限。",
                    "Break the chain by restricting sensitive data, external destinations, persistence, or execution authority.",
                ),
                metadata={
                    "rule_id": detection.rule_id,
                    "category": "COMPOSITE",
                    "component": "capability_graph",
                    "confidence_score": detection.confidence,
                    "evidence_path": evidence,
                    **dict(detection.metadata),
                },
            )
        )
    return findings


def correlate_findings(findings: Iterable[object], *, subject: str) -> List[Finding]:
    return findings_from_capabilities(
        analyze_capabilities(findings=findings), subject=subject
    )


__all__ = ["correlate_findings", "findings_from_capabilities"]
