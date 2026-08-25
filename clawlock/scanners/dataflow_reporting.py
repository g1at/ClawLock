"""Convert Detection Core v2 results into ClawLock's public Finding model."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from ..i18n import t
from . import CRIT, HIGH, INFO, WARN, Finding
from .dataflow import AnalysisResult, Confidence, FlowDetection, FlowLabel, SinkKind


_CATEGORY: Dict[SinkKind, str] = {
    SinkKind.COMMAND: "CMDI",
    SinkKind.CODE_EXECUTION: "RCE",
    SinkKind.NETWORK: "NETWORK",
    SinkKind.FILE_WRITE: "FILE_ACCESS",
    SinkKind.PROMPT: "INJECTION",
    SinkKind.MEMORY: "MEMORY",
    SinkKind.LOG: "DATA_EXPOSURE",
    SinkKind.TOOL_OUTPUT: "DATA_EXPOSURE",
}


def _severity(detection: FlowDetection) -> str:
    secret = FlowLabel.SECRET in detection.labels
    sink = detection.sink.kind
    if secret and sink in {SinkKind.NETWORK, SinkKind.LOG, SinkKind.TOOL_OUTPUT}:
        return CRIT
    if sink in {SinkKind.COMMAND, SinkKind.CODE_EXECUTION}:
        return CRIT if detection.confidence == Confidence.HIGH else HIGH
    if sink in {SinkKind.NETWORK, SinkKind.FILE_WRITE, SinkKind.PROMPT, SinkKind.MEMORY}:
        return HIGH if detection.confidence != Confidence.LOW else WARN
    return WARN


def _display_location(path: str, root: Path | None) -> str:
    source = Path(path)
    if root is not None:
        try:
            return str(source.resolve().relative_to(root.resolve()))
        except (OSError, ValueError):
            pass
    return path


def findings_from_dataflow(
    result: AnalysisResult,
    *,
    scanner: str,
    root: Path | None = None,
) -> List[Finding]:
    """Preserve precise source/sink/path evidence and fail closed on gaps."""

    findings: List[Finding] = []
    for detection in result.detections:
        sink = detection.sink
        source = detection.source
        source_location = _display_location(source.span.file, root)
        sink_location = _display_location(sink.span.file, root)
        evidence_path = [
            {
                "kind": step.kind,
                "symbol": step.symbol,
                "file": _display_location(step.span.file, root),
                "line": step.span.line,
                "column": step.span.column,
                "detail": step.detail,
            }
            for step in detection.path.steps
        ]
        labels = sorted(label.value for label in detection.labels)
        category = _CATEGORY[sink.kind]
        if FlowLabel.SECRET in detection.labels and sink.kind in {
            SinkKind.NETWORK,
            SinkKind.LOG,
            SinkKind.TOOL_OUTPUT,
        }:
            category = "EXFILTRATION"
        findings.append(
            Finding(
                scanner=scanner,
                level=_severity(detection),
                title=f"[{detection.rule_id}] {detection.message}",
                detail=t(
                    f"多标签数据流从 {source.kind} {source.symbol}（{source_location}:{source.span.line}）"
                    f"到达 {sink.kind.value} {sink.symbol}（{sink_location}:{sink.span.line}）。",
                    f"Multi-label flow from {source.kind} {source.symbol} "
                    f"({source_location}:{source.span.line}) reaches {sink.kind.value} "
                    f"{sink.symbol} ({sink_location}:{sink.span.line}).",
                ),
                location=f"{sink_location}:{sink.span.line}:{sink.span.column}",
                snippet=" -> ".join(step["symbol"] for step in evidence_path)[:500],
                remediation=t(
                    "在信任边界执行与目标 sink 匹配的白名单校验，并最小化该 sink 的权限。",
                    "Apply a sink-specific allowlist at the trust boundary and minimize sink authority.",
                ),
                metadata={
                    "rule_id": detection.rule_id,
                    "category": category,
                    "component": "dataflow_v2",
                    "confidence": detection.confidence.value,
                    "confidence_score": {
                        Confidence.HIGH: 0.95,
                        Confidence.MEDIUM: 0.78,
                        Confidence.LOW: 0.55,
                    }[detection.confidence],
                    "labels": labels,
                    "source": {
                        "kind": source.kind,
                        "symbol": source.symbol,
                        "file": source_location,
                        "line": source.span.line,
                        "column": source.span.column,
                    },
                    "sink": {
                        "kind": sink.kind.value,
                        "symbol": sink.symbol,
                        "file": sink_location,
                        "line": sink.span.line,
                        "column": sink.span.column,
                    },
                    "evidence_path": evidence_path,
                    "engine": result.engine,
                },
            )
        )
    if not result.complete:
        detail = "; ".join(
            f"{diagnostic.code}: {diagnostic.message}"
            for diagnostic in result.diagnostics[:20]
        ) or t("数据流覆盖不完整。", "Data-flow coverage was incomplete.")
        findings.append(
            Finding(
                scanner="internal",
                level=WARN,
                title=t("Detection Core v2 分析不完整", "Detection Core v2 analysis incomplete"),
                detail=detail,
                location=str(root or ""),
                metadata={
                    "scan_status": "error",
                    "component": "dataflow_v2",
                    "engine": result.engine,
                    "language": result.language,
                    "degraded": result.degraded,
                    "files_analyzed": result.files_analyzed,
                },
            )
        )
    elif result.diagnostics:
        findings.append(
            Finding(
                scanner=scanner,
                level=INFO,
                title=t("Detection Core v2 诊断", "Detection Core v2 diagnostics"),
                detail="; ".join(
                    f"{diagnostic.code}: {diagnostic.message}"
                    for diagnostic in result.diagnostics[:20]
                ),
                location=str(root or ""),
                metadata={
                    "component": "dataflow_v2",
                    "engine": result.engine,
                    "files_analyzed": result.files_analyzed,
                },
            )
        )
    return findings


__all__ = ["findings_from_dataflow"]
