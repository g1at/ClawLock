"""Capability graph primitives for higher-order Agent/Skill detections.

The existing scanners are deliberately good at reporting individual signals.
This module turns those signals (or raw source text) into a small provenance
graph and only raises high-impact composite detections when a source can be
connected to a sink.  It has no network or execution side effects and is safe
to use on untrusted text.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


class Capability(str, Enum):
    PRIVATE_READ = "private_read"
    SECRET_READ = "secret_read"
    UNTRUSTED_INPUT = "untrusted_input"
    EXTERNAL_NETWORK = "external_network"
    EXTERNAL_WRITE = "external_write"
    PATH_WRITE = "path_write"
    COMMAND_EXEC = "command_exec"
    PERSISTENCE = "persistence"
    MEMORY_WRITE = "memory_write"
    PROMPT_WRITE = "prompt_write"
    DESTRUCTIVE = "destructive"
    APPROVAL_GUARD = "approval_guard"
    AUTH_GUARD = "auth_guard"
    APPROVAL_BYPASS = "approval_bypass"
    AUTH_BYPASS = "auth_bypass"


class EventRole(str, Enum):
    SOURCE = "source"
    SINK = "sink"
    EFFECT = "effect"
    GUARD = "guard"


@dataclass(frozen=True)
class CapabilityEvent:
    event_id: str
    capability: Capability
    role: EventRole
    location: str
    line: Optional[int]
    column: Optional[int]
    evidence: str
    produces: Tuple[str, ...] = ()
    consumes: Tuple[str, ...] = ()
    confidence: float = 0.75
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "capability": self.capability.value,
            "role": self.role.value,
            "location": self.location,
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "produces": list(self.produces),
            "consumes": list(self.consumes),
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class CapabilityEdge:
    source_id: str
    target_id: str
    reason: str


@dataclass(frozen=True)
class CompositeDetection:
    rule_id: str
    title: str
    severity: str
    confidence: float
    detail: str
    event_ids: Tuple[str, ...]
    evidence_path: Tuple[CapabilityEvent, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
            "event_ids": list(self.event_ids),
            "evidence_path": [event.to_dict() for event in self.evidence_path],
            "metadata": dict(self.metadata),
        }


@dataclass
class CapabilityGraph:
    events: Dict[str, CapabilityEvent] = field(default_factory=dict)
    edges: List[CapabilityEdge] = field(default_factory=list)
    declared: Set[Capability] = field(default_factory=set)
    diagnostics: List[str] = field(default_factory=list)
    complete: bool = True

    def add_event(self, event: CapabilityEvent) -> CapabilityEvent:
        self.events.setdefault(event.event_id, event)
        return self.events[event.event_id]

    def add_edge(self, source_id: str, target_id: str, reason: str) -> None:
        if source_id == target_id:
            return
        if source_id not in self.events or target_id not in self.events:
            raise KeyError("capability edges must reference existing events")
        edge = CapabilityEdge(source_id, target_id, reason)
        if edge not in self.edges:
            self.edges.append(edge)

    def events_for(self, *capabilities: Capability) -> List[CapabilityEvent]:
        wanted = set(capabilities)
        return [event for event in self.events.values() if event.capability in wanted]

    def successors(self, event_id: str) -> List[str]:
        return [edge.target_id for edge in self.edges if edge.source_id == event_id]

    def find_paths(
        self,
        source_capabilities: Iterable[Capability],
        sink_capabilities: Iterable[Capability],
        *,
        max_depth: int = 12,
    ) -> List[Tuple[CapabilityEvent, ...]]:
        sources = set(source_capabilities)
        sinks = set(sink_capabilities)
        paths: List[Tuple[CapabilityEvent, ...]] = []
        for source in self.events.values():
            if source.capability not in sources:
                continue
            queue: List[Tuple[str, Tuple[str, ...]]] = [(source.event_id, (source.event_id,))]
            while queue:
                current_id, path = queue.pop(0)
                if len(path) > max_depth:
                    continue
                current = self.events[current_id]
                if len(path) > 1 and current.capability in sinks:
                    paths.append(tuple(self.events[event_id] for event_id in path))
                    continue
                for next_id in self.successors(current_id):
                    if next_id not in path:
                        queue.append((next_id, (*path, next_id)))
        return paths

    def composite_detections(self) -> List[CompositeDetection]:
        detections: List[CompositeDetection] = []
        detections.extend(self._flow_detections(
            "CAP-EXFIL-001",
            "Sensitive/private data reaches an external write",
            {Capability.SECRET_READ, Capability.PRIVATE_READ},
            {Capability.EXTERNAL_WRITE},
            "A sensitive read is connected to an outbound data sink.",
            "critical",
        ))
        detections.extend(self._download_execute_detections())
        detections.extend(self._memory_autorun_detections())
        detections.extend(self._untrusted_sink_detections())
        return _deduplicate_detections(detections)

    def declared_mismatches(
        self, declared: Optional[Iterable[object]] = None
    ) -> List[CompositeDetection]:
        declared_set = self.declared if declared is None else normalize_declared(declared)
        relevant = {
            Capability.PRIVATE_READ,
            Capability.SECRET_READ,
            Capability.EXTERNAL_NETWORK,
            Capability.EXTERNAL_WRITE,
            Capability.PATH_WRITE,
            Capability.COMMAND_EXEC,
            Capability.PERSISTENCE,
            Capability.MEMORY_WRITE,
            Capability.PROMPT_WRITE,
            Capability.DESTRUCTIVE,
        }
        detections: List[CompositeDetection] = []
        for capability in sorted(relevant - declared_set, key=lambda item: item.value):
            actual = self.events_for(capability)
            if not actual:
                continue
            # A declaration mismatch is contextual evidence, but never a
            # high/critical finding on a single capability alone.
            detections.append(
                CompositeDetection(
                    rule_id="CAP-DECL-001",
                    title=f"Undeclared capability: {capability.value}",
                    severity="medium",
                    confidence=max(event.confidence for event in actual),
                    detail="Observed behavior is absent from the declared capability set.",
                    event_ids=tuple(event.event_id for event in actual),
                    evidence_path=tuple(actual),
                    metadata={
                        "capability": capability.value,
                        "declared": sorted(item.value for item in declared_set),
                    },
                )
            )
        return detections

    def _flow_detections(
        self,
        rule_id: str,
        title: str,
        sources: Set[Capability],
        sinks: Set[Capability],
        detail: str,
        severity: str,
    ) -> List[CompositeDetection]:
        detections: List[CompositeDetection] = []
        for path in self.find_paths(sources, sinks):
            if not _has_independent_evidence(path):
                continue
            detections.append(self._make_detection(
                rule_id, title, severity, detail, path
            ))
        return detections

    def _download_execute_detections(self) -> List[CompositeDetection]:
        detections: List[CompositeDetection] = []
        for path in self.find_paths(
            {Capability.EXTERNAL_NETWORK}, {Capability.COMMAND_EXEC}
        ):
            if path[0].metadata.get("operation") != "download":
                continue
            if not _has_independent_evidence(path):
                continue
            detections.append(self._make_detection(
                "CAP-EXEC-001",
                "Downloaded content reaches code or command execution",
                "critical",
                "Remote content is consumed by an execution sink.",
                path,
            ))
        return detections

    def _memory_autorun_detections(self) -> List[CompositeDetection]:
        detections: List[CompositeDetection] = []
        for path in self.find_paths(
            {Capability.MEMORY_WRITE}, {Capability.PERSISTENCE}
        ):
            if path[-1].metadata.get("operation") != "future_auto_run":
                continue
            untrusted_prefixes = self.find_paths(
                {Capability.UNTRUSTED_INPUT}, {Capability.MEMORY_WRITE}
            )
            prefix = next(
                (candidate for candidate in untrusted_prefixes if candidate[-1] == path[0]),
                (),
            )
            full_path = (*prefix[:-1], *path) if prefix else path
            severity = "high" if prefix else "medium"
            detections.append(self._make_detection(
                "CAP-MEM-001",
                "Persistent memory is consumed by a future automatic run",
                severity,
                "Content written to memory can influence a later unattended execution.",
                full_path,
            ))
        return detections

    def _untrusted_sink_detections(self) -> List[CompositeDetection]:
        detections: List[CompositeDetection] = []
        for path in self.find_paths(
            {Capability.UNTRUSTED_INPUT},
            {Capability.PATH_WRITE, Capability.COMMAND_EXEC},
        ):
            if not _has_independent_evidence(path):
                continue
            guarded = self._guard_between(path)
            confidence_penalty = 0.15 if guarded else 0.0
            detection = self._make_detection(
                "CAP-PATH-001",
                "Untrusted input reaches a write or execution sink",
                "high",
                "An externally controlled value influences a filesystem or execution operation.",
                path,
                confidence_penalty=confidence_penalty,
            )
            if guarded:
                detection = CompositeDetection(
                    **{
                        **detection.__dict__,
                        "metadata": {**detection.metadata, "guard_present": True},
                    }
                )
            detections.append(detection)
        return detections

    def _guard_between(self, path: Sequence[CapabilityEvent]) -> bool:
        lines = [event.line for event in path if event.line is not None]
        if not lines:
            return False
        lower, upper = min(lines), max(lines)
        locations = {event.location for event in path}
        return any(
            event.role == EventRole.GUARD
            and event.location in locations
            and event.line is not None
            and lower <= event.line <= upper
            for event in self.events.values()
        )

    def _make_detection(
        self,
        rule_id: str,
        title: str,
        severity: str,
        detail: str,
        path: Sequence[CapabilityEvent],
        *,
        confidence_penalty: float = 0.0,
    ) -> CompositeDetection:
        confidence = max(
            0.0,
            min(1.0, min(event.confidence for event in path) - confidence_penalty),
        )
        return CompositeDetection(
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence=round(confidence, 3),
            detail=detail,
            event_ids=tuple(event.event_id for event in path),
            evidence_path=tuple(path),
            metadata={"capability_chain": [event.capability.value for event in path]},
        )


@dataclass(frozen=True)
class CapabilityAnalysis:
    graph: CapabilityGraph
    detections: Tuple[CompositeDetection, ...]
    mismatches: Tuple[CompositeDetection, ...]


_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")
_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)"
)
_UNTRUSTED_RE = re.compile(
    r"(?i)(?:\b(?:req(?:uest)?|params|query|body|webhook|event)\b\s*(?:\.|\[)|"
    r"\b(?:tool_input|tool_args|user_input|webhook_payload)\b|"
    r"\b(?:sys|process)\.argv\b|\bstdin\b|\binput\s*\()"
)
_SECRET_ENV_RE = re.compile(
    r"(?i)(?:os\.environ|os\.getenv|process\.env|env\s*\[).*?"
    r"(?:token|secret|password|api[_-]?key|credential|private[_-]?key)"
)
_SECRET_PATH_RE = re.compile(
    r"(?i)(?:\.ssh[/\\](?:id_rsa|id_ed25519|authorized_keys)|"
    r"\.aws[/\\]credentials|\.netrc|\.npmrc|\.pypirc|/etc/(?:shadow|passwd)|"
    r"(?:^|[/\\])\.env(?:\b|[/\\]))"
)
_PRIVATE_PATH_RE = re.compile(
    r"(?i)(?:\.ssh[/\\](?!id_rsa|id_ed25519|authorized_keys)|"
    r"(?:documents|desktop|keychain|cookies|login data)[/\\])"
)
_READ_RE = re.compile(
    r"(?i)(?:\bopen\s*\(|\.read(?:_text|_bytes)?\s*\(|readFile(?:Sync)?\s*\(|"
    r"\bcat\s+)"
)
_NETWORK_RE = re.compile(
    r"(?i)(?:requests?\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete)|"
    r"axios(?:\.(?:get|post|put|patch|delete))?|\bfetch\s*\(|urllib\.request|"
    r"https?\.request|\bcurl\b|\bwget\b)"
)
_LOCAL_URL_RE = re.compile(
    r"(?i)https?://(?:localhost|127(?:\.\d+){0,3}|\[?::1\]?)(?::\d+)?(?:/|\b)"
)
_OUTBOUND_RE = re.compile(
    r"(?i)(?:\.(?:post|put|patch)\s*\(|method\s*=\s*['\"](?:POST|PUT|PATCH)|"
    r"\b(?:upload|send|webhook)\b|\bcurl\b.*(?:-d|--data|-F|--form|-T|--upload-file))"
)
_COMMAND_RE = re.compile(
    r"(?i)(?:\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen|check_call|check_output)\s*\(|"
    r"\bchild_process\.(?:exec|execSync|spawn|spawnSync|execFile)\s*\(|"
    r"(?<![.\w])(?:eval|exec|Function)\s*\(|\b(?:bash|sh)\s+-c\b|"
    r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:bash|sh|python)\b)"
)
_PATH_WRITE_RE = re.compile(
    r"(?i)(?:\bopen\s*\([^\n]*(?:['\"](?:w|a|x|wb|ab)['\"]|mode\s*=\s*['\"](?:w|a|x))|"
    r"\.(?:write_text|write_bytes)\s*\(|(?:fs\.)?writeFile(?:Sync)?\s*\(|"
    r"createWriteStream\s*\()"
)
_PERSISTENCE_RE = re.compile(
    r"(?i)(?:\bcrontab\b|systemctl\s+enable|schtasks(?:\.exe)?\b.*?/create|"
    r"CurrentVersion[/\\]Run(?:Once)?|launchctl\s+(?:load|bootstrap)|"
    r"authorized_keys|\b(?:auto[_-]?run(?:[_-]?memory)?|autorun(?:[_-]?memory)?|"
    r"run[_-]?on[_-]?start|next[_-]?session|startup[_-]?task|"
    r"load[_-]?memory[_-]?on[_-]?start)\b)"
)
_FUTURE_AUTO_RUN_RE = re.compile(
    r"(?i)(?:auto[_-]?run|autorun|run[_-]?on[_-]?start|next[_-]?session|"
    r"startup[_-]?task|load[_-]?memory[_-]?on[_-]?start)"
)
_MEMORY_WRITE_RE = re.compile(
    r"(?i)(?:\b(?:memory|history|long[_-]?term[_-]?memory|vectorstore)\b[^\n]{0,40}"
    r"(?:\.\s*(?:append|add|set|save|store|persist|write|upsert)\s*\(|"
    r"\b(?:save|store|persist|write|upsert)\w*memory\s*\())"
)
_PROMPT_WRITE_RE = re.compile(
    r"(?i)(?:system[_-]?(?:prompt|message)|developer[_-]?message|instructions?|prompt)"
    r"\s*(?:\+?=|\.append\s*\()"
)
_DESTRUCTIVE_RE = re.compile(
    r"(?i)(?:\brm\s+-rf\b|shutil\.rmtree\s*\(|\b(?:mkfs|diskpart|wipefs)\b|"
    r"\bdd\s+if=.*\bof=/dev/|format(?:\.com)?\s+[A-Za-z]:)"
)
_AUTH_GUARD_RE = re.compile(
    r"(?i)(?:@(?:login|required_auth|auth_required)|\b(?:require|check|verify|validate)"
    r"[_-]?(?:auth|token|jwt|permission|role|user)\s*\(|\bpermission[_-]?check\b)"
)
_APPROVAL_GUARD_RE = re.compile(
    r"(?i)(?:\b(?:require|request|check|await)[_-]?(?:approval|confirmation|consent)\s*\(|"
    r"\b(?:approved|confirmed|user_consent)\b\s*(?:==|is))"
)
_AUTH_BYPASS_RE = re.compile(
    r"(?i)(?:\b(?:skip|disable|bypass|no)[_-]?auth\b|\ballow[_-]?anonymous\b|"
    r"\bauth(?:entication)?\s*[:=]\s*(?:false|off|none|null))"
)
_APPROVAL_BYPASS_RE = re.compile(
    r"(?i)(?:\b(?:skip|bypass)[_-]?(?:approval|confirmation|consent)\b|"
    r"\bauto[_-]?approve\s*[:=]\s*(?:true|on|1)|\bno[_-]?confirmation\b|"
    r"assume\s+(?:approval|permission)\s+(?:is\s+)?granted)"
)


def _stable_event_id(
    capability: Capability,
    location: str,
    line: Optional[int],
    evidence: str,
    ordinal: int,
) -> str:
    raw = f"{capability.value}\0{location}\0{line}\0{evidence}\0{ordinal}"
    return "evt-" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _symbols(text: str) -> Set[str]:
    ignored = {
        "const", "let", "var", "def", "function", "return", "await", "async",
        "true", "false", "none", "null", "open", "read", "write", "data",
        "json", "text", "content", "mode", "http", "https", "com", "org",
    }
    return {
        match.group(0)
        for match in _IDENTIFIER_RE.finditer(text)
        if match.group(0).lower() not in ignored
    }


def events_from_text(
    text: str,
    *,
    location: str = "<memory>",
    language: str = "",
) -> CapabilityGraph:
    graph = CapabilityGraph()
    provenance: Dict[str, Set[str]] = {}
    location_events: List[CapabilityEvent] = []

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line[:16_384]
        assign_match = _ASSIGN_RE.match(line)
        assigned = assign_match.group(1) if assign_match else ""
        expression = line[assign_match.end():] if assign_match else line
        referenced = _symbols(expression)
        events: List[CapabilityEvent] = []

        def emit(
            capability: Capability,
            role: EventRole,
            *,
            confidence: float = 0.8,
            operation: str = "",
        ) -> CapabilityEvent:
            metadata: Dict[str, Any] = {"language": language} if language else {}
            if operation:
                metadata["operation"] = operation
            produces = (assigned,) if assigned and role == EventRole.SOURCE else ()
            event = CapabilityEvent(
                event_id=_stable_event_id(
                    capability, location, line_number, line.strip(), len(events)
                ),
                capability=capability,
                role=role,
                location=location,
                line=line_number,
                column=max(1, len(raw_line) - len(raw_line.lstrip()) + 1),
                evidence=line.strip()[:500],
                produces=produces,
                consumes=tuple(sorted(referenced)),
                confidence=confidence,
                metadata=metadata,
            )
            graph.add_event(event)
            events.append(event)
            location_events.append(event)
            return event

        if _UNTRUSTED_RE.search(expression) and not any(
            symbol in provenance for symbol in referenced
        ):
            emit(Capability.UNTRUSTED_INPUT, EventRole.SOURCE, confidence=0.82)
        if _SECRET_ENV_RE.search(line):
            emit(Capability.SECRET_READ, EventRole.SOURCE, confidence=0.9)
        if _READ_RE.search(line) and _SECRET_PATH_RE.search(line):
            emit(Capability.SECRET_READ, EventRole.SOURCE, confidence=0.95)
        elif _READ_RE.search(line) and _PRIVATE_PATH_RE.search(line):
            emit(Capability.PRIVATE_READ, EventRole.SOURCE, confidence=0.88)

        network_match = _NETWORK_RE.search(line)
        if network_match and not _LOCAL_URL_RE.search(line):
            outbound = bool(_OUTBOUND_RE.search(line))
            operation = "upload" if outbound else "download"
            emit(
                Capability.EXTERNAL_NETWORK,
                EventRole.SINK if outbound else EventRole.SOURCE,
                confidence=0.82,
                operation=operation,
            )
            if outbound:
                emit(
                    Capability.EXTERNAL_WRITE,
                    EventRole.SINK,
                    confidence=0.88,
                    operation="upload",
                )
        if _PATH_WRITE_RE.search(line):
            emit(Capability.PATH_WRITE, EventRole.SINK, confidence=0.86)
        if _COMMAND_RE.search(line):
            emit(Capability.COMMAND_EXEC, EventRole.SINK, confidence=0.9)
        if _MEMORY_WRITE_RE.search(line):
            emit(Capability.MEMORY_WRITE, EventRole.SINK, confidence=0.84)
        if _PROMPT_WRITE_RE.search(line):
            emit(Capability.PROMPT_WRITE, EventRole.SINK, confidence=0.82)
        if _PERSISTENCE_RE.search(line):
            emit(
                Capability.PERSISTENCE,
                EventRole.EFFECT,
                confidence=0.88,
                operation=(
                    "future_auto_run" if _FUTURE_AUTO_RUN_RE.search(line) else "persistence"
                ),
            )
        if _DESTRUCTIVE_RE.search(line):
            emit(Capability.DESTRUCTIVE, EventRole.SINK, confidence=0.92)
        if _AUTH_GUARD_RE.search(line):
            emit(Capability.AUTH_GUARD, EventRole.GUARD, confidence=0.8)
        if _APPROVAL_GUARD_RE.search(line):
            emit(Capability.APPROVAL_GUARD, EventRole.GUARD, confidence=0.8)
        if _AUTH_BYPASS_RE.search(line):
            emit(Capability.AUTH_BYPASS, EventRole.EFFECT, confidence=0.88)
        if _APPROVAL_BYPASS_RE.search(line):
            emit(Capability.APPROVAL_BYPASS, EventRole.EFFECT, confidence=0.88)

        # Connect previously produced values to every event that consumes them.
        for event in events:
            for symbol in event.consumes:
                for producer_id in provenance.get(symbol, set()):
                    graph.add_edge(producer_id, event.event_id, f"value:{symbol}")

        # A source and sink in the same expression (for example
        # exec(request.args) or curl URL | bash) is an explicit flow.
        sources = [event for event in events if event.role == EventRole.SOURCE]
        sinks = [
            event
            for event in events
            if event.role in {EventRole.SINK, EventRole.EFFECT}
        ]
        for source in sources:
            for sink in sinks:
                produced_value_used = bool(
                    set(source.produces) & set(sink.consumes)
                )
                direct_inline_source = not assigned
                explicit_pipeline = bool(
                    "|" in line
                    and source.capability == Capability.EXTERNAL_NETWORK
                    and sink.capability == Capability.COMMAND_EXEC
                )
                if produced_value_used or direct_inline_source or explicit_pipeline:
                    graph.add_edge(source.event_id, sink.event_id, "same-expression")

        if assigned:
            producer_ids = {
                event.event_id for event in events if event.role == EventRole.SOURCE
            }
            for symbol in referenced:
                producer_ids.update(provenance.get(symbol, set()))
            # Assignment is a taint kill when the RHS has no producer.
            provenance[assigned] = producer_ids

    # Future auto-run settings often reference memory by convention rather
    # than by the exact variable name.  Link only nearby, same-file evidence.
    memory_events = graph.events_for(Capability.MEMORY_WRITE)
    persistence_events = [
        event
        for event in graph.events_for(Capability.PERSISTENCE)
        if event.metadata.get("operation") == "future_auto_run"
    ]
    for memory_event in memory_events:
        for persistence_event in persistence_events:
            if (
                memory_event.location == persistence_event.location
                and memory_event.line is not None
                and persistence_event.line is not None
                and 0 <= persistence_event.line - memory_event.line <= 50
            ):
                graph.add_edge(
                    memory_event.event_id,
                    persistence_event.event_id,
                    "future-memory-consumer",
                )

    return graph


def events_from_source(
    source: Path,
    *,
    max_bytes: int = 2 * 1024 * 1024,
    language: str = "",
) -> CapabilityGraph:
    """Read one bounded source file and normalize its capability events."""
    graph = CapabilityGraph()
    try:
        if not source.is_file():
            raise OSError("source is not a regular file")
        if source.stat().st_size > max_bytes:
            raise ValueError(f"source exceeds {max_bytes} byte analysis limit")
        text = source.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        graph.complete = False
        graph.diagnostics.append(f"{source}: {exc}")
        return graph
    if not language:
        language = {
            ".py": "python",
            ".js": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".sh": "shell",
            ".ps1": "powershell",
        }.get(source.suffix.lower(), "")
    return events_from_text(text, location=str(source), language=language)


_FINDING_CATEGORY_MAP: Dict[str, Capability] = {
    "CREDENTIAL": Capability.SECRET_READ,
    "FILE_ACCESS": Capability.PRIVATE_READ,
    "EXFILTRATION": Capability.EXTERNAL_WRITE,
    "NETWORK": Capability.EXTERNAL_NETWORK,
    "SSRF": Capability.EXTERNAL_NETWORK,
    "EXECUTION": Capability.COMMAND_EXEC,
    "RCE": Capability.COMMAND_EXEC,
    "CMDI": Capability.COMMAND_EXEC,
    "PERSISTENCE": Capability.PERSISTENCE,
    "DESTRUCTION": Capability.DESTRUCTIVE,
    "MEMORY": Capability.MEMORY_WRITE,
    "AUTHZ": Capability.AUTH_BYPASS,
    "INJECTION": Capability.UNTRUSTED_INPUT,
    "PROMPT": Capability.PROMPT_WRITE,
    "APPROVAL": Capability.APPROVAL_BYPASS,
}


def events_from_findings(findings: Iterable[object]) -> CapabilityGraph:
    graph = CapabilityGraph()
    for ordinal, finding in enumerate(findings):
        if isinstance(finding, Mapping):
            get = finding.get
        else:
            def get(key: str, default: Any = None) -> Any:
                return getattr(finding, key, default)
        metadata = get("metadata", {}) or {}
        if metadata.get("component") == "dataflow_v2":
            source_meta = metadata.get("source", {})
            sink_meta = metadata.get("sink", {})
            labels = {str(value) for value in metadata.get("labels", [])}
            sink_kind = str(sink_meta.get("kind", ""))
            source_capability = (
                Capability.SECRET_READ
                if "secret" in labels
                else Capability.PRIVATE_READ
                if "file" in labels
                else Capability.UNTRUSTED_INPUT
            )
            sink_capability = {
                "network": Capability.EXTERNAL_WRITE,
                "tool-output": Capability.EXTERNAL_WRITE,
                "command-execution": Capability.COMMAND_EXEC,
                "code-execution": Capability.COMMAND_EXEC,
                "file-write": Capability.PATH_WRITE,
                "prompt": Capability.PROMPT_WRITE,
                "memory": Capability.MEMORY_WRITE,
            }.get(sink_kind)
            if sink_capability is not None and isinstance(source_meta, Mapping) and isinstance(
                sink_meta, Mapping
            ):
                source_location = str(source_meta.get("file") or get("location", "") or "<finding>")
                sink_location = str(sink_meta.get("file") or get("location", "") or "<finding>")
                try:
                    source_line = int(source_meta.get("line"))
                except (TypeError, ValueError):
                    source_line = None
                try:
                    sink_line = int(sink_meta.get("line"))
                except (TypeError, ValueError):
                    sink_line = None
                token = f"flow:{metadata.get('rule_id', ordinal)}:{ordinal}"
                source_evidence = str(source_meta.get("symbol") or get("title", ""))[:500]
                sink_evidence = str(sink_meta.get("symbol") or get("title", ""))[:500]
                source_event = CapabilityEvent(
                    event_id=_stable_event_id(
                        source_capability,
                        source_location,
                        source_line,
                        source_evidence,
                        ordinal * 2,
                    ),
                    capability=source_capability,
                    role=EventRole.SOURCE,
                    location=source_location,
                    line=source_line,
                    column=None,
                    evidence=source_evidence,
                    produces=(token,),
                    confidence=float(metadata.get("confidence_score", 0.75)),
                    metadata={**dict(metadata), "origin": "dataflow-finding"},
                )
                sink_event = CapabilityEvent(
                    event_id=_stable_event_id(
                        sink_capability,
                        sink_location,
                        sink_line,
                        sink_evidence,
                        ordinal * 2 + 1,
                    ),
                    capability=sink_capability,
                    role=EventRole.SINK,
                    location=sink_location,
                    line=sink_line,
                    column=None,
                    evidence=sink_evidence,
                    consumes=(token,),
                    confidence=float(metadata.get("confidence_score", 0.75)),
                    metadata={**dict(metadata), "origin": "dataflow-finding"},
                )
                graph.add_event(source_event)
                graph.add_event(sink_event)
                graph.add_edge(source_event.event_id, sink_event.event_id, "dataflow evidence path")
                continue
        category = str(metadata.get("category", "")).upper()
        title = str(get("title", ""))
        detail = str(get("detail", ""))
        snippet = str(get("snippet", ""))
        location = str(get("location", "") or "<finding>")
        capability = _FINDING_CATEGORY_MAP.get(category)
        if capability is None:
            combined = f"{title}\n{detail}"
            for token, candidate in (
                (r"(?i)exfil|外传", Capability.EXTERNAL_WRITE),
                (r"(?i)credential|secret|token|凭证", Capability.SECRET_READ),
                (r"(?i)exec|command|rce|执行", Capability.COMMAND_EXEC),
                (r"(?i)persist|cron|持久", Capability.PERSISTENCE),
                (r"(?i)memory|记忆", Capability.MEMORY_WRITE),
            ):
                if re.search(token, combined):
                    capability = candidate
                    break
        if capability is None:
            continue
        line = metadata.get("line")
        try:
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None
        if capability in {
            Capability.SECRET_READ,
            Capability.PRIVATE_READ,
            Capability.UNTRUSTED_INPUT,
        }:
            role = EventRole.SOURCE
        elif capability in {Capability.AUTH_BYPASS, Capability.APPROVAL_BYPASS}:
            role = EventRole.EFFECT
        else:
            role = EventRole.SINK
        evidence = snippet or title
        event = CapabilityEvent(
            event_id=_stable_event_id(capability, location, line, evidence, ordinal),
            capability=capability,
            role=role,
            location=location,
            line=line,
            column=None,
            evidence=evidence[:500],
            confidence=float(metadata.get("confidence_score", 0.65)),
            metadata={**dict(metadata), "origin": "finding"},
        )
        graph.add_event(event)
    return graph


_DECLARED_ALIASES: Dict[str, Set[Capability]] = {
    "filesystem": {Capability.PRIVATE_READ, Capability.SECRET_READ, Capability.PATH_WRITE},
    "file_read": {Capability.PRIVATE_READ, Capability.SECRET_READ},
    "file_write": {Capability.PATH_WRITE},
    "network": {Capability.EXTERNAL_NETWORK, Capability.EXTERNAL_WRITE},
    "http": {Capability.EXTERNAL_NETWORK, Capability.EXTERNAL_WRITE},
    "shell": {Capability.COMMAND_EXEC},
    "process": {Capability.COMMAND_EXEC},
    "memory": {Capability.MEMORY_WRITE},
    "prompt": {Capability.PROMPT_WRITE},
    "admin": {Capability.PERSISTENCE, Capability.DESTRUCTIVE},
}


def normalize_declared(values: Iterable[object]) -> Set[Capability]:
    result: Set[Capability] = set()
    for value in values:
        if isinstance(value, Capability):
            result.add(value)
            continue
        normalized = str(value).strip().lower().replace("-", "_")
        result.update(_DECLARED_ALIASES.get(normalized, set()))
        try:
            result.add(Capability(normalized))
        except ValueError:
            pass
    return result


def merge_graphs(*graphs: CapabilityGraph) -> CapabilityGraph:
    merged = CapabilityGraph()
    for graph in graphs:
        for event in graph.events.values():
            merged.add_event(event)
        for edge in graph.edges:
            merged.add_edge(edge.source_id, edge.target_id, edge.reason)
        merged.declared.update(graph.declared)
        merged.diagnostics.extend(graph.diagnostics)
        merged.complete = merged.complete and graph.complete
    return merged


def analyze_capabilities(
    *,
    text: str = "",
    findings: Iterable[object] = (),
    declared: Optional[Iterable[object]] = None,
    location: str = "<memory>",
    language: str = "",
    source: Optional[Path] = None,
) -> CapabilityAnalysis:
    graphs = []
    if text:
        graphs.append(events_from_text(text, location=location, language=language))
    finding_list = list(findings)
    if finding_list:
        graphs.append(events_from_findings(finding_list))
    if source is not None:
        graphs.append(events_from_source(source, language=language))
    graph = merge_graphs(*graphs) if graphs else CapabilityGraph()
    if declared is not None:
        graph.declared = normalize_declared(declared)
    return CapabilityAnalysis(
        graph=graph,
        detections=tuple(graph.composite_detections()),
        # An absent declaration contract is different from an explicit empty
        # contract.  Aggregate scanners must not label every observed
        # capability "undeclared" when the project has no capability manifest.
        mismatches=tuple(graph.declared_mismatches()) if declared is not None else (),
    )


def _has_independent_evidence(path: Sequence[CapabilityEvent]) -> bool:
    if len({event.event_id for event in path}) < 2:
        return False
    # Two different capability nodes are required. A single regex/finding can
    # therefore never manufacture a critical chain, while an explicit compound
    # expression such as ``curl URL | bash`` can still provide two operations
    # on one source line.
    return len({event.capability for event in path}) >= 2


def _deduplicate_detections(
    detections: Iterable[CompositeDetection],
) -> List[CompositeDetection]:
    unique: List[CompositeDetection] = []
    seen: Set[Tuple[str, str, str]] = set()
    for detection in detections:
        first = detection.evidence_path[0]
        last = detection.evidence_path[-1]
        key = (detection.rule_id, first.event_id, last.event_id)
        if key not in seen:
            seen.add(key)
            unique.append(detection)
    return unique


__all__ = [
    "Capability",
    "EventRole",
    "CapabilityEvent",
    "CapabilityEdge",
    "CapabilityGraph",
    "CompositeDetection",
    "CapabilityAnalysis",
    "events_from_text",
    "events_from_source",
    "events_from_findings",
    "normalize_declared",
    "merge_graphs",
    "analyze_capabilities",
]
