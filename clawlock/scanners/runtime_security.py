"""Static container/runtime isolation audit with fail-closed parsing.

The module is intentionally independent of the core ``Finding`` model.  It
accepts a Dockerfile, Compose/Kubernetes YAML, or a directory containing those
files and returns neutral ``RuntimeSecurityIssue`` records.  It never builds an
image, talks to a cluster, follows filesystem links, or resolves remote YAML.

High/critical findings are reserved for explicit dangerous configuration.
Missing defense-in-depth controls are grouped as informational/medium
``hardening`` issues so an ordinary container is not mislabeled as malicious.
"""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import yaml


@dataclass(frozen=True)
class RuntimeAuditBudget:
    max_files: int = 200
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_yaml_documents: int = 256
    max_yaml_nodes: int = 100_000
    max_yaml_depth: int = 64
    max_semantic_items: int = 50_000
    max_issues: int = 10_000
    max_seconds: float = 8.0

    def __post_init__(self) -> None:
        values = (
            self.max_files,
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_yaml_documents,
            self.max_yaml_nodes,
            self.max_yaml_depth,
            self.max_semantic_items,
            self.max_issues,
        )
        if any(value < 0 for value in values):
            raise ValueError("runtime audit limits must be non-negative")
        if self.max_seconds < 0:
            raise ValueError("max_seconds must be non-negative")


@dataclass(frozen=True)
class RuntimeSecurityIssue:
    rule_id: str
    severity: str
    title: str
    detail: str
    location: str
    evidence: str = ""
    confidence: float = 0.8
    category: str = "danger"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_finding_kwargs(self) -> Dict[str, Any]:
        return {
            "scanner": "runtime_security",
            "level": self.severity,
            "title": self.title,
            "detail": self.detail,
            "location": self.location,
            "snippet": self.evidence,
            "metadata": {
                "rule_id": self.rule_id,
                "confidence": self.confidence,
                "issue_category": self.category,
                **dict(self.metadata),
            },
        }


@dataclass
class RuntimeSecurityReport:
    root: str
    inspected_files: List[str] = field(default_factory=list)
    issues: List[RuntimeSecurityIssue] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    complete: bool = True
    documents: int = 0
    bytes_read: int = 0

    @property
    def status(self) -> str:
        return "COMPLETE" if self.complete else "INCOMPLETE"

    def as_finding_kwargs(self) -> List[Dict[str, Any]]:
        return [issue.as_finding_kwargs() for issue in self.issues]


class _RuntimeAuditLimit(Exception):
    pass


class _LimitedSafeLoader(yaml.SafeLoader):
    def __init__(
        self,
        stream: str,
        max_nodes: int,
        max_depth: int,
        deadline: float,
    ) -> None:
        super().__init__(stream)
        self._runtime_nodes = 0
        self._runtime_depth = 0
        self._runtime_max_nodes = max_nodes
        self._runtime_max_depth = max_depth
        self._runtime_deadline = deadline

    def compose_node(self, parent: Any, index: Any) -> Any:
        self._runtime_nodes += 1
        self._runtime_depth += 1
        try:
            if self._runtime_nodes > self._runtime_max_nodes:
                raise _RuntimeAuditLimit("YAML node budget exceeded")
            if self._runtime_depth > self._runtime_max_depth:
                raise _RuntimeAuditLimit("YAML nesting-depth budget exceeded")
            if time.monotonic() > self._runtime_deadline:
                raise _RuntimeAuditLimit("runtime audit time budget exceeded")
            return super().compose_node(parent, index)
        finally:
            self._runtime_depth -= 1


_DANGEROUS_CAPS = frozenset({"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"})
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd|"
    r"private[_-]?key|client[_-]?secret|credential)"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_.-]*(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|"
    r"PASSWD|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|CREDENTIAL)[A-Z0-9_.-]*)"
    r"\s*=\s*([^\s]+)"
)
_SECRET_STRUCTURED_RE = re.compile(
    r"(?ix)(?P<prefix>[\"']?[A-Z0-9_.-]*(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET|"
    r"TOKEN|PASSWORD|PASSWD|PWD|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|CREDENTIAL)"
    r"[A-Z0-9_.-]*[\"']?\s*[:=]\s*)(?P<value>[^\s,}\]]+)"
)
_SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd|"
    r"credential)=)[^&#\s]+"
)
_PLACEHOLDER_RE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*(?::[-?][^}]*)?\}?|"
    r"<[^>]+>|\{\{[^}]+\}\}|)$"
)
_DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]{64}(?:$|\s)")
_DOWNLOAD_RE = re.compile(r"(?i)\b(?:curl|wget)\b")
_EXEC_AFTER_DOWNLOAD_RE = re.compile(
    r"(?is)(?:\|\s*(?:/[A-Za-z0-9._-]+/)?(?:ba|da|z|k)?sh\b|\|\s*powershell\b|"
    r"(?:&&|;)\s*(?:chmod\s+\+?x\b|(?:ba)?sh\b|powershell\b|"
    r"python\b|node\b|/tmp/|\./))"
)
_SENSITIVE_HOST_PATHS = (
    "/",
    "/proc",
    "/sys",
    "/etc",
    "/boot",
    "/dev",
    "/var/run",
    "/run",
)
_RUNTIME_SOCKET_RE = re.compile(
    r"(?i)(?:/var/run/docker\.sock|/run/docker\.sock|"
    r"/run/containerd(?:/containerd)?\.sock|/run/crio/crio\.sock)"
)
_DOCKERFILE_RE = re.compile(r"(?i)^(?:dockerfile|containerfile)(?:\..+)?$")
_COMPOSE_INTERPOLATION_RE = re.compile(
    r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?:(:-|-|:\+|\+|:\?|\?)(.*))?\}$",
    re.S,
)
_COMPOSE_NAMES = frozenset(
    {
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    }
)
_WORKLOAD_KINDS = frozenset(
    {
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    }
)


def _is_literal_secret(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip().strip("'\"")
    default, has_default = _compose_interpolation_default(text)
    if has_default:
        text = default.strip().strip("'\"")
    if not text or _PLACEHOLDER_RE.fullmatch(text):
        return False
    if text.lower() in {"null", "none"}:
        return False
    return True


def _is_root_user(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip().lower()
    default, has_default = _compose_interpolation_default(text)
    if has_default:
        text = default.strip().lower()
    identity = text.split(":", 1)[0]
    return identity in {"root", "0"}


def _is_dynamic_value(value: Any) -> bool:
    if value is None:
        return False
    return bool(_PLACEHOLDER_RE.fullmatch(str(value).strip().strip("'\"")))


def _compose_interpolation_default(value: str) -> Tuple[str, bool]:
    """Return a Compose interpolation fallback without reading host environment."""

    match = _COMPOSE_INTERPOLATION_RE.fullmatch(value.strip())
    if match and match.group(1) in {":-", "-"}:
        return match.group(2) or "", True
    return value, False


def _compose_static_value(value: Any) -> Tuple[Any, bool]:
    if not isinstance(value, str):
        return value, False
    default, has_default = _compose_interpolation_default(value.strip())
    return (default, True) if has_default else (value, False)


def _is_explicit_true(value: Any) -> bool:
    effective, _ = _compose_static_value(value)
    return effective is True or str(effective).strip().lower() in {"true", "1", "yes", "on"}


def _image_state(image: str) -> str:
    value = image.strip()
    if not value or "${" in value:
        return "unknown"
    if _DIGEST_RE.search(value + " "):
        return "digest"
    without_digest = value.split("@", 1)[0]
    final = without_digest.rsplit("/", 1)[-1]
    if ":" not in final or final.endswith(":latest"):
        return "latest"
    return "tag"


def _stringify(value: Any, limit: int = 240) -> str:
    text = str(value).replace("\n", " ").strip()
    return text[:limit]


def _redact_evidence(value: Any, limit: int = 240) -> str:
    text = str(value).replace("\n", " ").strip()
    text = _SECRET_ASSIGNMENT_RE.sub(
        lambda match: "%s=[REDACTED]" % match.group(1),
        text,
    )
    text = re.sub(
        r"(?i)(Authorization\s*[:=]\s*(?:Basic|Bearer)\s+)\S+",
        r"\1[REDACTED]",
        text,
    )
    text = _SECRET_STRUCTURED_RE.sub(
        lambda match: "%s[REDACTED]" % match.group("prefix"),
        text,
    )
    text = _SECRET_QUERY_RE.sub(r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)(https?://[^\s/:@]+:)[^\s/@]+(@)",
        r"\1[REDACTED]\2",
        text,
    )
    text = re.sub(
        r"(?i)(--(?:api[_-]?key|token|password|secret|credential)(?:=|\s+))\S+",
        r"\1[REDACTED]",
        text,
    )
    return text[:limit]


def _iter_mapping_items(value: Any) -> Iterable[Tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key), item
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            if isinstance(item, str) and "=" in item:
                key, content = item.split("=", 1)
                yield key, content


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return value
    return ()


class _Auditor:
    def __init__(self, root: Path, budget: RuntimeAuditBudget):
        self.root = root
        self.budget = budget
        self.report = RuntimeSecurityReport(str(root))
        self.started = time.monotonic()
        self.deadline = self.started + budget.max_seconds
        self._seen_issues: Set[Tuple[str, str, str]] = set()
        self._semantic_items = 0
        self.kubernetes: List[Tuple[Mapping[str, Any], str]] = []

    def expired(self) -> bool:
        return self.budget.max_seconds == 0 or time.monotonic() > self.deadline

    def checkpoint(self, units: int = 1) -> None:
        if self.expired():
            raise _RuntimeAuditLimit("runtime audit time budget exceeded")
        self._semantic_items += units
        if self._semantic_items > self.budget.max_semantic_items:
            raise _RuntimeAuditLimit("runtime semantic-item budget exceeded")

    def issue(
        self,
        rule_id: str,
        severity: str,
        title: str,
        detail: str,
        location: str,
        evidence: str = "",
        confidence: float = 0.8,
        category: str = "danger",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if rule_id != "RUN-INCOMPLETE-001":
            if self.expired():
                raise _RuntimeAuditLimit("runtime audit time budget exceeded")
            if len(self.report.issues) >= self.budget.max_issues:
                raise _RuntimeAuditLimit("runtime issue budget exceeded")
        key = (rule_id, location, evidence)
        if key in self._seen_issues:
            return
        self._seen_issues.add(key)
        self.report.issues.append(
            RuntimeSecurityIssue(
                rule_id,
                severity,
                title,
                detail,
                location,
                evidence,
                confidence,
                category,
                metadata or {},
            )
        )

    def incomplete(self, location: str, reason: str) -> None:
        self.report.complete = False
        safe_reason = _redact_evidence(reason, 500)
        diagnostic = "%s: %s" % (location, safe_reason)
        if diagnostic not in self.report.diagnostics:
            self.report.diagnostics.append(diagnostic)
        self.issue(
            "RUN-INCOMPLETE-001",
            "medium",
            "Runtime security audit incomplete",
            safe_reason,
            location,
            confidence=1.0,
            category="diagnostic",
            metadata={"scan_status": "error", "component": "runtime_security"},
        )

    def relative(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix() if self.root.is_dir() else path.name
        except ValueError:
            return path.name


def _stat_is_link_or_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _read_file(path: Path, limit: int) -> Tuple[bytes, bool]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        chunks: List[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        return content[:limit], len(content) > limit
    finally:
        os.close(descriptor)


def _docker_instructions(text: str) -> List[Tuple[int, str, str]]:
    instructions: List[Tuple[int, str, str]] = []
    lines = text.splitlines()
    buffer = ""
    start_line = 0
    number = 0
    while number < len(lines):
        raw = lines[number]
        number += 1
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start_line = number
        segment = stripped
        continued = segment.endswith("\\")
        if continued:
            segment = segment[:-1].rstrip()
        buffer = (buffer + " " + segment).strip()
        if continued:
            continue
        match = re.match(r"^([A-Za-z]+)\s+(.*)$", buffer, re.S)
        if match:
            operation = match.group(1).upper()
            argument = match.group(2).strip()
            heredoc = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", argument)
            if heredoc:
                delimiter = heredoc.group(1)
                body: List[str] = []
                terminated = False
                while number < len(lines):
                    heredoc_line = lines[number]
                    number += 1
                    if heredoc_line.strip() == delimiter:
                        terminated = True
                        break
                    body.append(heredoc_line)
                if not terminated:
                    raise ValueError("unterminated Dockerfile heredoc at line %d" % start_line)
                argument = argument + "\n" + "\n".join(body)
            instructions.append((start_line, operation, argument))
        buffer = ""
    if buffer:
        match = re.match(r"^([A-Za-z]+)\s+(.*)$", buffer, re.S)
        if match:
            instructions.append((start_line, match.group(1).upper(), match.group(2).strip()))
    return instructions


def _strip_shell_comment(command: str) -> str:
    """Drop unquoted shell comments before applying command heuristics."""

    result: List[str] = []
    quote = ""
    escaped = False
    in_comment = False
    for index, character in enumerate(command):
        if in_comment:
            if character in {"\n", "\r"}:
                in_comment = False
                result.append(character)
            continue
        if escaped:
            result.append(character)
            escaped = False
            continue
        if character == "\\" and quote != "'":
            result.append(character)
            escaped = True
            continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
            result.append(character)
            continue
        if character == "#" and not quote and (index == 0 or command[index - 1].isspace()):
            in_comment = True
            continue
        result.append(character)
    return "".join(result)


def _audit_image(auditor: _Auditor, image: str, location: str) -> None:
    state = _image_state(image)
    if state == "latest":
        auditor.issue(
            "RUN-IMAGE-LATEST-001",
            "medium",
            "Container image uses a mutable latest/implicit tag",
            "Use an immutable digest for reproducible provenance.",
            location,
            image,
            0.98,
            "hardening",
        )
    elif state == "tag":
        auditor.issue(
            "RUN-IMAGE-PIN-001",
            "info",
            "Container image is not pinned by digest",
            "A version tag can still be replaced; prefer image@sha256:... for high-assurance deployments.",
            location,
            image,
            0.98,
            "hardening",
        )
    elif state == "unknown":
        auditor.issue(
            "RUN-IMAGE-PIN-001",
            "info",
            "Container image pinning could not be proven statically",
            "Resolve the image variable to an immutable digest during deployment verification.",
            location,
            image,
            0.6,
            "hardening",
        )


def _audit_dockerfile(auditor: _Auditor, text: str, location: str) -> None:
    instructions = _docker_instructions(text)
    stages: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line, operation, argument in instructions:
        auditor.checkpoint()
        item_location = "%s:%d" % (location, line)
        onbuild = operation == "ONBUILD"
        if onbuild:
            nested = re.match(r"^([A-Za-z]+)\s+(.*)$", argument, re.S)
            if not nested:
                auditor.incomplete(item_location, "ONBUILD instruction could not be parsed")
                continue
            operation = nested.group(1).upper()
            argument = nested.group(2).strip()
        if operation == "FROM":
            tokens = argument.split()
            image = next((token for token in tokens if not token.startswith("--")), "")
            current = {"image": image, "user": None, "line": line}
            stages.append(current)
            if image.lower() != "scratch":
                _audit_image(auditor, image, item_location)
        elif operation == "USER" and current is not None:
            user = argument.split()[0] if argument else ""
            if onbuild and _is_root_user(user):
                auditor.issue(
                    "RUN-ROOT-001",
                    "high",
                    "ONBUILD configures descendant images to run as root",
                    "Avoid a root USER in inherited build triggers.",
                    item_location,
                    "ONBUILD USER %s" % user,
                    0.97,
                )
            elif not onbuild:
                current["user"] = user
        elif operation in {"ARG", "ENV"}:
            assignments = list(_SECRET_ASSIGNMENT_RE.finditer(argument))
            if operation == "ENV" and not assignments:
                legacy = argument.split(None, 1)
                if len(legacy) == 2 and _SECRET_KEY_RE.search(legacy[0]):
                    severity = "high" if _is_literal_secret(legacy[1]) else "medium"
                    auditor.issue(
                        "RUN-SECRET-LAYER-001",
                        severity,
                        "Secret-like value is placed in the image environment",
                        "Docker ENV values persist in image metadata and runtime configuration.",
                        item_location,
                        "%s=[REDACTED]" % legacy[0],
                        0.95,
                        "danger" if severity == "high" else "hardening",
                        {"instruction": operation, "key": legacy[0]},
                    )
            for match in assignments:
                key, value = match.group(1), match.group(2)
                severity = "high" if _is_literal_secret(value) else "medium"
                auditor.issue(
                    "RUN-SECRET-LAYER-001",
                    severity,
                    "Secret-like value is placed in a build argument or image environment",
                    "Docker ARG/ENV and derived layers or history are not secret stores.",
                    item_location,
                    "%s=[REDACTED]" % key,
                    0.95,
                    "danger" if severity == "high" else "hardening",
                    {"instruction": operation, "key": key},
                )
            if operation == "ARG" and not assignments:
                key = argument.split("=", 1)[0].strip()
                if _SECRET_KEY_RE.search(key):
                    auditor.issue(
                        "RUN-SECRET-BUILDARG-001",
                        "medium",
                        "Secret-like Docker build argument declared",
                        "Build arguments may leak through build logs or history; use BuildKit secret mounts.",
                        item_location,
                        key,
                        0.9,
                        "hardening",
                    )
        elif operation == "ADD":
            remote = re.search(r"(?i)https?://[^\s,'\"\]]+", argument)
            if remote:
                source = remote.group(0)
                auditor.issue(
                    "RUN-REMOTE-ADD-001",
                    "high",
                    "Dockerfile ADD fetches a remote URL",
                    "Remote ADD content is mutable and executes outside an explicit verification chain.",
                    item_location,
                    _redact_evidence(source),
                    0.98,
                )
        elif operation == "RUN":
            executable = _strip_shell_comment(argument)
            if _DOWNLOAD_RE.search(executable) and _EXEC_AFTER_DOWNLOAD_RE.search(executable):
                auditor.issue(
                    "RUN-DOWNLOAD-EXEC-001",
                    "critical",
                    "Docker build downloads and executes remote content",
                    "Separate download, integrity verification, and execution using a pinned digest; an unrelated check in the same layer is not proof of verification.",
                    item_location,
                    _redact_evidence(executable),
                    0.99,
                    "danger",
                    {"integrity_check_proven": False},
                )
            for match in _SECRET_ASSIGNMENT_RE.finditer(executable):
                if _is_literal_secret(match.group(2)):
                    auditor.issue(
                        "RUN-SECRET-LAYER-001",
                        "high",
                        "Secret-like value is embedded in a build layer",
                        "RUN commands and their output may persist in build cache or image history.",
                        item_location,
                        "%s=[REDACTED]" % match.group(1),
                        0.92,
                    )
            if re.search(r"(?i)(?:--privileged\b|--network\s*=\s*host\b)", executable):
                auditor.issue(
                    "RUN-BUILD-ESCAPE-001",
                    "high",
                    "Docker build invokes a host-privileged execution mode",
                    "Privileged or host-network nested container execution weakens the build boundary.",
                    item_location,
                    _redact_evidence(executable),
                    0.95,
                )
        socket_argument = executable if operation == "RUN" else argument
        if operation in {"RUN", "CMD", "ENTRYPOINT", "ENV"} and _RUNTIME_SOCKET_RE.search(socket_argument):
            auditor.issue(
                "RUN-SOCKET-001",
                "critical",
                "Container runtime socket is referenced",
                "Access to a Docker/containerd socket is commonly equivalent to host control.",
                item_location,
                socket_argument[:240],
                0.99,
            )
        if "0.0.0.0" in argument and operation in {"CMD", "ENTRYPOINT", "ENV", "EXPOSE"}:
            auditor.issue(
                "RUN-BIND-001",
                "medium",
                "Container process explicitly binds all interfaces",
                "Confirm that the orchestrator limits host exposure and authentication.",
                item_location,
                argument[:160],
                0.9,
                "hardening",
            )

    if not stages:
        auditor.incomplete(location, "Dockerfile contains no valid FROM instruction")
    else:
        final = stages[-1]
        final_location = "%s:%d" % (location, final["line"])
        if _is_root_user(final["user"]):
            auditor.issue(
                "RUN-ROOT-001",
                "high",
                "Final container stage explicitly runs as root",
                "Use a dedicated non-root UID/GID in the final image.",
                final_location,
                "USER %s" % final["user"],
                0.99,
            )
        elif (
            final["user"] is None or _is_dynamic_value(final["user"])
        ) and str(final["image"]).lower() != "scratch":
            auditor.issue(
                "RUN-BASELINE-001",
                "info",
                "Final image does not declare a non-root user",
                "The effective image user cannot be proven from this Dockerfile.",
                final_location,
                category="hardening",
                confidence=0.65,
                metadata={"missing": ["non_root_user"]},
            )


def _volume_source(volume: Any) -> Tuple[str, bool]:
    if isinstance(volume, Mapping):
        source = str(volume.get("source") or "")
        kind = str(volume.get("type") or "").lower()
        return source, kind == "bind"
    text = str(volume)
    if not text:
        return "", False
    if re.match(r"^[A-Za-z]:[\\/]", text):
        parts = text.split(":", 2)
        return ":".join(parts[:2]), True
    source = text.split(":", 1)[0]
    return source, source.startswith(("/", "~", "."))


def _sensitive_host_path(path: str) -> bool:
    normalized = path.replace("\\", "/").rstrip("/") or "/"
    if normalized == "/":
        return True
    return any(
        normalized == prefix or normalized.startswith(prefix.rstrip("/") + "/")
        for prefix in _SENSITIVE_HOST_PATHS
        if prefix != "/"
    )


def _compose_port_exposure(port: Any) -> Tuple[bool, str]:
    if isinstance(port, Mapping):
        host_ip = port.get("host_ip")
        published = port.get("published")
        return published is not None and host_ip in (None, "", "0.0.0.0", "::"), _stringify(port)
    text = str(port).strip().strip("'\"")
    if not text:
        return False, text
    segments = text.split(":")
    if len(segments) == 1:
        return True, text
    if segments[0] in {"127.0.0.1", "::1", "localhost"}:
        return False, text
    return True, text


def _compose_network_is_internal(
    service: Mapping[str, Any],
    networks: Mapping[str, Any],
) -> bool:
    network_mode, _ = _compose_static_value(service.get("network_mode"))
    if str(network_mode or "").lower() == "none":
        return True
    attached = service.get("networks")
    if attached is None:
        return bool(_as_mapping(networks.get("default")).get("internal"))
    if isinstance(attached, Mapping):
        names = [str(name) for name in attached]
    else:
        names = [str(name) for name in _as_sequence(attached)]
    return bool(names) and all(
        bool(_as_mapping(networks.get(name)).get("internal")) for name in names
    )


def _audit_secret_mapping(
    auditor: _Auditor,
    value: Any,
    location: str,
    build_time: bool = False,
) -> None:
    for key, content in _iter_mapping_items(value):
        auditor.checkpoint()
        if not _SECRET_KEY_RE.search(key):
            continue
        literal = _is_literal_secret(content)
        if literal or build_time:
            auditor.issue(
                "RUN-SECRET-BUILDARG-001" if build_time else "RUN-SECRET-ENV-001",
                "high" if literal else "medium",
                "Secret-like value is embedded in runtime/build configuration",
                "Use a runtime secret reference rather than a literal or build argument.",
                location,
                "%s=[REDACTED]" % key,
                0.96 if literal else 0.8,
                "danger" if literal else "hardening",
                {"key": key, "build_time": build_time},
            )


def _audit_compose(auditor: _Auditor, document: Mapping[str, Any], location: str) -> None:
    services = _as_mapping(document.get("services"))
    networks = _as_mapping(document.get("networks"))
    for service_name, raw_service in services.items():
        auditor.checkpoint()
        if not isinstance(raw_service, Mapping):
            auditor.incomplete(
                "%s:services.%s" % (location, service_name),
                "Compose service definition is not a mapping",
            )
            continue
        service = _as_mapping(raw_service)
        service_location = "%s:services.%s" % (location, service_name)
        if not service:
            continue
        if _is_explicit_true(service.get("privileged")):
            auditor.issue(
                "RUN-PRIVILEGED-001",
                "critical",
                "Compose service runs privileged",
                "Privileged containers have near-host-level device and kernel access.",
                service_location,
                "privileged: true",
                1.0,
            )
        for key, rule_id, title in (
            ("network_mode", "RUN-HOSTNET-001", "Compose service shares the host network"),
            ("pid", "RUN-HOSTPID-001", "Compose service shares the host PID namespace"),
            ("ipc", "RUN-HOSTIPC-001", "Compose service shares the host IPC namespace"),
        ):
            effective, _ = _compose_static_value(service.get(key))
            if str(effective or "").lower() == "host":
                auditor.issue(
                    rule_id,
                    "high",
                    title,
                    "Host namespace sharing weakens container isolation.",
                    service_location,
                    "%s: host" % key,
                    0.99,
                )
        if _is_root_user(service.get("user")):
            auditor.issue(
                "RUN-ROOT-001",
                "high",
                "Compose service explicitly runs as root",
                "Use a dedicated non-root UID/GID.",
                service_location,
                "user: %s" % service.get("user"),
                0.99,
            )
        caps = {str(cap).upper().removeprefix("CAP_") for cap in _as_sequence(service.get("cap_add"))}
        dangerous = sorted(caps & _DANGEROUS_CAPS)
        if "ALL" in caps or dangerous:
            auditor.issue(
                "RUN-CAPABILITY-001",
                "critical" if "ALL" in caps or "SYS_ADMIN" in dangerous else "high",
                "Compose service adds dangerous Linux capabilities",
                "Drop all capabilities and add back only the minimum required set.",
                service_location,
                ", ".join(sorted(caps)),
                0.99,
                metadata={"capabilities": sorted(caps)},
            )
        security_options = [str(value).lower() for value in _as_sequence(service.get("security_opt"))]
        if any("seccomp=unconfined" in value or "seccomp:unconfined" in value for value in security_options):
            auditor.issue(
                "RUN-SECCOMP-001",
                "high",
                "Compose service disables seccomp",
                "Use the runtime/default seccomp profile or a restrictive custom profile.",
                service_location,
                "seccomp=unconfined",
                0.99,
            )
        for volume in _as_sequence(service.get("volumes")):
            auditor.checkpoint()
            source, is_bind = _volume_source(volume)
            if not source:
                continue
            evidence = _stringify(volume)
            if _RUNTIME_SOCKET_RE.search(source):
                auditor.issue(
                    "RUN-SOCKET-001",
                    "critical",
                    "Compose service mounts a container runtime socket",
                    "Runtime socket access is commonly equivalent to host control.",
                    service_location,
                    evidence,
                    1.0,
                )
            elif is_bind and _sensitive_host_path(source):
                auditor.issue(
                    "RUN-HOSTPATH-001",
                    "high",
                    "Compose service mounts a sensitive host path",
                    "Sensitive host filesystems expose kernel or host configuration.",
                    service_location,
                    evidence,
                    0.98,
                )
            elif is_bind:
                auditor.issue(
                    "RUN-HOSTPATH-001",
                    "medium",
                    "Compose service uses a host bind mount",
                    "Review ownership, write access, and the minimum required host path.",
                    service_location,
                    evidence,
                    0.9,
                    "hardening",
                )
        for port in _as_sequence(service.get("ports")):
            auditor.checkpoint()
            exposed, evidence = _compose_port_exposure(port)
            if exposed:
                auditor.issue(
                    "RUN-HOSTPORT-001",
                    "medium",
                    "Compose service publishes a port on all host interfaces",
                    "Bind to loopback or a controlled interface unless public exposure is intentional.",
                    service_location,
                    evidence,
                    0.97,
                    "hardening",
                )
        image = service.get("image")
        if image:
            _audit_image(auditor, str(image), service_location)
        _audit_secret_mapping(auditor, service.get("environment"), service_location)
        build = service.get("build")
        if isinstance(build, Mapping):
            _audit_secret_mapping(auditor, build.get("args"), service_location, True)

        limits = _as_mapping(_as_mapping(service.get("deploy")).get("resources")).get("limits")
        has_limits = bool(limits) or bool(service.get("mem_limit") and service.get("cpus"))
        missing: List[str] = []
        read_only, _ = _compose_static_value(service.get("read_only"))
        if not _is_explicit_true(read_only):
            missing.append("read_only_root_filesystem")
        user_value, user_has_default = _compose_static_value(service.get("user"))
        if user_value is None or (_is_dynamic_value(service.get("user")) and not user_has_default):
            missing.append("explicit_non_root_user")
        if not has_limits:
            missing.append("cpu_memory_limits")
        if not any("no-new-privileges:true" in value.replace("=", ":") for value in security_options):
            missing.append("no_new_privileges")
        if missing:
            auditor.issue(
                "RUN-BASELINE-001",
                "info",
                "Compose service is missing defense-in-depth controls",
                "These are hardening recommendations, not proof that the service is malicious.",
                service_location,
                ", ".join(missing),
                0.9,
                "hardening",
                {"missing": missing},
            )
        if not _compose_network_is_internal(service, networks):
            auditor.issue(
                "RUN-EGRESS-001",
                "info",
                "Compose service has no explicit egress restriction evidence",
                "Default Compose networking normally permits outbound traffic; use an internal network or an external policy layer where appropriate.",
                service_location,
                confidence=0.75,
                category="hardening",
                metadata={"evidence_scope": "audited_compose_document"},
            )


def _workload_spec(resource: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    kind = str(resource.get("kind") or "")
    spec = _as_mapping(resource.get("spec"))
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return _as_mapping(
            _as_mapping(_as_mapping(spec.get("jobTemplate")).get("spec")).get("template")
        ).get("spec")  # type: ignore[return-value]
    if kind in _WORKLOAD_KINDS:
        return _as_mapping(_as_mapping(spec.get("template")).get("spec"))
    return None


def _resource_labels(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    kind = str(resource.get("kind") or "")
    if kind == "Pod":
        return _as_mapping(_as_mapping(resource.get("metadata")).get("labels"))
    spec = _as_mapping(resource.get("spec"))
    if kind == "CronJob":
        template = _as_mapping(
            _as_mapping(_as_mapping(spec.get("jobTemplate")).get("spec")).get("template")
        )
    else:
        template = _as_mapping(spec.get("template"))
    return _as_mapping(_as_mapping(template.get("metadata")).get("labels"))


def _namespace(resource: Mapping[str, Any]) -> str:
    return str(_as_mapping(resource.get("metadata")).get("namespace") or "default")


def _has_matching_egress_policy(
    auditor: _Auditor,
    resource: Mapping[str, Any],
    policies: Sequence[Mapping[str, Any]],
) -> bool:
    labels = _resource_labels(resource)
    namespace = _namespace(resource)
    matched_restrictive = False
    for policy in policies:
        auditor.checkpoint()
        if _namespace(policy) != namespace:
            continue
        spec = _as_mapping(policy.get("spec"))
        if "podSelector" not in spec:
            continue
        pod_selector = _as_mapping(spec.get("podSelector"))
        selector = _as_mapping(pod_selector.get("matchLabels"))
        if selector and any(labels.get(key) != value for key, value in selector.items()):
            continue
        expressions = _as_sequence(pod_selector.get("matchExpressions"))
        expression_match = True
        for expression in expressions:
            item = _as_mapping(expression)
            key = str(item.get("key") or "")
            operator = str(item.get("operator") or "")
            values = {str(value) for value in _as_sequence(item.get("values"))}
            current = labels.get(key)
            if operator == "In":
                expression_match = current is not None and str(current) in values
            elif operator == "NotIn":
                expression_match = current is not None and str(current) not in values
            elif operator == "Exists":
                expression_match = key in labels
            elif operator == "DoesNotExist":
                expression_match = key not in labels
            else:
                expression_match = False
            if not expression_match:
                break
        if not expression_match:
            continue
        policy_types = {str(item) for item in _as_sequence(spec.get("policyTypes"))}
        if "Egress" in policy_types or "egress" in spec:
            rules = spec.get("egress")
            if rules is None:
                matched_restrictive = True
                continue
            if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
                continue
            rule_list = _as_sequence(rules)
            if not rule_list:
                matched_restrictive = True
                continue
            if any(not isinstance(rule, Mapping) for rule in rule_list):
                continue
            permits_all = any(
                isinstance(rule, Mapping)
                and (
                    (not rule.get("to") and not rule.get("ports"))
                    or any(
                        str(_as_mapping(_as_mapping(peer).get("ipBlock")).get("cidr") or "")
                        in {"0.0.0.0/0", "::/0"}
                        and not _as_mapping(_as_mapping(peer).get("ipBlock")).get("except")
                        for peer in _as_sequence(rule.get("to"))
                    )
                )
                for rule in rule_list
            )
            if permits_all:
                return False
            matched_restrictive = True
    return matched_restrictive


def _audit_k8s_container(
    auditor: _Auditor,
    container: Mapping[str, Any],
    pod_security: Mapping[str, Any],
    location: str,
) -> None:
    auditor.checkpoint()
    name = str(container.get("name") or "<unnamed>")
    container_location = "%s:container.%s" % (location, name)
    security = _as_mapping(container.get("securityContext"))
    if security.get("privileged") is True:
        auditor.issue(
            "RUN-PRIVILEGED-001",
            "critical",
            "Kubernetes container runs privileged",
            "Privileged containers substantially bypass the container isolation boundary.",
            container_location,
            "privileged: true",
            1.0,
        )
    if security.get("allowPrivilegeEscalation") is True:
        auditor.issue(
            "RUN-PRIVESC-001",
            "high",
            "Kubernetes container allows privilege escalation",
            "Set allowPrivilegeEscalation: false unless a reviewed workload requires it.",
            container_location,
            "allowPrivilegeEscalation: true",
            0.99,
        )
    run_as_user = security.get("runAsUser", pod_security.get("runAsUser"))
    run_as_non_root = security.get("runAsNonRoot", pod_security.get("runAsNonRoot"))
    if _is_root_user(run_as_user) or run_as_non_root is False:
        auditor.issue(
            "RUN-ROOT-001",
            "high",
            "Kubernetes container permits or requests root",
            "Set runAsNonRoot: true and a non-zero runAsUser.",
            container_location,
            "runAsUser=%s runAsNonRoot=%s" % (run_as_user, run_as_non_root),
            0.99,
        )
    capabilities = _as_mapping(security.get("capabilities"))
    added = {str(cap).upper().removeprefix("CAP_") for cap in _as_sequence(capabilities.get("add"))}
    dangerous = sorted(added & _DANGEROUS_CAPS)
    if "ALL" in added or dangerous:
        auditor.issue(
            "RUN-CAPABILITY-001",
            "critical" if "ALL" in added or "SYS_ADMIN" in dangerous else "high",
            "Kubernetes container adds dangerous Linux capabilities",
            "Drop ALL and add back only narrowly required capabilities.",
            container_location,
            ", ".join(sorted(added)),
            0.99,
            metadata={"capabilities": sorted(added)},
        )
    seccomp = _as_mapping(security.get("seccompProfile")) or _as_mapping(
        pod_security.get("seccompProfile")
    )
    if str(seccomp.get("type") or "").lower() == "unconfined":
        auditor.issue(
            "RUN-SECCOMP-001",
            "high",
            "Kubernetes container disables seccomp",
            "Use RuntimeDefault or a restrictive Localhost profile.",
            container_location,
            "seccompProfile.type: Unconfined",
            0.99,
        )
    for port in _as_sequence(container.get("ports")):
        auditor.checkpoint()
        port_map = _as_mapping(port)
        host_port = port_map.get("hostPort")
        host_ip = port_map.get("hostIP")
        try:
            published_port = int(host_port) if host_port is not None else 0
        except (TypeError, ValueError):
            published_port = 0
        if published_port > 0:
            auditor.issue(
                "RUN-HOSTPORT-001",
                "medium",
                "Kubernetes container publishes a hostPort",
                "hostPort consumes a node port and broadens host exposure.",
                container_location,
                "hostPort=%s hostIP=%s" % (published_port, host_ip or "0.0.0.0"),
                0.98,
                "hardening",
            )
    image = container.get("image")
    if image:
        _audit_image(auditor, str(image), container_location)
    else:
        auditor.incomplete(container_location, "container image is missing")
    command_text = " ".join(
        str(value)
        for value in (*_as_sequence(container.get("command")), *_as_sequence(container.get("args")))
    )
    if "0.0.0.0" in command_text or "[::]" in command_text:
        auditor.issue(
            "RUN-BIND-001",
            "medium",
            "Kubernetes container process explicitly binds all interfaces",
            "Confirm that Service, ingress, and network policy controls match the intended exposure.",
            container_location,
            command_text[:200],
            0.9,
            "hardening",
        )
    for variable in _as_sequence(container.get("env")):
        auditor.checkpoint()
        item = _as_mapping(variable)
        key = str(item.get("name") or "")
        if _SECRET_KEY_RE.search(key) and "value" in item and _is_literal_secret(item.get("value")):
            auditor.issue(
                "RUN-SECRET-ENV-001",
                "high",
                "Kubernetes manifest contains a literal secret environment value",
                "Use secretKeyRef or an external secret provider.",
                container_location,
                "%s=[REDACTED]" % key,
                0.98,
            )

    limits = _as_mapping(_as_mapping(container.get("resources")).get("limits"))
    missing: List[str] = []
    if security.get("readOnlyRootFilesystem") is not True:
        missing.append("read_only_root_filesystem")
    if security.get("allowPrivilegeEscalation") is not False:
        missing.append("allow_privilege_escalation_false")
    if not (run_as_non_root is True and not _is_root_user(run_as_user)):
        missing.append("non_root_user")
    if str(seccomp.get("type") or "") not in {"RuntimeDefault", "Localhost"}:
        missing.append("seccomp_profile")
    if not (limits.get("cpu") and limits.get("memory")):
        missing.append("cpu_memory_limits")
    if missing:
        auditor.issue(
            "RUN-BASELINE-001",
            "info",
            "Kubernetes container is missing defense-in-depth controls",
            "These are baseline recommendations, not proof of malicious behavior.",
            container_location,
            ", ".join(missing),
            0.9,
            "hardening",
            {"missing": missing},
        )


def _audit_kubernetes(auditor: _Auditor) -> None:
    resources: List[Tuple[Mapping[str, Any], str]] = []
    for resource, location in auditor.kubernetes:
        auditor.checkpoint()
        if str(resource.get("kind") or "") == "List":
            for index, item in enumerate(_as_sequence(resource.get("items"))):
                auditor.checkpoint()
                if isinstance(item, Mapping):
                    resources.append((item, "%s:item%d" % (location, index + 1)))
        else:
            resources.append((resource, location))
    policies = [resource for resource, _ in resources if resource.get("kind") == "NetworkPolicy"]
    for resource, location in resources:
        auditor.checkpoint()
        kind = str(resource.get("kind") or "")
        if kind not in _WORKLOAD_KINDS:
            continue
        spec = _workload_spec(resource)
        if not isinstance(spec, Mapping):
            auditor.incomplete(location, "%s has no parseable PodSpec" % kind)
            continue
        containers = _as_sequence(spec.get("containers"))
        if not containers:
            auditor.incomplete(location, "%s PodSpec has no containers" % kind)
        if spec.get("hostNetwork") is True:
            auditor.issue(
                "RUN-HOSTNET-001",
                "high",
                "Kubernetes workload shares the host network",
                "hostNetwork bypasses the pod network namespace.",
                location,
                "hostNetwork: true",
                1.0,
            )
        if spec.get("hostPID") is True:
            auditor.issue(
                "RUN-HOSTPID-001",
                "high",
                "Kubernetes workload shares the host PID namespace",
                "Host PID visibility enables sensitive process inspection and interaction.",
                location,
                "hostPID: true",
                1.0,
            )
        if spec.get("hostIPC") is True:
            auditor.issue(
                "RUN-HOSTIPC-001",
                "high",
                "Kubernetes workload shares the host IPC namespace",
                "Host IPC sharing weakens process isolation.",
                location,
                "hostIPC: true",
                1.0,
            )
        for volume in _as_sequence(spec.get("volumes")):
            auditor.checkpoint()
            volume_map = _as_mapping(volume)
            host_path = _as_mapping(volume_map.get("hostPath"))
            if not host_path:
                continue
            path = str(host_path.get("path") or "")
            if _RUNTIME_SOCKET_RE.search(path):
                auditor.issue(
                    "RUN-SOCKET-001",
                    "critical",
                    "Kubernetes workload mounts a container runtime socket",
                    "Runtime socket access is commonly equivalent to node control.",
                    location,
                    path,
                    1.0,
                )
            else:
                auditor.issue(
                    "RUN-HOSTPATH-001",
                    "critical" if path.rstrip("/") == "" else "high",
                    "Kubernetes workload uses hostPath",
                    "hostPath exposes node files outside the container filesystem boundary.",
                    location,
                    path,
                    0.99,
                    metadata={"sensitive": _sensitive_host_path(path)},
                )
        pod_security = _as_mapping(spec.get("securityContext"))
        container_groups = (
            ("container", containers),
            ("initContainer", spec.get("initContainers")),
            ("ephemeralContainer", spec.get("ephemeralContainers")),
        )
        for group, values in container_groups:
            for index, container in enumerate(_as_sequence(values)):
                if isinstance(container, Mapping):
                    _audit_k8s_container(
                        auditor,
                        container,
                        pod_security,
                        "%s:%s%d" % (location, group, index + 1),
                    )
                else:
                    auditor.incomplete(
                        "%s:%s%d" % (location, group, index + 1),
                        "container definition is not a mapping",
                    )
        if not _has_matching_egress_policy(auditor, resource, policies):
            auditor.issue(
                "RUN-EGRESS-001",
                "info",
                "No matching Kubernetes egress policy was present in the audited manifests",
                "This is absence of static evidence, not proof that the live cluster has unrestricted egress.",
                location,
                confidence=0.65,
                category="hardening",
                metadata={"evidence_scope": "audited_manifests"},
            )


def _parse_yaml(
    auditor: _Auditor,
    text: str,
    location: str,
) -> List[Any]:
    if auditor.expired():
        raise _RuntimeAuditLimit("runtime audit time budget exceeded")
    loader = _LimitedSafeLoader(
        text,
        auditor.budget.max_yaml_nodes,
        auditor.budget.max_yaml_depth,
        auditor.deadline,
    )
    documents: List[Any] = []
    try:
        while loader.check_data():
            if auditor.report.documents >= auditor.budget.max_yaml_documents:
                raise _RuntimeAuditLimit("YAML document budget exceeded")
            documents.append(loader.get_data())
            auditor.report.documents += 1
    finally:
        loader.dispose()
    return documents


def _audit_yaml_file(
    auditor: _Auditor,
    text: str,
    location: str,
    require_runtime_document: bool = False,
) -> None:
    try:
        documents = _parse_yaml(auditor, text, location)
    except _RuntimeAuditLimit as exc:
        auditor.incomplete(location, "YAML parse/limit failure: %s" % exc)
        return
    except (yaml.YAMLError, RecursionError, ValueError):
        # Parser exceptions commonly quote the offending source line.  Never
        # copy attacker-controlled YAML (which can contain credentials) into
        # findings or diagnostics.
        auditor.incomplete(location, "YAML syntax or structure could not be parsed")
        return
    recognized = False
    for index, document in enumerate(documents, 1):
        if document is None:
            continue
        doc_location = "%s:doc%d" % (location, index)
        if not isinstance(document, Mapping):
            continue
        if "services" in document:
            if isinstance(document.get("services"), Mapping) and document.get("services"):
                recognized = True
                _audit_compose(auditor, document, doc_location)
            else:
                auditor.incomplete(doc_location, "Compose services must be a non-empty mapping")
        if document.get("apiVersion") and document.get("kind"):
            recognized = True
            auditor.kubernetes.append((document, doc_location))
    if require_runtime_document and not recognized:
        auditor.incomplete(location, "YAML contains no recognized Compose/Kubernetes document")


def _candidate(path: Path, explicit: bool = False) -> bool:
    name = path.name.lower()
    return bool(
        explicit
        or _DOCKERFILE_RE.match(path.name)
        or name in _COMPOSE_NAMES
        or path.suffix.lower() in {".yaml", ".yml"}
    )


def _discover(auditor: _Auditor, path: Path) -> List[Path]:
    if path.is_file():
        if auditor.budget.max_files < 1:
            auditor.incomplete(str(path), "runtime configuration file-count budget exceeded")
            return []
        return [path]
    files: List[Path] = []
    stack = [path]
    while stack:
        if auditor.expired():
            auditor.incomplete(str(stack[-1]), "runtime audit time budget exceeded")
            break
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            auditor.incomplete(str(directory), "directory unreadable: %s" % exc)
            continue
        children: List[Path] = []
        for entry in entries:
            candidate_path = Path(entry.path)
            try:
                info = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or _stat_is_link_or_reparse(info):
                    if _candidate(candidate_path):
                        auditor.incomplete(
                            auditor.relative(candidate_path),
                            "runtime configuration link was not followed",
                        )
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in {".git", "node_modules", "__pycache__", ".venv", "venv"}:
                        children.append(candidate_path)
                elif entry.is_file(follow_symlinks=False) and _candidate(candidate_path):
                    if len(files) >= auditor.budget.max_files:
                        auditor.incomplete(
                            auditor.relative(candidate_path),
                            "runtime configuration file-count budget exceeded",
                        )
                        return files
                    files.append(candidate_path)
            except OSError as exc:
                auditor.incomplete(auditor.relative(candidate_path), "path unreadable: %s" % exc)
        stack.extend(reversed(children))
    return files


def audit_runtime_security(
    path: Path,
    budget: Optional[RuntimeAuditBudget] = None,
    *,
    require_candidates: bool = False,
) -> RuntimeSecurityReport:
    """Audit Dockerfile, Compose, and Kubernetes runtime isolation settings."""

    target = Path(path)
    auditor = _Auditor(target, budget or RuntimeAuditBudget())
    try:
        try:
            target_info = target.lstat()
        except OSError as exc:
            auditor.incomplete(str(target), "runtime audit path unreadable: %s" % exc)
            return auditor.report
        if _stat_is_link_or_reparse(target_info):
            auditor.incomplete(str(target), "runtime audit root link was not followed")
            return auditor.report
        if not (stat.S_ISREG(target_info.st_mode) or stat.S_ISDIR(target_info.st_mode)):
            auditor.incomplete(str(target), "runtime audit path is not a regular file/directory")
            return auditor.report

        files = _discover(auditor, target)
        if require_candidates and stat.S_ISDIR(target_info.st_mode) and not files:
            auditor.incomplete(
                str(target), "no Dockerfile, Compose, or Kubernetes configuration was discovered"
            )
        for file_path in files:
            if auditor.expired():
                auditor.incomplete(auditor.relative(file_path), "runtime audit time budget exceeded")
                break
            location = auditor.relative(file_path)
            try:
                # ``Path.stat(follow_symlinks=...)`` is unavailable on the
                # oldest supported Python releases; lstat is equivalent here.
                size = file_path.lstat().st_size
            except OSError as exc:
                auditor.incomplete(location, "file unreadable: %s" % exc)
                continue
            if size > auditor.budget.max_file_bytes:
                auditor.incomplete(location, "runtime config exceeds single-file byte budget")
                continue
            if auditor.report.bytes_read + size > auditor.budget.max_total_bytes:
                auditor.incomplete(location, "runtime config total-byte budget exceeded")
                break
            try:
                content, truncated = _read_file(file_path, auditor.budget.max_file_bytes)
            except OSError as exc:
                auditor.incomplete(location, "file unreadable: %s" % exc)
                continue
            if truncated:
                auditor.incomplete(location, "runtime config changed or exceeded byte budget while read")
                continue
            auditor.report.bytes_read += len(content)
            auditor.report.inspected_files.append(location)
            try:
                text = content.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                auditor.incomplete(location, "runtime config is not valid UTF-8: %s" % exc)
                continue
            if _DOCKERFILE_RE.match(file_path.name) or (
                target.is_file() and re.search(r"(?im)^\s*FROM\s+\S+", text)
            ):
                _audit_dockerfile(auditor, text, location)
            elif file_path.suffix.lower() in {".yaml", ".yml"} or file_path.name.lower() in _COMPOSE_NAMES:
                _audit_yaml_file(
                    auditor,
                    text,
                    location,
                    require_runtime_document=(
                        target.is_file() or file_path.name.lower() in _COMPOSE_NAMES
                    ),
                )
            elif target.is_file():
                auditor.incomplete(location, "explicit file is not recognized as Dockerfile or YAML")
        _audit_kubernetes(auditor)
    except (OSError, RecursionError, ValueError, _RuntimeAuditLimit) as exc:
        auditor.incomplete(str(target), "runtime audit failed closed: %s" % exc)
    return auditor.report


__all__ = [
    "RuntimeAuditBudget",
    "RuntimeSecurityIssue",
    "RuntimeSecurityReport",
    "audit_runtime_security",
]
