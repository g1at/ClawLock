"""Fail-closed dynamic analysis through an external container sandbox.

ClawLock never executes an untrusted Skill or MCP server directly on the host.
This module provides a small, auditable contract for a purpose-built analyzer
image: mount the target read-only, drop Linux capabilities except the narrowly
required ``SYS_PTRACE`` tracer capability, disable network by default, inject
synthetic canaries, and consume bounded NDJSON events.

The analyzer image writes one event per line using this prefix::

    CLAWLOCK_EVENT\t{"kind":"file_read","target":"/workspace/a"}

Images are never pulled automatically and must be pinned by sha256 digest.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


EVENT_PREFIX = "CLAWLOCK_EVENT\t"
_MAX_EVENT_BYTES = 4 * 1024 * 1024
_MAX_EVENTS = 10_000
_MAX_CAPTURE_BYTES = 256 * 1024
_PINNED_IMAGE_RE = re.compile(r"(?:@sha256:|^sha256:)[0-9a-f]{64}$", re.I)
_NETWORK_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_WINDOWS_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class DynamicIssue:
    rule_id: str
    level: str
    title: str
    detail: str
    location: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass(frozen=True)
class BehaviorEvent:
    kind: str
    operation: str = ""
    target: str = ""
    process: str = ""
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    timestamp: float = 0.0
    labels: Tuple[str, ...] = ()
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SandboxPolicy:
    timeout_seconds: float = 30.0
    memory: str = "512m"
    cpus: str = "1.0"
    pids_limit: int = 64
    tmpfs_size: str = "64m"
    network: str = "none"
    user: str = "65534:65534"
    max_events: int = _MAX_EVENTS
    max_event_bytes: int = _MAX_EVENT_BYTES


@dataclass
class DynamicResult:
    status: str
    backend: str = ""
    events: List[BehaviorEvent] = field(default_factory=list)
    issues: List[DynamicIssue] = field(default_factory=list)
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    command_preview: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class _BoundedProcessResult:
    returncode: Optional[int]
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False


_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|[/\\])(?:\.ssh|\.aws|\.azure|\.config[/\\]gcloud|"
    r"\.kube|\.npmrc|\.pypirc|\.netrc|\.git-credentials|id_rsa|id_ed25519|"
    r"credentials?|secrets?|keychains?|cookies?|sessions?)(?:[/\\]|$)"
)
_PERSISTENCE_PATH_RE = re.compile(
    r"(?i)(?:sitecustomize\.py|usercustomize\.py|authorized_keys|"
    r"[/\\](?:cron(?:\.d)?|systemd|launchagents|launchdaemons|startup|"
    r"autostart|run[/\\]keys?)(?:[/\\]|$)|\.bashrc$|\.zshrc$|\.profile$)"
)
_HOST_ESCAPE_RE = re.compile(
    r"(?i)(?:docker\.sock|containerd\.sock|/proc/(?:1|sys)|/sys/kernel|"
    r"/dev/kvm|/dev/mem|hostpath|hostnetwork)"
)
_INJECTION_RE = re.compile(
    r"(?i)ignore\s+(?:all\s+)?(?:previous|system)\s+instructions?|"
    r"(?:do\s+not|don't)\s+ask.{0,30}(?:approval|permission)|"
    r"reveal.{0,30}(?:system\s+prompt|secret|credential)"
)


def resolve_container_engine(preferred: str = "") -> Optional[str]:
    candidates = [preferred] if preferred else ["docker", "podman"]
    cwd = Path.cwd().resolve()
    safe_path_entries: List[str] = []
    for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
        if not raw_entry:
            continue
        entry = Path(raw_entry)
        if not entry.is_absolute():
            continue
        try:
            resolved_entry = entry.resolve(strict=True)
        except OSError:
            continue
        if resolved_entry == cwd or cwd in resolved_entry.parents:
            continue
        safe_path_entries.append(str(resolved_entry))
    safe_path = os.pathsep.join(safe_path_entries)
    for candidate in candidates:
        if not candidate:
            continue
        candidate_path = Path(candidate)
        if candidate_path.stem.lower() not in {"docker", "podman"}:
            continue
        if candidate_path.is_absolute():
            try:
                candidate_stat = candidate_path.lstat()
                resolved_path = candidate_path.resolve(strict=True)
            except OSError:
                continue
            attrs = int(getattr(candidate_stat, "st_file_attributes", 0) or 0)
            if stat.S_ISLNK(candidate_stat.st_mode) or attrs & _WINDOWS_REPARSE_POINT:
                continue
            if resolved_path.is_file():
                return str(resolved_path)
            continue
        if candidate_path.parent != Path("."):
            # Relative tool paths make a scanned repository an execution
            # source.  Users may instead pass an explicit absolute engine.
            continue
        resolved = shutil.which(candidate, path=safe_path)
        if resolved:
            resolved_path = Path(resolved).resolve(strict=True)
            if resolved_path != cwd and cwd not in resolved_path.parents:
                return str(resolved_path)
    return None


def _validate_policy(image: str, policy: SandboxPolicy) -> None:
    if not _PINNED_IMAGE_RE.search(image):
        raise ValueError(
            "Analyzer image must be pinned as name@sha256:<64 hex digits> "
            "or a local sha256:<image id>"
        )
    if policy.network == "host":
        raise ValueError("Host networking is never allowed for dynamic analysis")
    if policy.network != "none" and not _NETWORK_NAME_RE.fullmatch(policy.network):
        raise ValueError("Network must be 'none' or a pre-created isolated network name")
    if policy.timeout_seconds <= 0 or policy.timeout_seconds > 900:
        raise ValueError("Sandbox timeout must be between 0 and 900 seconds")
    if not 1 <= policy.pids_limit <= 512:
        raise ValueError("Sandbox pid limit must be between 1 and 512")
    if not 1 <= policy.max_events <= 100_000:
        raise ValueError("Event limit is outside the safe range")
    if not 1024 <= policy.max_event_bytes <= 32 * 1024 * 1024:
        raise ValueError("Event byte budget is outside the safe range")


def build_container_command(
    engine: str,
    target: Path,
    image: str,
    entrypoint: Sequence[str],
    *,
    policy: SandboxPolicy = SandboxPolicy(),
    canary_ids: Optional[Mapping[str, str]] = None,
    container_name: str = "",
) -> List[str]:
    """Build a shell-free Docker/Podman invocation with safe defaults."""

    _validate_policy(image, policy)
    # Resolve only after rejecting links/reparse points at the caller-selected
    # boundary.  Otherwise a malicious target can redirect the read-only mount
    # to an unrelated host location before Docker/Podman starts.
    target_stat = target.lstat()
    file_attributes = int(getattr(target_stat, "st_file_attributes", 0) or 0)
    if stat.S_ISLNK(target_stat.st_mode) or file_attributes & _WINDOWS_REPARSE_POINT:
        raise ValueError("Dynamic target must not be a symlink or reparse point")
    resolved = target.resolve(strict=True)
    if not (resolved.is_dir() or resolved.is_file()):
        raise ValueError("Dynamic target must be a regular file or directory")
    mount_source = resolved
    if resolved.is_dir():
        mount_destination = "/workspace"
        workspace_target = "/workspace"
        workdir = "/workspace"
    else:
        mount_destination = f"/workspace/{resolved.name}"
        workspace_target = mount_destination
        workdir = "/workspace"
    if not entrypoint:
        raise ValueError("A container entrypoint argv is required")
    if container_name and not re.fullmatch(r"clawlock-[0-9a-f]{32}", container_name):
        raise ValueError("Dynamic container name does not match the safe generated form")
    command = [
        engine,
        "run",
        "--rm",
        "--pull=never",
        "--read-only",
        "--cap-drop=ALL",
        # The trusted helper uses strace.  Keep only the tracer capability in
        # the container's private PID namespace; never share the host PID ns.
        "--cap-add=SYS_PTRACE",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        f"--pids-limit={policy.pids_limit}",
        f"--memory={policy.memory}",
        f"--cpus={policy.cpus}",
        f"--network={policy.network}",
        f"--user={policy.user}",
        f"--tmpfs=/tmp:rw,noexec,nosuid,size={policy.tmpfs_size}",
        "--mount",
        f"type=bind,src={mount_source},dst={mount_destination},readonly",
        f"--workdir={workdir}",
        "--label=clawlock.dynamic=true",
        "--env=CLAWLOCK_TARGET=" + workspace_target,
        "--env=CLAWLOCK_EVENT_PROTOCOL=1",
    ]
    if container_name:
        command.insert(3, f"--name={container_name}")
    for name in sorted((canary_ids or {}).keys()):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name):
            raise ValueError(f"Invalid canary environment name: {name!r}")
        # Docker inherits the value from its own environment.  Keep synthetic
        # canaries out of argv so they are not exposed through process listings.
        command.append(f"--env={name}")
    command.extend([image, *[str(value) for value in entrypoint]])
    return command


def _run_bounded_process(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
) -> _BoundedProcessResult:
    """Run the container client while draining both pipes with hard bounds.

    ``subprocess.run(capture_output=True)`` buffers attacker-controlled analyzer
    output without a limit.  The drain threads retain a small prefix and keep
    consuming the rest so the child cannot deadlock on a full pipe.
    """

    process = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        shell=False,
        env=dict(env),
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}

    def drain(name: str, stream: Any, limit: int) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                remaining = limit - len(buffers[name])
                if remaining > 0:
                    buffers[name].extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    truncated[name] = True
        except (OSError, ValueError):
            truncated[name] = True

    threads = [
        threading.Thread(
            target=drain,
            args=("stdout", process.stdout, stdout_limit),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=("stderr", process.stderr, stderr_limit),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)
    for thread in threads:
        thread.join(timeout=2.0)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass

    return _BoundedProcessResult(
        returncode=process.returncode,
        stdout=bytes(buffers["stdout"]).decode("utf-8", errors="replace"),
        stderr=bytes(buffers["stderr"]).decode("utf-8", errors="replace"),
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
        timed_out=timed_out,
    )


def _force_remove_container(
    engine: str,
    container_name: str,
    *,
    env: Mapping[str, str],
) -> bool:
    """Remove exactly one generated container after an interrupted client."""

    try:
        cleanup = _run_bounded_process(
            [engine, "rm", "-f", "--", container_name],
            env=env,
            timeout_seconds=10.0,
            stdout_limit=32 * 1024,
            stderr_limit=32 * 1024,
        )
    except Exception:
        return False
    return not cleanup.timed_out and cleanup.returncode == 0


def _bounded_json(value: Any, *, max_chars: int = 4096) -> Any:
    if isinstance(value, str):
        return value[:max_chars]
    if isinstance(value, Mapping):
        return {
            str(key)[:128]: _bounded_json(child, max_chars=max_chars)
            for index, (key, child) in enumerate(value.items())
            if index < 64
        }
    if isinstance(value, list):
        return [_bounded_json(child, max_chars=max_chars) for child in value[:64]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:max_chars]


def _event_from_mapping(value: Mapping[str, Any]) -> BehaviorEvent:
    raw_labels = value.get("labels", [])
    labels = tuple(str(label)[:64] for label in raw_labels[:32]) if isinstance(raw_labels, list) else ()
    pid = value.get("pid")
    parent_pid = value.get("parent_pid")
    return BehaviorEvent(
        kind=str(value.get("kind") or "unknown")[:64],
        operation=str(value.get("operation") or "")[:128],
        target=str(value.get("target") or "")[:4096],
        process=str(value.get("process") or "")[:1024],
        pid=int(pid) if isinstance(pid, int) else None,
        parent_pid=int(parent_pid) if isinstance(parent_pid, int) else None,
        timestamp=float(value.get("timestamp") or 0.0),
        labels=labels,
        metadata=_bounded_json(value.get("metadata") or {}),
    )


def parse_behavior_events(
    output: str,
    *,
    max_events: int = _MAX_EVENTS,
    max_bytes: int = _MAX_EVENT_BYTES,
) -> Tuple[List[BehaviorEvent], List[DynamicIssue]]:
    """Parse bounded analyzer events and report malformed/truncated coverage."""

    issues: List[DynamicIssue] = []
    raw = output.encode("utf-8", errors="replace")
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
        output = raw.decode("utf-8", errors="ignore")
        issues.append(
            DynamicIssue(
                "DYN-COVERAGE-BYTES",
                "medium",
                "Dynamic event byte budget exceeded",
                f"Only the first {max_bytes} bytes of analyzer output were parsed.",
                evidence={"scan_status": "incomplete"},
            )
        )
    events: List[BehaviorEvent] = []
    malformed = 0
    for line_number, line in enumerate(output.splitlines(), 1):
        if not line.startswith(EVENT_PREFIX):
            continue
        if len(events) >= max_events:
            issues.append(
                DynamicIssue(
                    "DYN-COVERAGE-EVENTS",
                    "medium",
                    "Dynamic event count budget exceeded",
                    f"Only the first {max_events} events were retained.",
                    evidence={"scan_status": "incomplete"},
                )
            )
            break
        try:
            value = json.loads(line[len(EVENT_PREFIX) :])
            if not isinstance(value, Mapping):
                raise ValueError("event must be an object")
            events.append(_event_from_mapping(value))
        except Exception:
            malformed += 1
            if malformed <= 3:
                issues.append(
                    DynamicIssue(
                        "DYN-EVENT-MALFORMED",
                        "medium",
                        "Malformed dynamic analyzer event",
                        f"Event at output line {line_number} could not be decoded.",
                        evidence={"scan_status": "incomplete"},
                    )
                )
    if not events:
        issues.append(
            DynamicIssue(
                "DYN-EVENT-NONE",
                "medium",
                "Dynamic analyzer produced no structured events",
                "Execution output cannot establish behavioral coverage.",
                evidence={"scan_status": "incomplete"},
            )
        )
    return events, issues


def _event_summary(event: BehaviorEvent) -> Dict[str, Any]:
    return {
        "kind": event.kind,
        "operation": event.operation,
        "target": event.target[:240],
        "process": event.process[:160],
        "pid": event.pid,
        "labels": list(event.labels),
    }


def analyze_behavior(events: Sequence[BehaviorEvent]) -> List[DynamicIssue]:
    """Correlate low-level events into high-confidence attack chains."""

    issues: List[DynamicIssue] = []
    sensitive_reads: Dict[Optional[int], List[BehaviorEvent]] = {}
    downloads: List[BehaviorEvent] = []
    network_events: List[BehaviorEvent] = []
    parents = {
        event.pid: event.parent_pid
        for event in events
        if event.pid is not None and event.parent_pid is not None
    }
    for event in events:
        target = event.target
        labels = {label.upper() for label in event.labels}
        if event.kind in {"file_read", "secret_read", "credential_read"} and (
            _SENSITIVE_PATH_RE.search(target) or labels & {"SECRET", "PII", "PRIVATE"}
        ):
            sensitive_reads.setdefault(event.pid, []).append(event)
        if event.kind in {"network", "http", "dns", "socket"}:
            network_events.append(event)
            canary_names = event.metadata.get("canary_ids", []) if isinstance(event.metadata, Mapping) else []
            if "CANARY" in labels or canary_names:
                issues.append(
                    DynamicIssue(
                        "DYN-CANARY-EXFIL",
                        "critical",
                        "Synthetic secret left the sandbox process",
                        "A controlled canary was observed in a network event.",
                        target,
                        evidence={"event": _event_summary(event), "canary_ids": list(canary_names)[:16]},
                        remediation="Remove the exfiltration path and rotate any real credentials exposed to the component.",
                    )
                )
        if event.kind in {"download", "http"} and (
            "DOWNLOAD" in labels or event.operation.lower() in {"download", "response_body"}
        ):
            downloads.append(event)
        if event.kind in {"file_write", "memory_write"} and _PERSISTENCE_PATH_RE.search(target):
            issues.append(
                DynamicIssue(
                    "DYN-PERSISTENCE",
                    "high",
                    "Runtime persistence location modified",
                    "The component wrote to an automatic-load or persistence location.",
                    target,
                    evidence={"event": _event_summary(event)},
                    remediation="Remove the write and require explicit, scoped installation steps.",
                )
            )
        if _HOST_ESCAPE_RE.search(target) or _HOST_ESCAPE_RE.search(event.operation):
            issues.append(
                DynamicIssue(
                    "DYN-HOST-ESCAPE",
                    "critical",
                    "Container host escape surface accessed",
                    "The component attempted to access a host-management device, socket, or namespace.",
                    target,
                    evidence={"event": _event_summary(event)},
                )
            )
        if event.kind in {"prompt", "tool_output", "resource", "model_input"} and _INJECTION_RE.search(target):
            issues.append(
                DynamicIssue(
                    "DYN-PROMPT-INJECTION",
                    "high",
                    "Runtime content attempted instruction control",
                    "A prompt, resource, or tool result contained control-plane instructions.",
                    target[:240],
                    evidence={"event": _event_summary(event)},
                    remediation="Treat runtime content as untrusted data and isolate it from system instructions.",
                )
            )

    for network in network_events:
        related: List[BehaviorEvent] = []
        lineage: List[Optional[int]] = [network.pid]
        current = network.parent_pid or parents.get(network.pid)
        visited: set[Optional[int]] = set(lineage)
        while current is not None and current not in visited and len(lineage) < 64:
            lineage.append(current)
            visited.add(current)
            current = parents.get(current)
        for pid in lineage:
            related.extend(sensitive_reads.get(pid, []))
        if related:
            issues.append(
                DynamicIssue(
                    "DYN-SENSITIVE-EXFIL",
                    "critical",
                    "Sensitive data read followed by network access",
                    "The same process lineage read sensitive material and contacted an external target.",
                    network.target,
                    evidence={
                        "source": _event_summary(related[-1]),
                        "sink": _event_summary(network),
                    },
                    remediation="Remove secret access or restrict egress to an explicit allowlist.",
                )
            )
    for event in events:
        if event.kind not in {"process", "exec", "command"}:
            continue
        for download in downloads:
            artifact = str(download.metadata.get("path") or download.target)
            if artifact and (artifact in event.target or artifact in event.process):
                issues.append(
                    DynamicIssue(
                        "DYN-DOWNLOAD-EXEC",
                        "critical",
                        "Downloaded artifact was executed",
                        "A network-retrieved artifact crossed directly into command execution.",
                        event.target or event.process,
                        evidence={
                            "download": _event_summary(download),
                            "execution": _event_summary(event),
                        },
                        remediation="Require a pinned digest/signature and a separate approval before execution.",
                    )
                )
                break
    return _dedupe_issues(issues)


def _redact_text(text: str, canaries: Mapping[str, str]) -> str:
    result = text
    for name, value in canaries.items():
        result = result.replace(value, f"[REDACTED:{name}]")
    return result


def _redact_event(event: BehaviorEvent, canaries: Mapping[str, str]) -> BehaviorEvent:
    metadata_text = json.dumps(event.metadata, ensure_ascii=False)
    matched = [name for name, value in canaries.items() if value in metadata_text or value in event.target]
    metadata = json.loads(_redact_text(metadata_text, canaries))
    if matched:
        existing = metadata.get("canary_ids", []) if isinstance(metadata, dict) else []
        if isinstance(metadata, dict):
            metadata["canary_ids"] = sorted(set([*existing, *matched]))
    labels = tuple(sorted(set(list(event.labels) + (["CANARY"] if matched else []))))
    return replace(
        event,
        target=_redact_text(event.target, canaries),
        process=_redact_text(event.process, canaries),
        labels=labels,
        metadata=metadata,
    )


def run_dynamic_analysis(
    target: Path,
    image: str,
    entrypoint: Sequence[str],
    *,
    policy: SandboxPolicy = SandboxPolicy(),
    engine: str = "",
    allow_execute: bool = False,
) -> DynamicResult:
    """Execute the pinned analyzer container; never fall back to the host."""

    if not allow_execute:
        return DynamicResult(
            status="blocked",
            error="Dynamic execution requires explicit allow_execute consent",
            issues=[
                DynamicIssue(
                    "DYN-CONSENT-REQUIRED",
                    "medium",
                    "Dynamic analysis was not executed",
                    "Starting untrusted code requires an explicit approval boundary.",
                    evidence={"scan_status": "skipped", "requested": True},
                )
            ],
        )
    resolved_engine = resolve_container_engine(engine)
    if not resolved_engine:
        return DynamicResult(
            status="unavailable",
            error="No Docker or Podman executable is installed",
            issues=[
                DynamicIssue(
                    "DYN-BACKEND-UNAVAILABLE",
                    "medium",
                    "Isolated dynamic backend unavailable",
                    "ClawLock refused to execute the target directly on the host.",
                    evidence={"scan_status": "incomplete"},
                )
            ],
        )
    canaries = {
        "CLAWLOCK_CANARY_SECRET": "clawlock-secret-" + secrets.token_hex(16),
        "CLAWLOCK_CANARY_PII": "clawlock-pii-" + secrets.token_hex(16),
    }
    container_name = "clawlock-" + secrets.token_hex(16)
    try:
        command = build_container_command(
            resolved_engine,
            target,
            image,
            entrypoint,
            policy=policy,
            canary_ids=canaries,
            container_name=container_name,
        )
    except Exception as exc:
        return DynamicResult(
            status="error",
            backend=resolved_engine,
            error=f"{type(exc).__name__}: {exc}",
            issues=[
                DynamicIssue(
                    "DYN-POLICY-INVALID",
                    "medium",
                    "Dynamic sandbox policy is invalid",
                    f"{type(exc).__name__}: {exc}",
                    evidence={"scan_status": "error"},
                )
            ],
        )
    started = time.monotonic()
    try:
        process_env = dict(os.environ)
        process_env.update(canaries)
        completed = _run_bounded_process(
            command,
            env=process_env,
            timeout_seconds=policy.timeout_seconds,
            # Retain one byte beyond the parser budget so exact boundary
            # overflows are observable and cannot be reported as complete.
            stdout_limit=policy.max_event_bytes + 1,
            stderr_limit=_MAX_CAPTURE_BYTES + 1,
        )
    except Exception as exc:
        return DynamicResult(
            status="error",
            backend=resolved_engine,
            error=f"{type(exc).__name__}: {exc}",
            issues=[
                DynamicIssue(
                    "DYN-BACKEND-FAILED",
                    "medium",
                    "Dynamic backend failed",
                    "The isolated container backend could not be completed.",
                    evidence={"scan_status": "error"},
                )
            ],
            command_preview=[Path(resolved_engine).name, "run", "…", image],
        )
    if completed.timed_out:
        stdout = _redact_text(completed.stdout[:_MAX_CAPTURE_BYTES], canaries)
        stderr = _redact_text(completed.stderr[:_MAX_CAPTURE_BYTES], canaries)
        cleanup_verified = _force_remove_container(
            resolved_engine, container_name, env=process_env
        )
        timeout_issues = [
            DynamicIssue(
                "DYN-TIMEOUT",
                "medium",
                "Dynamic analysis timed out",
                "Behavior after the timeout was not observed.",
                evidence={
                    "scan_status": "incomplete",
                    "elapsed": time.monotonic() - started,
                },
            )
        ]
        if not cleanup_verified:
            timeout_issues.append(
                DynamicIssue(
                    "DYN-CONTAINER-CLEANUP",
                    "high",
                    "Timed-out analyzer container cleanup was not verified",
                    "ClawLock could not confirm removal of the exact generated container.",
                    evidence={"scan_status": "incomplete"},
                )
            )
        return DynamicResult(
            status="incomplete",
            backend=resolved_engine,
            stdout=stdout,
            stderr=stderr,
            error=f"Sandbox exceeded {policy.timeout_seconds:g}s timeout",
            issues=timeout_issues,
            command_preview=[Path(resolved_engine).name, "run", "…", image],
        )

    raw_stdout = completed.stdout
    raw_stderr = completed.stderr
    events, parse_issues = parse_behavior_events(
        raw_stdout,
        max_events=policy.max_events,
        max_bytes=policy.max_event_bytes,
    )
    events = [_redact_event(event, canaries) for event in events]
    issues = list(parse_issues)
    if completed.stdout_truncated or completed.stderr_truncated:
        issues.append(
            DynamicIssue(
                "DYN-OUTPUT-TRUNCATED",
                "medium",
                "Dynamic analyzer output exceeded capture limits",
                "Excess output was drained and discarded; behavioral coverage is incomplete.",
                evidence={
                    "scan_status": "incomplete",
                    "stdout_truncated": completed.stdout_truncated,
                    "stderr_truncated": completed.stderr_truncated,
                },
            )
        )

    analyzer_error = False
    for event in events:
        metadata_status = str(event.metadata.get("scan_status") or "").lower()
        labels = {label.lower() for label in event.labels}
        if (
            event.kind.lower() == "analyzer_diagnostic"
            or metadata_status in {"incomplete", "error"}
            or labels & {"incomplete", "error"}
        ):
            diagnostic_status = "error" if metadata_status == "error" or "error" in labels else "incomplete"
            analyzer_error = analyzer_error or diagnostic_status == "error"
            issues.append(
                DynamicIssue(
                    "DYN-ANALYZER-DIAGNOSTIC",
                    "high" if diagnostic_status == "error" else "medium",
                    "Dynamic analyzer reported incomplete coverage",
                    "The trusted analyzer emitted a structured coverage diagnostic.",
                    evidence={"scan_status": diagnostic_status},
                )
            )
    issues.extend(analyze_behavior(events))
    stdout = _redact_text(raw_stdout[:_MAX_CAPTURE_BYTES], canaries)
    stderr = _redact_text(raw_stderr[:_MAX_CAPTURE_BYTES], canaries)
    incomplete = any(issue.evidence.get("scan_status") == "incomplete" for issue in issues)
    if completed.returncode != 0:
        issues.append(
            DynamicIssue(
                "DYN-ANALYZER-EXIT",
                "medium",
                "Dynamic analyzer exited unsuccessfully",
                f"Container exited with code {completed.returncode}.",
                evidence={"scan_status": "incomplete", "exit_code": completed.returncode},
            )
        )
        incomplete = True
    return DynamicResult(
        status="error" if analyzer_error else ("incomplete" if incomplete else "complete"),
        backend=resolved_engine,
        events=events,
        issues=_dedupe_issues(issues),
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        command_preview=[Path(resolved_engine).name, "run", "…", image],
    )


def _dedupe_issues(issues: Iterable[DynamicIssue]) -> List[DynamicIssue]:
    seen: set[Tuple[str, str, str]] = set()
    result: List[DynamicIssue] = []
    for issue in issues:
        key = (issue.rule_id, issue.location, issue.detail)
        if key not in seen:
            seen.add(key)
            result.append(issue)
    return result


__all__ = [
    "BehaviorEvent",
    "DynamicIssue",
    "DynamicResult",
    "EVENT_PREFIX",
    "SandboxPolicy",
    "analyze_behavior",
    "build_container_command",
    "parse_behavior_events",
    "resolve_container_engine",
    "run_dynamic_analysis",
]
