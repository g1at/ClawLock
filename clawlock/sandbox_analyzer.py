"""Trusted helper for ClawLock's optional container dynamic backend.

This module is intended to run *inside* the locked-down analyzer image, never
directly on an operator workstation.  It executes a caller-supplied argv under
``strace`` (without a shell), converts kernel-observed file/process/network
operations into ClawLock's bounded event protocol, and keeps child stdout away
from that protocol so an untrusted program cannot forge analyzer events.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


EVENT_PREFIX = "CLAWLOCK_EVENT\t"
_MAX_TRACE_BYTES = 8 * 1024 * 1024
_MAX_OUTPUT_BYTES = 256 * 1024
_MAX_EVENTS = 20_000
_CONTAINER_MARKER = "1"
_TRACE_LINE_RE = re.compile(
    r"^(?:(?P<pid>\d+)\s+)?(?:(?P<time>\d+(?:\.\d+)?)\s+)?"
    r"(?P<call>[A-Za-z_][A-Za-z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<result>.*)$"
)
_QUOTED_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_WRITE_FLAGS_RE = re.compile(r"\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)\b")
_FD_RE = re.compile(r"^\s*(-?\d+)")
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|[/\\])(?:\.ssh|\.aws|\.azure|\.kube|\.npmrc|\.pypirc|"
    r"\.netrc|\.git-credentials|id_rsa|id_ed25519|credentials?|secrets?|"
    r"cookies?|sessions?)(?:[/\\]|$)"
)
_PERSISTENCE_RE = re.compile(
    r"(?i)(?:sitecustomize\.py|usercustomize\.py|authorized_keys|"
    r"[/\\](?:cron(?:\.d)?|systemd|launchagents|launchdaemons|startup|autostart)"
    r"(?:[/\\]|$)|\.bashrc$|\.zshrc$|\.profile$)"
)
_INJECTION_PATTERNS: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    (
        "instruction_override",
        re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|system)\s+instructions?"),
        "ignore previous instructions",
    ),
    (
        "approval_bypass",
        re.compile(r"(?i)(?:do\s+not|don't)\s+ask.{0,30}(?:approval|permission)"),
        "do not ask for approval",
    ),
    (
        "secret_request",
        re.compile(r"(?i)reveal.{0,40}(?:system\s+prompt|secret|credential)"),
        "reveal secret credentials",
    ),
)


def _decode_quoted(token: str) -> str:
    try:
        value = json.loads(token)
    except (json.JSONDecodeError, TypeError):
        return token.strip('"')
    return value if isinstance(value, str) else str(value)


def _first_quoted(text: str) -> str:
    match = _QUOTED_RE.search(text)
    return _decode_quoted(match.group(0)) if match else ""


def _canary_hits(text: str, canaries: Mapping[str, str]) -> List[str]:
    return sorted(name for name, value in canaries.items() if value and value in text)


def _redact_canaries(text: str, canaries: Mapping[str, str]) -> str:
    redacted = text
    for name, value in canaries.items():
        if value:
            redacted = redacted.replace(value, f"[REDACTED:{name}]")
    return redacted


def _network_target(arguments: str) -> str:
    ipv4 = re.search(r'inet_addr\("([^"\r\n]+)"\)', arguments)
    ipv6 = re.search(r'inet_pton\(AF_INET6,\s*"([^"\r\n]+)"\)', arguments)
    unix = re.search(r'sun_path="([^"\r\n]+)"', arguments)
    port = re.search(r"sin6?_port=htons\((\d+)\)", arguments)
    host = (
        ipv4.group(1)
        if ipv4
        else ipv6.group(1)
        if ipv6
        else f"unix:{unix.group(1)}"
        if unix
        else "unknown"
    )
    return f"{host}:{port.group(1)}" if port and not host.startswith("unix:") else host


def parse_strace_line(
    line: str,
    *,
    pid_hint: Optional[int] = None,
    canaries: Optional[Mapping[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """Convert one complete strace line into one redacted behavior event."""

    canary_values = dict(canaries or {})
    match = _TRACE_LINE_RE.match(line.strip())
    if not match:
        return None
    call = match.group("call")
    arguments = match.group("args")
    result = match.group("result")
    pid = int(match.group("pid")) if match.group("pid") else pid_hint
    timestamp = float(match.group("time")) if match.group("time") else 0.0
    canary_ids = _canary_hits(line, canary_values)
    labels: List[str] = ["CANARY"] if canary_ids else []
    event: Dict[str, Any] = {
        "kind": "syscall",
        "operation": call,
        "target": "",
        "pid": pid,
        "timestamp": timestamp,
        "labels": labels,
        "metadata": {
            "result": result[:160],
            **({"canary_ids": canary_ids} if canary_ids else {}),
        },
    }

    if call in {"open", "openat", "openat2", "creat"}:
        target = _first_quoted(arguments)
        is_write = call == "creat" or bool(_WRITE_FLAGS_RE.search(arguments))
        event["kind"] = "file_write" if is_write else "file_read"
        event["target"] = target[:4096]
        if _SENSITIVE_PATH_RE.search(target):
            event["labels"].append("SECRET")
        if is_write and _PERSISTENCE_RE.search(target):
            event["labels"].append("PERSISTENCE")
        fd_match = _FD_RE.match(result)
        if fd_match and int(fd_match.group(1)) >= 0:
            event["metadata"]["fd"] = int(fd_match.group(1))
            event["metadata"]["access"] = "write" if is_write else "read"
    elif call in {
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "renameat2",
        "mkdir",
        "mkdirat",
        "rmdir",
        "chmod",
        "fchmodat",
        "chown",
        "fchownat",
        "symlink",
        "symlinkat",
        "link",
        "linkat",
    }:
        target = _first_quoted(arguments)
        event.update(kind="file_write", target=target[:4096])
        if _PERSISTENCE_RE.search(target):
            event["labels"].append("PERSISTENCE")
    elif call in {"execve", "execveat"}:
        event.update(kind="exec", target=_first_quoted(arguments)[:4096])
    elif call in {"connect", "sendto", "sendmsg", "recvfrom", "recvmsg"}:
        event.update(kind="network", target=_network_target(arguments))
        fd_match = _FD_RE.match(arguments)
        if fd_match and int(fd_match.group(1)) >= 0:
            event["metadata"]["fd"] = int(fd_match.group(1))
        event["metadata"]["direction"] = (
            "outbound" if call in {"connect", "sendto", "sendmsg"} else "inbound"
        )
    elif call in {"clone", "clone3", "fork", "vfork"}:
        child_match = re.match(r"\s*(\d+)", result)
        event.update(kind="process", target="child-process")
        if child_match:
            event["metadata"]["child_pid"] = int(child_match.group(1))
    elif call in {"read", "write", "readv", "writev", "close", "dup", "dup2", "dup3"}:
        fd_match = _FD_RE.match(arguments)
        if not fd_match:
            return None
        fd = int(fd_match.group(1))
        event.update(kind="descriptor", target=f"fd:{fd}")
        event["metadata"]["fd"] = fd
        event["metadata"]["direction"] = (
            "read" if call in {"read", "readv"} else "write" if call in {"write", "writev"} else call
        )
        result_match = _FD_RE.match(result)
        if result_match:
            event["metadata"]["result_fd_or_bytes"] = int(result_match.group(1))
    else:
        return None

    event["target"] = _redact_canaries(str(event["target"]), canary_values)
    event["labels"] = sorted(set(event["labels"]))
    return event


def _inherit_pid_state(
    child_pid: int,
    parent_pid: Optional[int],
    files: Dict[Tuple[Optional[int], int], Tuple[str, str]],
    sockets: Dict[Tuple[Optional[int], int], str],
) -> None:
    if parent_pid is None:
        return
    for (pid, fd), value in list(files.items()):
        if pid == parent_pid:
            files[(child_pid, fd)] = value
    for (pid, fd), value in list(sockets.items()):
        if pid == parent_pid:
            sockets[(child_pid, fd)] = value


def _enrich_trace_events(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach process lineage and derive socket-to-file download provenance."""

    parents: Dict[int, Optional[int]] = {}
    files: Dict[Tuple[Optional[int], int], Tuple[str, str]] = {}
    sockets: Dict[Tuple[Optional[int], int], str] = {}
    network_reads: Dict[Optional[int], str] = {}
    enriched: List[Dict[str, Any]] = []
    for event in events:
        pid = event.get("pid") if isinstance(event.get("pid"), int) else None
        if pid is not None and pid in parents:
            event["parent_pid"] = parents[pid]
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        fd = metadata.get("fd") if isinstance(metadata.get("fd"), int) else None

        child_pid = metadata.get("child_pid")
        if event.get("kind") == "process" and isinstance(child_pid, int):
            parents[child_pid] = pid
            _inherit_pid_state(child_pid, pid, files, sockets)
        elif event.get("kind") in {"file_read", "file_write"} and fd is not None:
            files[(pid, fd)] = (str(event.get("target") or ""), str(metadata.get("access") or ""))
        elif event.get("kind") == "network" and fd is not None:
            key = (pid, fd)
            target = str(event.get("target") or "")
            if target and target != "unknown":
                sockets[key] = target
            if metadata.get("direction") == "inbound":
                network_reads[pid] = sockets.get(key, target)
        elif event.get("kind") == "descriptor" and fd is not None:
            direction = metadata.get("direction")
            key = (pid, fd)
            if direction == "read" and key in sockets:
                network_reads[pid] = sockets[key]
            elif direction == "write" and key in files and pid in network_reads:
                path, access = files[key]
                if access == "write" and path:
                    enriched.append(
                        {
                            "kind": "download",
                            "operation": "socket_to_file",
                            "target": network_reads[pid],
                            "pid": pid,
                            "parent_pid": parents.get(pid) if pid is not None else None,
                            "timestamp": event.get("timestamp", 0.0),
                            "labels": ["DOWNLOAD"],
                            "metadata": {"path": path, "fd": fd},
                        }
                    )
            elif direction == "close":
                files.pop(key, None)
                sockets.pop(key, None)
        enriched.append(event)
    return enriched


def _pid_from_trace_name(path: Path) -> Optional[int]:
    suffix = path.name.rsplit(".", 1)[-1]
    return int(suffix) if suffix.isdigit() else None


def parse_trace_files(
    paths: Iterable[Path],
    *,
    canaries: Optional[Mapping[str, str]] = None,
    max_bytes: int = _MAX_TRACE_BYTES,
    max_events: int = _MAX_EVENTS,
) -> Tuple[List[Dict[str, Any]], bool]:
    events: List[Dict[str, Any]] = []
    consumed = 0
    truncated = False
    for path in sorted(paths, key=lambda value: value.name):
        pid_hint = _pid_from_trace_name(path)
        try:
            with path.open("rb") as stream:
                while True:
                    raw = stream.readline(64 * 1024)
                    if not raw:
                        break
                    consumed += len(raw)
                    if consumed > max_bytes or len(events) >= max_events:
                        truncated = True
                        ordered = sorted(events, key=lambda item: float(item.get("timestamp") or 0.0))
                        return _enrich_trace_events(ordered), truncated
                    event = parse_strace_line(
                        raw.decode("utf-8", errors="replace"),
                        pid_hint=pid_hint,
                        canaries=canaries,
                    )
                    if event is not None:
                        events.append(event)
        except OSError:
            truncated = True
    ordered = sorted(events, key=lambda item: float(item.get("timestamp") or 0.0))
    return _enrich_trace_events(ordered), truncated


def _output_events(
    output: bytes,
    *,
    stream_name: str,
    canaries: Mapping[str, str],
) -> List[Dict[str, Any]]:
    bounded = output[:_MAX_OUTPUT_BYTES]
    text = bounded.decode("utf-8", errors="replace")
    canary_ids = _canary_hits(text, canaries)
    events: List[Dict[str, Any]] = []
    if canary_ids:
        events.append(
            {
                "kind": "tool_output",
                "operation": stream_name,
                "target": "[REDACTED synthetic canary output]",
                "labels": ["CANARY"],
                "metadata": {"canary_ids": canary_ids, "bytes": len(output)},
            }
        )
    for pattern_name, pattern, canonical in _INJECTION_PATTERNS:
        if pattern.search(text):
            events.append(
                {
                    "kind": "tool_output",
                    "operation": stream_name,
                    "target": canonical,
                    "labels": ["UNTRUSTED_INSTRUCTION"],
                    "metadata": {
                        "pattern": pattern_name,
                        "bytes": len(output),
                        "sha256": hashlib.sha256(output).hexdigest(),
                    },
                }
            )
    if not events and output:
        events.append(
            {
                "kind": "process_output",
                "operation": stream_name,
                "target": "",
                "labels": [],
                "metadata": {
                    "bytes": len(output),
                    "truncated": len(output) > len(bounded),
                    "sha256": hashlib.sha256(output).hexdigest(),
                },
            }
        )
    return events


def emit_event(event: Mapping[str, Any]) -> None:
    print(
        EVENT_PREFIX
        + json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        flush=True,
    )


def run_traced(command: Sequence[str]) -> int:
    if os.environ.get("CLAWLOCK_ANALYZER_CONTAINER") != _CONTAINER_MARKER:
        print(
            "ClawLock sandbox analyzer refused to execute outside its trusted image.",
            file=sys.stderr,
        )
        return 2
    strace = shutil.which("strace", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not strace:
        emit_event(
            {
                "kind": "analyzer_diagnostic",
                "operation": "unavailable",
                "target": "strace is not installed in the trusted analyzer image",
                "labels": ["INCOMPLETE"],
                "metadata": {"scan_status": "incomplete"},
            }
        )
        return 2
    if not command:
        emit_event(
            {
                "kind": "analyzer_diagnostic",
                "operation": "invalid_argv",
                "target": "no target argv was supplied",
                "labels": ["INCOMPLETE"],
                "metadata": {"scan_status": "error"},
            }
        )
        return 2

    canaries = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("CLAWLOCK_CANARY_") and value
    }
    try:
        timeout = min(600.0, max(0.1, float(os.environ.get("CLAWLOCK_ANALYZER_TIMEOUT", "25"))))
    except ValueError:
        timeout = 25.0

    with tempfile.TemporaryDirectory(prefix="clawlock-trace-") as temp_name:
        temp_dir = Path(temp_name)
        trace_base = temp_dir / "trace"
        stdout_path = temp_dir / "stdout"
        stderr_path = temp_dir / "stderr"
        traced_command = [
            strace,
            "-ff",
            "-ttt",
            "-yy",
            "-s",
            "2048",
            "-e",
            "trace=file,process,network,read,write,readv,writev,close,dup,dup2,dup3",
            "-o",
            str(trace_base),
            "--",
            *[str(value) for value in command],
        ]
        try:
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                completed = subprocess.run(
                    traced_command,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=timeout,
                    shell=False,
                )
        except subprocess.TimeoutExpired:
            emit_event(
                {
                    "kind": "analyzer_diagnostic",
                    "operation": "timeout",
                    "target": "target execution exceeded analyzer timeout",
                    "labels": ["INCOMPLETE"],
                    "metadata": {"scan_status": "incomplete", "timeout": timeout},
                }
            )
            return 2
        except OSError as exc:
            emit_event(
                {
                    "kind": "analyzer_diagnostic",
                    "operation": "execution_error",
                    "target": type(exc).__name__,
                    "labels": ["INCOMPLETE"],
                    "metadata": {"scan_status": "error"},
                }
            )
            return 2

        trace_paths = list(temp_dir.glob("trace*"))
        events, truncated = parse_trace_files(trace_paths, canaries=canaries)
        try:
            stdout = stdout_path.read_bytes()[: _MAX_OUTPUT_BYTES + 1]
        except OSError:
            stdout = b""
        try:
            stderr = stderr_path.read_bytes()[: _MAX_OUTPUT_BYTES + 1]
        except OSError:
            stderr = b""
        events.extend(_output_events(stdout, stream_name="stdout", canaries=canaries))
        events.extend(_output_events(stderr, stream_name="stderr", canaries=canaries))
        for event in events[:_MAX_EVENTS]:
            emit_event(event)
        if truncated or len(events) > _MAX_EVENTS:
            emit_event(
                {
                    "kind": "analyzer_diagnostic",
                    "operation": "budget_exhausted",
                    "target": "trace event budget was exhausted",
                    "labels": ["INCOMPLETE"],
                    "metadata": {"scan_status": "incomplete"},
                }
            )
        emit_event(
            {
                "kind": "process_exit",
                "operation": "exit",
                "target": "target process",
                "labels": [],
                "metadata": {"exit_code": completed.returncode},
            }
        )
        if not trace_paths:
            emit_event(
                {
                    "kind": "analyzer_diagnostic",
                    "operation": "trace_missing",
                    "target": "strace produced no trace files",
                    "labels": ["INCOMPLETE"],
                    "metadata": {"scan_status": "incomplete"},
                }
            )
            return 2
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ClawLock container behavior analyzer")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(argv)
    command = list(parsed.command)
    if command and command[0] == "--":
        command.pop(0)
    return run_traced(command)


if __name__ == "__main__":  # pragma: no cover - exercised in the container
    raise SystemExit(main())


__all__ = [
    "EVENT_PREFIX",
    "emit_event",
    "main",
    "parse_strace_line",
    "parse_trace_files",
    "run_traced",
]
