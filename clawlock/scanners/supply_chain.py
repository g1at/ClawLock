"""Offline-first supply-chain and external-instruction analysis.

The module intentionally never downloads tools or remote content. Optional
OSV-Scanner/Gitleaks adapters only execute an already installed binary with a
fixed timeout, an argv list, and ``shell=False``. Remote instruction bodies can
only be supplied through an explicit caller-provided loader.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlsplit, urlunsplit

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - exercised only on Python 3.9/3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]


EXTERNAL_TOOL_TIMEOUT_SECONDS = 30
EXTERNAL_TOOL_MAX_STDOUT_BYTES = 16 * 1024 * 1024
EXTERNAL_TOOL_MAX_STDERR_BYTES = 1 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_FILES = 5_000
MAX_INVENTORY_VISITS = 50_000
MAX_INVENTORY_BYTES = 128 * 1024 * 1024
MAX_INVENTORY_SECONDS = 10.0
MAX_REQUIREMENTS_DEPTH = 8
MAX_REQUIREMENTS_FILES = 256
MAX_REQUIREMENTS_BYTES = 16 * 1024 * 1024
MAX_LOCK_PACKAGES = 20_000
DEFAULT_INSTRUCTION_MAX_DEPTH = 6
DEFAULT_INSTRUCTION_MAX_NODES = 256
DEFAULT_INSTRUCTION_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_INSTRUCTION_MAX_SECONDS = 10.0
MAX_DIAGNOSTICS = 100

_ORIGINAL_SUBPROCESS_RUN = subprocess.run


@dataclass(frozen=True)
class SupplyChainIssue:
    rule_id: str
    severity: str
    title: str
    detail: str
    location: str
    evidence: str = ""
    confidence: float = 0.75
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DependencyRecord:
    ecosystem: str
    name: str
    spec: str
    source: str
    group: str = "dependencies"
    kind: str = "registry"
    pinned: bool = False
    mutable: bool = True
    hashes: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScriptRecord:
    ecosystem: str
    name: str
    command: str
    source: str
    lifecycle: bool = False


@dataclass
class SupplyChainReport:
    root: str
    manifests: List[str] = field(default_factory=list)
    dependencies: List[DependencyRecord] = field(default_factory=list)
    scripts: List[ScriptRecord] = field(default_factory=list)
    build_backends: List[str] = field(default_factory=list)
    lockfiles: List[str] = field(default_factory=list)
    sboms: List[str] = field(default_factory=list)
    issues: List[SupplyChainIssue] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    complete: bool = True


@dataclass(frozen=True)
class InstructionNode:
    node_id: str
    reference: str
    kind: str
    depth: int
    resolved: str = ""
    exists: Optional[bool] = None
    pinned: bool = False
    mutable: bool = True
    content_hash: str = ""
    expected_hash: str = ""


@dataclass(frozen=True)
class InstructionEdge:
    source_id: str
    target_id: str
    line: int
    reference: str


@dataclass
class InstructionGraph:
    root: str
    nodes: Dict[str, InstructionNode] = field(default_factory=dict)
    edges: List[InstructionEdge] = field(default_factory=list)
    issues: List[SupplyChainIssue] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    complete: bool = True


@dataclass(frozen=True)
class ExternalToolFinding:
    rule_id: str
    severity: str
    title: str
    location: str
    detail: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExternalToolResult:
    tool: str
    status: str
    available: bool
    complete: bool
    command: Tuple[str, ...]
    findings: Tuple[ExternalToolFinding, ...] = ()
    diagnostics: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ProvenanceIssue:
    code: str
    severity: str
    detail: str


@dataclass(frozen=True)
class ProvenanceValidation:
    valid: bool
    complete: bool
    trusted: bool
    signature_present: bool
    signature_verified: bool
    statement: Mapping[str, Any]
    matched: Mapping[str, Any]
    issues: Tuple[ProvenanceIssue, ...]


_NPM_LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
    "publish",
    "postpublish",
}
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}
_LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "pdm.lock",
    "requirements.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    "packages.lock.json",
    "gradle.lockfile",
}
_SBOM_NAME_RE = re.compile(
    r"(?i)(?:^bom\.(?:json|xml)$|\.cdx\.(?:json|xml)$|\.spdx(?:\.json|\.ya?ml|\.rdf|\.rdf\.xml)?$)"
)
_EXACT_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
_FULL_COMMIT_RE = re.compile(r"(?i)(?:[#@]|/)([0-9a-f]{40})(?:$|[?&#/])")
_SHA256_RE = re.compile(r"(?i)(?:sha256[:=])?([0-9a-f]{64})")
_SUSPICIOUS_INSTALL_RE = re.compile(
    r"(?i)(?:https?://|\bcurl\b|\bwget\b|\bnpx\b|\buvx\b|\bpowershell\b|"
    r"\b(?:bash|sh)\s+-c\b|\beval\b|\bexec\b)"
)
_URL_USERINFO_RE = re.compile(r"(?i)(https?://)[^/@\s]+@")
_URL_SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:token|key|api[_-]?key|secret|password|signature|sig)=)[^&#\s]+"
)
_SRI_TOKEN_RE = re.compile(
    r"(?i)^(sha(?:1|256|384|512))-([A-Za-z0-9+/]+={0,2})(?:\?[^\s]+)?$"
)


def _redact_reference(value: str) -> str:
    """Redact URL credentials without ever parsing them into diagnostics.

    The regex fallback also handles a URL embedded in prose.  For a complete
    HTTP(S) reference, splitting the authority at the *last* ``@`` avoids
    leaking passwords that themselves contain ``@``.
    """

    redacted = value
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() in {"http", "https"} and "@" in parsed.netloc:
            safe_netloc = "[REDACTED]@" + parsed.netloc.rsplit("@", 1)[1]
            redacted = urlunsplit(
                (parsed.scheme, safe_netloc, parsed.path, parsed.query, parsed.fragment)
            )
    except (TypeError, ValueError):
        # Malformed references still pass through the conservative regexes.
        pass
    redacted = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", redacted)
    return _URL_SECRET_QUERY_RE.sub(r"\1[REDACTED]", redacted)


def _is_reparse_stat(value: os.stat_result) -> bool:
    attributes = int(getattr(value, "st_file_attributes", 0) or 0)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(value.st_mode) or bool(attributes & reparse_flag)


def _same_file_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _stable_file_metadata(value: os.stat_result) -> Tuple[int, int]:
    return (
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))),
    )


def _safe_read_bytes(path: Path, limit: int = MAX_MANIFEST_BYTES) -> bytes:
    """Read one stable regular file through a bounded descriptor.

    ``Path.stat(); Path.read_*()`` has a swap window.  This routine lstats the
    name, opens without following the final link where the platform supports
    it, validates the descriptor, reads at most ``limit + 1`` bytes, and then
    verifies both the descriptor and path again.  The checks work on Python
    3.9 and include Windows junction/reparse metadata.
    """

    if limit < 0:
        raise ValueError("analysis byte limit must be non-negative")
    absolute_path = _absolute_without_resolving(path)
    unsafe_component = _first_reparse_component(absolute_path)
    if unsafe_component is not None:
        raise ValueError(f"symlink/reparse path component refused: {unsafe_component}")
    path = absolute_path
    before = os.lstat(os.fspath(path))
    if _is_reparse_stat(before):
        raise ValueError("symlink/reparse point refused")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("path is not a regular file")
    if before.st_size > limit:
        raise ValueError(f"file exceeds {limit} byte analysis limit")

    flags = os.O_RDONLY
    for flag_name in (
        "O_BINARY",
        "O_CLOEXEC",
        "O_NOINHERIT",
        "O_NOFOLLOW",
        "O_NONBLOCK",
    ):
        flags |= int(getattr(os, flag_name, 0) or 0)
    descriptor = os.open(os.fspath(path), flags)
    try:
        opened = os.fstat(descriptor)
        if _is_reparse_stat(opened) or not stat.S_ISREG(opened.st_mode):
            raise ValueError("opened object is not a regular file")
        if not _same_file_object(before, opened):
            raise ValueError("file changed while it was being opened")
        if opened.st_size > limit:
            raise ValueError(f"file exceeds {limit} byte analysis limit")

        chunks: List[bytes] = []
        total = 0
        while True:
            remaining = limit + 1 - total
            if remaining <= 0:
                raise ValueError(f"file exceeds {limit} byte analysis limit")
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    final = os.lstat(os.fspath(path))
    if _is_reparse_stat(final) or not _same_file_object(opened, final):
        raise ValueError("file changed while it was being read")
    if _stable_file_metadata(opened) != _stable_file_metadata(
        after
    ) or _stable_file_metadata(after) != _stable_file_metadata(final):
        raise ValueError("file changed while it was being read")
    content = b"".join(chunks)
    if len(content) > limit:
        raise ValueError(f"file exceeds {limit} byte analysis limit")
    return content


def _read_limited(path: Path, limit: int = MAX_MANIFEST_BYTES) -> str:
    return _safe_read_bytes(path, limit).decode("utf-8", errors="replace")


def _append_diagnostic(target: List[str], message: str) -> None:
    if len(target) < MAX_DIAGNOSTICS:
        target.append(message)


def _dependency_kind(spec: str) -> str:
    value = spec.strip().lower()
    if value.startswith(("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:")):
        return "git"
    if value.startswith(("http://", "https://")):
        return "http"
    if value.startswith(("file:", "link:", "../", "./", "/")):
        return "file"
    if value.startswith("workspace:"):
        return "workspace"
    return "registry"


def _hashes_in(value: str) -> Tuple[str, ...]:
    hashes = []
    for match in _SHA256_RE.finditer(value):
        digest = match.group(1).lower()
        if digest not in hashes:
            hashes.append(digest)
    return tuple(hashes)


def _is_pinned(spec: str, kind: str) -> bool:
    value = spec.strip()
    if kind == "registry":
        return bool(_EXACT_VERSION_RE.fullmatch(value))
    if kind == "git":
        return bool(_FULL_COMMIT_RE.search(value))
    if kind == "http":
        return bool(_hashes_in(value))
    if kind in {"file", "workspace"}:
        return bool(_hashes_in(value))
    return False


def dependency_record(
    ecosystem: str,
    name: str,
    spec: str,
    source: Union[str, Path],
    *,
    group: str = "dependencies",
    metadata: Optional[Mapping[str, Any]] = None,
) -> DependencyRecord:
    kind = _dependency_kind(spec)
    pinned = _is_pinned(spec, kind)
    safe_spec = _redact_reference(spec)
    return DependencyRecord(
        ecosystem=ecosystem,
        name=name,
        spec=safe_spec,
        source=str(source),
        group=group,
        kind=kind,
        pinned=pinned,
        mutable=not pinned,
        hashes=_hashes_in(spec),
        metadata=dict(metadata or {}),
    )


def _mutable_dependency_issue(dep: DependencyRecord) -> SupplyChainIssue:
    severity = "info" if dep.kind in {"file", "workspace"} else "medium"
    return SupplyChainIssue(
        rule_id="SC-DEP-MUTABLE-001",
        severity=severity,
        title=f"Mutable or unpinned dependency: {dep.name}",
        detail=(
            f"The {dep.kind} dependency is not bound to an immutable version, "
            "commit, or SHA-256 digest."
        ),
        location=dep.source,
        evidence=f"{dep.name}: {dep.spec}",
        confidence=0.88,
        metadata={"ecosystem": dep.ecosystem, "kind": dep.kind, "group": dep.group},
    )


def parse_package_json(path: Path) -> SupplyChainReport:
    report = SupplyChainReport(root=str(path.parent), manifests=[str(path)])
    try:
        data = json.loads(_read_limited(path))
    except (OSError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        report.complete = False
        report.diagnostics.append(f"{path}: {exc}")
        return report
    if not isinstance(data, dict):
        report.complete = False
        report.diagnostics.append(f"{path}: package.json root is not an object")
        return report

    for group in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        values = data.get(group, {})
        if not isinstance(values, dict):
            continue
        for name, raw_spec in values.items():
            dep = dependency_record("npm", str(name), str(raw_spec), path, group=group)
            report.dependencies.append(dep)
            if dep.mutable:
                report.issues.append(_mutable_dependency_issue(dep))

    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for name, raw_command in scripts.items():
            command = str(raw_command)
            safe_command = _redact_reference(command)
            lifecycle = name in _NPM_LIFECYCLE_SCRIPTS
            report.scripts.append(
                ScriptRecord(
                    ecosystem="npm",
                    name=str(name),
                    command=safe_command,
                    source=str(path),
                    lifecycle=lifecycle,
                )
            )
            if lifecycle:
                suspicious = bool(_SUSPICIOUS_INSTALL_RE.search(command))
                report.issues.append(
                    SupplyChainIssue(
                        rule_id="SC-NPM-LIFECYCLE-001",
                        severity="high" if suspicious else "medium",
                        title=f"npm lifecycle script executes during package handling: {name}",
                        detail=(
                            "Lifecycle scripts execute with installer privileges; review the exact command "
                            "and pin the package source."
                        ),
                        location=str(path),
                        evidence=safe_command[:500],
                        confidence=0.92 if suspicious else 0.75,
                        metadata={"script": name, "suspicious_command": suspicious},
                    )
                )
    return report


def _integrity_algorithms(integrity: str) -> Tuple[str, ...]:
    algorithms: List[str] = []
    for token in integrity.split():
        match = _SRI_TOKEN_RE.fullmatch(token)
        if match and match.group(1).lower() not in algorithms:
            algorithms.append(match.group(1).lower())
    return tuple(algorithms)


def _package_lock_entries(
    data: Mapping[str, Any], report: SupplyChainReport
) -> List[Tuple[str, Mapping[str, Any], str]]:
    entries: List[Tuple[str, Mapping[str, Any], str]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for lock_path, raw_entry in packages.items():
            if not lock_path or not isinstance(raw_entry, dict):
                continue
            if len(entries) >= MAX_LOCK_PACKAGES:
                report.complete = False
                _append_diagnostic(
                    report.diagnostics, "package-lock package budget exceeded"
                )
                break
            marker = "node_modules/"
            name = str(raw_entry.get("name", ""))
            if not name:
                name = str(lock_path).rsplit(marker, 1)[-1]
            entries.append((name, raw_entry, str(lock_path)))
        return entries

    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        return entries
    pending = deque(
        (str(name), value, f"dependencies.{name}")
        for name, value in dependencies.items()
        if isinstance(value, dict)
    )
    while pending:
        if len(entries) >= MAX_LOCK_PACKAGES:
            report.complete = False
            _append_diagnostic(
                report.diagnostics, "package-lock package budget exceeded"
            )
            break
        name, raw_entry, lock_path = pending.popleft()
        entries.append((name, raw_entry, lock_path))
        nested = raw_entry.get("dependencies")
        if isinstance(nested, dict):
            for child_name, child in nested.items():
                if isinstance(child, dict):
                    pending.append(
                        (
                            str(child_name),
                            child,
                            f"{lock_path}.dependencies.{child_name}",
                        )
                    )
    return entries


def _lock_dependency_record(
    path: Path,
    name: str,
    entry: Mapping[str, Any],
    lock_path: str,
) -> DependencyRecord:
    version = str(entry.get("version", "")).strip()
    resolved = str(entry.get("resolved", "")).strip()
    integrity = str(entry.get("integrity", "")).strip()
    algorithms = _integrity_algorithms(integrity)
    kind = _dependency_kind(resolved or version)
    if kind == "registry":
        pinned = bool(_EXACT_VERSION_RE.fullmatch(version)) and (
            not resolved or bool(set(algorithms) & {"sha256", "sha384", "sha512"})
        )
    elif kind == "git":
        pinned = _is_pinned(resolved, kind)
    elif kind == "http":
        pinned = bool(set(algorithms) & {"sha256", "sha384", "sha512"})
    else:
        pinned = bool(entry.get("link")) or _is_pinned(resolved or version, kind)
    return DependencyRecord(
        ecosystem="npm-lock",
        name=name,
        spec=version or _redact_reference(resolved) or "*",
        source=str(path),
        group="lockfile",
        kind=kind,
        pinned=pinned,
        mutable=not pinned,
        hashes=_hashes_in(integrity),
        metadata={
            "lock_path": lock_path,
            "resolved": _redact_reference(resolved)[:500],
            "integrity_algorithms": algorithms,
            "dev": bool(entry.get("dev")),
            "optional": bool(entry.get("optional")),
            "link": bool(entry.get("link")),
        },
    )


def _package_lock_entry_issues(
    path: Path,
    dep: DependencyRecord,
    entry: Mapping[str, Any],
) -> List[SupplyChainIssue]:
    issues: List[SupplyChainIssue] = []
    resolved = str(entry.get("resolved", "")).strip()
    integrity = str(entry.get("integrity", "")).strip()
    algorithms = _integrity_algorithms(integrity)
    location = f"{path}:{dep.metadata.get('lock_path', dep.name)}"
    redacted_resolved = _redact_reference(resolved)
    if resolved and redacted_resolved != resolved:
        issues.append(
            SupplyChainIssue(
                rule_id="SC-LOCK-RESOLVED-CREDENTIAL-001",
                severity="high",
                title=f"Lockfile resolved URL embeds credentials: {dep.name}",
                detail="Credentials in lockfile URLs can leak through source control and logs.",
                location=location,
                evidence=redacted_resolved[:500],
                confidence=0.98,
            )
        )
    parsed = urlparse(resolved)
    if parsed.scheme.lower() == "http":
        issues.append(
            SupplyChainIssue(
                rule_id="SC-LOCK-RESOLVED-HTTP-001",
                severity="high",
                title=f"Lockfile artifact uses plaintext HTTP: {dep.name}",
                detail="The resolved package artifact can be modified in transit.",
                location=location,
                evidence=redacted_resolved[:500],
                confidence=0.98,
            )
        )
    if resolved and dep.kind == "git" and not _is_pinned(resolved, "git"):
        issues.append(
            SupplyChainIssue(
                rule_id="SC-LOCK-RESOLVED-MUTABLE-001",
                severity="high",
                title=f"Lockfile git dependency is not commit-pinned: {dep.name}",
                detail="The resolved git source is still controlled by a mutable ref.",
                location=location,
                evidence=redacted_resolved[:500],
                confidence=0.96,
            )
        )
    if resolved and dep.kind in {"registry", "http"} and not integrity:
        issues.append(
            SupplyChainIssue(
                rule_id="SC-LOCK-INTEGRITY-MISSING-001",
                severity="medium",
                title=f"Lockfile artifact has no integrity value: {dep.name}",
                detail="A resolved archive without SRI cannot be checked against content drift.",
                location=location,
                evidence=redacted_resolved[:500],
                confidence=0.9,
            )
        )
    elif integrity and not algorithms:
        issues.append(
            SupplyChainIssue(
                rule_id="SC-LOCK-INTEGRITY-INVALID-001",
                severity="high",
                title=f"Lockfile integrity value is malformed: {dep.name}",
                detail="No valid Subresource Integrity token could be parsed.",
                location=location,
                evidence="malformed integrity metadata",
                confidence=0.98,
            )
        )
    elif algorithms and not (set(algorithms) & {"sha256", "sha384", "sha512"}):
        issues.append(
            SupplyChainIssue(
                rule_id="SC-LOCK-INTEGRITY-WEAK-001",
                severity="medium",
                title=f"Lockfile uses only weak SHA-1 integrity: {dep.name}",
                detail="Regenerate the lockfile with SHA-256 or stronger integrity metadata.",
                location=location,
                evidence="integrity algorithm: sha1",
                confidence=0.95,
            )
        )
    return issues


def _dependency_tables(data: Mapping[str, Any]) -> Dict[str, str]:
    dependencies: Dict[str, str] = {}
    for group in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        values = data.get(group)
        if isinstance(values, dict):
            dependencies.update({str(name): str(spec) for name, spec in values.items()})
    return dependencies


def _package_lock_manifest_drift(
    path: Path,
    lock_data: Mapping[str, Any],
    report: SupplyChainReport,
) -> None:
    manifest_path = path.parent / "package.json"
    try:
        manifest_stat = os.lstat(os.fspath(manifest_path))
    except FileNotFoundError:
        return
    except OSError as exc:
        report.complete = False
        _append_diagnostic(report.diagnostics, f"{manifest_path}: {exc}")
        return
    if _is_reparse_stat(manifest_stat) or not stat.S_ISREG(manifest_stat.st_mode):
        report.complete = False
        _append_diagnostic(
            report.diagnostics,
            f"package manifest for lock drift check is unsafe: {manifest_path}",
        )
        return
    try:
        manifest_data = json.loads(_read_limited(manifest_path))
    except (OSError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        report.complete = False
        _append_diagnostic(report.diagnostics, f"{manifest_path}: {exc}")
        return
    if not isinstance(manifest_data, dict):
        report.complete = False
        _append_diagnostic(
            report.diagnostics, f"{manifest_path}: root is not an object"
        )
        return
    packages = lock_data.get("packages")
    lock_root = packages.get("") if isinstance(packages, dict) else None
    manifest_dependencies = _dependency_tables(manifest_data)
    if isinstance(lock_root, dict):
        lock_dependencies = _dependency_tables(lock_root)
        names = sorted(set(manifest_dependencies) | set(lock_dependencies))
        for name in names:
            manifest_spec = manifest_dependencies.get(name)
            lock_spec = lock_dependencies.get(name)
            if manifest_spec == lock_spec:
                continue
            report.issues.append(
                SupplyChainIssue(
                    rule_id="SC-LOCK-MANIFEST-DRIFT-001",
                    severity="high",
                    title=f"package.json and lockfile declarations drift: {name}",
                    detail="The reviewed manifest and lockfile root declare different dependency inputs.",
                    location=str(path),
                    evidence=_redact_reference(
                        f"manifest={manifest_spec!r} lock={lock_spec!r}"
                    )[:500],
                    confidence=0.98,
                    metadata={"package": name},
                )
            )
        return
    if isinstance(packages, dict) and manifest_dependencies:
        for name in sorted(manifest_dependencies):
            report.issues.append(
                SupplyChainIssue(
                    rule_id="SC-LOCK-MANIFEST-DRIFT-001",
                    severity="high",
                    title=f"Lockfile root declaration is missing: {name}",
                    detail="The modern package lock has no root dependency declaration to compare.",
                    location=str(path),
                    evidence=name[:500],
                    confidence=0.95,
                    metadata={"package": name},
                )
            )
        return
    legacy = lock_data.get("dependencies")
    if isinstance(legacy, dict):
        missing = sorted(set(manifest_dependencies) - {str(name) for name in legacy})
        for name in missing:
            report.issues.append(
                SupplyChainIssue(
                    rule_id="SC-LOCK-MANIFEST-DRIFT-001",
                    severity="high",
                    title=f"Manifest dependency is absent from lockfile: {name}",
                    detail="The legacy lockfile does not resolve a dependency declared by package.json.",
                    location=str(path),
                    evidence=name[:500],
                    confidence=0.96,
                    metadata={"package": name},
                )
            )


def parse_package_lock(path: Path) -> SupplyChainReport:
    report = SupplyChainReport(root=str(path.parent), lockfiles=[str(path)])
    try:
        data = json.loads(_read_limited(path))
    except (OSError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        report.complete = False
        report.diagnostics.append(f"{path}: {exc}")
        return report
    if not isinstance(data, dict):
        report.complete = False
        report.diagnostics.append(f"{path}: package lock root is not an object")
        return report
    for name, entry, lock_path in _package_lock_entries(data, report):
        dep = _lock_dependency_record(path, name, entry, lock_path)
        report.dependencies.append(dep)
        report.issues.extend(_package_lock_entry_issues(path, dep, entry))
    _package_lock_manifest_drift(path, data, report)
    return report


_PEP508_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_pep508_dependency(
    value: str, source: Path, group: str
) -> Optional[DependencyRecord]:
    cleaned = value.strip()
    match = _PEP508_NAME_RE.match(cleaned)
    if not match:
        return None
    name = match.group(1)
    remainder = cleaned[match.end() :].strip()
    if remainder.startswith("["):
        closing = remainder.find("]")
        remainder = remainder[closing + 1 :].strip() if closing >= 0 else remainder
    if remainder.startswith("@"):
        spec = remainder[1:].strip()
    else:
        spec = remainder.split(";", 1)[0].strip()
        if spec.startswith("=="):
            spec = spec[2:].strip()
    if not spec:
        spec = "*"
    return dependency_record("pypi", name, spec, source, group=group)


def parse_pyproject(path: Path) -> SupplyChainReport:
    report = SupplyChainReport(root=str(path.parent), manifests=[str(path)])
    if tomllib is None:
        report.complete = False
        report.diagnostics.append(
            "TOML parser unavailable (install tomli on Python <3.11)"
        )
        return report
    try:
        raw = _safe_read_bytes(path, MAX_MANIFEST_BYTES)
        data = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        report.complete = False
        report.diagnostics.append(f"{path}: {exc}")
        return report

    build_system = data.get("build-system", {})
    if isinstance(build_system, dict):
        backend = str(build_system.get("build-backend", "")).strip()
        if backend:
            report.build_backends.append(backend)
        backend_path = build_system.get("backend-path", [])
        if backend_path:
            report.issues.append(
                SupplyChainIssue(
                    rule_id="SC-PY-BACKEND-PATH-001",
                    severity="medium",
                    title="pyproject uses an in-tree build backend",
                    detail="An in-tree backend executes repository-controlled code during build isolation.",
                    location=str(path),
                    evidence=str(backend_path)[:500],
                    confidence=0.88,
                )
            )
        for raw in build_system.get("requires", []) or []:
            dep = _parse_pep508_dependency(str(raw), path, "build-system.requires")
            if dep:
                report.dependencies.append(dep)
                if dep.mutable:
                    report.issues.append(_mutable_dependency_issue(dep))

    project = data.get("project", {})
    if isinstance(project, dict):
        for raw in project.get("dependencies", []) or []:
            dep = _parse_pep508_dependency(str(raw), path, "project.dependencies")
            if dep:
                report.dependencies.append(dep)
                if dep.mutable:
                    report.issues.append(_mutable_dependency_issue(dep))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, values in optional.items():
                for raw in values or []:
                    dep = _parse_pep508_dependency(
                        str(raw), path, f"project.optional-dependencies.{group}"
                    )
                    if dep:
                        report.dependencies.append(dep)
                        if dep.mutable:
                            report.issues.append(_mutable_dependency_issue(dep))
        for table_name in ("scripts", "gui-scripts"):
            table = project.get(table_name, {})
            if isinstance(table, dict):
                for name, target in table.items():
                    report.scripts.append(
                        ScriptRecord(
                            ecosystem="pypi",
                            name=str(name),
                            command=str(target),
                            source=str(path),
                            lifecycle=False,
                        )
                    )
        entry_points = project.get("entry-points", {})
        if isinstance(entry_points, dict):
            for group, entries in entry_points.items():
                if not isinstance(entries, dict):
                    continue
                for name, target in entries.items():
                    report.scripts.append(
                        ScriptRecord(
                            ecosystem="pypi",
                            name=f"{group}:{name}",
                            command=str(target),
                            source=str(path),
                            lifecycle=False,
                        )
                    )
    return report


def _logical_requirement_lines(text: str) -> List[str]:
    logical: List[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pending += (" " if pending else "") + stripped.rstrip("\\").strip()
        if stripped.endswith("\\"):
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)
    return logical


_REQUIREMENT_INCLUDE_RE = re.compile(
    r"^(?:(-r)(?:\s*=?\s*)(.+)|(--requirement)(?:\s+|=)(.+)|"
    r"(-c)(?:\s*=?\s*)(.+)|(--constraint)(?:\s+|=)(.+))$",
    re.IGNORECASE,
)


def _requirement_include(line: str) -> Optional[Tuple[str, str]]:
    match = _REQUIREMENT_INCLUDE_RE.fullmatch(line.strip())
    if not match:
        return None
    constraint = bool(match.group(5) or match.group(7))
    reference = next(
        (
            value
            for value in (
                match.group(2),
                match.group(4),
                match.group(6),
                match.group(8),
            )
            if value
        ),
        "",
    ).strip()
    reference = re.split(r"\s+#", reference, maxsplit=1)[0].strip()
    if len(reference) >= 2 and reference[0] == reference[-1] and reference[0] in "\"'":
        reference = reference[1:-1]
    return ("constraints" if constraint else "requirements", reference)


def _requirements_issue(
    rule_id: str,
    severity: str,
    title: str,
    detail: str,
    location: Path,
    reference: str,
) -> SupplyChainIssue:
    return SupplyChainIssue(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        location=str(location),
        evidence=_redact_reference(reference)[:500],
        confidence=0.95,
    )


def _append_requirement_dependency(
    report: SupplyChainReport,
    line: str,
    source: Path,
    group: str,
    hash_mode: bool,
) -> None:
    editable = False
    value = line
    if value.startswith(("-e ", "--editable ")):
        parts = value.split(None, 1)
        if len(parts) != 2:
            return
        editable = True
        value = parts[1]
    hashes = _hashes_in(value)
    value_without_options = re.split(
        r"\s+--(?:hash|config-settings|global-option)=", value, 1
    )[0]
    if value_without_options.startswith(("git+", "http://", "https://", "file:")):
        egg = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", value_without_options)
        name = egg.group(1) if egg else Path(urlparse(value_without_options).path).stem
        spec = value_without_options
    else:
        match = _PEP508_NAME_RE.match(value_without_options)
        if not match:
            return
        name = match.group(1)
        rest = value_without_options[match.end() :].strip()
        if rest.startswith("=="):
            spec = rest[2:].split(";", 1)[0].strip()
        elif rest.startswith("@"):
            spec = rest[1:].strip()
        else:
            spec = rest or "*"
    dep = dependency_record(
        "pypi",
        name,
        spec,
        source,
        group=group,
        metadata={"editable": editable, "hash_mode": hash_mode},
    )
    if hashes:
        dep = DependencyRecord(
            **{
                **dep.__dict__,
                "hashes": hashes,
                "pinned": dep.pinned or bool(hashes),
                "mutable": False,
            }
        )
    report.dependencies.append(dep)
    if dep.mutable:
        report.issues.append(_mutable_dependency_issue(dep))
    if hash_mode and not hashes:
        report.issues.append(
            SupplyChainIssue(
                rule_id="SC-REQ-HASH-MISSING-001",
                severity="medium",
                title=f"Requirement lacks a hash in hash-locked file: {name}",
                detail="Every requirement should carry a cryptographic hash when hash mode is used.",
                location=str(source),
                evidence=_redact_reference(line)[:500],
                confidence=0.9,
            )
        )


def parse_requirements(path: Path) -> SupplyChainReport:
    initial = _absolute_without_resolving(path)
    allowed_root = initial.parent
    report = SupplyChainReport(root=str(allowed_root))
    unsafe_root = _first_reparse_component(allowed_root)
    if unsafe_root is not None:
        report.complete = False
        _append_diagnostic(
            report.diagnostics,
            f"requirements root contains a symlink/reparse point: {unsafe_root}",
        )
        return report

    pending = deque([(initial, 0, "requirements", str(initial))])
    scheduled = {os.path.normcase(os.fspath(initial))}
    visited: Set[str] = set()
    total_bytes = 0
    while pending:
        current, depth, group, display_reference = pending.popleft()
        key = os.path.normcase(os.fspath(current))
        scheduled.discard(key)
        if key in visited:
            report.issues.append(
                _requirements_issue(
                    "SC-REQ-INCLUDE-CYCLE-001",
                    "medium",
                    "Requirements include cycle or reuse",
                    "The same included requirements file was reached more than once.",
                    current,
                    display_reference,
                )
            )
            continue
        if len(visited) >= MAX_REQUIREMENTS_FILES:
            report.complete = False
            _append_diagnostic(
                report.diagnostics, "requirements include file budget exceeded"
            )
            break
        visited.add(key)
        if str(current) not in report.manifests:
            report.manifests.append(str(current))

        unsafe_component = _first_reparse_component(current, root=allowed_root)
        if unsafe_component is not None:
            report.complete = False
            report.issues.append(
                _requirements_issue(
                    "SC-REQ-INCLUDE-SYMLINK-001",
                    "high",
                    "Requirements include crosses a symlink/reparse point",
                    "Requirements links and junctions are not followed.",
                    current,
                    display_reference,
                )
            )
            _append_diagnostic(
                report.diagnostics,
                f"requirements symlink/reparse point refused: {unsafe_component}",
            )
            continue
        try:
            content = _safe_read_bytes(current, MAX_REQUIREMENTS_BYTES - total_bytes)
        except (OSError, ValueError) as exc:
            report.complete = False
            report.issues.append(
                _requirements_issue(
                    "SC-REQ-INCLUDE-READ-001",
                    "medium",
                    "Requirements include could not be read",
                    "A root or included requirements file was missing, unsafe, or unreadable.",
                    current,
                    display_reference,
                )
            )
            _append_diagnostic(report.diagnostics, f"{current}: {exc}")
            continue
        total_bytes += len(content)
        lines = _logical_requirement_lines(content.decode("utf-8", errors="replace"))
        hash_mode = any("--hash=" in line for line in lines)
        for line in lines:
            include = _requirement_include(line)
            if include is None:
                _append_requirement_dependency(report, line, current, group, hash_mode)
                continue
            include_group, reference = include
            child_group = "constraints" if group == "constraints" else include_group
            raw_target = Path(unquote(reference)).expanduser()
            scheme = urlparse(reference).scheme.lower()
            if scheme and not raw_target.is_absolute():
                report.complete = False
                report.issues.append(
                    _requirements_issue(
                        "SC-REQ-INCLUDE-REMOTE-001",
                        "high",
                        "Remote requirements include was not fetched",
                        "Only local includes inside the package root are inspected offline.",
                        current,
                        reference,
                    )
                )
                _append_diagnostic(
                    report.diagnostics,
                    f"remote requirements include was not read: {_redact_reference(reference)}",
                )
                continue
            target = _local_instruction_target(allowed_root, str(current), reference)
            if target is None:
                report.complete = False
                report.issues.append(
                    _requirements_issue(
                        "SC-REQ-INCLUDE-PATH-ESCAPE-001",
                        "high",
                        "Requirements include escapes the package root",
                        "Local includes are restricted to the root requirements directory.",
                        current,
                        reference,
                    )
                )
                _append_diagnostic(
                    report.diagnostics,
                    f"requirements include path escaped the root: {_redact_reference(reference)}",
                )
                continue
            child_key = os.path.normcase(os.fspath(target))
            if child_key in visited or child_key in scheduled:
                report.issues.append(
                    _requirements_issue(
                        "SC-REQ-INCLUDE-CYCLE-001",
                        "medium",
                        "Requirements include cycle or reuse",
                        "The same included requirements file was reached more than once.",
                        current,
                        reference,
                    )
                )
                _append_diagnostic(
                    report.diagnostics,
                    f"requirements include depth budget reached: {_redact_reference(reference)}",
                )
                continue
            if depth >= MAX_REQUIREMENTS_DEPTH:
                report.complete = False
                report.issues.append(
                    _requirements_issue(
                        "SC-REQ-INCLUDE-DEPTH-001",
                        "medium",
                        "Requirements include depth budget exceeded",
                        "Nested includes beyond the bounded depth were not inspected.",
                        current,
                        reference,
                    )
                )
                continue
            if len(visited) + len(scheduled) >= MAX_REQUIREMENTS_FILES:
                report.complete = False
                _append_diagnostic(
                    report.diagnostics, "requirements include file budget exceeded"
                )
                continue
            pending.append((target, depth + 1, child_group, reference))
            scheduled.add(child_key)
    return report


def _merge_report(target: SupplyChainReport, source: SupplyChainReport) -> None:
    target.manifests.extend(
        item for item in source.manifests if item not in target.manifests
    )
    target.dependencies.extend(source.dependencies)
    target.scripts.extend(source.scripts)
    target.build_backends.extend(source.build_backends)
    target.lockfiles.extend(
        item for item in source.lockfiles if item not in target.lockfiles
    )
    target.sboms.extend(item for item in source.sboms if item not in target.sboms)
    target.issues.extend(source.issues)
    target.diagnostics.extend(source.diagnostics)
    target.complete = target.complete and source.complete


def _parse_sbom_json(path: Path) -> List[DependencyRecord]:
    data = json.loads(_read_limited(path))
    records: List[DependencyRecord] = []
    if isinstance(data, dict) and isinstance(data.get("components"), list):
        for component in data["components"]:
            if not isinstance(component, dict) or not component.get("name"):
                continue
            records.append(
                dependency_record(
                    "sbom",
                    str(component["name"]),
                    str(component.get("version", "*")),
                    path,
                    group="cyclonedx",
                    metadata={"purl": component.get("purl", "")},
                )
            )
    if isinstance(data, dict) and isinstance(data.get("packages"), list):
        for package in data["packages"]:
            if not isinstance(package, dict) or not package.get("name"):
                continue
            records.append(
                dependency_record(
                    "sbom",
                    str(package["name"]),
                    str(package.get("versionInfo", "*")),
                    path,
                    group="spdx",
                    metadata={"spdx_id": package.get("SPDXID", "")},
                )
            )
    return records


def _is_manifest_candidate(path: Path) -> bool:
    name = path.name
    return bool(
        name in {"package.json", "pyproject.toml"}
        or re.fullmatch(r"(?i)requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt", name)
        or name in _LOCKFILE_NAMES
        or _SBOM_NAME_RE.search(name)
    )


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _inventory_supply_files(root: Path, report: SupplyChainReport) -> List[Path]:
    """Inventory only relevant files while bounding all directory work."""

    candidates: List[Path] = []
    scan_root = _absolute_without_resolving(root)
    try:
        root_stat = os.lstat(os.fspath(scan_root))
    except OSError as exc:
        report.complete = False
        _append_diagnostic(
            report.diagnostics, f"path is not readable: {scan_root}: {exc}"
        )
        return candidates

    unsafe_root = _first_reparse_component(scan_root)
    if _is_reparse_stat(root_stat) or unsafe_root is not None:
        report.complete = False
        _append_diagnostic(
            report.diagnostics,
            f"explicit symlink/reparse scan target refused: {unsafe_root or scan_root}",
        )
        return candidates
    if stat.S_ISREG(root_stat.st_mode):
        return [scan_root]
    if not stat.S_ISDIR(root_stat.st_mode):
        report.complete = False
        _append_diagnostic(
            report.diagnostics, f"scan target is not a file or directory: {scan_root}"
        )
        return candidates

    started = time.monotonic()
    pending = [scan_root]
    visits = 0
    candidate_bytes = 0
    budget_exhausted = False
    while pending and not budget_exhausted:
        if time.monotonic() - started > MAX_INVENTORY_SECONDS:
            report.complete = False
            _append_diagnostic(
                report.diagnostics, "manifest inventory time budget exceeded"
            )
            break
        directory = pending.pop()
        try:
            iterator = os.scandir(os.fspath(directory))
        except OSError as exc:
            report.complete = False
            _append_diagnostic(
                report.diagnostics,
                f"directory could not be inventoried: {directory}: {exc}",
            )
            continue
        with iterator:
            for entry in iterator:
                visits += 1
                if visits > MAX_INVENTORY_VISITS:
                    report.complete = False
                    _append_diagnostic(
                        report.diagnostics, "manifest inventory visit budget exceeded"
                    )
                    budget_exhausted = True
                    break
                if time.monotonic() - started > MAX_INVENTORY_SECONDS:
                    report.complete = False
                    _append_diagnostic(
                        report.diagnostics, "manifest inventory time budget exceeded"
                    )
                    budget_exhausted = True
                    break
                entry_path = Path(entry.path)
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    report.complete = False
                    _append_diagnostic(
                        report.diagnostics,
                        f"inventory entry could not be inspected: {entry_path}: {exc}",
                    )
                    continue
                if _is_reparse_stat(entry_stat):
                    report.complete = False
                    _append_diagnostic(
                        report.diagnostics,
                        f"symlink/reparse entry was not followed: {entry_path}",
                    )
                    continue
                if stat.S_ISDIR(entry_stat.st_mode):
                    if entry.name not in _SKIP_DIRS:
                        pending.append(entry_path)
                    continue
                if not stat.S_ISREG(entry_stat.st_mode) or not _is_manifest_candidate(
                    entry_path
                ):
                    continue
                if len(candidates) >= MAX_MANIFEST_FILES:
                    report.complete = False
                    _append_diagnostic(
                        report.diagnostics, "manifest candidate budget exceeded"
                    )
                    budget_exhausted = True
                    break
                if candidate_bytes + entry_stat.st_size > MAX_INVENTORY_BYTES:
                    report.complete = False
                    _append_diagnostic(
                        report.diagnostics, "manifest inventory byte budget exceeded"
                    )
                    budget_exhausted = True
                    break
                candidate_bytes += entry_stat.st_size
                candidates.append(entry_path)
    return candidates


def scan_supply_chain(root: Path) -> SupplyChainReport:
    root = root.expanduser()
    report = SupplyChainReport(root=str(root))
    candidates = _inventory_supply_files(root, report)

    for path in sorted(candidates, key=lambda item: str(item).lower()):
        name = path.name
        if name == "package.json":
            _merge_report(report, parse_package_json(path))
        elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
            _merge_report(report, parse_package_lock(path))
        elif name == "pyproject.toml":
            _merge_report(report, parse_pyproject(path))
        elif re.fullmatch(r"(?i)requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt", name):
            _merge_report(report, parse_requirements(path))
        if name in _LOCKFILE_NAMES and str(path) not in report.lockfiles:
            report.lockfiles.append(str(path))
        if _SBOM_NAME_RE.search(name):
            report.sboms.append(str(path))
            if path.suffix.lower() == ".json":
                try:
                    report.dependencies.extend(_parse_sbom_json(path))
                except (
                    OSError,
                    ValueError,
                    json.JSONDecodeError,
                    RecursionError,
                ) as exc:
                    report.complete = False
                    _append_diagnostic(report.diagnostics, f"{path}: {exc}")
    return report


_URL_RE = re.compile(r"https?://[^\s<>'\"`)\]]+")
_MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
_LOCAL_REF_RE = re.compile(
    r"(?im)^\s*(?:include|source|import|instructions?|load)\s*[:=]\s*[\"']?([^\s\"']+)"
    r"|(?<!\w)@((?:\.{0,2}[/\\])?[A-Za-z0-9_.-]+(?:[/\\][A-Za-z0-9_.-]+)*\.(?:md|txt|ya?ml|json|toml))"
)


def _instruction_refs(text: str) -> List[Tuple[str, int]]:
    refs: List[Tuple[str, int]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        found: List[str] = []
        found.extend(match.group(0).rstrip(".,;") for match in _URL_RE.finditer(line))
        found.extend(
            match.group(1).strip() for match in _MARKDOWN_LINK_RE.finditer(line)
        )
        for match in _LOCAL_REF_RE.finditer(line):
            found.append((match.group(1) or match.group(2) or "").strip())
        for reference in found:
            if reference and not reference.startswith("#"):
                item = (reference, line_number)
                if item not in refs:
                    refs.append(item)
    return refs


def _normalized_digest(value: str) -> str:
    match = _SHA256_RE.search(value or "")
    return match.group(1).lower() if match else ""


def _url_pin(url: str) -> str:
    digest = _normalized_digest(url)
    if digest:
        return digest
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for key in ("sha256", "digest", "checksum"):
        for value in query.get(key, []):
            digest = _normalized_digest(value)
            if digest:
                return digest
    match = re.search(r"(?i)/(?:raw|blob)/([0-9a-f]{40})/", parsed.path)
    return f"git:{match.group(1).lower()}" if match else ""


def _instruction_node_id(kind: str, reference: str, resolved: str) -> str:
    raw = f"{kind}\0{resolved or reference}"
    return (
        "ref-" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
    )


def _first_reparse_component(
    path: Path, *, root: Optional[Path] = None
) -> Optional[Path]:
    """Return the first existing symlink/reparse component without following it."""

    if root is None:
        anchor = Path(path.anchor)
        parts = path.parts[1:] if path.anchor else path.parts
        current = anchor
    else:
        current = root
        try:
            parts = path.relative_to(root).parts
        except ValueError:
            return path
    try:
        current_stat = os.lstat(os.fspath(current))
    except OSError:
        return current
    if _is_reparse_stat(current_stat):
        return current
    for part in parts:
        current = current / part
        try:
            current_stat = os.lstat(os.fspath(current))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return current
        if _is_reparse_stat(current_stat):
            return current
    return None


def _local_instruction_target(
    root: Path,
    parent_location: str,
    reference: str,
) -> Optional[Path]:
    parent_dir = Path(parent_location).parent if parent_location else root
    raw_reference = unquote(reference).strip()
    if "\x00" in raw_reference:
        return None
    target = Path(raw_reference).expanduser()
    if not target.is_absolute():
        target = parent_dir / target
    target = _absolute_without_resolving(target)
    try:
        common = Path(os.path.commonpath((os.fspath(root), os.fspath(target))))
    except (OSError, ValueError):
        return None
    if os.path.normcase(os.fspath(common)) != os.path.normcase(os.fspath(root)):
        return None
    return target


def _instruction_read_issue(location: str, reference: str) -> SupplyChainIssue:
    return SupplyChainIssue(
        rule_id="SC-INSTR-READ-001",
        severity="medium",
        title="Instruction content could not be inspected",
        detail="The referenced instruction was not safely and completely readable.",
        location=_redact_reference(location),
        evidence=_redact_reference(reference)[:500],
        confidence=0.95,
    )


def build_instruction_graph(
    root: Path,
    entry_points: Iterable[Union[str, Path]],
    *,
    expected_hashes: Optional[Mapping[str, str]] = None,
    remote_loader: Optional[Callable[[str], Optional[Union[str, bytes]]]] = None,
    max_depth: int = DEFAULT_INSTRUCTION_MAX_DEPTH,
    max_nodes: int = DEFAULT_INSTRUCTION_MAX_NODES,
    max_bytes: int = DEFAULT_INSTRUCTION_MAX_BYTES,
) -> InstructionGraph:
    root_resolved = _absolute_without_resolving(root)
    graph = InstructionGraph(root=str(root_resolved))
    if max_depth < 0 or max_nodes < 1 or max_bytes < 0:
        graph.complete = False
        _append_diagnostic(graph.diagnostics, "invalid instruction graph budget")
        return graph
    try:
        root_stat = os.lstat(os.fspath(root_resolved))
    except OSError:
        graph.complete = False
        _append_diagnostic(
            graph.diagnostics, "instruction analysis root is not readable"
        )
        return graph
    unsafe_root = _first_reparse_component(root_resolved)
    if _is_reparse_stat(root_stat) or unsafe_root is not None:
        graph.complete = False
        _append_diagnostic(
            graph.diagnostics,
            f"instruction analysis root contains a symlink/reparse point: {unsafe_root or root_resolved}",
        )
        return graph
    if not stat.S_ISDIR(root_stat.st_mode):
        graph.complete = False
        _append_diagnostic(
            graph.diagnostics, "instruction analysis root is not a directory"
        )
        return graph

    expected = dict(expected_hashes or {})
    total_bytes = 0
    started = time.monotonic()
    queue = deque()
    for entry in entry_points:
        if len(queue) >= max_nodes:
            graph.complete = False
            _append_diagnostic(
                graph.diagnostics, "instruction graph entry-point budget exceeded"
            )
            break
        if time.monotonic() - started > DEFAULT_INSTRUCTION_MAX_SECONDS:
            graph.complete = False
            _append_diagnostic(
                graph.diagnostics, "instruction graph time budget exceeded"
            )
            break
        queue.append((str(entry), "", 0, "", 0))

    reference_visits = 0
    max_reference_visits = max_nodes * 8
    while queue:
        if time.monotonic() - started > DEFAULT_INSTRUCTION_MAX_SECONDS:
            graph.complete = False
            _append_diagnostic(
                graph.diagnostics, "instruction graph time budget exceeded"
            )
            break
        reference_visits += 1
        if reference_visits > max_reference_visits:
            graph.complete = False
            _append_diagnostic(
                graph.diagnostics, "instruction graph reference budget exceeded"
            )
            break
        reference, parent_id, depth, parent_location, edge_line = queue.popleft()
        if (
            parent_location
            and urlparse(parent_location).scheme in {"http", "https"}
            and urlparse(reference).scheme not in {"http", "https"}
        ):
            reference = urljoin(parent_location, reference)
        is_url = bool(urlparse(reference).scheme in {"http", "https"})
        kind = "url" if is_url else "file"
        resolved = ""
        exists: Optional[bool] = None
        content: Optional[bytes] = None
        expected_digest = _normalized_digest(expected.get(reference, ""))
        pinned_token = _url_pin(reference) if is_url else expected_digest

        if is_url:
            resolved = reference
            node_id = _instruction_node_id(kind, reference, resolved)
            if node_id in graph.nodes:
                if parent_id:
                    edge = InstructionEdge(
                        parent_id, node_id, edge_line, _redact_reference(reference)
                    )
                    if edge not in graph.edges:
                        graph.edges.append(edge)
                    _append_diagnostic(
                        graph.diagnostics,
                        f"instruction cycle/reuse stopped at {_redact_reference(reference)}",
                    )
                continue
            if len(graph.nodes) >= max_nodes:
                graph.complete = False
                _append_diagnostic(
                    graph.diagnostics, "instruction graph node budget exceeded"
                )
                break
            if remote_loader is not None:
                try:
                    loaded = remote_loader(reference)
                    if loaded is None:
                        exists = False
                        graph.complete = False
                        _append_diagnostic(
                            graph.diagnostics,
                            f"remote instruction was not returned: {_redact_reference(reference)}",
                        )
                    elif isinstance(loaded, str):
                        remaining = max_bytes - total_bytes
                        if len(loaded) > remaining:
                            raise ValueError(
                                "remote instruction exceeds remaining byte budget"
                            )
                        encoded = loaded.encode("utf-8", errors="replace")
                        if len(encoded) > remaining:
                            raise ValueError(
                                "remote instruction exceeds remaining byte budget"
                            )
                        content = encoded
                        exists = True
                    elif isinstance(loaded, bytes):
                        if len(loaded) > max_bytes - total_bytes:
                            raise ValueError(
                                "remote instruction exceeds remaining byte budget"
                            )
                        content = loaded
                        exists = True
                    else:
                        raise TypeError(
                            "remote loader returned an unsupported content type"
                        )
                except (
                    Exception
                ):  # caller-owned loader; never expose its exception text
                    exists = False
                    graph.complete = False
                    _append_diagnostic(
                        graph.diagnostics,
                        f"remote loader failed for {_redact_reference(reference)}",
                    )
                    content = None
        else:
            target_resolved = _local_instruction_target(
                root_resolved, parent_location, reference
            )
            if target_resolved is None:
                issue_location = _redact_reference(parent_location) or str(
                    root_resolved
                )
                graph.issues.append(
                    SupplyChainIssue(
                        rule_id="SC-INSTR-PATH-ESCAPE-001",
                        severity="high",
                        title="Instruction reference escapes the analysis root",
                        detail="A local instruction include resolves outside the allowed package root.",
                        location=issue_location,
                        evidence=_redact_reference(reference)[:500],
                        confidence=0.95,
                    )
                )
                continue
            resolved = str(target_resolved)
            node_id = _instruction_node_id(kind, reference, resolved)
            if node_id in graph.nodes:
                if parent_id:
                    edge = InstructionEdge(
                        parent_id, node_id, edge_line, _redact_reference(reference)
                    )
                    if edge not in graph.edges:
                        graph.edges.append(edge)
                    _append_diagnostic(
                        graph.diagnostics,
                        f"instruction cycle/reuse stopped at {_redact_reference(reference)}",
                    )
                continue
            if len(graph.nodes) >= max_nodes:
                graph.complete = False
                _append_diagnostic(
                    graph.diagnostics, "instruction graph node budget exceeded"
                )
                break
            for key in (resolved, target_resolved.as_posix()):
                if not expected_digest:
                    expected_digest = _normalized_digest(expected.get(key, ""))
            try:
                relative_key = target_resolved.relative_to(root_resolved).as_posix()
                if not expected_digest:
                    expected_digest = _normalized_digest(expected.get(relative_key, ""))
            except ValueError:
                pass
            unsafe_component = _first_reparse_component(
                target_resolved, root=root_resolved
            )
            if unsafe_component is not None:
                exists = False
                graph.complete = False
                graph.issues.append(
                    SupplyChainIssue(
                        rule_id="SC-INSTR-SYMLINK-001",
                        severity="high",
                        title="Instruction reference crosses a symlink/reparse point",
                        detail="Local instruction links and junctions are not followed.",
                        location=_redact_reference(parent_location)
                        or str(root_resolved),
                        evidence=_redact_reference(reference)[:500],
                        confidence=0.98,
                    )
                )
                _append_diagnostic(
                    graph.diagnostics,
                    f"instruction symlink/reparse point refused: {unsafe_component}",
                )
            else:
                try:
                    target_stat = os.lstat(os.fspath(target_resolved))
                    exists = stat.S_ISREG(target_stat.st_mode) and not _is_reparse_stat(
                        target_stat
                    )
                except FileNotFoundError:
                    exists = False
                except OSError as exc:
                    exists = False
                    graph.complete = False
                    _append_diagnostic(graph.diagnostics, f"{target_resolved}: {exc}")
                    graph.issues.append(_instruction_read_issue(resolved, reference))
                if exists:
                    try:
                        content = _safe_read_bytes(
                            target_resolved, max_bytes - total_bytes
                        )
                    except (OSError, ValueError) as exc:
                        graph.complete = False
                        _append_diagnostic(
                            graph.diagnostics, f"{target_resolved}: {exc}"
                        )
                        graph.issues.append(
                            _instruction_read_issue(resolved, reference)
                        )
                        content = None
                elif not any(
                    issue.rule_id in {"SC-INSTR-SYMLINK-001", "SC-INSTR-READ-001"}
                    and issue.evidence == _redact_reference(reference)[:500]
                    for issue in graph.issues
                ):
                    graph.complete = False
                    graph.issues.append(
                        SupplyChainIssue(
                            rule_id="SC-INSTR-MISSING-001",
                            severity="medium",
                            title="Referenced instruction file is missing",
                            detail="The local reference could not be resolved to a readable file.",
                            location=_redact_reference(parent_location)
                            or str(root_resolved),
                            evidence=_redact_reference(reference)[:500],
                            confidence=0.9,
                        )
                    )
                    _append_diagnostic(
                        graph.diagnostics,
                        f"instruction file was not readable: {_redact_reference(reference)}",
                    )

        if content is not None:
            total_bytes += len(content)
            if total_bytes > max_bytes:
                graph.complete = False
                _append_diagnostic(
                    graph.diagnostics, "instruction graph byte budget exceeded"
                )
                content = None

        content_hash = (
            hashlib.sha256(content).hexdigest() if content is not None else ""
        )
        pinned = bool(pinned_token or expected_digest)
        node_id = _instruction_node_id(kind, reference, resolved)
        node = InstructionNode(
            node_id=node_id,
            reference=_redact_reference(reference),
            kind=kind,
            depth=depth,
            resolved=_redact_reference(resolved),
            exists=exists,
            pinned=pinned,
            mutable=not pinned,
            content_hash=content_hash,
            expected_hash=expected_digest or _normalized_digest(pinned_token),
        )
        graph.nodes[node_id] = node
        if parent_id:
            edge = InstructionEdge(
                parent_id, node_id, edge_line, _redact_reference(reference)
            )
            if edge not in graph.edges:
                graph.edges.append(edge)

        if expected_digest and content_hash and expected_digest != content_hash:
            graph.issues.append(
                SupplyChainIssue(
                    rule_id="SC-INSTR-HASH-DRIFT-001",
                    severity="high",
                    title="Instruction content hash drift",
                    detail="Current instruction content does not match its expected SHA-256 digest.",
                    location=_redact_reference(resolved or reference),
                    evidence=f"expected={expected_digest} actual={content_hash}",
                    confidence=0.99,
                )
            )
        if node.mutable and (node.kind == "url" or parent_id):
            graph.issues.append(
                SupplyChainIssue(
                    rule_id="SC-INSTR-MUTABLE-001",
                    severity="medium" if node.kind == "url" else "info",
                    title="Mutable external instruction reference",
                    detail="The instruction is not pinned to a SHA-256 digest or immutable commit.",
                    location=_redact_reference(
                        parent_location or resolved or reference
                    ),
                    evidence=_redact_reference(reference)[:500],
                    confidence=0.85,
                    metadata={"kind": node.kind},
                )
            )

        if content is None:
            continue
        decoded = content.decode("utf-8", errors="replace")
        child_refs = _instruction_refs(decoded)
        if depth >= max_depth:
            if child_refs:
                graph.complete = False
                _append_diagnostic(
                    graph.diagnostics,
                    f"instruction depth budget reached at {_redact_reference(reference)}",
                )
            continue
        pending_budget = max_nodes * 4
        for child_ref, line in child_refs:
            if len(queue) >= pending_budget:
                graph.complete = False
                _append_diagnostic(
                    graph.diagnostics, "instruction pending-reference budget exceeded"
                )
                break
            queue.append((child_ref, node_id, depth + 1, resolved, line))

    return graph


def _tool_unavailable(name: str) -> ExternalToolResult:
    return ExternalToolResult(
        tool=name,
        status="unavailable",
        available=False,
        complete=False,
        command=(),
        diagnostics=(
            f"{name} is not installed or not on PATH; nothing was downloaded",
        ),
    )


def _tool_refused(name: str, diagnostic: str) -> ExternalToolResult:
    return ExternalToolResult(
        tool=name,
        status="refused",
        available=False,
        complete=False,
        command=(),
        diagnostics=(diagnostic,),
    )


def _path_is_within(candidate: Path, parent: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(candidate), os.fspath(parent)))
    except (OSError, ValueError):
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(parent))


def _validate_external_target(target: Path) -> Tuple[Optional[Path], str]:
    absolute = _absolute_without_resolving(target)
    unsafe = _first_reparse_component(absolute)
    if unsafe is not None:
        return (
            None,
            f"external scanner target contains a symlink/reparse point: {unsafe}",
        )
    try:
        target_stat = os.lstat(os.fspath(absolute))
    except OSError:
        return None, "external scanner target is missing or unreadable"
    if not (stat.S_ISREG(target_stat.st_mode) or stat.S_ISDIR(target_stat.st_mode)):
        return None, "external scanner target is not a regular file or directory"
    if stat.S_ISREG(target_stat.st_mode):
        return absolute, ""

    pending = [absolute]
    visits = 0
    started = time.monotonic()
    while pending:
        if time.monotonic() - started > MAX_INVENTORY_SECONDS:
            return None, "external scanner target inventory exceeded its time budget"
        directory = pending.pop()
        try:
            iterator = os.scandir(os.fspath(directory))
        except OSError:
            return None, "external scanner target directory could not be inventoried"
        with iterator:
            for entry in iterator:
                visits += 1
                if visits > MAX_INVENTORY_VISITS:
                    return (
                        None,
                        "external scanner target inventory exceeded its visit budget",
                    )
                if time.monotonic() - started > MAX_INVENTORY_SECONDS:
                    return (
                        None,
                        "external scanner target inventory exceeded its time budget",
                    )
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError:
                    return None, "external scanner target entry could not be inspected"
                if _is_reparse_stat(entry_stat):
                    return None, (
                        "external scanner target contains a symlink/reparse entry: "
                        f"{entry.path}"
                    )
                if stat.S_ISDIR(entry_stat.st_mode):
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(entry_stat.st_mode):
                    return (
                        None,
                        "external scanner target contains a special filesystem entry",
                    )
    return absolute, ""


def _safe_path_for_lookup(target: Path) -> str:
    cwd = _absolute_without_resolving(Path.cwd())
    target_scope = target if target.is_dir() else target.parent
    entries: List[str] = []
    for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
        raw_entry = raw_entry.strip().strip('"')
        if not raw_entry:
            continue
        entry = Path(raw_entry).expanduser()
        if not entry.is_absolute():
            continue
        absolute = _absolute_without_resolving(entry)
        if _path_is_within(absolute, cwd) or _path_is_within(absolute, target_scope):
            continue
        if _first_reparse_component(absolute) is not None:
            continue
        entries.append(str(absolute))
    return os.pathsep.join(entries)


def _resolve_external_executable(
    executable: str,
    target: Path,
) -> Tuple[Optional[str], str]:
    requested = Path(executable).expanduser()
    candidate_display = ""
    if requested.is_absolute():
        candidate = _absolute_without_resolving(requested)
        candidate_display = str(candidate)
    else:
        if requested.parent != Path("."):
            return None, "relative external-tool paths are refused"
        safe_path = _safe_path_for_lookup(target)
        try:
            resolved = shutil.which(executable, path=safe_path)
        except TypeError:
            # Compatibility with simple caller/test shims; the result is still
            # subjected to the same absolute path and scope checks below.
            resolved = shutil.which(executable)
        if not resolved:
            return None, ""
        candidate = Path(resolved)
        if not candidate.is_absolute():
            return None, "external tool resolved through a relative PATH entry"
        candidate_display = str(resolved)
        candidate = _absolute_without_resolving(candidate)

    cwd = _absolute_without_resolving(Path.cwd())
    target_scope = target if target.is_dir() else target.parent
    if _path_is_within(candidate, cwd):
        return (
            None,
            "external tools found inside the current working directory are refused",
        )
    if _path_is_within(candidate, target_scope):
        return None, "external tools found inside the analysis target are refused"
    if os.name == "nt" and candidate.suffix.lower() not in {".exe", ".com"}:
        return None, "Windows script/batch external-tool launchers are refused"
    try:
        candidate_stat = os.lstat(os.fspath(candidate))
    except FileNotFoundError:
        # A real shutil.which never returns a missing file.  Keeping the
        # absolute path lets the spawn boundary report a fail-closed error and
        # preserves compatibility with caller-provided resolver shims.
        return candidate_display, ""
    except OSError:
        return None, "external tool could not be inspected"
    if _is_reparse_stat(candidate_stat):
        return None, "symlink/reparse external-tool executables are refused"
    if not stat.S_ISREG(candidate_stat.st_mode):
        return None, "external tool is not a regular file"
    if _first_reparse_component(candidate) is not None:
        return None, "external-tool path contains a symlink/reparse point"
    if os.name != "nt" and not os.access(os.fspath(candidate), os.X_OK):
        return None, "external tool is not executable"
    return candidate_display, ""


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except (OSError, ValueError):
            pass
    try:
        process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_bounded_process(
    name: str,
    command: Tuple[str, ...],
) -> Tuple[Optional[int], bytes, Optional[ExternalToolResult]]:
    popen_options: Dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
        "bufsize": 0,
    }
    if os.name == "nt":
        popen_options["creationflags"] = int(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) or 0
        )
    else:
        popen_options["start_new_session"] = True
    try:
        process = subprocess.Popen(list(command), **popen_options)
    except OSError:
        return (
            None,
            b"",
            ExternalToolResult(
                name,
                "error",
                True,
                False,
                command,
                diagnostics=("external tool could not be started",),
            ),
        )

    stdout_parts: List[bytes] = []
    overflow_labels: List[str] = []
    reader_errors: List[str] = []
    stop_event = threading.Event()
    list_lock = threading.Lock()

    def read_stream(stream: Any, limit: int, label: str, output: bool) -> None:
        total = 0
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                remaining = limit - total
                if remaining <= 0 or len(chunk) > remaining:
                    if output and remaining > 0:
                        stdout_parts.append(chunk[:remaining])
                    with list_lock:
                        overflow_labels.append(label)
                    stop_event.set()
                    break
                if output:
                    stdout_parts.append(chunk)
                total += len(chunk)
        except (OSError, ValueError):
            with list_lock:
                reader_errors.append(label)
            stop_event.set()
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    assert process.stdout is not None
    assert process.stderr is not None
    readers = [
        threading.Thread(
            target=read_stream,
            args=(process.stdout, EXTERNAL_TOOL_MAX_STDOUT_BYTES, "stdout", True),
            daemon=True,
        ),
        threading.Thread(
            target=read_stream,
            args=(process.stderr, EXTERNAL_TOOL_MAX_STDERR_BYTES, "stderr", False),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + EXTERNAL_TOOL_TIMEOUT_SECONDS
    timed_out = False
    while process.poll() is None:
        if stop_event.is_set():
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        try:
            process.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            continue
    if timed_out or stop_event.is_set():
        _terminate_process(process)
    for reader in readers:
        reader.join(timeout=1.0)
    stalled_stream = any(reader.is_alive() for reader in readers)
    if stalled_stream:
        _terminate_process(process)

    if timed_out:
        return (
            None,
            b"",
            ExternalToolResult(
                name,
                "timeout",
                True,
                False,
                command,
                diagnostics=(
                    f"{name} exceeded the fixed {EXTERNAL_TOOL_TIMEOUT_SECONDS}s timeout",
                ),
            ),
        )
    if overflow_labels:
        labels = ", ".join(sorted(set(overflow_labels)))
        return (
            None,
            b"",
            ExternalToolResult(
                name,
                "output_limit",
                True,
                False,
                command,
                diagnostics=(f"{name} exceeded the bounded {labels} output limit",),
            ),
        )
    if reader_errors or stalled_stream:
        return (
            None,
            b"",
            ExternalToolResult(
                name,
                "error",
                True,
                False,
                command,
                diagnostics=(f"{name} output streams could not be read completely",),
            ),
        )
    return process.returncode, b"".join(stdout_parts), None


def _parse_tool_json(
    name: str,
    command: Tuple[str, ...],
    returncode: int,
    stdout: Union[str, bytes],
) -> Tuple[Optional[Any], ExternalToolResult]:
    output = (
        stdout.decode("utf-8", errors="replace")
        if isinstance(stdout, bytes)
        else stdout
    )
    output = output.strip()
    try:
        payload = json.loads(output) if output else None
    except (json.JSONDecodeError, RecursionError) as exc:
        return None, ExternalToolResult(
            name,
            "error",
            True,
            False,
            command,
            diagnostics=(f"invalid JSON output: {exc}",),
        )
    if payload is None:
        return None, ExternalToolResult(
            name,
            "error",
            True,
            False,
            command,
            diagnostics=("tool produced no JSON report",),
        )
    if returncode not in (0, 1):
        return payload, ExternalToolResult(
            name,
            "error",
            True,
            False,
            command,
            diagnostics=(
                f"tool exited with code {returncode}; stderr was not retained",
            ),
        )
    return payload, ExternalToolResult(name, "complete", True, True, command)


def _execute_json_tool(
    name: str,
    executable: str,
    args: Sequence[str],
) -> Tuple[Optional[Any], ExternalToolResult]:
    command = (executable, *args)
    if subprocess.run is not _ORIGINAL_SUBPROCESS_RUN:
        # Existing callers sometimes inject a deterministic runner.  Enforce
        # the same postcondition limits even though production always streams.
        try:
            completed = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                timeout=EXTERNAL_TOOL_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return None, ExternalToolResult(
                name,
                "timeout",
                True,
                False,
                command,
                diagnostics=(
                    f"{name} exceeded the fixed {EXTERNAL_TOOL_TIMEOUT_SECONDS}s timeout",
                ),
            )
        except OSError:
            return None, ExternalToolResult(
                name,
                "error",
                True,
                False,
                command,
                diagnostics=("external tool could not be started",),
            )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        stdout_size = len(
            stdout.encode("utf-8", errors="replace")
            if isinstance(stdout, str)
            else stdout
        )
        stderr_size = len(
            stderr.encode("utf-8", errors="replace")
            if isinstance(stderr, str)
            else stderr
        )
        if (
            stdout_size > EXTERNAL_TOOL_MAX_STDOUT_BYTES
            or stderr_size > EXTERNAL_TOOL_MAX_STDERR_BYTES
        ):
            return None, ExternalToolResult(
                name,
                "output_limit",
                True,
                False,
                command,
                diagnostics=(f"{name} exceeded the bounded output limit",),
            )
        return _parse_tool_json(name, command, completed.returncode, stdout)

    returncode, stdout, failure = _run_bounded_process(name, command)
    if failure is not None or returncode is None:
        return None, failure or ExternalToolResult(
            name, "error", True, False, command, diagnostics=("external tool failed",)
        )
    return _parse_tool_json(name, command, returncode, stdout)


def run_osv_scanner(
    target: Path, *, executable: str = "osv-scanner"
) -> ExternalToolResult:
    safe_target, target_error = _validate_external_target(target)
    if safe_target is None:
        return _tool_refused("osv-scanner", target_error)
    resolved_executable, executable_error = _resolve_external_executable(
        executable, safe_target
    )
    if not resolved_executable:
        if executable_error:
            return _tool_refused("osv-scanner", executable_error)
        return _tool_unavailable("osv-scanner")
    payload, base = _execute_json_tool(
        "osv-scanner",
        resolved_executable,
        ("scan", "source", "--format", "json", str(safe_target)),
    )
    if payload is None or not base.complete:
        return base
    findings: List[ExternalToolFinding] = []
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return ExternalToolResult(
            base.tool,
            "error",
            base.available,
            False,
            base.command,
            diagnostics=("osv-scanner returned an unexpected JSON schema",),
        )
    schema_error = False
    results = payload["results"]
    for result in results:
        if not isinstance(result, dict):
            schema_error = True
            continue
        source = result.get("source", {})
        source_path = (
            source.get("path", "") if isinstance(source, dict) else str(source)
        )
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            schema_error = True
            continue
        for package_result in packages:
            if not isinstance(package_result, dict):
                schema_error = True
                continue
            package = package_result.get("package", {})
            package_name = package.get("name", "") if isinstance(package, dict) else ""
            version = str(package_result.get("version", ""))
            vulnerabilities = package_result.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                schema_error = True
                continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    schema_error = True
                    continue
                vuln_id = str(vulnerability.get("id", "OSV"))
                findings.append(
                    ExternalToolFinding(
                        rule_id=vuln_id,
                        severity=str(
                            vulnerability.get("database_specific", {}).get(
                                "severity", "high"
                            )
                        ).lower()
                        if isinstance(vulnerability.get("database_specific"), dict)
                        else "high",
                        title=f"Vulnerable dependency: {package_name} {version}".strip(),
                        location=_redact_reference(str(source_path or target)),
                        detail=str(vulnerability.get("summary", ""))[:500],
                        metadata={
                            "package": package_name,
                            "version": version,
                            "source": "osv-scanner",
                        },
                    )
                )
    return ExternalToolResult(
        tool=base.tool,
        status="error" if schema_error else base.status,
        available=base.available,
        complete=base.complete and not schema_error,
        command=base.command,
        findings=tuple(findings),
        diagnostics=("osv-scanner JSON report was only partially understood",)
        if schema_error
        else base.diagnostics,
    )


def run_gitleaks(target: Path, *, executable: str = "gitleaks") -> ExternalToolResult:
    safe_target, target_error = _validate_external_target(target)
    if safe_target is None:
        return _tool_refused("gitleaks", target_error)
    resolved_executable, executable_error = _resolve_external_executable(
        executable, safe_target
    )
    if not resolved_executable:
        if executable_error:
            return _tool_refused("gitleaks", executable_error)
        return _tool_unavailable("gitleaks")
    payload, base = _execute_json_tool(
        "gitleaks",
        resolved_executable,
        (
            "dir",
            str(safe_target),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
            "--no-color",
            "--redact=100",
        ),
    )
    if payload is None or not base.complete:
        return base
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        rows = payload["findings"]
    else:
        return ExternalToolResult(
            base.tool,
            "error",
            base.available,
            False,
            base.command,
            diagnostics=("gitleaks returned an unexpected JSON schema",),
        )
    findings: List[ExternalToolFinding] = []
    schema_error = False
    for row in rows:
        if not isinstance(row, dict):
            schema_error = True
            continue
        rule_id = str(row.get("RuleID", row.get("rule_id", "gitleaks")))
        file_name = _redact_reference(str(row.get("File", row.get("file", target))))
        line = row.get("StartLine", row.get("line", ""))
        location = f"{file_name}:{line}" if line else file_name
        # Deliberately omit Secret/Match fields from both detail and metadata.
        findings.append(
            ExternalToolFinding(
                rule_id=rule_id,
                severity="high",
                title=_redact_reference(
                    str(
                        row.get(
                            "Description", row.get("description", "Potential secret")
                        )
                    )
                )[:500],
                location=location,
                detail="Secret material was redacted at the adapter boundary.",
                metadata={
                    "fingerprint": row.get("Fingerprint", row.get("fingerprint", "")),
                    "source": "gitleaks",
                },
            )
        )
    return ExternalToolResult(
        tool=base.tool,
        status="error" if schema_error else base.status,
        available=base.available,
        complete=base.complete and not schema_error,
        command=base.command,
        findings=tuple(findings),
        diagnostics=("gitleaks JSON report was only partially understood",)
        if schema_error
        else base.diagnostics,
    )


def _load_provenance(value: Union[Path, str, Mapping[str, Any]]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, Path):
        return json.loads(_read_limited(value))
    candidate = Path(value)
    if len(value) < 1_024 and candidate.exists():
        return json.loads(_read_limited(candidate))
    return json.loads(value)


def _extract_statement(payload: Mapping[str, Any]) -> Tuple[Mapping[str, Any], bool]:
    if "payload" not in payload or "payloadType" not in payload:
        return payload, False
    raw = base64.b64decode(str(payload["payload"]), validate=True)
    statement = json.loads(raw.decode("utf-8"))
    if not isinstance(statement, dict):
        raise ValueError("DSSE payload is not a JSON object")
    signatures = payload.get("signatures", [])
    return statement, bool(signatures)


def _collect_source_uris(predicate: Mapping[str, Any]) -> Set[str]:
    uris: Set[str] = set()

    def walk(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                if child_key.lower() in {"uri", "repository", "source"} and isinstance(
                    child, str
                ):
                    uris.add(child)
                walk(child, child_key)
        elif isinstance(value, list):
            for child in value:
                walk(child, key)

    for section in ("materials", "invocation", "buildDefinition"):
        if section in predicate:
            walk(predicate[section], section)
    return uris


def validate_slsa_provenance(
    provenance: Union[Path, str, Mapping[str, Any]],
    *,
    expected_digest: str = "",
    expected_builder: str = "",
    expected_source: str = "",
    expected_predicate_type: str = "",
    expected_subject: str = "",
    expected: Optional[Mapping[str, str]] = None,
) -> ProvenanceValidation:
    conditions = dict(expected or {})
    expected_digest = conditions.get("digest", expected_digest)
    expected_builder = conditions.get("builder", expected_builder)
    expected_source = conditions.get("source", expected_source)
    expected_predicate_type = conditions.get(
        "predicate", conditions.get("predicate_type", expected_predicate_type)
    )
    expected_subject = conditions.get("subject", expected_subject)
    issues: List[ProvenanceIssue] = []
    matched: Dict[str, Any] = {}
    try:
        loaded = _load_provenance(provenance)
        statement, signature_present = _extract_statement(loaded)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        base64.binascii.Error,
        RecursionError,
    ) as exc:
        return ProvenanceValidation(
            valid=False,
            complete=False,
            trusted=False,
            signature_present=False,
            signature_verified=False,
            statement={},
            matched={},
            issues=(ProvenanceIssue("SLSA-PARSE-001", "error", str(exc)[:500]),),
        )

    statement_type = str(statement.get("_type", ""))
    if statement_type not in {
        "https://in-toto.io/Statement/v0.1",
        "https://in-toto.io/Statement/v1",
    }:
        issues.append(
            ProvenanceIssue(
                "SLSA-STATEMENT-TYPE-001",
                "error",
                "provenance is not a supported in-toto Statement",
            )
        )

    predicate_type = str(statement.get("predicateType", ""))
    predicate = statement.get("predicate", {})
    if not isinstance(predicate, dict):
        predicate = {}
    if not predicate_type:
        issues.append(
            ProvenanceIssue(
                "SLSA-PREDICATE-MISSING-001", "error", "predicateType is missing"
            )
        )
    elif expected_predicate_type and predicate_type != expected_predicate_type:
        issues.append(
            ProvenanceIssue(
                "SLSA-PREDICATE-MISMATCH-001",
                "error",
                f"expected predicateType {expected_predicate_type}, got {predicate_type}",
            )
        )
    else:
        matched["predicate_type"] = predicate_type

    subjects = statement.get("subject", [])
    valid_digests: List[Tuple[str, str, str]] = []
    for subject in subjects if isinstance(subjects, list) else []:
        if not isinstance(subject, dict):
            continue
        name = str(subject.get("name", ""))
        digest_map = subject.get("digest", {})
        if not isinstance(digest_map, dict):
            continue
        for algorithm, raw_digest in digest_map.items():
            digest = str(raw_digest).lower()
            if algorithm.lower() == "sha256" and re.fullmatch(r"[0-9a-f]{64}", digest):
                valid_digests.append((name, "sha256", digest))
    if not valid_digests:
        issues.append(
            ProvenanceIssue(
                "SLSA-DIGEST-MISSING-001",
                "error",
                "no valid subject SHA-256 digest was found",
            )
        )
    normalized_expected = _normalized_digest(expected_digest)
    if expected_digest and not normalized_expected:
        issues.append(
            ProvenanceIssue(
                "SLSA-EXPECTED-DIGEST-INVALID-001",
                "error",
                "expected digest is not a valid SHA-256 value",
            )
        )
    elif normalized_expected:
        digest_matches = [
            item for item in valid_digests if item[2] == normalized_expected
        ]
        if expected_subject:
            digest_matches = [
                item for item in digest_matches if item[0] == expected_subject
            ]
        if not digest_matches:
            issues.append(
                ProvenanceIssue(
                    "SLSA-DIGEST-MISMATCH-001",
                    "error",
                    "subject name/digest does not match the expected artifact",
                )
            )
        else:
            matched["digest"] = normalized_expected
            matched["subject"] = digest_matches[0][0]
    elif expected_subject and not any(
        item[0] == expected_subject for item in valid_digests
    ):
        issues.append(
            ProvenanceIssue(
                "SLSA-SUBJECT-MISMATCH-001",
                "error",
                "expected subject name was not found",
            )
        )

    builder = ""
    run_details = predicate.get("runDetails", {})
    if isinstance(run_details, dict):
        builder_obj = run_details.get("builder", {})
        if isinstance(builder_obj, dict):
            builder = str(builder_obj.get("id", ""))
    if not builder:
        builder_obj = predicate.get("builder", {})
        if isinstance(builder_obj, dict):
            builder = str(builder_obj.get("id", ""))
    if not builder:
        issues.append(
            ProvenanceIssue(
                "SLSA-BUILDER-MISSING-001", "error", "builder.id is missing"
            )
        )
    elif expected_builder and builder != expected_builder:
        issues.append(
            ProvenanceIssue(
                "SLSA-BUILDER-MISMATCH-001",
                "error",
                f"expected builder {expected_builder}, got {builder}",
            )
        )
    else:
        matched["builder"] = builder

    sources = _collect_source_uris(predicate)
    if not sources:
        issues.append(
            ProvenanceIssue(
                "SLSA-SOURCE-MISSING-001", "error", "no source/material URI was found"
            )
        )
    elif expected_source and expected_source not in sources:
        issues.append(
            ProvenanceIssue(
                "SLSA-SOURCE-MISMATCH-001",
                "error",
                f"expected source {expected_source} was not found",
            )
        )
    else:
        matched["sources"] = sorted(sources)

    if signature_present:
        issues.append(
            ProvenanceIssue(
                "SLSA-SIGNATURE-UNVERIFIED-001",
                "warning",
                "DSSE signatures are present but cryptographic verification requires a trusted key policy",
            )
        )
    else:
        issues.append(
            ProvenanceIssue(
                "SLSA-SIGNATURE-MISSING-001",
                "warning",
                "The provenance statement is structurally valid but has no verified DSSE signature",
            )
        )

    valid = not any(issue.severity == "error" for issue in issues)
    return ProvenanceValidation(
        valid=valid,
        complete=True,
        trusted=False,
        signature_present=signature_present,
        signature_verified=False,
        statement=statement,
        matched=matched,
        issues=tuple(issues),
    )


__all__ = [
    "EXTERNAL_TOOL_TIMEOUT_SECONDS",
    "SupplyChainIssue",
    "DependencyRecord",
    "ScriptRecord",
    "SupplyChainReport",
    "InstructionNode",
    "InstructionEdge",
    "InstructionGraph",
    "ExternalToolFinding",
    "ExternalToolResult",
    "ProvenanceIssue",
    "ProvenanceValidation",
    "dependency_record",
    "parse_package_json",
    "parse_package_lock",
    "parse_pyproject",
    "parse_requirements",
    "scan_supply_chain",
    "build_instruction_graph",
    "run_osv_scanner",
    "run_gitleaks",
    "validate_slsa_provenance",
]
