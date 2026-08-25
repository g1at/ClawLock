"""Bounded, read-only inspection of packaged Skill artifacts.

The core Skill scanner is intentionally line-oriented.  This module provides
the package layer that can feed it text from archives and bytecode without
extracting anything to disk.  Every encountered file/member receives an
``InspectionLedgerEntry`` so an uninspected artifact can never be confused
with a clean one.

Typical integration::

    inspection = inspect_artifacts(skill_path)
    for item in inspection.texts:
        scan_text(item.text, virtual_path=item.path)
    findings.extend(Finding(**row) for row in inspection.as_finding_kwargs())

The implementation deliberately uses only the Python standard library.  It
does not execute bytecode, import archive content, follow filesystem links, or
materialize archive members in the workspace.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import time
import unicodedata
import zipfile
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple


LEDGER_STATUSES = frozenset(
    {
        "scanned",
        "skipped",
        "unreadable",
        "oversized",
        "encrypted",
        "unsupported",
        "parse_failed",
    }
)


@dataclass(frozen=True)
class InspectionBudget:
    """Hard resource limits for a single package inspection."""

    max_depth: int = 3
    max_members: int = 2_000
    max_expanded_bytes: int = 32 * 1024 * 1024
    max_container_bytes: int = 16 * 1024 * 1024
    max_member_bytes: int = 2 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_seconds: float = 8.0

    def __post_init__(self) -> None:
        numeric = (
            self.max_depth,
            self.max_members,
            self.max_expanded_bytes,
            self.max_container_bytes,
            self.max_member_bytes,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("inspection limits must be non-negative")
        if self.max_compression_ratio <= 0:
            raise ValueError("max_compression_ratio must be positive")
        if self.max_seconds < 0:
            raise ValueError("max_seconds must be non-negative")


@dataclass
class InspectionLedgerEntry:
    """One auditable decision for one real or virtual path."""

    path: str
    status: str
    kind: str
    reason: str = ""
    critical: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in LEDGER_STATUSES:
            raise ValueError("unsupported ledger status: %s" % self.status)

    @property
    def incomplete(self) -> bool:
        return self.critical and (
            self.status != "scanned" or bool(self.metadata.get("opaque"))
        )


@dataclass(frozen=True)
class VirtualText:
    """Text recovered without writing an archive member to disk."""

    path: str
    text: str
    kind: str
    depth: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArtifactIssue:
    """Security-relevant artifact condition ready to become a Finding."""

    rule_id: str
    level: str
    title: str
    detail: str
    path: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_finding_kwargs(self) -> Dict[str, Any]:
        metadata = {"rule_id": self.rule_id, **self.metadata}
        return {
            "scanner": "artifact",
            "level": self.level,
            "title": self.title,
            "detail": self.detail,
            "location": self.path,
            "metadata": metadata,
        }


@dataclass
class ArtifactInspectionResult:
    """Inspection output consumed by ``scan_skill`` or another caller."""

    ledger: List[InspectionLedgerEntry] = field(default_factory=list)
    texts: List[VirtualText] = field(default_factory=list)
    issues: List[ArtifactIssue] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    members_seen: int = 0
    expanded_bytes: int = 0

    @property
    def complete(self) -> bool:
        return not any(entry.incomplete for entry in self.ledger)

    @property
    def status(self) -> str:
        return "COMPLETE" if self.complete else "INCOMPLETE"

    @property
    def incomplete_entries(self) -> List[InspectionLedgerEntry]:
        return [entry for entry in self.ledger if entry.incomplete]

    def as_finding_kwargs(self) -> List[Dict[str, Any]]:
        """Return rows accepted by the core ``Finding`` dataclass."""

        rows = [issue.as_finding_kwargs() for issue in self.issues]
        if not self.complete:
            reasons = [
                "%s: %s" % (entry.path, entry.reason or entry.status)
                for entry in self.incomplete_entries[:20]
            ]
            rows.append(
                {
                    "scanner": "internal",
                    "level": "medium",
                    "title": "Artifact inspection incomplete",
                    "detail": "; ".join(reasons),
                    "location": self.incomplete_entries[0].path,
                    "metadata": {
                        "scan_status": "error",
                        "component": "artifact_inspection",
                        "incomplete_count": len(self.incomplete_entries),
                    },
                }
            )
        return rows


_ZIP_EXTENSIONS = (
    ".zip",
    ".whl",
    ".jar",
    ".docx",
    ".xlsx",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
)
_TAR_EXTENSIONS = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
_TEXT_EXTENSIONS = frozenset(
    {
        ".c",
        ".cfg",
        ".conf",
        ".cpp",
        ".css",
        ".csv",
        ".env",
        ".go",
        ".h",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".kt",
        ".lock",
        ".md",
        ".mjs",
        ".php",
        ".plist",
        ".ps1",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".sql",
        ".svg",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
_BINARY_EXTENSIONS = frozenset(
    {
        ".a",
        ".bin",
        ".bmp",
        ".class",
        ".dll",
        ".dylib",
        ".exe",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".mp3",
        ".mp4",
        ".o",
        ".pdf",
        ".png",
        ".so",
        ".wasm",
        ".webp",
    }
)
_SAFE_OPAQUE_EXTENSIONS = frozenset(
    {
        ".bmp",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".emf",
        ".mp3",
        ".mp4",
        ".otf",
        ".png",
        ".ttf",
        ".webp",
        ".wmf",
        ".woff",
        ".woff2",
    }
)
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_DANGEROUS_PYC_NAMES = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
        "os",
        "popen",
        "Popen",
        "requests",
        "socket",
        "subprocess",
        "system",
        "urlopen",
    }
)
_DANGEROUS_TEXT_RE = re.compile(
    r"(?i)(?:https?://|curl\b|wget\b|/etc/(?:passwd|shadow)|\.ssh[/\\]|"
    r"(?:api[_-]?key|token|secret|password)|powershell|/dev/tcp|"
    r"authorized_keys|sitecustomize|ld\.so\.preload)"
)
_EXTERNAL_REL_RE = re.compile(
    r"(?is)<Relationship\b[^>]*\bTargetMode\s*=\s*['\"]External['\"][^>]*>"
)
_MACRO_NAMES = ("vbaproject.bin", "vbaData.xml", "embeddings/")


def _compound_suffix(name: str) -> str:
    lower = name.lower()
    for suffix in sorted(_TAR_EXTENSIONS + _ZIP_EXTENSIONS, key=len, reverse=True):
        if lower.endswith(suffix):
            return suffix
    return PurePosixPath(lower).suffix


def _zip_magic(data: bytes) -> bool:
    return any(data.startswith(prefix) for prefix in _ZIP_MAGIC)


def _looks_like_tar(data: bytes) -> bool:
    return (
        (len(data) >= 265 and data[257:262] == b"ustar")
        or data.startswith(_GZIP_MAGIC)
        or data.startswith(b"BZh")
        or data.startswith(b"\xfd7zXZ\x00")
    )


def _decode_text(name: str, data: bytes) -> Optional[str]:
    if not data:
        return ""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:8192]:
        return None
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        if _compound_suffix(name) not in _TEXT_EXTENSIONS:
            return None
        text = data.decode("utf-8", errors="replace")
    if not text:
        return text
    controls = sum(ord(char) < 32 and char not in "\n\r\t\f" for char in text[:8192])
    if controls / min(len(text), 8192) > 0.03:
        return None
    return text


def _safe_member_name(name: str) -> Tuple[Optional[str], str]:
    replaced = name.replace("\\", "/")
    if (
        not replaced
        or "\x00" in replaced
        or replaced.startswith("/")
        or _DRIVE_RE.match(replaced)
    ):
        return None, "absolute archive path"
    path = PurePosixPath(replaced)
    if any(part in ("", ".", "..") for part in path.parts):
        return None, "archive path traversal"
    if any(
        ":" in part
        or part != part.rstrip(" .")
        or any(ord(char) < 32 for char in part)
        for part in path.parts
    ):
        return None, "ambiguous or platform-unsafe archive path"
    return str(path), ""


def _normalized_archive_key(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold()


def _archive_path_collides(
    key: str,
    is_directory: bool,
    seen: Dict[str, bool],
) -> bool:
    if key in seen:
        return True
    parts = PurePosixPath(key).parts
    for index in range(1, len(parts)):
        ancestor = "/".join(parts[:index])
        if ancestor in seen and not seen[ancestor]:
            return True
    if not is_directory and any(existing.startswith(key + "/") for existing in seen):
        return True
    return False


def _link_escapes(member_name: str, target: str) -> bool:
    replaced = target.replace("\\", "/")
    if replaced.startswith("/") or _DRIVE_RE.match(replaced):
        return True
    base = PurePosixPath(member_name).parent
    depth = 0
    for part in (base / replaced).parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def _virtual_child(parent: str, child: str) -> str:
    return "%s!%s" % (parent, child)


@dataclass(frozen=True)
class _PycWorkerResult:
    status: str
    payload: Dict[str, Any] = field(default_factory=dict)


_PYC_WORKER_MAX_OUTPUT = 1024 * 1024
_PYC_WORKER_MEMORY = 256 * 1024 * 1024
_PYC_WORKER_CPU_SECONDS = 2
_PYC_WORKER = r"""
import dis, hashlib, json, marshal, os, sys, types

MAX_OBJECTS = 100000
MAX_DEPTH = 200
seen_objects = 0

def bump(depth):
    global seen_objects
    seen_objects += 1
    if seen_objects > MAX_OBJECTS or depth > MAX_DEPTH:
        raise ValueError("semantic structure limit")

def constant(value, depth):
    bump(depth)
    if isinstance(value, types.CodeType):
        return ["code", semantic(value, depth + 1)]
    if isinstance(value, tuple):
        return ["tuple", [constant(item, depth + 1) for item in value]]
    if isinstance(value, frozenset):
        items = [constant(item, depth + 1) for item in value]
        items.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        return ["frozenset", items]
    return [type(value).__name__, marshal.dumps(value).hex()]

def semantic(code, depth=0):
    bump(depth)
    # co_filename is deliberately normalized away because it identifies the
    # build location, not behavior. All other public semantic fields are kept.
    return {
        "argcount": code.co_argcount,
        "posonlyargcount": getattr(code, "co_posonlyargcount", 0),
        "kwonlyargcount": code.co_kwonlyargcount,
        "nlocals": code.co_nlocals,
        "stacksize": code.co_stacksize,
        "flags": code.co_flags,
        "code": code.co_code.hex(),
        "consts": [constant(item, depth + 1) for item in code.co_consts],
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
        "freevars": list(code.co_freevars),
        "cellvars": list(code.co_cellvars),
        "name": code.co_name,
        "qualname": getattr(code, "co_qualname", code.co_name),
        "firstlineno": code.co_firstlineno,
        "linetable": getattr(code, "co_linetable", getattr(code, "co_lnotab", b"")).hex(),
        "exceptiontable": getattr(code, "co_exceptiontable", b"").hex(),
    }

def walk(code, depth=0):
    if depth > MAX_DEPTH:
        raise ValueError("code nesting limit")
    yield code
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            yield from walk(item, depth + 1)

def emit(payload):
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(raw) > 1048576:
        raw = b'{"status":"output_limit"}'
    os.write(1, raw)

try:
    mode = sys.argv[1]
    recovered_limit = min(max(int(sys.argv[2]), 4096), 262144)
    optimize = int(sys.argv[3])
    data = sys.stdin.buffer.read(2097153)
    if len(data) > 2097152:
        raise ValueError("input limit")
    if mode == "pyc":
        if len(data) < 16:
            raise ValueError("header")
        stream = __import__("io").BytesIO(data[16:])
        code = marshal.load(stream)
        if not isinstance(code, types.CodeType) or stream.read(1):
            raise ValueError("payload")
    elif mode == "source":
        code = compile(data.decode("utf-8"), "<verified-source>", "exec", dont_inherit=True, optimize=optimize)
    else:
        raise ValueError("mode")
    canonical = json.dumps(semantic(code), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    signature = hashlib.sha256(canonical).hexdigest()
    names, strings, opcodes, rendered = set(), [], set(), []
    chars = 0
    instructions = 0
    truncated = False
    for nested in walk(code):
        names.update(nested.co_names)
        if len(names) > 20000:
            truncated = True
            break
        for value in nested.co_consts:
            if isinstance(value, str):
                chars += len(value)
                if chars > recovered_limit:
                    truncated = True
                    break
                strings.append(value)
        if truncated:
            break
        for item in dis.get_instructions(nested):
            instructions += 1
            opcodes.add(item.opname)
            line = "%s %s" % (item.opname, item.argrepr)
            chars += len(line) + 1
            if instructions > 100000 or chars > recovered_limit:
                truncated = True
                break
            rendered.append(line)
        if truncated:
            break
    emit({"status":"ok", "signature":signature, "names":sorted(names),
          "strings":strings, "opcodes":sorted(opcodes), "disassembly":rendered,
          "truncated":truncated})
except BaseException:
    # Do not serialize exception text: malformed data can contain secrets.
    emit({"status":"failed"})
"""


def _pyc_worker_environment() -> Dict[str, str]:
    environment = {"PYTHONHASHSEED": "0", "PYTHONIOENCODING": "utf-8"}
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _posix_pyc_limits() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (_PYC_WORKER_MEMORY, _PYC_WORKER_MEMORY))
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (_PYC_WORKER_CPU_SECONDS, _PYC_WORKER_CPU_SECONDS),
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (_PYC_WORKER_MAX_OUTPUT, _PYC_WORKER_MAX_OUTPUT),
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def _assign_windows_job(process: subprocess.Popen[bytes]) -> Optional[Any]:
    """Attach hard process/memory limits, returning ``None`` on failure."""

    if os.name != "nt":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class _BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimits),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x8 | 0x100 | 0x200 | 0x2000
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        limits.ProcessMemoryLimit = _PYC_WORKER_MEMORY
        limits.JobMemoryLimit = _PYC_WORKER_MEMORY
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ) or not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle)):
            kernel32.CloseHandle(job)
            return None
        return (kernel32, job)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _run_pyc_worker(
    data: bytes,
    *,
    mode: str,
    timeout: float,
    recovered_limit: int,
    optimize: int = 0,
) -> _PycWorkerResult:
    kwargs: Dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "env": _pyc_worker_environment(),
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        try:
            import resource  # noqa: F401
        except ImportError:
            return _PycWorkerResult("resource_unavailable")
        kwargs["preexec_fn"] = _posix_pyc_limits
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", _PYC_WORKER, mode,
             str(recovered_limit), str(optimize)],
            **kwargs,
        )
    except (OSError, subprocess.SubprocessError):
        return _PycWorkerResult("failed")
    job = _assign_windows_job(process)
    if os.name == "nt" and job is None:
        process.kill()
        process.wait()
        return _PycWorkerResult("resource_unavailable")
    try:
        output, _ = process.communicate(input=data, timeout=max(timeout, 0.01))
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return _PycWorkerResult("timeout")
    finally:
        if isinstance(job, tuple):
            job[0].CloseHandle(job[1])
    if process.returncode != 0 or len(output) > _PYC_WORKER_MAX_OUTPUT:
        status = "output_limit" if len(output) > _PYC_WORKER_MAX_OUTPUT else "failed"
        return _PycWorkerResult(status)
    try:
        payload = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _PycWorkerResult("failed")
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        status = payload.get("status") if isinstance(payload, dict) else "failed"
        allowed = {"failed", "output_limit"}
        return _PycWorkerResult(status if status in allowed else "failed")
    signature = payload.get("signature")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        return _PycWorkerResult("failed")
    return _PycWorkerResult("ok", payload)


def _pyc_source_path(path: str) -> str:
    marker = "__pycache__/"
    if marker in path:
        prefix, filename = path.rsplit(marker, 1)
        prefix = prefix.rstrip("/")
        stem = filename.split(".", 1)[0]
        return "%s%s.py" % ((prefix + "/") if prefix else "", stem)
    return path[:-1] if path.lower().endswith(".pyc") else path + ".py"


def _pyc_sibling_source(path: Path) -> Path:
    if path.parent.name == "__pycache__":
        stem = path.name.split(".", 1)[0]
        return path.parent.parent / (stem + ".py")
    return path.with_suffix(".py")


class _InspectionState:
    def __init__(self, budget: InspectionBudget):
        self.budget = budget
        self.result = ArtifactInspectionResult()
        self.started = time.monotonic()
        self.source_texts: Dict[str, str] = {}
        self.pending_pyc: List[Tuple[str, str, InspectionLedgerEntry]] = []

    def expired(self) -> bool:
        return self.budget.max_seconds == 0 or (
            time.monotonic() - self.started > self.budget.max_seconds
        )

    def add_ledger(
        self,
        path: str,
        status: str,
        kind: str,
        reason: str = "",
        critical: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InspectionLedgerEntry:
        entry = InspectionLedgerEntry(
            path,
            status,
            kind,
            reason,
            critical,
            metadata or {},
        )
        self.result.ledger.append(entry)
        return entry

    def issue(
        self,
        rule_id: str,
        level: str,
        title: str,
        detail: str,
        path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.result.issues.append(
            ArtifactIssue(rule_id, level, title, detail, path, metadata or {})
        )

    def begin_path(self, path: str, kind: str) -> bool:
        if self.expired():
            self.add_ledger(
                path,
                "skipped",
                kind,
                "inspection time budget exhausted",
                True,
            )
            return False
        if self.result.members_seen >= self.budget.max_members:
            self.add_ledger(
                path,
                "skipped",
                kind,
                "member-count budget exhausted",
                True,
            )
            return False
        self.result.members_seen += 1
        return True

    def consume(self, size: int, path: str, kind: str) -> bool:
        if size < 0 or self.result.expanded_bytes + size > self.budget.max_expanded_bytes:
            self.add_ledger(
                path,
                "oversized",
                kind,
                "expanded-byte budget exceeded",
                True,
                {"declared_size": size},
            )
            return False
        self.result.expanded_bytes += size
        return True


def _expected_container(name: str) -> Optional[str]:
    suffix = _compound_suffix(name)
    if suffix in _ZIP_EXTENSIONS:
        return "zip"
    if suffix in _TAR_EXTENSIONS:
        return "tar"
    if suffix == ".pyc":
        return "pyc"
    return None


def _kind_from_data(name: str, data: bytes) -> str:
    if _zip_magic(data):
        return "zip"
    if _looks_like_tar(data):
        return "tar"
    if _compound_suffix(name) == ".pyc":
        return "pyc"
    if _decode_text(name, data) is not None:
        return "text"
    return "binary"


def _record_magic_mismatch(
    state: _InspectionState,
    path: str,
    expected: Optional[str],
    actual: str,
) -> None:
    suffix = _compound_suffix(path)
    mismatch = False
    if expected and expected != actual:
        mismatch = True
    elif actual in ("zip", "tar") and expected != actual:
        mismatch = True
    elif actual == "text" and suffix in _BINARY_EXTENSIONS:
        mismatch = True
    if mismatch:
        state.issue(
            "ART-MAGIC-001",
            "high",
            "Artifact extension does not match content",
            "Expected %s content from the path, but detected %s."
            % (expected or suffix or "ordinary", actual),
            path,
            {"expected": expected or suffix, "actual": actual},
        )


def _process_text(
    state: _InspectionState,
    path: str,
    data: bytes,
    depth: int,
) -> None:
    text = _decode_text(path, data)
    if text is None:
        state.add_ledger(
            path,
            "unsupported",
            "binary",
            "binary content has no supported parser",
            True,
            {"opaque": True},
        )
        return
    suffix = _compound_suffix(path)
    kind = "source" if suffix in _TEXT_EXTENSIONS else "text"
    state.result.texts.append(VirtualText(path, text, kind, depth))
    if suffix == ".py":
        state.source_texts[path] = text
    if suffix in (".xml", ".rels") and _EXTERNAL_REL_RE.search(text):
        state.issue(
            "ART-OOXML-REL-001",
            "medium",
            "OOXML contains an external relationship",
            "External OOXML relationships were recorded but never fetched.",
            path,
        )
    if suffix in (".xml", ".rels") and "!" in path:
        try:
            root = ElementTree.fromstring(text)
            normalized = " ".join(part.strip() for part in root.itertext() if part.strip())
        except ElementTree.ParseError as exc:
            state.add_ledger(
                path,
                "parse_failed",
                "xml",
                "archive XML could not be parsed: %s" % exc,
                True,
            )
            return
        if normalized:
            state.result.texts.append(
                VirtualText(path + "#text", normalized, "xml-text", depth)
            )
        if re.search(r"(?i)(?:<w:vanish\b|<w:instrText\b|display\s*:\s*none)", text):
            state.issue(
                "ART-OOXML-HIDDEN-001",
                "medium",
                "Office XML contains hidden or instruction text",
                "Hidden text was normalized and supplied to the upper scanner.",
                path,
            )
    state.add_ledger(path, "scanned", kind, metadata={"characters": len(text)})


def _process_pyc(
    state: _InspectionState,
    path: str,
    data: bytes,
    depth: int,
) -> None:
    if len(data) < 16:
        state.add_ledger(path, "parse_failed", "pyc", "truncated pyc header", True)
        return
    if data[:4] != importlib.util.MAGIC_NUMBER:
        strings = re.findall(rb"[ -~]{6,}", data)
        if strings:
            text = "\n".join(item.decode("ascii", "replace") for item in strings)
            state.result.texts.append(
                VirtualText(path, text, "pyc-strings", depth, {"opaque": True})
            )
        state.add_ledger(
            path,
            "unsupported",
            "pyc",
            "bytecode magic is incompatible with this Python runtime",
            True,
            {"opaque": True, "magic": data[:4].hex()},
        )
        return
    flags = int.from_bytes(data[4:8], "little")
    if flags & ~0x03 or flags == 0x02:
        state.add_ledger(
            path,
            "parse_failed",
            "pyc",
            "invalid PEP 552 header flags",
            True,
            {"flags": flags},
        )
        return
    remaining = state.budget.max_seconds - (time.monotonic() - state.started)
    worker = _run_pyc_worker(
        data,
        mode="pyc",
        timeout=min(2.0, max(remaining, 0.01)),
        recovered_limit=state.budget.max_member_bytes,
    )
    if worker.status != "ok":
        reasons = {
            "timeout": "isolated bytecode analysis timed out",
            "output_limit": "isolated bytecode analysis exceeded its output limit",
            "resource_unavailable": "isolated bytecode resource limits unavailable",
        }
        state.add_ledger(
            path,
            "parse_failed",
            "pyc",
            reasons.get(worker.status, "isolated bytecode analysis failed"),
            True,
            {"opaque": True, "worker_status": worker.status},
        )
        return
    payload = worker.payload
    names = {item for item in payload.get("names", []) if isinstance(item, str)}
    strings = [item for item in payload.get("strings", []) if isinstance(item, str)]
    opcodes = {item for item in payload.get("opcodes", []) if isinstance(item, str)}
    disassembly = [
        item for item in payload.get("disassembly", []) if isinstance(item, str)
    ]
    truncated = bool(payload.get("truncated"))

    recovered = "\n".join(
        ["NAMES: " + " ".join(sorted(names)), *strings, *disassembly]
    )
    if len(recovered) > state.budget.max_member_bytes:
        recovered = recovered[: state.budget.max_member_bytes]
        truncated = True
    state.result.texts.append(
        VirtualText(
            path,
            recovered,
            "pyc-disassembly",
            depth,
            {"opcodes": sorted(opcodes)},
        )
    )
    dangerous_names = sorted(names & _DANGEROUS_PYC_NAMES)
    dangerous_strings = sorted(
        {value[:200] for value in strings if _DANGEROUS_TEXT_RE.search(value)}
    )
    hard_sinks = {
        "__import__",
        "compile",
        "eval",
        "exec",
        "popen",
        "Popen",
        "system",
        "urlopen",
    }
    dangerous_level = "high" if names & hard_sinks else "medium"
    if dangerous_names or dangerous_strings:
        state.issue(
            "ART-PYC-001",
            dangerous_level,
            "Python bytecode contains dangerous execution surfaces",
            "Recovered dangerous names or strings without executing the bytecode.",
            path,
            {
                "names": dangerous_names,
                "strings": dangerous_strings[:20],
            },
        )
    entry = state.add_ledger(
        path,
        "scanned",
        "pyc",
        "bytecode decoded; source equivalence pending",
        True,
        {
            "opaque": True,
            "opcodes": sorted(opcodes),
            "disassembly_truncated": truncated,
        },
    )
    state.pending_pyc.append((path, payload["signature"], entry))


def _inspect_zip(
    state: _InspectionState,
    path: str,
    data: bytes,
    depth: int,
) -> None:
    if depth >= state.budget.max_depth:
        state.add_ledger(path, "skipped", "zip", "nesting-depth limit reached", True)
        return
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = archive.infolist()
    except (OSError, ValueError, zipfile.BadZipFile, EOFError) as exc:
        state.add_ledger(path, "parse_failed", "zip", str(exc), True)
        return

    seen: Dict[str, bool] = {}
    declared_total = 0
    try:
        for info in members:
            if state.expired() or state.result.members_seen >= state.budget.max_members:
                reason = (
                    "inspection time budget exhausted"
                    if state.expired()
                    else "member-count budget exhausted"
                )
                state.add_ledger(
                    _virtual_child(path, "<remaining-members>"),
                    "skipped",
                    "zip-member",
                    reason,
                    True,
                )
                break
            child_name, unsafe_reason = _safe_member_name(info.filename)
            raw_virtual = _virtual_child(path, info.filename or "<empty>")
            if not state.begin_path(raw_virtual, "zip-member"):
                continue
            if unsafe_reason or child_name is None:
                state.add_ledger(
                    raw_virtual,
                    "skipped",
                    "zip-member",
                    unsafe_reason,
                    True,
                )
                state.issue(
                    "ART-ARCHIVE-PATH-001",
                    "critical",
                    "Unsafe archive member path",
                    unsafe_reason,
                    raw_virtual,
                )
                continue
            virtual = _virtual_child(path, child_name)
            normalized = _normalized_archive_key(child_name)
            if _archive_path_collides(normalized, info.is_dir(), seen):
                state.add_ledger(
                    virtual,
                    "skipped",
                    "zip-member",
                    "duplicate member would overwrite an earlier path",
                    True,
                )
                state.issue(
                    "ART-ARCHIVE-DUP-001",
                    "high",
                    "Archive contains duplicate output paths",
                    "Multiple members normalize to the same output path.",
                    virtual,
                )
                continue
            seen[normalized] = info.is_dir()
            if info.is_dir():
                state.add_ledger(virtual, "skipped", "directory", "directory marker")
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            ratio = (
                float("inf")
                if info.file_size and info.compress_size == 0
                else info.file_size / max(info.compress_size, 1)
            )
            if info.flag_bits & 0x1:
                state.add_ledger(
                    virtual,
                    "encrypted",
                    "zip-member",
                    "encrypted member cannot be inspected",
                    True,
                )
                state.issue(
                    "ART-ARCHIVE-ENC-001",
                    "high",
                    "Encrypted archive member",
                    "Encrypted content was not treated as clean.",
                    virtual,
                )
                continue
            if info.file_size > state.budget.max_member_bytes:
                state.add_ledger(
                    virtual,
                    "oversized",
                    "zip-member",
                    "single-member byte limit exceeded",
                    True,
                    {"declared_size": info.file_size},
                )
                continue
            if ratio > state.budget.max_compression_ratio:
                state.add_ledger(
                    virtual,
                    "oversized",
                    "zip-member",
                    "compression-ratio limit exceeded",
                    True,
                    {"ratio": ratio},
                )
                state.issue(
                    "ART-ARCHIVE-BOMB-001",
                    "critical",
                    "Possible archive decompression bomb",
                    "Declared compression ratio %.1f exceeds the configured limit."
                    % ratio,
                    virtual,
                )
                continue
            if stat.S_ISLNK(mode):
                if not state.consume(info.file_size, virtual, "zip-member"):
                    continue
                try:
                    with archive.open(info) as stream:
                        target_data = stream.read(state.budget.max_member_bytes + 1)
                    if len(target_data) > state.budget.max_member_bytes:
                        raise OSError("symlink target exceeded member byte limit")
                    target = target_data.decode("utf-8", "replace")
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    target = ""
                    unsafe_reason = str(exc)
                escapes = not target or _link_escapes(child_name, target)
                state.add_ledger(
                    virtual,
                    "skipped",
                    "symlink",
                    unsafe_reason or "archive links are never followed",
                    escapes,
                    {"target": target},
                )
                if escapes:
                    state.issue(
                        "ART-ARCHIVE-LINK-001",
                        "critical",
                        "Archive symlink escapes its package",
                        "Symlink target %r is outside the archive root." % target,
                        virtual,
                    )
                continue
            if not state.consume(info.file_size, virtual, "zip-member"):
                continue
            declared_total += info.file_size
            try:
                with archive.open(info) as stream:
                    member_data = stream.read(state.budget.max_member_bytes + 1)
            except RuntimeError as exc:
                status = "encrypted" if "password" in str(exc).lower() else "unreadable"
                state.add_ledger(virtual, status, "zip-member", str(exc), True)
                continue
            except (OSError, zipfile.BadZipFile, EOFError) as exc:
                state.add_ledger(virtual, "unreadable", "zip-member", str(exc), True)
                continue
            if len(member_data) > state.budget.max_member_bytes:
                state.add_ledger(
                    virtual,
                    "oversized",
                    "zip-member",
                    "actual member size exceeded the byte limit",
                    True,
                )
                continue
            if len(member_data) > info.file_size:
                if not state.consume(
                    len(member_data) - info.file_size,
                    virtual,
                    "zip-member",
                ):
                    continue
            lower_name = child_name.lower()
            if any(marker.lower() in lower_name for marker in _MACRO_NAMES):
                state.issue(
                    "ART-OOXML-EMBED-001",
                    "high",
                    "Office package contains embedded or macro content",
                    "Embedded content is inspected when supported and otherwise marks the scan incomplete.",
                    virtual,
                )
            _process_blob(state, virtual, member_data, depth + 1, reserved=True)
    finally:
        archive.close()
    state.add_ledger(
        path,
        "scanned",
        "zip",
        metadata={"member_count": len(members), "declared_expanded": declared_total},
    )


def _inspect_tar(
    state: _InspectionState,
    path: str,
    data: bytes,
    depth: int,
) -> None:
    if depth >= state.budget.max_depth:
        state.add_ledger(path, "skipped", "tar", "nesting-depth limit reached", True)
        return
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (OSError, EOFError, tarfile.TarError, ValueError) as exc:
        state.add_ledger(path, "parse_failed", "tar", str(exc), True)
        return

    seen: Dict[str, bool] = {}
    total_declared = 0
    member_count = 0
    archive_failed = False
    try:
        for member in archive:
            member_count += 1
            if member.isfile():
                total_declared += max(member.size, 0)
                ratio = total_declared / max(len(data), 1)
                if ratio > state.budget.max_compression_ratio:
                    state.add_ledger(
                        path,
                        "oversized",
                        "tar",
                        "archive compression-ratio limit exceeded",
                        True,
                        {"ratio": ratio},
                    )
                    state.issue(
                        "ART-ARCHIVE-BOMB-001",
                        "critical",
                        "Possible archive decompression bomb",
                        "Declared compression ratio %.1f exceeds the configured limit."
                        % ratio,
                        path,
                    )
                    archive_failed = True
                    break
            if state.expired() or state.result.members_seen >= state.budget.max_members:
                reason = (
                    "inspection time budget exhausted"
                    if state.expired()
                    else "member-count budget exhausted"
                )
                state.add_ledger(
                    _virtual_child(path, "<remaining-members>"),
                    "skipped",
                    "tar-member",
                    reason,
                    True,
                )
                break
            child_name, unsafe_reason = _safe_member_name(member.name)
            raw_virtual = _virtual_child(path, member.name or "<empty>")
            if not state.begin_path(raw_virtual, "tar-member"):
                continue
            if unsafe_reason or child_name is None:
                state.add_ledger(
                    raw_virtual,
                    "skipped",
                    "tar-member",
                    unsafe_reason,
                    True,
                )
                state.issue(
                    "ART-ARCHIVE-PATH-001",
                    "critical",
                    "Unsafe archive member path",
                    unsafe_reason,
                    raw_virtual,
                )
                continue
            virtual = _virtual_child(path, child_name)
            normalized = _normalized_archive_key(child_name)
            if _archive_path_collides(normalized, member.isdir(), seen):
                state.add_ledger(
                    virtual,
                    "skipped",
                    "tar-member",
                    "duplicate member would overwrite an earlier path",
                    True,
                )
                state.issue(
                    "ART-ARCHIVE-DUP-001",
                    "high",
                    "Archive contains duplicate output paths",
                    "Multiple members normalize to the same output path.",
                    virtual,
                )
                continue
            seen[normalized] = member.isdir()
            if member.isdir():
                state.add_ledger(virtual, "skipped", "directory", "directory marker")
                continue
            if member.issym() or member.islnk():
                escapes = _link_escapes(child_name, member.linkname)
                kind = "symlink" if member.issym() else "hardlink"
                state.add_ledger(
                    virtual,
                    "skipped",
                    kind,
                    "archive links are never followed",
                    escapes,
                    {"target": member.linkname},
                )
                if escapes:
                    state.issue(
                        "ART-ARCHIVE-LINK-001",
                        "critical",
                        "Archive link escapes its package",
                        "%s target %r is outside the archive root."
                        % (kind, member.linkname),
                        virtual,
                    )
                continue
            if not member.isfile():
                state.add_ledger(
                    virtual,
                    "unsupported",
                    "tar-special",
                    "special archive member was not materialized",
                    True,
                    {"opaque": True},
                )
                continue
            if member.size > state.budget.max_member_bytes:
                state.add_ledger(
                    virtual,
                    "oversized",
                    "tar-member",
                    "single-member byte limit exceeded",
                    True,
                    {"declared_size": member.size},
                )
                continue
            if not state.consume(member.size, virtual, "tar-member"):
                continue
            try:
                stream = archive.extractfile(member)
                if stream is None:
                    raise OSError("tar member has no readable stream")
                member_data = stream.read(state.budget.max_member_bytes + 1)
            except (OSError, EOFError, tarfile.TarError) as exc:
                state.add_ledger(virtual, "unreadable", "tar-member", str(exc), True)
                continue
            if len(member_data) > state.budget.max_member_bytes:
                state.add_ledger(
                    virtual,
                    "oversized",
                    "tar-member",
                    "actual member size exceeded the byte limit",
                    True,
                )
                continue
            _process_blob(state, virtual, member_data, depth + 1, reserved=True)
    finally:
        archive.close()
    if not archive_failed:
        state.add_ledger(
            path,
            "scanned",
            "tar",
            metadata={
                "member_count": member_count,
                "declared_expanded": total_declared,
            },
        )


def _process_blob(
    state: _InspectionState,
    path: str,
    data: bytes,
    depth: int,
    reserved: bool = False,
) -> None:
    expected = _expected_container(path)
    actual = _kind_from_data(path, data)
    _record_magic_mismatch(state, path, expected, actual)
    if not reserved and not state.consume(len(data), path, actual):
        return
    if expected and expected != actual:
        if actual == "text":
            text = _decode_text(path, data)
            if text is not None:
                state.result.texts.append(
                    VirtualText(path, text, "mismatched-text", depth)
                )
        state.add_ledger(
            path,
            "parse_failed",
            expected,
            "declared artifact type did not contain the expected format",
            True,
            {"actual": actual},
        )
        return
    if actual == "zip":
        _inspect_zip(state, path, data, depth)
    elif actual == "tar":
        _inspect_tar(state, path, data, depth)
    elif actual == "pyc":
        _process_pyc(state, path, data, depth)
    elif actual == "text":
        _process_text(state, path, data, depth)
    else:
        state.add_ledger(
            path,
            "unsupported",
            "binary",
            "binary content has no supported parser",
            bool(
                expected
                or _compound_suffix(path) not in _SAFE_OPAQUE_EXTENSIONS
            ),
            {"opaque": True},
        )


def _read_disk_file(path: Path, limit: int) -> Tuple[bytes, bool]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("path is not a regular file")
        chunks: List[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        return data[:limit], len(data) > limit
    finally:
        os.close(descriptor)


def _stat_is_link_or_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _inspect_disk_file(
    state: _InspectionState,
    root: Path,
    path: Path,
) -> None:
    try:
        virtual = path.relative_to(root).as_posix() if root.is_dir() else path.name
    except ValueError:
        virtual = path.name
    if not state.begin_path(virtual, "file"):
        return
    try:
        size = path.stat(follow_symlinks=False).st_size
    except OSError as exc:
        state.add_ledger(virtual, "unreadable", "file", str(exc), True)
        return
    expected = _expected_container(virtual)
    limit = (
        state.budget.max_container_bytes
        if expected in ("zip", "tar")
        else state.budget.max_member_bytes
    )
    if size > limit:
        state.add_ledger(
            virtual,
            "oversized",
            expected or "file",
            "disk artifact exceeds its byte limit",
            True,
            {"size": size, "limit": limit},
        )
        return
    try:
        data, truncated = _read_disk_file(path, limit)
    except OSError as exc:
        state.add_ledger(virtual, "unreadable", expected or "file", str(exc), True)
        return
    if truncated:
        state.add_ledger(
            virtual,
            "oversized",
            expected or "file",
            "file changed or exceeded its byte limit while being read",
            True,
        )
        return
    _process_blob(state, virtual, data, 0)


def _walk_disk(root: Path, state: _InspectionState) -> None:
    stack = [root]
    resolved_root = root.resolve()
    while stack:
        directory = stack.pop()
        if state.expired():
            state.add_ledger(
                str(directory),
                "skipped",
                "directory",
                "inspection time budget exhausted",
                True,
            )
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            state.add_ledger(str(directory), "unreadable", "directory", str(exc), True)
            continue
        child_dirs: List[Path] = []
        for entry in entries:
            if state.expired() or state.result.members_seen >= state.budget.max_members:
                reason = (
                    "inspection time budget exhausted"
                    if state.expired()
                    else "member-count budget exhausted"
                )
                state.add_ledger(
                    str(directory / "<remaining-paths>"),
                    "skipped",
                    "path",
                    reason,
                    True,
                )
                return
            path = Path(entry.path)
            virtual = path.relative_to(root).as_posix()
            try:
                entry_info = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or _stat_is_link_or_reparse(entry_info):
                    target = path.resolve(strict=False)
                    try:
                        target.relative_to(resolved_root)
                        external = False
                    except ValueError:
                        external = True
                    state.add_ledger(
                        virtual,
                        "skipped",
                        "symlink",
                        "filesystem links are never followed",
                        external,
                        {"target": str(target)},
                    )
                    if external:
                        state.issue(
                            "ART-FS-LINK-001",
                            "critical",
                            "Filesystem link escapes the Skill package",
                            "The link was recorded and not followed.",
                            virtual,
                            {"target": str(target)},
                        )
                    continue
                if entry.is_dir(follow_symlinks=False):
                    child_dirs.append(path)
                elif entry.is_file(follow_symlinks=False):
                    _inspect_disk_file(state, root, path)
                else:
                    state.add_ledger(
                        virtual,
                        "unsupported",
                        "special-file",
                        "special filesystem object was not read",
                        True,
                        {"opaque": True},
                    )
            except OSError as exc:
                state.add_ledger(virtual, "unreadable", "path", str(exc), True)
        stack.extend(reversed(child_dirs))


def _finalize_pyc(state: _InspectionState) -> None:
    for path, bytecode_signature, entry in state.pending_pyc:
        source_path = _pyc_source_path(path)
        source = state.source_texts.get(source_path)
        if source is None:
            entry.reason = "bytecode inspected, but no matching source was available"
            entry.metadata["opaque"] = True
            entry.metadata["source_path"] = source_path
            state.issue(
                "ART-PYC-OPAQUE-001",
                "medium",
                "Python bytecode has no verifiable source",
                "Strings and opcodes were inspected, but source equivalence cannot be proven.",
                path,
                {"source_path": source_path},
            )
            continue
        try:
            optimize_match = re.search(r"\.opt-([012])\.pyc$", path, re.I)
            optimize = int(optimize_match.group(1)) if optimize_match else 0
            remaining = state.budget.max_seconds - (time.monotonic() - state.started)
            compiled = _run_pyc_worker(
                source.encode("utf-8"),
                mode="source",
                timeout=min(2.0, max(remaining, 0.01)),
                recovered_limit=4096,
                optimize=optimize,
            )
            if compiled.status != "ok":
                raise ValueError(compiled.status)
            matches = bytecode_signature == compiled.payload["signature"]
        except (UnicodeEncodeError, ValueError, TypeError):
            entry.reason = "source equivalence check failed in isolated analyzer"
            entry.metadata["opaque"] = True
            entry.metadata["source_path"] = source_path
            entry.metadata["source_match"] = None
            entry.critical = True
            continue
        truncated = bool(entry.metadata.get("disassembly_truncated"))
        entry.critical = bool(truncated and not matches)
        entry.metadata["opaque"] = bool(truncated and not matches)
        entry.metadata["source_path"] = source_path
        entry.metadata["source_match"] = matches
        entry.reason = (
            "bytecode matches sibling source"
            if matches
            else "bytecode differs from sibling source"
        )
        if not matches:
            state.issue(
                "ART-PYC-MISMATCH-001",
                "critical",
                "Python bytecode differs from sibling source",
                "The executable code object does not match a fresh compile of the visible source.",
                path,
                {"source_path": source_path},
            )


def inspect_artifacts(
    skill_path: Path,
    budget: Optional[InspectionBudget] = None,
) -> ArtifactInspectionResult:
    """Inspect a file or directory without extraction or link traversal.

    ``ArtifactInspectionResult.complete`` is false whenever a security-relevant
    path was encrypted, unreadable, unsupported, over budget, or otherwise
    opaque.  Security findings and scan completeness are intentionally
    separate: a fully inspected malicious archive can be COMPLETE and still
    contain critical issues.
    """

    state = _InspectionState(budget or InspectionBudget())
    path = Path(skill_path)
    try:
        try:
            root_info = path.lstat()
        except OSError:
            root_info = None
        if root_info is not None and _stat_is_link_or_reparse(root_info):
            state.add_ledger(
                str(path),
                "skipped",
                "symlink",
                "Skill root links are never followed",
                True,
            )
            state.issue(
                "ART-FS-LINK-001",
                "critical",
                "Skill root is a filesystem link",
                "The linked target was not followed.",
                str(path),
            )
        elif path.is_file():
            if path.suffix.lower() == ".pyc" and path.parent.name == "__pycache__":
                pyc_root = path.parent.parent
            else:
                pyc_root = path
            _inspect_disk_file(state, pyc_root, path)
            if path.suffix.lower() == ".pyc":
                source = _pyc_sibling_source(path)
                try:
                    source_info = source.lstat()
                except OSError:
                    source_info = None
                if (
                    source_info is not None
                    and stat.S_ISREG(source_info.st_mode)
                    and not _stat_is_link_or_reparse(source_info)
                ):
                    source_root = (
                        path.parent.parent
                        if path.parent.name == "__pycache__"
                        else path.parent
                    )
                    _inspect_disk_file(state, source_root, source)
        elif path.is_dir():
            _walk_disk(path, state)
        else:
            state.add_ledger(
                str(path),
                "unreadable",
                "path",
                "Skill path does not exist or is not a regular file/directory",
                True,
            )
    except OSError as exc:
        state.add_ledger(str(path), "unreadable", "path", str(exc), True)
    _finalize_pyc(state)
    state.result.elapsed_seconds = time.monotonic() - state.started
    return state.result


__all__ = [
    "ArtifactInspectionResult",
    "ArtifactIssue",
    "InspectionBudget",
    "InspectionLedgerEntry",
    "LEDGER_STATUSES",
    "VirtualText",
    "inspect_artifacts",
]
