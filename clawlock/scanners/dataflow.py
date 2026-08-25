"""Shared, dependency-free data-flow analysis for ClawLock scanners.

The Python analyser is deliberately small and conservative.  It is not a
replacement for a whole-program compiler; it provides a stable interchange
format and enough inter-procedural modelling for security scanners to share
source-to-sink evidence.  Unsupported JavaScript/TypeScript input is reported
as degraded instead of being presented as a complete analysis.
"""

from __future__ import annotations

import ast
import os
import stat
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple, Union


class FlowLabel(str, Enum):
    UNTRUSTED = "untrusted"
    FUNCTION_INPUT = "function-input"
    TOOL_INPUT = "tool-input"
    REQUEST = "request"
    JSON = "json"
    ENV = "environment"
    SECRET = "secret"
    FILE = "file"
    NETWORK_RESPONSE = "network-response"
    TOOL_OUTPUT = "tool-output"


class SinkKind(str, Enum):
    COMMAND = "command-execution"
    CODE_EXECUTION = "code-execution"
    NETWORK = "network"
    FILE_WRITE = "file-write"
    PROMPT = "prompt"
    MEMORY = "memory"
    LOG = "log"
    TOOL_OUTPUT = "tool-output"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class FlowSpan:
    file: str
    line: int
    column: int
    end_line: int
    end_column: int


@dataclass(frozen=True)
class FlowSource:
    source_id: str
    kind: str
    symbol: str
    labels: FrozenSet[FlowLabel]
    span: FlowSpan
    confidence: Confidence = Confidence.MEDIUM


@dataclass(frozen=True)
class FlowSink:
    kind: SinkKind
    symbol: str
    span: FlowSpan
    argument: str = "value"
    confidence: Confidence = Confidence.HIGH


@dataclass(frozen=True)
class FlowStep:
    kind: str
    symbol: str
    span: FlowSpan
    detail: str = ""


@dataclass(frozen=True)
class FlowPath:
    source: FlowSource
    sink: FlowSink
    labels: FrozenSet[FlowLabel]
    confidence: Confidence
    steps: Tuple[FlowStep, ...]


@dataclass(frozen=True)
class FlowDetection:
    rule_id: str
    message: str
    labels: FrozenSet[FlowLabel]
    confidence: Confidence
    path: FlowPath

    @property
    def source(self) -> FlowSource:
        return self.path.source

    @property
    def sink(self) -> FlowSink:
        return self.path.sink

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class AnalysisDiagnostic:
    code: str
    message: str
    severity: str = "warning"
    span: Optional[FlowSpan] = None


@dataclass(frozen=True)
class AnalysisResult:
    detections: Tuple[FlowDetection, ...] = ()
    diagnostics: Tuple[AnalysisDiagnostic, ...] = ()
    complete: bool = True
    language: str = "python"
    engine: str = "python-ast"
    degraded: bool = False
    files_analyzed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class AnalysisBudget:
    """Hard limits for one data-flow analysis invocation.

    All limits are aggregate across the project, except ``max_file_bytes``.
    A zero value is valid and intentionally permits no work, which is useful
    for callers that need to verify fail-closed handling.
    """

    max_files: int = 2_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_ast_nodes: int = 500_000
    max_functions: int = 20_000
    max_seconds: float = 10.0

    def __post_init__(self) -> None:
        values = {
            "max_files": self.max_files,
            "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_ast_nodes": self.max_ast_nodes,
            "max_functions": self.max_functions,
            "max_seconds": self.max_seconds,
        }
        invalid = [name for name, value in values.items() if value < 0]
        if invalid:
            raise ValueError(f"AnalysisBudget values must be non-negative: {', '.join(invalid)}")


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _absolute_path(path: Union[os.PathLike[str], str]) -> Path:
    """Return an absolute lexical path without resolving links."""

    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(file_stat: os.stat_result) -> bool:
    attributes = int(getattr(file_stat, "st_file_attributes", 0) or 0)
    return stat.S_ISLNK(file_stat.st_mode) or bool(attributes & _REPARSE_POINT)


class _BudgetState:
    def __init__(self, budget: AnalysisBudget) -> None:
        self.budget = budget
        self.started = time.monotonic()
        self.diagnostics: List[AnalysisDiagnostic] = []
        self.files_reserved = 0
        self.total_bytes = 0
        self.ast_nodes = 0
        self.functions = 0
        self.exhausted = False
        self.discovery_stopped = False
        self._once: Set[str] = set()

    def error(
        self,
        code: str,
        message: str,
        span: Optional[FlowSpan] = None,
        *,
        once: bool = False,
        exhausted: bool = False,
    ) -> None:
        if once and code in self._once:
            return
        self._once.add(code)
        self.diagnostics.append(AnalysisDiagnostic(code, message, "error", span))
        self.exhausted = self.exhausted or exhausted

    def check_time(self) -> bool:
        if self.budget.max_seconds > 0 and (
            time.monotonic() - self.started <= self.budget.max_seconds
        ):
            return True
        self.error(
            "DFV2-TIMEOUT",
            f"Data-flow analysis exceeded its {self.budget.max_seconds:g} second budget.",
            once=True,
            exhausted=True,
        )
        return False

    def reserve_file(self, path: Path) -> bool:
        if self.files_reserved >= self.budget.max_files:
            self.error(
                "DFV2-FILE-LIMIT",
                f"Python file count exceeds the {self.budget.max_files} file budget; "
                f"analysis stopped before {path}.",
                once=True,
            )
            self.discovery_stopped = True
            return False
        self.files_reserved += 1
        return True

    def account_tree(self, path: Path, tree: ast.AST) -> bool:
        node_count = 0
        function_count = 0
        for node_count, node in enumerate(ast.walk(tree), start=1):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_count += 1
            if node_count % 256 == 0 and not self.check_time():
                return False
            if self.ast_nodes + node_count > self.budget.max_ast_nodes:
                self.error(
                    "DFV2-AST-NODE-LIMIT",
                    f"AST node count exceeds the {self.budget.max_ast_nodes} node budget "
                    f"while parsing {path}.",
                    once=True,
                    exhausted=True,
                )
                return False
            if self.functions + function_count > self.budget.max_functions:
                self.error(
                    "DFV2-FUNCTION-LIMIT",
                    f"Function count exceeds the {self.budget.max_functions} function budget "
                    f"while parsing {path}.",
                    once=True,
                    exhausted=True,
                )
                return False
        self.ast_nodes += node_count
        self.functions += function_count
        return self.check_time()


def _path_span(path: Path) -> FlowSpan:
    return FlowSpan(str(path), 1, 1, 1, 1)


def _safe_lstat(path: Path, state: _BudgetState, *, kind: str) -> Optional[os.stat_result]:
    try:
        result = os.lstat(str(path))
    except OSError as exc:
        state.error(
            "DFV2-PATH-ERROR",
            f"Unable to inspect {kind} {path}: {exc}",
            _path_span(path),
        )
        return None
    if _is_link_or_reparse(result):
        state.error(
            "DFV2-LINK-REFUSED",
            f"Refused to follow {kind} symlink or reparse point: {path}",
            _path_span(path),
        )
        return None
    return result


def _validate_root(root: Path, state: _BudgetState) -> bool:
    root_stat = _safe_lstat(root, state, kind="analysis root")
    if root_stat is None:
        return False
    if not stat.S_ISDIR(root_stat.st_mode):
        state.error(
            "DFV2-ROOT-NOT-DIRECTORY",
            f"Analysis root is not a directory: {root}",
            _path_span(root),
        )
        return False
    return state.check_time()


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    left_id = (getattr(left, "st_dev", None), getattr(left, "st_ino", None))
    right_id = (getattr(right, "st_dev", None), getattr(right, "st_ino", None))
    # Some Windows filesystems report zero for both identifiers.  The mode
    # check still prevents accepting a non-regular handle in that case.
    return left_id == right_id or left_id == (0, 0) or right_id == (0, 0)


def _safe_read_text(path: Path, state: _BudgetState) -> Optional[str]:
    if not state.check_time() or state.exhausted:
        return None
    before = _safe_lstat(path, state, kind="Python source file")
    if before is None:
        return None
    if not stat.S_ISREG(before.st_mode):
        state.error(
            "DFV2-NONREGULAR-FILE",
            f"Refused non-regular Python source file: {path}",
            _path_span(path),
        )
        return None
    if before.st_size > state.budget.max_file_bytes:
        state.error(
            "DFV2-FILE-SIZE-LIMIT",
            f"Python source file {path} is {before.st_size} bytes, exceeding the "
            f"{state.budget.max_file_bytes} byte per-file budget.",
            _path_span(path),
        )
        return None
    remaining_total = state.budget.max_total_bytes - state.total_bytes
    if before.st_size > remaining_total:
        state.error(
            "DFV2-TOTAL-SIZE-LIMIT",
            f"Reading {path} would exceed the {state.budget.max_total_bytes} byte "
            "aggregate source budget.",
            _path_span(path),
            once=True,
            exhausted=True,
        )
        return None

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: Optional[int] = None
    data = bytearray()
    try:
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_or_reparse(opened)
            or not _same_file_identity(before, opened)
        ):
            state.error(
                "DFV2-FILE-RACE",
                f"Python source file changed identity or type while being opened: {path}",
                _path_span(path),
            )
            return None

        hard_limit = min(state.budget.max_file_bytes, remaining_total)
        while len(data) <= hard_limit:
            if not state.check_time():
                return None
            chunk = os.read(descriptor, min(64 * 1024, hard_limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > state.budget.max_file_bytes:
            state.error(
                "DFV2-FILE-SIZE-LIMIT",
                f"Python source file grew beyond the {state.budget.max_file_bytes} byte "
                f"per-file budget while reading: {path}",
                _path_span(path),
            )
            return None
        if len(data) > remaining_total:
            state.error(
                "DFV2-TOTAL-SIZE-LIMIT",
                f"Reading {path} exceeded the {state.budget.max_total_bytes} byte "
                "aggregate source budget.",
                _path_span(path),
                once=True,
                exhausted=True,
            )
            return None
    except OSError as exc:
        state.error(
            "DFV2-FILE-READ-ERROR",
            f"Unable to safely read Python source file {path}: {exc}",
            _path_span(path),
        )
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)

    state.total_bytes += len(data)
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        state.error(
            "DFV2-PYTHON-DECODE-ERROR",
            f"Python source file is not valid UTF-8: {path}: {exc}",
            _path_span(path),
        )
        return None


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset, tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class JavaScriptParseResult:
    """Language-neutral input accepted from an optional real JS/TS parser."""

    detections: Tuple[FlowDetection, ...] = ()
    diagnostics: Tuple[AnalysisDiagnostic, ...] = ()
    complete: bool = True
    engine: str = "external-js-parser"


class JavaScriptAnalyzer(Protocol):
    def analyze(self, path: Path, source: str) -> JavaScriptParseResult:
        ...


def analyze_javascript_file(
    path: Union[os.PathLike[str], str],
    *,
    parser: Optional[JavaScriptAnalyzer] = None,
) -> AnalysisResult:
    """Analyse JS/TS only through an explicitly supplied parser.

    There is intentionally no regex fallback: without a parser we cannot make
    sound claims about scope, reassignment or call binding.
    """

    file_path = Path(path)
    if parser is None:
        diagnostic = AnalysisDiagnostic(
            code="DFV2-JS-PARSER-UNAVAILABLE",
            message=(
                "JavaScript/TypeScript data-flow analysis was not run: install "
                "and supply a tree-sitter-compatible JavaScriptAnalyzer."
            ),
        )
        return AnalysisResult(
            diagnostics=(diagnostic,), complete=False, language=_js_language(file_path),
            engine="none", degraded=True, files_analyzed=0,
        )
    try:
        source = file_path.read_text(encoding="utf-8")
        parsed = parser.analyze(file_path, source)
    except Exception as exc:  # Parser is an extension boundary.
        diagnostic = AnalysisDiagnostic(
            code="DFV2-JS-PARSER-ERROR", message=f"JavaScript parser failed: {exc}", severity="error"
        )
        return AnalysisResult(
            diagnostics=(diagnostic,), complete=False, language=_js_language(file_path),
            engine=type(parser).__name__, degraded=True, files_analyzed=0,
        )
    return AnalysisResult(
        detections=tuple(parsed.detections), diagnostics=tuple(parsed.diagnostics),
        complete=parsed.complete, language=_js_language(file_path), engine=parsed.engine,
        degraded=not parsed.complete, files_analyzed=1,
    )


def _js_language(path: Path) -> str:
    return "typescript" if path.suffix.lower() in {".ts", ".tsx"} else "javascript"


@dataclass(frozen=True)
class _Origin:
    parameter: Optional[str] = None
    source: Optional[FlowSource] = None


@dataclass(frozen=True)
class _Trace:
    origin: _Origin
    labels: FrozenSet[FlowLabel] = frozenset()
    guards: FrozenSet[SinkKind] = frozenset()
    steps: Tuple[FlowStep, ...] = ()
    confidence: Confidence = Confidence.MEDIUM


@dataclass(frozen=True)
class _Value:
    traces: Tuple[_Trace, ...] = ()
    types: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class _SinkEffect:
    sink: FlowSink
    traces: Tuple[_Trace, ...]


@dataclass(frozen=True)
class _Summary:
    returned: _Value = _Value()
    effects: Tuple[_SinkEffect, ...] = ()


@dataclass
class _Module:
    name: str
    path: Path
    tree: ast.Module
    package: str
    aliases: Dict[str, str] = field(default_factory=dict)


@dataclass
class _Function:
    key: str
    module: _Module
    node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    params: Tuple[str, ...]
    param_nodes: Mapping[str, ast.arg]
    class_name: Optional[str] = None
    tool_entry: bool = False
    request_entry: bool = False
    module_entry: bool = False


_SECRET_WORDS = ("secret", "token", "password", "passwd", "api_key", "apikey", "credential", "private_key")
_REQUEST_WORDS = ("request", "payload", "body", "query", "input", "message", "prompt", "command", "cmd", "url", "path")


def _span(path: Path, node: ast.AST) -> FlowSpan:
    line = int(getattr(node, "lineno", 1) or 1)
    col = int(getattr(node, "col_offset", 0) or 0) + 1
    end_line = int(getattr(node, "end_lineno", line) or line)
    end_col = int(getattr(node, "end_col_offset", col) or col)
    return FlowSpan(str(_absolute_path(path)), line, col, end_line, max(col, end_col))


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _target_key(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _target_key(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Subscript):
        base = _target_key(node.value)
        key: Any = None
        if isinstance(node.slice, ast.Constant):
            key = node.slice.value
        if base is not None and isinstance(key, (str, int)):
            return f"{base}[{key!r}]"
    return None


def _merge(*values: _Value) -> _Value:
    traces: Dict[Tuple[Any, ...], _Trace] = {}
    types: Set[str] = set()
    for value in values:
        types.update(value.types)
        for trace in value.traces:
            origin_key = trace.origin.parameter or (
                trace.origin.source.source_id if trace.origin.source else ""
            )
            key = (origin_key, trace.labels, trace.guards)
            previous = traces.get(key)
            if previous is None or len(trace.steps) < len(previous.steps):
                traces[key] = trace
    ordered = sorted(
        traces.values(),
        key=lambda item: (
            item.origin.parameter or (item.origin.source.source_id if item.origin.source else ""),
            tuple(sorted(label.value for label in item.labels)),
            tuple(sorted(kind.value for kind in item.guards)),
        ),
    )
    return _Value(tuple(ordered[:64]), frozenset(types))


def _with_step(value: _Value, step: FlowStep) -> _Value:
    return _Value(
        tuple(
            _Trace(t.origin, t.labels, t.guards, t.steps + (step,), t.confidence)
            for t in value.traces
        ),
        value.types,
    )


def _with_labels(value: _Value, labels: Iterable[FlowLabel]) -> _Value:
    extra = frozenset(labels)
    return _Value(
        tuple(_Trace(t.origin, t.labels | extra, t.guards, t.steps, t.confidence) for t in value.traces),
        value.types,
    )


def _guard(value: _Value, kinds: Iterable[SinkKind]) -> _Value:
    guards = frozenset(kinds)
    return _Value(
        tuple(_Trace(t.origin, t.labels, t.guards | guards, t.steps, t.confidence) for t in value.traces),
        value.types,
    )


class _Index:
    def __init__(self, root: Path, paths: Sequence[Path], state: _BudgetState) -> None:
        self.root = _absolute_path(root)
        self.state = state
        self.modules: Dict[str, _Module] = {}
        self.functions: Dict[str, _Function] = {}
        self.classes: Set[str] = set()
        self.diagnostics = state.diagnostics
        for path in paths:
            if state.exhausted or not state.check_time():
                break
            self._parse(path)
        for module in self.modules.values():
            if state.exhausted or not state.check_time():
                break
            self._imports(module)
        for module in self.modules.values():
            if state.exhausted or not state.check_time():
                break
            self._symbols(module)

    def _module_name(self, path: Path) -> Tuple[str, str]:
        relative = _absolute_path(path).relative_to(self.root)
        parts = list(relative.with_suffix("").parts)
        is_init = bool(parts and parts[-1] == "__init__")
        if is_init:
            parts.pop()
        name = ".".join(parts) or path.parent.name
        package = name if is_init else ".".join(name.split(".")[:-1])
        return name, package

    def _parse(self, path: Path) -> None:
        source = _safe_read_text(path, self.state)
        if source is None:
            return
        try:
            tree = ast.parse(source, filename=str(path), type_comments=True)
        except Exception as exc:
            line = getattr(exc, "lineno", 1) or 1
            offset = getattr(exc, "offset", 1) or 1
            diagnostic_span = FlowSpan(str(_absolute_path(path)), line, offset, line, offset)
            self.state.error(
                "DFV2-PYTHON-PARSE-ERROR",
                f"Unable to parse Python source {path}: {exc}",
                diagnostic_span,
            )
            return
        if not self.state.account_tree(path, tree):
            return
        name, package = self._module_name(path)
        self.modules[name] = _Module(name, _absolute_path(path), tree, package)

    def _imports(self, module: _Module) -> None:
        for node in module.tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    module.aliases[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                imported_module = node.module or ""
                if node.level:
                    base = module.package.split(".") if module.package else []
                    ascend = max(0, node.level - 1)
                    if ascend:
                        base = base[:-ascend] if ascend <= len(base) else []
                    imported_module = ".".join(base + ([imported_module] if imported_module else []))
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    module.aliases[local] = ".".join(part for part in (imported_module, alias.name) if part)

    def canonical(self, module: _Module, raw: str) -> str:
        if not raw:
            return raw
        head, dot, tail = raw.partition(".")
        if head in module.aliases:
            return module.aliases[head] + (dot + tail if dot else "")
        local = f"{module.name}.{raw}"
        if local in self.functions or local in self.classes:
            return local
        return raw

    def _symbols(self, module: _Module) -> None:
        def add(
            node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
            class_name: Optional[str],
        ) -> None:
            prefix = f"{module.name}.{class_name}" if class_name else module.name
            key = f"{prefix}.{node.name}"
            args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
            if node.args.vararg:
                args.append(node.args.vararg)
            if node.args.kwarg:
                args.append(node.args.kwarg)
            params = tuple(arg.arg for arg in args)
            param_nodes = {arg.arg: arg for arg in args}
            decorators = [self.canonical(module, _name(dec.func if isinstance(dec, ast.Call) else dec)) for dec in node.decorator_list]
            endings = {item.rsplit(".", 1)[-1].lower() for item in decorators}
            tool = bool(endings & {"tool", "function_tool", "register_tool", "mcp_tool"})
            request = bool(endings & {"get", "post", "put", "patch", "delete", "route", "api_route", "webhook", "handler"})
            self.functions[key] = _Function(
                key,
                module,
                node,
                params,
                param_nodes,
                class_name,
                tool,
                request,
            )

        # Model executable module statements as a synthetic, parameterless
        # entry point.  Keeping the original statement nodes preserves exact
        # source/sink spans while excluding definitions avoids analysing a
        # function body twice as module code.
        module_node = ast.FunctionDef(
            name="<module>",
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=[
                node
                for node in module.tree.body
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ],
            decorator_list=[],
            returns=None,
            type_comment=None,
        )
        module_key = f"{module.name}.<module>"
        self.functions[module_key] = _Function(
            module_key,
            module,
            module_node,
            (),
            {},
            module_entry=True,
        )

        for node in module.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                add(node, None)
            elif isinstance(node, ast.ClassDef):
                self.classes.add(f"{module.name}.{node.name}")
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        add(child, node.name)


class _FunctionAnalyzer:
    def __init__(
        self,
        index: _Index,
        info: _Function,
        summaries: Mapping[str, _Summary],
        state: _BudgetState,
    ) -> None:
        self.index = index
        self.info = info
        self.summaries = summaries
        self.state = state
        self.env: Dict[str, _Value] = {}
        self.effects: List[_SinkEffect] = []
        self.returns: List[_Value] = []
        for param in info.params:
            arg_node = info.param_nodes[param]
            labels: FrozenSet[FlowLabel] = frozenset()
            step = FlowStep("parameter", param, _span(info.module.path, arg_node), info.key)
            value = _Value((_Trace(_Origin(parameter=param), labels, steps=(step,)),))
            if param in {"self", "cls"} and info.class_name:
                value = _Value(value.traces, frozenset({f"{info.module.name}.{info.class_name}"}))
            self.env[param] = value

    def run(self) -> _Summary:
        self._block(self.info.node.body)
        return _Summary(_merge(*self.returns) if self.returns else _Value(), tuple(self.effects))

    def _block(self, statements: Sequence[ast.stmt]) -> bool:
        for statement in statements:
            if self.state.exhausted or not self.state.check_time():
                return True
            if self._stmt(statement):
                return True
        return False

    def _stmt(self, node: ast.stmt) -> bool:
        if isinstance(node, ast.Assign):
            value = self._eval(node.value)
            for target in node.targets:
                self._assign(target, value, node)
        elif isinstance(node, ast.AnnAssign):
            self._assign(node.target, self._eval(node.value) if node.value else _Value(), node)
        elif isinstance(node, ast.AugAssign):
            key = _target_key(node.target)
            self._assign(node.target, _merge(self.env.get(key or "", _Value()), self._eval(node.value)), node)
        elif isinstance(node, ast.Expr):
            self._eval(node.value)
        elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
            value_node = getattr(node, "value", None)
            value = self._eval(value_node) if value_node else _Value()
            value = _with_step(value, FlowStep("return", self.info.key, _span(self.info.module.path, node)))
            self.returns.append(value)
            if self.info.tool_entry:
                self._effect(SinkKind.TOOL_OUTPUT, self.info.key, node, value, "return")
            return isinstance(node, ast.Return)
        elif isinstance(node, ast.Raise):
            if node.exc:
                self._eval(node.exc)
            return True
        elif isinstance(node, ast.Assert):
            self._eval(node.test)
            self._apply_condition(self.env, node.test, True)
        elif isinstance(node, ast.If):
            self._eval(node.test)
            before = dict(self.env)
            body_env = dict(before)
            self.env = body_env
            self._apply_condition(self.env, node.test, True)
            body_exits = self._block(node.body)
            body_env = dict(self.env)
            else_env = dict(before)
            self.env = else_env
            self._apply_condition(self.env, node.test, False)
            else_exits = self._block(node.orelse) if node.orelse else False
            else_env = dict(self.env)
            if body_exits and not else_exits:
                self.env = else_env
            elif else_exits and not body_exits:
                self.env = body_env
            else:
                self.env = self._merge_envs(body_env, else_env)
            return body_exits and else_exits
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            iterable = self._eval(node.iter)
            before = dict(self.env)
            self._assign(node.target, iterable, node)
            self._block(node.body)
            self.env = self._merge_envs(before, self.env)
            self._block(node.orelse)
        elif isinstance(node, ast.While):
            self._eval(node.test)
            before = dict(self.env)
            self._apply_condition(self.env, node.test, True)
            self._block(node.body)
            self.env = self._merge_envs(before, self.env)
            self._block(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self._eval(item.context_expr)
                if item.optional_vars:
                    self._assign(item.optional_vars, value, node)
            self._block(node.body)
        elif isinstance(node, ast.Try):
            before = dict(self.env)
            self._block(node.body)
            envs = [dict(self.env)]
            for handler in node.handlers:
                self.env = dict(before)
                if handler.name:
                    self.env[handler.name] = _Value()
                self._block(handler.body)
                envs.append(dict(self.env))
            self.env = self._merge_envs(*envs)
            self._block(node.orelse)
            self._block(node.finalbody)
        return False

    def _merge_envs(self, *envs: Mapping[str, _Value]) -> Dict[str, _Value]:
        keys: Set[str] = set()
        for env in envs:
            keys.update(env)
        return {key: _merge(*(env.get(key, _Value()) for env in envs)) for key in keys}

    def _assign(self, target: ast.AST, value: _Value, node: ast.AST) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self._assign(child, value, node)
            return
        key = _target_key(target)
        if key is None:
            return
        # Reassignment is a kill for the target and its previously modelled children.
        for old in list(self.env):
            if old == key or old.startswith(key + ".") or old.startswith(key + "["):
                self.env.pop(old, None)
        if not value.traces and isinstance(getattr(node, "value", None), ast.Constant):
            literal = getattr(node, "value").value
            if isinstance(literal, str) and len(literal) >= 8 and _is_secret_name(key):
                value = self._source("hardcoded-secret", key, {FlowLabel.SECRET}, target, Confidence.HIGH)
        step = FlowStep("assignment", key, _span(self.info.module.path, target))
        self.env[key] = _with_step(value, step)

    def _eval(self, node: Optional[ast.AST]) -> _Value:
        if node is None or isinstance(node, ast.Constant):
            return _Value()
        if isinstance(node, ast.Name):
            return self.env.get(node.id, _Value())
        if isinstance(node, ast.Attribute):
            key = _target_key(node)
            if key and key in self.env:
                return self.env[key]
            raw = self.index.canonical(self.info.module, _name(node))
            lowered = raw.lower()
            if any(part in lowered for part in ("request.args", "request.form", "request.json", "request.body", "request.headers")):
                labels = {FlowLabel.REQUEST, FlowLabel.UNTRUSTED}
                if lowered.endswith(".json"):
                    labels.add(FlowLabel.JSON)
                return self._source("request", raw, labels, node, Confidence.HIGH)
            return self._eval(node.value)
        if isinstance(node, ast.Subscript):
            key = _target_key(node)
            if key and key in self.env:
                return self.env[key]
            base_name = self.index.canonical(self.info.module, _name(node.value))
            if base_name in {"os.environ", "environ"}:
                secret = _constant_text(node.slice)
                labels = {FlowLabel.ENV}
                if _is_secret_name(secret):
                    labels.add(FlowLabel.SECRET)
                return self._source("environment", secret or base_name, labels, node, Confidence.HIGH)
            value = self._eval(node.value)
            return _merge(value, self._eval(node.slice))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _merge(*(self._eval(item) for item in node.elts))
        if isinstance(node, ast.Dict):
            return _merge(*(self._eval(item) for pair in zip(node.keys, node.values) for item in pair if item is not None))
        if isinstance(node, ast.BinOp):
            return _merge(self._eval(node.left), self._eval(node.right))
        if isinstance(node, ast.BoolOp):
            return _merge(*(self._eval(item) for item in node.values))
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand)
        if isinstance(node, ast.Compare):
            return _merge(self._eval(node.left), *(self._eval(item) for item in node.comparators))
        if isinstance(node, ast.IfExp):
            return _merge(self._eval(node.test), self._eval(node.body), self._eval(node.orelse))
        if isinstance(node, ast.JoinedStr):
            return _merge(*(self._eval(item) for item in node.values))
        if isinstance(node, ast.FormattedValue):
            return self._eval(node.value)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return _merge(self._eval(node.elt), *(self._eval(gen.iter) for gen in node.generators))
        if isinstance(node, ast.DictComp):
            return _merge(self._eval(node.key), self._eval(node.value), *(self._eval(gen.iter) for gen in node.generators))
        if isinstance(node, ast.NamedExpr):
            value = self._eval(node.value)
            self._assign(node.target, value, node)
            return value
        if isinstance(node, ast.Await):
            return self._eval(node.value)
        if isinstance(node, ast.Call):
            return self._call(node)
        return _merge(*(self._eval(child) for child in ast.iter_child_nodes(node)))

    def _call(self, node: ast.Call) -> _Value:
        raw = _name(node.func)
        canonical = self.index.canonical(self.info.module, raw)
        receiver = self._eval(node.func.value) if isinstance(node.func, ast.Attribute) else _Value()
        args = [self._eval(item) for item in node.args]
        kwargs = {item.arg: self._eval(item.value) for item in node.keywords if item.arg}
        splats = [self._eval(item.value) for item in node.keywords if item.arg is None]
        combined = _merge(receiver, *args, *kwargs.values(), *splats)
        callee = self._resolve_callee(node, canonical, receiver)

        sink = _sink_for(canonical, raw, node, receiver.types)
        if sink is not None:
            kind, argument = sink
            sink_value = self._sink_value(kind, receiver, args, kwargs, combined)
            self._effect(kind, canonical or raw, node, sink_value, argument)

        special = self._special_source(node, canonical or raw, combined, receiver)
        if special is not None:
            return special

        if callee and callee in self.index.functions:
            bindings = self._bind(self.index.functions[callee], node, receiver, args, kwargs, splats)
            return self._instantiate(callee, bindings, node)

        if canonical in self.index.classes:
            return _Value(combined.traces, frozenset({canonical}))
        ending = (canonical or raw).rsplit(".", 1)[-1]
        symbol_head = raw.partition(".")[0]
        if (
            canonical in {"pathlib.Path", "pathlib.PurePath"}
            and symbol_head not in self.env
        ):
            return _Value(combined.traces, frozenset({"pathlib.Path"}))
        if ending == "open" or canonical in {"builtins.open", "io.open"}:
            mode = _call_constant(node, 1, "mode") or "r"
            file_type = "file-writer" if any(char in str(mode) for char in "wax+") else "file-reader"
            return _Value(combined.traces, frozenset({file_type}))
        if combined.traces:
            return _with_step(combined, FlowStep("call", canonical or raw or "<call>", _span(self.info.module.path, node)))
        return combined

    def _resolve_callee(self, node: ast.Call, canonical: str, receiver: _Value) -> Optional[str]:
        if canonical in self.index.functions:
            return canonical
        if isinstance(node.func, ast.Name):
            local = f"{self.info.module.name}.{node.func.id}"
            return local if local in self.index.functions else None
        if isinstance(node.func, ast.Attribute):
            for value_type in receiver.types:
                candidate = f"{value_type}.{node.func.attr}"
                if candidate in self.index.functions:
                    return candidate
            if isinstance(node.func.value, ast.Name) and node.func.value.id in {"self", "cls"} and self.info.class_name:
                candidate = f"{self.info.module.name}.{self.info.class_name}.{node.func.attr}"
                if candidate in self.index.functions:
                    return candidate
            # A receiver passed through a wrapper has no concrete type in a
            # context-independent summary.  A unique project method is still
            # unambiguous and lets the fixed point retain that call edge.
            candidates = [
                key for key, info in self.index.functions.items()
                if info.class_name is not None and info.node.name == node.func.attr
            ]
            if len(candidates) == 1:
                return candidates[0]
        return None

    def _bind(
        self, callee: _Function, node: ast.Call, receiver: _Value, args: Sequence[_Value],
        kwargs: Mapping[str, _Value], splats: Sequence[_Value],
    ) -> Dict[str, _Value]:
        result: Dict[str, _Value] = {param: _Value() for param in callee.params}
        position = 0
        if callee.params and callee.params[0] in {"self", "cls"} and isinstance(node.func, ast.Attribute):
            result[callee.params[0]] = receiver
            position = 1
        for value in args:
            if position < len(callee.params):
                result[callee.params[position]] = value
                position += 1
        for name, value in kwargs.items():
            if name in result:
                result[name] = value
            elif callee.node.args.kwarg:
                result[callee.node.args.kwarg.arg] = _merge(result.get(callee.node.args.kwarg.arg, _Value()), value)
        if splats and callee.node.args.kwarg:
            key = callee.node.args.kwarg.arg
            result[key] = _merge(result.get(key, _Value()), *splats)
        return result

    def _instantiate(self, key: str, bindings: Mapping[str, _Value], call: ast.Call) -> _Value:
        summary = self.summaries.get(key, _Summary())
        call_step = FlowStep("call", key, _span(self.info.module.path, call))

        def substitute(trace: _Trace) -> Tuple[_Trace, ...]:
            if trace.origin.parameter is None:
                return (trace,)
            base = bindings.get(trace.origin.parameter, _Value())
            tail = trace.steps[1:] if trace.steps and trace.steps[0].kind == "parameter" else trace.steps
            return tuple(
                _Trace(
                    item.origin, item.labels | trace.labels, item.guards | trace.guards,
                    item.steps + (call_step,) + tail, _min_confidence(item.confidence, trace.confidence),
                )
                for item in base.traces
            )

        returned_traces = tuple(item for trace in summary.returned.traces for item in substitute(trace))
        for effect in summary.effects:
            traces = tuple(item for trace in effect.traces for item in substitute(trace))
            if traces:
                self.effects.append(_SinkEffect(effect.sink, _merge(_Value(traces)).traces))
        return _Value(_merge(_Value(returned_traces)).traces, summary.returned.types)

    def _special_source(self, node: ast.Call, symbol: str, combined: _Value, receiver: _Value) -> Optional[_Value]:
        lowered = symbol.lower()
        ending = lowered.rsplit(".", 1)[-1]
        if symbol in {"os.getenv", "os.environ.get", "getenv"} or ending == "getenv":
            key = _call_constant(node, 0, "key") or symbol
            labels = {FlowLabel.ENV}
            if _is_secret_name(str(key)):
                labels.add(FlowLabel.SECRET)
            return self._source("environment", str(key), labels, node, Confidence.HIGH)
        if ending in {"loads", "load"} and ("json" in lowered or symbol in {"loads", "load"}):
            value = _with_labels(combined, {FlowLabel.JSON})
            if value.traces:
                return value
            if ending == "load":
                return self._source("json-file", symbol, {FlowLabel.FILE, FlowLabel.JSON, FlowLabel.UNTRUSTED}, node)
        if ending in {"read_text", "read_bytes"} or (ending == "read" and "file-reader" in receiver.types):
            return self._source("file", symbol, {FlowLabel.FILE, FlowLabel.UNTRUSTED}, node)
        if any(token in lowered for token in ("requests.get", "requests.post", "httpx.get", "httpx.post", "urlopen", "aiohttp")):
            return self._source("network-response", symbol, {FlowLabel.NETWORK_RESPONSE, FlowLabel.UNTRUSTED}, node)
        if ending in {"call_tool", "invoke_tool", "run_tool"}:
            return self._source("tool-output", symbol, {FlowLabel.TOOL_OUTPUT, FlowLabel.UNTRUSTED}, node, Confidence.HIGH)
        if symbol in {"input", "builtins.input", "sys.stdin.read", "sys.stdin.readline"}:
            return self._source("request", symbol, {FlowLabel.REQUEST, FlowLabel.UNTRUSTED}, node, Confidence.HIGH)
        return None

    def _source(
        self, kind: str, symbol: str, labels: Iterable[FlowLabel], node: ast.AST,
        confidence: Confidence = Confidence.MEDIUM,
    ) -> _Value:
        source_span = _span(self.info.module.path, node)
        label_set = frozenset(labels)
        source_id = f"{source_span.file}:{source_span.line}:{source_span.column}:{kind}:{symbol}"
        source = FlowSource(source_id, kind, symbol, label_set, source_span, confidence)
        step = FlowStep("source", symbol, source_span, kind)
        return _Value((_Trace(_Origin(source=source), label_set, steps=(step,), confidence=confidence),))

    def _sink_value(
        self, kind: SinkKind, receiver: _Value, args: Sequence[_Value],
        kwargs: Mapping[str, _Value], combined: _Value,
    ) -> _Value:
        if kind in {SinkKind.COMMAND, SinkKind.CODE_EXECUTION}:
            preferred = [kwargs[name] for name in ("args", "command", "cmd", "url", "code", "source") if name in kwargs]
            return _merge(*(preferred or list(args[:1]) or [combined]))
        if kind == SinkKind.NETWORK:
            # Both the destination and headers/body/query values matter: the
            # former models SSRF, while the latter models data exfiltration.
            return combined
        if kind == SinkKind.FILE_WRITE:
            return _merge(receiver, *(args[:2]), *kwargs.values())
        return combined

    def _effect(self, kind: SinkKind, symbol: str, node: ast.AST, value: _Value, argument: str) -> None:
        traces = tuple(trace for trace in value.traces if kind not in trace.guards)
        if not traces:
            return
        sink = FlowSink(kind, symbol, _span(self.info.module.path, node), argument, Confidence.HIGH)
        self.effects.append(_SinkEffect(sink, _merge(_Value(traces)).traces))

    def _apply_condition(self, env: Dict[str, _Value], test: ast.AST, truth: bool) -> None:
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            self._apply_condition(env, test.operand, not truth)
            return
        if isinstance(test, ast.BoolOp):
            # Applying all conjuncts is valid only for a true AND / false OR.
            if (isinstance(test.op, ast.And) and truth) or (isinstance(test.op, ast.Or) and not truth):
                for value in test.values:
                    self._apply_condition(env, value, truth)
            return
        kinds: FrozenSet[SinkKind] = frozenset()
        subject: Optional[ast.AST] = None
        if isinstance(test, ast.Call):
            # ``Path.resolve`` followed by the real ``Path.is_relative_to``
            # is a structural containment proof when the boundary itself is
            # not tainted.  Arbitrary helpers named ``is_safe_path`` or
            # ``validate_path`` are deliberately not trusted.
            if (
                truth
                and isinstance(test.func, ast.Attribute)
                and test.func.attr == "is_relative_to"
                and len(test.args) == 1
                and (_target_key(test.func) or "") not in env
            ):
                candidate_key = _target_key(test.func.value)
                candidate = env.get(candidate_key or "", _Value())
                boundary_key = _target_key(test.args[0])
                boundary = env.get(boundary_key or "", _Value())
                fixed_boundary = isinstance(test.args[0], ast.Constant) or (
                    boundary_key is not None
                    and boundary_key in env
                    and not boundary.traces
                )
                if _is_resolved_path(candidate) and fixed_boundary:
                    subject = test.func.value
                    kinds = frozenset({SinkKind.FILE_WRITE})
        elif isinstance(test, ast.Compare) and len(test.ops) == 1:
            op = test.ops[0]
            safe_membership = (isinstance(op, ast.In) and truth) or (isinstance(op, ast.NotIn) and not truth)
            if safe_membership and _literal_container(test.comparators[0]):
                subject = test.left
                kinds = frozenset({SinkKind.COMMAND, SinkKind.CODE_EXECUTION})
        if subject is not None and kinds:
            key = _target_key(subject)
            if key and key in env:
                env[key] = _guard(env[key], kinds)


def _literal_container(node: ast.AST) -> bool:
    return isinstance(node, (ast.Set, ast.List, ast.Tuple)) and bool(node.elts) and all(isinstance(item, ast.Constant) for item in node.elts)


def _constant_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return str(node.value)
    return ""


def _call_constant(node: ast.Call, position: int, keyword: str) -> Any:
    if position < len(node.args) and isinstance(node.args[position], ast.Constant):
        return node.args[position].value
    for item in node.keywords:
        if item.arg == keyword and isinstance(item.value, ast.Constant):
            return item.value.value
    return None


def _is_secret_name(name: str) -> bool:
    lowered = (name or "").lower()
    return any(word in lowered for word in _SECRET_WORDS)


def _is_resolved_path(value: _Value) -> bool:
    """Return true only for tainted ``pathlib.Path`` values proven resolved."""

    return (
        bool(value.traces)
        and "pathlib.Path" in value.types
        and all(
            any(
                step.kind == "call" and step.symbol.rsplit(".", 1)[-1] == "resolve"
                for step in trace.steps
            )
            for trace in value.traces
        )
    )


def _sink_for(symbol: str, raw: str, node: ast.Call, receiver_types: FrozenSet[str]) -> Optional[Tuple[SinkKind, str]]:
    lowered = (symbol or raw).lower()
    ending = lowered.rsplit(".", 1)[-1]
    if symbol in {"os.system", "os.popen"} or ending in {"system", "popen"} and lowered.startswith("os."):
        return SinkKind.COMMAND, "command"
    if "subprocess." in lowered and ending in {"run", "popen", "call", "check_call", "check_output"}:
        return SinkKind.COMMAND, "command"
    if symbol in {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile", "importlib.import_module"}:
        return SinkKind.CODE_EXECUTION, "code"
    network_markers = ("requests.", "httpx.", "urllib.request.", "aiohttp.", "socket.")
    if any(marker in lowered for marker in network_markers) and ending in {"get", "post", "put", "patch", "delete", "request", "urlopen", "open", "send", "sendall", "connect"}:
        return SinkKind.NETWORK, "url"
    mode = _call_constant(node, 1, "mode") if ending == "open" else None
    if ending == "open" and mode is not None and any(char in str(mode) for char in "wax+"):
        return SinkKind.FILE_WRITE, "path"
    if ending in {"write_text", "write_bytes", "writelines"} or (ending == "write" and "file-writer" in receiver_types):
        return SinkKind.FILE_WRITE, "path-or-content"
    if ending in {"create", "generate", "invoke", "complete", "chat", "predict"} and any(
        word in lowered for word in ("llm", "model", "completion", "responses", "chat", "prompt")
    ):
        return SinkKind.PROMPT, "prompt"
    if ending in {"append", "add", "save", "store", "put", "remember", "add_message", "save_context"} and any(
        word in lowered for word in ("memory", "history", "context", "vector", "conversation")
    ):
        return SinkKind.MEMORY, "value"
    if ending in {"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "print"} and (
        ending == "print" or any(word in lowered for word in ("log", "logger", "logging"))
    ):
        return SinkKind.LOG, "message"
    if ending in {"tool_result", "toolresponse", "tool_response", "result_text"}:
        return SinkKind.TOOL_OUTPUT, "value"
    return None


def _min_confidence(left: Confidence, right: Confidence) -> Confidence:
    rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    return left if rank[left] <= rank[right] else right


def _entry_source(info: _Function, param: str) -> FlowSource:
    arg = info.param_nodes[param]
    source_span = _span(info.module.path, arg)
    labels: Set[FlowLabel] = {FlowLabel.UNTRUSTED}
    kind = "function-parameter"
    confidence = Confidence.MEDIUM
    if info.tool_entry:
        labels.add(FlowLabel.TOOL_INPUT)
        kind = "tool-parameter"
        confidence = Confidence.HIGH
    elif info.request_entry:
        labels.add(FlowLabel.REQUEST)
        kind = "request-parameter"
        confidence = Confidence.HIGH
    else:
        labels.add(FlowLabel.FUNCTION_INPUT)
    if _is_secret_name(param):
        labels.add(FlowLabel.SECRET)
    if any(word in param.lower() for word in _REQUEST_WORDS):
        labels.add(FlowLabel.REQUEST)
    source_id = f"{info.key}:{param}:{source_span.line}:{source_span.column}"
    return FlowSource(source_id, kind, param, frozenset(labels), source_span, confidence)


def _build_summaries(index: _Index, state: _BudgetState) -> Dict[str, _Summary]:
    summaries: Dict[str, _Summary] = {key: _Summary() for key in index.functions}
    limit = max(8, len(index.functions) * 3)
    converged = False
    for _ in range(limit):
        if state.exhausted or not state.check_time():
            break
        changed = False
        updated: Dict[str, _Summary] = {}
        for key in sorted(index.functions):
            if state.exhausted or not state.check_time():
                break
            summary = _FunctionAnalyzer(index, index.functions[key], summaries, state).run()
            if not state.check_time():
                break
            updated[key] = summary
            changed = changed or summary != summaries[key]
        if state.exhausted:
            break
        summaries = updated
        if not changed:
            converged = True
            break
    if not converged and not state.exhausted:
        state.error(
            "DFV2-FIXPOINT-LIMIT",
            "Inter-procedural analysis reached its iteration limit; recursive flows may be incomplete.",
        )
    return summaries


def _confidence_for(trace: _Trace, sink: FlowSink) -> Confidence:
    high_pairs = (
        FlowLabel.SECRET in trace.labels and sink.kind in {SinkKind.NETWORK, SinkKind.LOG, SinkKind.TOOL_OUTPUT},
        bool(trace.labels & {FlowLabel.UNTRUSTED, FlowLabel.REQUEST, FlowLabel.TOOL_INPUT})
        and sink.kind in {SinkKind.COMMAND, SinkKind.CODE_EXECUTION},
    )
    return Confidence.HIGH if any(high_pairs) else _min_confidence(trace.confidence, sink.confidence)


def _rule_id(labels: FrozenSet[FlowLabel], sink: SinkKind) -> str:
    order = (
        FlowLabel.SECRET, FlowLabel.TOOL_INPUT, FlowLabel.TOOL_OUTPUT, FlowLabel.REQUEST,
        FlowLabel.FILE, FlowLabel.ENV, FlowLabel.JSON, FlowLabel.NETWORK_RESPONSE,
        FlowLabel.FUNCTION_INPUT, FlowLabel.UNTRUSTED,
    )
    source = next((label.value.upper().replace("-", "_") for label in order if label in labels), "TAINT")
    return f"DFV2-{source}-{sink.value.upper().replace('-', '_')}"


def _ordered_detections(found: Mapping[Tuple[Any, ...], FlowDetection]) -> Tuple[FlowDetection, ...]:
    return tuple(
        sorted(
            found.values(),
            key=lambda item: (
                item.sink.span.file,
                item.sink.span.line,
                item.rule_id,
                item.source.source_id,
            ),
        )
    )


def _detections(
    index: _Index,
    summaries: Mapping[str, _Summary],
    selected: Optional[Set[Path]],
    state: _BudgetState,
) -> Tuple[FlowDetection, ...]:
    found: Dict[Tuple[Any, ...], FlowDetection] = {}
    for key in sorted(index.functions):
        if state.exhausted or not state.check_time():
            break
        info = index.functions[key]
        if selected is not None and info.module.path not in selected:
            continue
        public = info.class_name is None and not info.node.name.startswith("_")
        if not (public or info.tool_entry or info.request_entry):
            if not info.module_entry:
                continue
        bindings: Dict[str, _Value] = {}
        for param in info.params:
            if param in {"self", "cls"}:
                bindings[param] = _Value(types=frozenset({f"{info.module.name}.{info.class_name}"}) if info.class_name else frozenset())
                continue
            source = _entry_source(info, param)
            step = FlowStep("source", param, source.span, source.kind)
            bindings[param] = _Value((_Trace(_Origin(source=source), source.labels, steps=(step,), confidence=source.confidence),))
        summary = summaries[key]
        for effect in summary.effects:
            if state.exhausted or not state.check_time():
                return _ordered_detections(found)
            for template in effect.traces:
                if state.exhausted or not state.check_time():
                    return _ordered_detections(found)
                traces: Tuple[_Trace, ...]
                if template.origin.parameter:
                    base = bindings.get(template.origin.parameter, _Value())
                    tail = template.steps[1:] if template.steps and template.steps[0].kind == "parameter" else template.steps
                    traces = tuple(
                        _Trace(item.origin, item.labels | template.labels, item.guards | template.guards, item.steps + tail, item.confidence)
                        for item in base.traces
                    )
                else:
                    traces = (template,)
                for trace in traces:
                    if state.exhausted or not state.check_time():
                        return _ordered_detections(found)
                    source = trace.origin.source
                    if source is None or effect.sink.kind in trace.guards:
                        continue
                    labels = trace.labels | source.labels
                    confidence = _confidence_for(trace, effect.sink)
                    sink_step = FlowStep("sink", effect.sink.symbol, effect.sink.span, effect.sink.kind.value)
                    path = FlowPath(source, effect.sink, labels, confidence, trace.steps + (sink_step,))
                    rule = _rule_id(labels, effect.sink.kind)
                    detection = FlowDetection(
                        rule, f"{source.kind} '{source.symbol}' reaches {effect.sink.kind.value} '{effect.sink.symbol}'",
                        labels, confidence, path,
                    )
                    dedupe = (rule, source.source_id, effect.sink.span, tuple((step.kind, step.symbol, step.span) for step in path.steps))
                    found[dedupe] = detection
    state.check_time()
    return _ordered_detections(found)


_IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
}


def _is_within(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_descendant_parents(root: Path, path: Path, state: _BudgetState) -> bool:
    if not _is_within(root, path):
        state.error(
            "DFV2-TARGET-OUTSIDE-ROOT",
            f"Python target is outside the lexical project root: {path}",
            _path_span(path),
        )
        return False
    relative = path.relative_to(root)
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        current_stat = _safe_lstat(current, state, kind="source directory")
        if current_stat is None:
            return False
        if not stat.S_ISDIR(current_stat.st_mode):
            state.error(
                "DFV2-PARENT-NOT-DIRECTORY",
                f"Python source parent is not a directory: {current}",
                _path_span(current),
            )
            return False
    return True


def _add_python_path(
    path: Path,
    state: _BudgetState,
    paths: List[Path],
    seen: Set[Path],
    *,
    explicit: bool = False,
) -> None:
    path = _absolute_path(path)
    if path in seen or state.discovery_stopped or state.exhausted:
        return
    if not explicit and path.suffix.lower() != ".py":
        return
    file_stat = _safe_lstat(path, state, kind="Python source file")
    if file_stat is None:
        return
    if not stat.S_ISREG(file_stat.st_mode):
        state.error(
            "DFV2-NONREGULAR-FILE",
            f"Refused non-regular Python source file: {path}",
            _path_span(path),
        )
        return
    if not state.reserve_file(path):
        return
    paths.append(path)
    seen.add(path)


def _python_paths(
    root: Path,
    state: _BudgetState,
    *,
    priority: Optional[Path] = None,
    recursive: bool = True,
) -> List[Path]:
    root = _absolute_path(root)
    paths: List[Path] = []
    seen: Set[Path] = set()
    if not _validate_root(root, state):
        return paths

    if priority is not None:
        priority = _absolute_path(priority)
        if _validate_descendant_parents(root, priority, state):
            _add_python_path(priority, state, paths, seen, explicit=True)
    if not recursive or state.discovery_stopped or state.exhausted:
        return paths

    pending = [root]
    while pending and not state.discovery_stopped and not state.exhausted:
        if not state.check_time():
            break
        directory = pending.pop()
        directory_stat = _safe_lstat(directory, state, kind="source directory")
        if directory_stat is None:
            continue
        if not stat.S_ISDIR(directory_stat.st_mode):
            state.error(
                "DFV2-DIRECTORY-TYPE-ERROR",
                f"Source tree entry is no longer a directory: {directory}",
                _path_span(directory),
            )
            continue
        try:
            with os.scandir(str(directory)) as entries:
                for entry in entries:
                    if state.discovery_stopped or state.exhausted or not state.check_time():
                        break
                    entry_path = _absolute_path(directory / entry.name)
                    try:
                        entry_stat = os.lstat(str(entry_path))
                    except OSError as exc:
                        state.error(
                            "DFV2-PATH-ERROR",
                            f"Unable to inspect source tree entry {entry_path}: {exc}",
                            _path_span(entry_path),
                        )
                        continue
                    if _is_link_or_reparse(entry_stat):
                        state.error(
                            "DFV2-LINK-REFUSED",
                            "Refused to follow source tree symlink or reparse point: "
                            f"{entry_path}",
                            _path_span(entry_path),
                        )
                        continue
                    if stat.S_ISDIR(entry_stat.st_mode):
                        if entry.name not in _IGNORED_DIRECTORIES:
                            pending.append(entry_path)
                    elif stat.S_ISREG(entry_stat.st_mode):
                        _add_python_path(entry_path, state, paths, seen)
                    elif entry_path.suffix.lower() == ".py":
                        state.error(
                            "DFV2-NONREGULAR-FILE",
                            f"Refused non-regular Python source file: {entry_path}",
                            _path_span(entry_path),
                        )
        except OSError as exc:
            state.error(
                "DFV2-DIRECTORY-READ-ERROR",
                f"Unable to enumerate source directory {directory}: {exc}",
                _path_span(directory),
            )
    return sorted(paths, key=lambda item: os.path.normcase(str(item)))


def analyze_python_file(
    path: Union[os.PathLike[str], str],
    *,
    project_root: Optional[Union[os.PathLike[str], str]] = None,
    budget: Optional[AnalysisBudget] = None,
) -> AnalysisResult:
    """Analyse one Python file, optionally resolving imports inside a project."""

    target = _absolute_path(path)
    root = _absolute_path(project_root) if project_root is not None else target.parent
    state = _BudgetState(budget or AnalysisBudget())
    paths = _python_paths(
        root,
        state,
        priority=target,
        recursive=project_root is not None,
    )
    index = _Index(root, paths, state)
    summaries = _build_summaries(index, state)
    detections = _detections(index, summaries, {target}, state)
    complete = not any(item.severity == "error" for item in index.diagnostics)
    return AnalysisResult(
        detections,
        tuple(index.diagnostics),
        complete,
        "python",
        "python-ast-fixed-point",
        not complete,
        len(index.modules),
    )


def analyze_project(
    root: Union[os.PathLike[str], str],
    *,
    budget: Optional[AnalysisBudget] = None,
) -> AnalysisResult:
    """Analyse all Python files under *root* with relative-import summaries."""

    project_root = _absolute_path(root)
    state = _BudgetState(budget or AnalysisBudget())
    paths = _python_paths(project_root, state)
    index = _Index(project_root, paths, state)
    summaries = _build_summaries(index, state)
    detections = _detections(index, summaries, None, state)
    complete = not any(item.severity == "error" for item in index.diagnostics)
    return AnalysisResult(
        detections,
        tuple(index.diagnostics),
        complete,
        "python",
        "python-ast-fixed-point",
        not complete,
        len(index.modules),
    )


__all__ = [
    "AnalysisBudget", "AnalysisDiagnostic", "AnalysisResult", "Confidence", "FlowDetection", "FlowLabel",
    "FlowPath", "FlowSink", "FlowSource", "FlowSpan", "FlowStep", "JavaScriptAnalyzer",
    "JavaScriptParseResult", "SinkKind", "analyze_javascript_file", "analyze_project",
    "analyze_python_file",
]
