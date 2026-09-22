from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, local

import pytest

from clawlock.scanners import dataflow
from clawlock.scanners.dataflow_reporting import findings_from_dataflow


TRACE_LIMIT_CODE = "DFV2-TRACE-LIMIT"


def _write(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _aggregate_source(count: int, form: str = "expression") -> tuple[str, int]:
    names = [f"item_{index:03d}" for index in range(count)]
    first = ", ".join(names[:32])
    second = ", ".join(names[32:])
    all_items = ", ".join(names)
    header = f"def aggregate(choose, {all_items}):\n"
    if form == "branch":
        return header + (
            f"    if choose:\n        items = ({first})\n"
            f"    else:\n        items = ({second})\n    return items\n"
        ), 2
    if form == "returns":
        return header + (
            f"    if choose:\n        return ({first})\n"
            f"    return ({second})\n"
        ), 1
    if form == "call":
        return header + f"    return collect({all_items})\n", 2
    if form == "augmentation":
        return header + f"    items = ({first})\n    items += ({second})\n    return items\n", 3
    return header + f"    return ({all_items})\n", 2


@pytest.mark.parametrize("form", ["expression", "branch", "returns", "call", "augmentation"])
@pytest.mark.parametrize("project", [False, True])
def test_trace_overflow_marks_public_result_and_report_incomplete(
    tmp_path: Path, form: str, project: bool
) -> None:
    source, expected_line = _aggregate_source(65, form)
    target = _write(tmp_path / "values.py", source)

    result = dataflow.analyze_project(tmp_path) if project else dataflow.analyze_python_file(target)

    assert result.complete is False
    assert result.degraded is True
    assert result.files_analyzed == 1
    assert not result.detections  # The fixture only combines and returns values.
    diagnostics = [item for item in result.diagnostics if item.code == TRACE_LIMIT_CODE]
    assert len(diagnostics) == 1  # Fixed-point passes do not repeat the diagnostic.
    diagnostic = diagnostics[0]
    assert diagnostic.severity == "error"
    assert diagnostic.span is not None
    assert Path(diagnostic.span.file) == target
    assert diagnostic.span.line == expected_line
    assert diagnostic.span.column >= 1
    assert "64 trace limit" in diagnostic.message
    assert "1 distinct source traces were omitted" in diagnostic.message
    assert str(target) in diagnostic.message
    serialized = result.to_dict()
    assert serialized["complete"] is False
    assert serialized["degraded"] is True
    assert serialized["diagnostics"][0]["span"]["line"] == expected_line

    findings = findings_from_dataflow(result, scanner="test", root=tmp_path)
    assert len(findings) == 1
    assert findings[0].metadata["scan_status"] == "error"
    assert findings[0].metadata["degraded"] is True
    assert TRACE_LIMIT_CODE in findings[0].detail
    assert f"{target}:{expected_line}:" in findings[0].detail


def test_exact_trace_limit_stays_complete(tmp_path: Path) -> None:
    source, _ = _aggregate_source(64)
    target = _write(tmp_path / "values.py", source)

    result = dataflow.analyze_python_file(target)

    assert result.complete is True
    assert result.degraded is False
    assert not result.diagnostics
    assert not result.detections


def _value(start: int, stop: int) -> dataflow._Value:
    return dataflow._Value(tuple(
        dataflow._Trace(dataflow._Origin(parameter=f"value_{index:03d}"))
        for index in range(start, stop)
    ))


def test_merge_deduplicates_before_counting_and_keeps_bounded_output(tmp_path: Path) -> None:
    span = dataflow.FlowSpan(str(tmp_path / "values.py"), 4, 5, 4, 12)
    state = dataflow._BudgetState(dataflow.AnalysisBudget())

    within_limit = dataflow._merge(_value(0, 64), _value(0, 64), state=state, span=span)
    assert len(within_limit.traces) == 64
    assert not state.diagnostics

    overflow = dataflow._merge(_value(0, 65), _value(0, 64), state=state, span=span)
    assert len(overflow.traces) == 64
    assert overflow == within_limit
    assert state.diagnostics[0].span == span
    assert state.diagnostics[0].code == TRACE_LIMIT_CODE
    assert state.exhausted is False  # Other bounded analysis can still continue.


def _analyzer(tmp_path: Path, source: str) -> dataflow._FunctionAnalyzer:
    target = _write(tmp_path / "values.py", source)
    state = dataflow._BudgetState(dataflow.AnalysisBudget())
    index = dataflow._Index(tmp_path, [target], state)
    function = next(item for item in index.functions.values() if item.node.name == "aggregate")
    return dataflow._FunctionAnalyzer(index, function, {}, state)


@pytest.mark.parametrize("splatted", [False, True])
def test_argument_binding_reports_trace_overflow(tmp_path: Path, splatted: bool) -> None:
    analyzer = _analyzer(tmp_path, "def aggregate(**options):\n    return options\n")
    call = ast.parse("aggregate()", mode="eval").body
    assert isinstance(call, ast.Call)
    kwargs = {} if splatted else {"first": _value(0, 32), "second": _value(32, 65)}
    splats = [_value(0, 32), _value(32, 65)] if splatted else []

    bindings = analyzer._bind(analyzer.info, call, dataflow._Value(), [], kwargs, splats)

    assert len(bindings["options"].traces) == 64
    assert [item.code for item in analyzer.state.diagnostics] == [TRACE_LIMIT_CODE]
    assert analyzer.state.diagnostics[0].span.line == 1


def test_summary_instantiation_reports_return_and_effect_truncation(tmp_path: Path) -> None:
    analyzer = _analyzer(tmp_path, "def aggregate(first, second):\n    return first\n")
    call = ast.parse("aggregate()", mode="eval").body
    assert isinstance(call, ast.Call)
    templates = dataflow._Value(tuple(
        dataflow._Trace(dataflow._Origin(parameter=name)) for name in ("first", "second")
    ))
    sink = dataflow.FlowSink(
        dataflow.SinkKind.LOG, "audit.record", dataflow._span(analyzer.info.module.path, call)
    )
    analyzer.summaries = {
        analyzer.info.key: dataflow._Summary(
            returned=templates, effects=(dataflow._SinkEffect(sink, templates.traces),)
        )
    }

    result = analyzer._instantiate(
        analyzer.info.key, {"first": _value(0, 32), "second": _value(32, 65)}, call
    )

    assert len(result.traces) == 64
    assert len(analyzer.effects[0].traces) == 64
    assert [item.code for item in analyzer.state.diagnostics] == [TRACE_LIMIT_CODE]


def test_concurrent_analyses_keep_completeness_state_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limited_source, _ = _aggregate_source(65)
    clean_source, _ = _aggregate_source(64)
    limited = _write(tmp_path / "limited" / "values.py", limited_source)
    clean = _write(tmp_path / "clean" / "values.py", clean_source)
    real_merge = dataflow._merge
    barrier = Barrier(2)
    thread_state = local()

    def synchronized_merge(*values, state, span):
        if not getattr(thread_state, "started", False):
            thread_state.started = True
            barrier.wait(timeout=10)
        return real_merge(*values, state=state, span=span)

    monkeypatch.setattr(dataflow, "_merge", synchronized_merge)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(dataflow.analyze_python_file, [limited, clean]))

    assert results[0].complete is False
    assert results[0].degraded is True
    assert [item.code for item in results[0].diagnostics] == [TRACE_LIMIT_CODE]
    assert Path(results[0].diagnostics[0].span.file) == limited
    assert results[1].complete is True
    assert results[1].degraded is False
    assert not results[1].diagnostics
