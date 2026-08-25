from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from clawlock.scanners import dataflow
from clawlock.scanners.dataflow import AnalysisBudget, SinkKind, analyze_project, analyze_python_file


def _write(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _codes(result: dataflow.AnalysisResult) -> set[str]:
    return {item.code for item in result.diagnostics}


def _assert_failed_closed(result: dataflow.AnalysisResult, code: str) -> None:
    assert result.complete is False
    assert result.degraded is True
    assert code in _codes(result)
    assert all(item.severity == "error" for item in result.diagnostics if item.code == code)


def test_file_count_budget_is_hard_and_reported(tmp_path: Path) -> None:
    _write(tmp_path / "one.py", "def one(value):\n    return value\n")
    _write(tmp_path / "two.py", "def two(value):\n    return value\n")

    result = analyze_project(tmp_path, budget=AnalysisBudget(max_files=1))

    _assert_failed_closed(result, "DFV2-FILE-LIMIT")
    assert result.files_analyzed == 1


def test_file_and_total_byte_budgets_fail_closed(tmp_path: Path) -> None:
    large = _write(tmp_path / "large.py", "value = '1234567890'\n")

    per_file = analyze_python_file(large, budget=AnalysisBudget(max_file_bytes=4))
    aggregate = analyze_python_file(large, budget=AnalysisBudget(max_total_bytes=4))

    _assert_failed_closed(per_file, "DFV2-FILE-SIZE-LIMIT")
    _assert_failed_closed(aggregate, "DFV2-TOTAL-SIZE-LIMIT")
    assert per_file.files_analyzed == aggregate.files_analyzed == 0


def test_ast_and_function_budgets_fail_closed(tmp_path: Path) -> None:
    target = _write(tmp_path / "module.py", "def entry(value):\n    return value\n")

    nodes = analyze_python_file(target, budget=AnalysisBudget(max_ast_nodes=0))
    functions = analyze_python_file(target, budget=AnalysisBudget(max_functions=0))

    _assert_failed_closed(nodes, "DFV2-AST-NODE-LIMIT")
    _assert_failed_closed(functions, "DFV2-FUNCTION-LIMIT")


def test_zero_second_budget_times_out_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path / "module.py", "answer = 42\n")

    result = analyze_project(tmp_path, budget=AnalysisBudget(max_seconds=0))

    _assert_failed_closed(result, "DFV2-TIMEOUT")
    assert result.files_analyzed == 0


def test_parse_failure_is_an_error_and_analysis_is_incomplete(tmp_path: Path) -> None:
    target = _write(tmp_path / "broken.py", "def broken(:\n    pass\n")

    result = analyze_python_file(target)

    _assert_failed_closed(result, "DFV2-PYTHON-PARSE-ERROR")


def test_fixed_point_limit_is_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = _write(tmp_path / "module.py", "def entry(value):\n    return value\n")
    calls = 0

    def never_stable(_self: object) -> dataflow._Summary:
        nonlocal calls
        calls += 1
        value = dataflow._Value(types=frozenset({str(calls)}))
        return dataflow._Summary(returned=value)

    monkeypatch.setattr(dataflow._FunctionAnalyzer, "run", never_stable)

    result = analyze_python_file(target)

    _assert_failed_closed(result, "DFV2-FIXPOINT-LIMIT")


def test_target_outside_project_root_is_never_read(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = _write(
        tmp_path / "outside.py",
        "import os\ndef entry(command):\n    os.system(command)\n",
    )

    result = analyze_python_file(outside, project_root=project)

    _assert_failed_closed(result, "DFV2-TARGET-OUTSIDE-ROOT")
    assert result.files_analyzed == 0
    assert result.detections == ()


def test_file_and_directory_symlinks_are_not_followed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    evil = _write(
        outside / "evil.py",
        "import os\ndef entry(command):\n    os.system(command)\n",
    )
    linked_file = project / "linked.py"
    linked_directory = project / "linked-directory"
    try:
        linked_file.symlink_to(evil)
        linked_directory.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    result = analyze_project(project)

    _assert_failed_closed(result, "DFV2-LINK-REFUSED")
    assert result.files_analyzed == 0
    assert result.detections == ()


def test_symlink_root_is_refused(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    _write(real_root / "module.py", "answer = 42\n")
    linked_root = tmp_path / "linked-root"
    try:
        linked_root.symlink_to(real_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    result = analyze_project(linked_root)

    _assert_failed_closed(result, "DFV2-LINK-REFUSED")
    assert result.files_analyzed == 0


def test_windows_reparse_attribute_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    blocked = project / "blocked"
    _write(
        blocked / "evil.py",
        "import os\ndef entry(command):\n    os.system(command)\n",
    )
    real_lstat = os.lstat

    def marked_lstat(path: str) -> object:
        result = real_lstat(path)
        if Path(path) == blocked:
            return SimpleNamespace(
                st_mode=result.st_mode,
                st_size=result.st_size,
                st_dev=result.st_dev,
                st_ino=result.st_ino,
                st_file_attributes=0x400,
            )
        return result

    monkeypatch.setattr(dataflow.os, "lstat", marked_lstat)

    result = analyze_project(project)

    _assert_failed_closed(result, "DFV2-LINK-REFUSED")
    assert SinkKind.COMMAND not in {item.sink.kind for item in result.detections}


def test_negative_budget_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        AnalysisBudget(max_files=-1)
