from pathlib import Path
from textwrap import dedent

from clawlock.scanners.dataflow import (
    AnalysisResult,
    JavaScriptParseResult,
    SinkKind,
    analyze_javascript_file,
    analyze_project,
    analyze_python_file,
)


def write(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source), encoding="utf-8")
    return path


def sinks(result: AnalysisResult) -> set[SinkKind]:
    return {item.sink.kind for item in result.detections}


def test_direct_tool_parameter_has_precise_evidence(tmp_path: Path) -> None:
    target = write(
        tmp_path / "tool.py",
        """
        import os

        @mcp.tool()
        def shell(command):
            os.system(command)
        """,
    )

    result = analyze_python_file(target)

    finding = next(item for item in result.detections if item.sink.kind == SinkKind.COMMAND)
    assert finding.source.kind == "tool-parameter"
    assert finding.source.span.file == str(target.resolve())
    assert finding.source.span.line == 5
    assert finding.sink.span.line == 6
    assert [step.kind for step in finding.path.steps][0] == "source"
    assert [step.kind for step in finding.path.steps][-1] == "sink"
    assert finding.path.labels
    assert finding.path.confidence.value == "high"


def test_import_alias_kwargs_and_return_propagation(tmp_path: Path) -> None:
    target = write(
        tmp_path / "aliasing.py",
        """
        from subprocess import run as launch

        def identity(value):
            return value

        def entry(payload):
            command = identity(payload)
            launch(args=command, shell=True)
        """,
    )

    result = analyze_python_file(target)

    finding = next(item for item in result.detections if item.sink.kind == SinkKind.COMMAND)
    assert finding.sink.symbol == "subprocess.run"
    assert any(step.kind == "call" and step.symbol.endswith("identity") for step in finding.path.steps)


def test_two_wrappers_and_receiver_method_fixed_point(tmp_path: Path) -> None:
    target = write(
        tmp_path / "wrappers.py",
        """
        import os

        class Runner:
            def execute(self, value):
                os.system(value)

        def _second(runner, data):
            runner.execute(data)

        def _first(runner, data):
            _second(runner, data)

        def entry(user_input):
            runner = Runner()
            _first(runner, user_input)
        """,
    )

    result = analyze_python_file(target)

    finding = next(item for item in result.detections if item.sink.kind == SinkKind.COMMAND)
    calls = [step.symbol for step in finding.path.steps if step.kind == "call"]
    assert any(symbol.endswith("._first") for symbol in calls)
    assert any(symbol.endswith("._second") for symbol in calls)
    assert any(symbol.endswith(".Runner.execute") for symbol in calls)


def test_relative_import_cross_file_one_to_many(tmp_path: Path) -> None:
    write(tmp_path / "pkg" / "__init__.py", "")
    write(
        tmp_path / "pkg" / "helpers.py",
        """
        import os
        def _dispatch(value):
            os.system(value)
        """,
    )
    write(
        tmp_path / "pkg" / "first.py",
        """
        from .helpers import _dispatch as send
        def first(command):
            send(command)
        """,
    )
    write(
        tmp_path / "pkg" / "second.py",
        """
        from .helpers import _dispatch
        def second(payload):
            _dispatch(payload)
        """,
    )

    result = analyze_project(tmp_path)

    commands = [item for item in result.detections if item.sink.kind == SinkKind.COMMAND]
    assert {Path(item.source.span.file).name for item in commands} == {"first.py", "second.py"}
    assert len({item.source.source_id for item in commands}) == 2


def test_attributes_subscripts_and_containers_propagate(tmp_path: Path) -> None:
    target = write(
        tmp_path / "containers.py",
        """
        import os
        class Box:
            pass

        def entry(payload):
            record = {"nested": [payload]}
            box = Box()
            box.command = record["nested"]
            os.system(box.command)
        """,
    )

    assert SinkKind.COMMAND in sinks(analyze_python_file(target))


def test_reassignment_kills_taint(tmp_path: Path) -> None:
    target = write(
        tmp_path / "kill.py",
        """
        import os
        def entry(command):
            command = "status"
            os.system(command)
        """,
    )

    assert SinkKind.COMMAND not in sinks(analyze_python_file(target))


def test_env_secret_and_file_sources_reach_sinks(tmp_path: Path) -> None:
    target = write(
        tmp_path / "sources.py",
        """
        import os
        import requests
        from pathlib import Path

        def publish():
            api_token = os.getenv("SERVICE_API_TOKEN")
            requests.post("https://example.invalid", data=api_token)

        def evaluate(path):
            text = Path(path).read_text()
            eval(text)
        """,
    )

    result = analyze_python_file(target)

    network = next(item for item in result.detections if item.sink.kind == SinkKind.NETWORK)
    assert {label.value for label in network.labels} >= {"environment", "secret"}
    assert any(item.sink.kind == SinkKind.CODE_EXECUTION and item.source.kind == "file" for item in result.detections)


def test_prompt_memory_log_and_tool_output_sinks(tmp_path: Path) -> None:
    target = write(
        tmp_path / "agent.py",
        """
        @mcp.tool()
        def assistant(prompt):
            logger.info(prompt)
            memory.append(prompt)
            llm.invoke(prompt)
            return prompt
        """,
    )

    found = sinks(analyze_python_file(target))

    assert {SinkKind.PROMPT, SinkKind.MEMORY, SinkKind.LOG, SinkKind.TOOL_OUTPUT} <= found


def test_structural_guards_work_and_resolve_alone_is_not_a_guard(tmp_path: Path) -> None:
    target = write(
        tmp_path / "guards.py",
        """
        import os
        from pathlib import Path

        def unsafe(path):
            resolved = Path(path).resolve()
            resolved.write_text("x")

        def safe_path(path):
            root = Path("/srv/uploads").resolve()
            checked = (root / path).resolve()
            if not checked.is_relative_to(root):
                raise ValueError("outside root")
            checked.write_text("x")

        def safe_command(command):
            if command not in {"status", "version"}:
                raise ValueError("denied")
            os.system(command)

        """,
    )

    result = analyze_python_file(target)
    file_writes = [item for item in result.detections if item.sink.kind == SinkKind.FILE_WRITE]

    assert len(file_writes) == 1
    assert file_writes[0].source.span.line == 5
    assert SinkKind.COMMAND not in sinks(result)


def test_user_defined_name_only_sanitizers_and_guards_do_not_remove_taint(
    tmp_path: Path,
) -> None:
    target = write(
        tmp_path / "fake_guards.py",
        """
        import os
        import requests
        from pathlib import Path

        def validate_command(value):
            return value

        def is_safe_url(value):
            return True

        def validate_path(value):
            return value

        def run(command, url, path):
            os.system(validate_command(command))
            if is_safe_url(url):
                requests.get(url)
            Path(validate_path(path)).write_text("x")
        """,
    )

    assert {
        SinkKind.COMMAND,
        SinkKind.NETWORK,
        SinkKind.FILE_WRITE,
    } <= sinks(analyze_python_file(target))


def test_module_top_level_source_reaches_sink(tmp_path: Path) -> None:
    target = write(
        tmp_path / "top_level.py",
        """
        import os

        command = input("command: ")
        os.system(command)
        """,
    )

    result = analyze_python_file(target)

    finding = next(item for item in result.detections if item.sink.kind == SinkKind.COMMAND)
    assert finding.source.kind == "request"
    assert finding.source.span.line == 4
    assert finding.sink.span.line == 5


def test_metamorphic_rename_and_irrelevant_assignment_keep_detection(tmp_path: Path) -> None:
    first = write(
        tmp_path / "first.py",
        """
        import os
        def execute(payload):
            os.system(payload)
        """,
    )
    second = write(
        tmp_path / "second.py",
        """
        import os
        def execute(renamed):
            harmless = 42
            os.system(renamed)
        """,
    )

    left = analyze_python_file(first)
    right = analyze_python_file(second)

    assert [(item.sink.kind, item.confidence) for item in left.detections] == [
        (item.sink.kind, item.confidence) for item in right.detections
    ]


def test_js_without_parser_is_explicitly_degraded(tmp_path: Path) -> None:
    target = write(tmp_path / "tool.ts", "export function tool(x: string) { return eval(x); }")

    result = analyze_javascript_file(target)

    assert result.degraded is True
    assert result.complete is False
    assert result.engine == "none"
    assert result.detections == ()
    assert result.diagnostics[0].code == "DFV2-JS-PARSER-UNAVAILABLE"


def test_optional_js_parser_contract(tmp_path: Path) -> None:
    target = write(tmp_path / "safe.js", "export const answer = 42")

    class Parser:
        def analyze(self, path: Path, source: str) -> JavaScriptParseResult:
            assert path == target
            assert "answer" in source
            return JavaScriptParseResult(engine="tree-sitter-test")

    result = analyze_javascript_file(target, parser=Parser())

    assert result.complete is True
    assert result.degraded is False
    assert result.engine == "tree-sitter-test"
