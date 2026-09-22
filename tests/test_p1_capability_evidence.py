"""Evidence contract tests using inert text markers and synthetic flow events.

No inspected source is executed and no fixture performs external operations.
"""

from __future__ import annotations

import re

import pytest

import clawlock.scanners.capabilities as capabilities
from clawlock.scanners.capabilities import (
    Capability,
    CapabilityEvent,
    CapabilityGraph,
    EventRole,
    analyze_capabilities,
)
from clawlock.scanners.capability_reporting import findings_from_capabilities


@pytest.fixture
def fixture_markers(monkeypatch):
    """Map harmless markers to capabilities to test correlation independently."""
    monkeypatch.setattr(capabilities, "_READ_RE", re.compile(r"read_fixture\("))
    monkeypatch.setattr(capabilities, "_PRIVATE_PATH_RE", re.compile(r"read_fixture\("))
    monkeypatch.setattr(capabilities, "_NETWORK_RE", re.compile(r"record_fixture\("))
    monkeypatch.setattr(capabilities, "_OUTBOUND_RE", re.compile(r"record_fixture\("))


def _structured_finding(confidence=0.95):
    return {
        "title": "Synthetic flow evidence",
        "location": "fixture.py:2",
        "metadata": {
            "component": "dataflow_v2",
            "rule_id": "DFV2-FIXTURE",
            "labels": ["file"],
            "confidence_score": confidence,
            "source": {"file": "fixture.py", "line": 1, "symbol": "sample"},
            "sink": {"file": "fixture.py", "line": 2, "symbol": "record", "kind": "network"},
        },
    }


@pytest.mark.parametrize("language", ["", "python"])
def test_equal_local_names_do_not_connect_separate_functions(fixture_markers, language):
    analysis = analyze_capabilities(
        text=(
            "def summarize():\n"
            "    sample = read_fixture()\n"
            "    return sample\n"
            "def display(sample):\n"
            "    record_fixture(sample)\n"
        ),
        location="fixture.py",
        language=language,
    )
    assert analysis.graph.events_for(Capability.PRIVATE_READ)
    assert analysis.graph.events_for(Capability.EXTERNAL_WRITE)
    assert not analysis.graph.find_paths({Capability.PRIVATE_READ}, {Capability.EXTERNAL_WRITE})
    assert analysis.detections == ()


def test_module_provenance_survives_an_unrelated_function(fixture_markers):
    analysis = analyze_capabilities(
        text=(
            "sample = read_fixture()\n"
            "def display():\n"
            "    sample = 'public fixture'\n"
            "    return sample\n"
            "record_fixture(sample)\n"
        ),
        location="fixture.py",
    )
    assert len(analysis.detections) == 1
    assert [event.line for event in analysis.detections[0].evidence_path] == [1, 5]


def test_comments_and_docstrings_do_not_supply_flow_evidence(fixture_markers):
    analysis = analyze_capabilities(
        text=(
            '"""read_fixture() documentation"""\n'
            '# sample = read_fixture()\n'
            'note = "说明"; """read_fixture()"""\n'
            'def display(sample):\n'
            '    """sample = read_fixture()\n'
            '    This is documentation only.\n'
            '    """\n'
            '    record_fixture(sample)  # read_fixture()\n'
        ),
        location="fixture.py",
    )
    assert not analysis.graph.events_for(Capability.PRIVATE_READ)
    assert analysis.graph.events_for(Capability.EXTERNAL_WRITE)
    assert analysis.detections == ()


def test_text_association_remains_visible_as_review_evidence(fixture_markers):
    analysis = analyze_capabilities(
        text="sample = read_fixture()\nrecord_fixture(sample)\n",
        location="fixture.py",
    )
    detection, = analysis.detections
    assert detection.severity == "medium"
    assert detection.confidence <= 0.6
    assert detection.metadata["evidence_kind"] == "text-heuristic"
    assert detection.metadata["correlation_reasons"] == ["value:sample"]
    assert "unconfirmed" in detection.detail
    finding, = findings_from_capabilities(analysis, subject="fixture")
    assert finding.level == "medium"
    assert finding.metadata["confidence_score"] <= 0.6
    assert finding.metadata["evidence_kind"] == "text-heuristic"


def test_structured_evidence_wins_without_reducing_its_severity(fixture_markers):
    analysis = analyze_capabilities(
        text="sample = read_fixture()\nrecord_fixture(sample)\n",
        findings=[_structured_finding()],
        location="fixture.py",
    )
    detection, = analysis.detections
    assert detection.severity == "critical"
    assert detection.confidence == 0.95
    assert detection.metadata["evidence_kind"] == "structured-dataflow"
    assert detection.metadata["correlation_reasons"] == ["dataflow evidence path"]
    assert all(event.metadata["origin"] == "dataflow-finding" for event in detection.evidence_path)


@pytest.mark.parametrize("reverse", [False, True])
def test_same_line_structured_flows_keep_distinct_evidence_with_text(fixture_markers, reverse):
    first = _structured_finding(confidence=0.91)
    first["metadata"]["source"].update(symbol="first_sample", column=5)
    first["metadata"]["sink"].update(symbol="first_record", column=9)
    second = _structured_finding(confidence=0.97)
    second["metadata"]["source"].update(symbol="second_sample", column=23)
    second["metadata"]["sink"].update(symbol="second_record", column=31)
    findings = [second, first] if reverse else [first, second]

    analysis = analyze_capabilities(
        text="sample = read_fixture()\nrecord_fixture(sample)\n",
        findings=findings,
        location="fixture.py",
    )

    assert len(analysis.detections) == 2
    retained = {}
    for detection in analysis.detections:
        assert detection.severity == "critical"
        assert detection.metadata["evidence_kind"] == "structured-dataflow"
        assert detection.metadata["correlation_reasons"] == ["dataflow evidence path"]
        source, sink = detection.evidence_path
        retained[source.evidence] = (
            source.metadata["source"]["column"],
            sink.evidence,
            sink.metadata["sink"]["column"],
            detection.confidence,
        )
    assert retained == {
        "first_sample": (5, "first_record", 9, 0.91),
        "second_sample": (23, "second_record", 31, 0.97),
    }
    rendered = findings_from_capabilities(analysis, subject="fixture")
    assert len(rendered) == 2
    assert all(item.level == "critical" for item in rendered)
    assert {
        item.metadata["evidence_path"][0]["metadata"]["source"]["column"]
        for item in rendered
    } == {5, 23}


def test_explicit_event_graph_retains_strong_evidence():
    graph = CapabilityGraph()
    graph.add_event(CapabilityEvent(
        "source", Capability.PRIVATE_READ, EventRole.SOURCE,
        "fixture", 1, None, "synthetic source event", confidence=0.93,
    ))
    graph.add_event(CapabilityEvent(
        "sink", Capability.EXTERNAL_WRITE, EventRole.SINK,
        "fixture", 2, None, "synthetic sink event", confidence=0.96,
    ))
    graph.add_edge("source", "sink", "synthetic explicit value binding")
    detection, = graph.composite_detections()
    assert detection.severity == "critical"
    assert detection.confidence == 0.93
    assert detection.metadata["evidence_kind"] == "event-graph"


@pytest.mark.parametrize("characters, complete", [(16_384, True), (16_385, False)])
def test_long_line_budget_has_explicit_status(characters, complete):
    analysis = analyze_capabilities(text="#" + "x" * (characters - 1), location="fixture.py")
    assert analysis.graph.complete is complete
    findings = findings_from_capabilities(analysis, subject="fixture")
    if complete:
        assert analysis.graph.diagnostics == []
        assert findings == []
    else:
        assert "16384-character" in analysis.graph.diagnostics[0]
        assert "first line: 1" in analysis.graph.diagnostics[0]
        diagnostic, = findings
        assert diagnostic.scanner == "internal"
        assert diagnostic.metadata["scan_status"] == "error"


def test_truncated_scan_preserves_prefix_and_structured_evidence(fixture_markers):
    analysis = analyze_capabilities(
        text="sample = read_fixture() #" + "x" * 16_384 + "\nrecord_fixture(sample)\n",
        findings=[_structured_finding()],
        location="fixture.py",
    )
    assert analysis.graph.complete is False
    assert analysis.graph.events_for(Capability.PRIVATE_READ)
    detection, = analysis.detections
    assert detection.severity == "critical"
    assert detection.metadata["evidence_kind"] == "structured-dataflow"
