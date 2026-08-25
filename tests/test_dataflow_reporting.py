from __future__ import annotations

from clawlock.scanners.dataflow import AnalysisDiagnostic, AnalysisResult, analyze_project
from clawlock.scanners.dataflow_reporting import findings_from_dataflow


def test_reporting_preserves_cross_file_evidence(tmp_path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "sink.py").write_text(
        "import os\ndef dispatch(value):\n    os.system(value)\n", encoding="utf-8"
    )
    (package / "entry.py").write_text(
        "from .sink import dispatch\ndef handle(request):\n    dispatch(request)\n",
        encoding="utf-8",
    )

    findings = findings_from_dataflow(
        analyze_project(tmp_path), scanner="test_dataflow", root=tmp_path
    )

    finding = next(
        item
        for item in findings
        if item.metadata.get("rule_id", "").startswith("DFV2-")
        and item.metadata["source"]["file"].replace("\\", "/").endswith(
            "pkg/entry.py"
        )
    )
    assert finding.level == "critical"
    assert finding.metadata["source"]["file"] == "pkg\\entry.py" or finding.metadata[
        "source"
    ]["file"] == "pkg/entry.py"
    assert finding.metadata["sink"]["file"].endswith("sink.py")
    assert len(finding.metadata["evidence_path"]) >= 3


def test_reporting_turns_incomplete_analysis_into_scan_error(tmp_path) -> None:
    result = AnalysisResult(
        complete=False,
        degraded=True,
        engine="none",
        diagnostics=(AnalysisDiagnostic("DFV2-GAP", "parser unavailable", "error"),),
    )

    findings = findings_from_dataflow(result, scanner="test", root=tmp_path)

    assert findings[-1].metadata["scan_status"] == "error"
    assert findings[-1].metadata["degraded"] is True
