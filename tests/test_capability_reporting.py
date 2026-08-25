from __future__ import annotations

from clawlock.scanners.capabilities import analyze_capabilities
from clawlock.scanners.capability_reporting import findings_from_capabilities


def test_dataflow_finding_becomes_evidence_linked_capability_chain() -> None:
    finding = {
        "title": "secret reaches network",
        "location": "send.py:8",
        "metadata": {
            "component": "dataflow_v2",
            "rule_id": "DFV2-SECRET-NETWORK",
            "labels": ["secret", "environment"],
            "confidence_score": 0.95,
            "source": {"file": "read.py", "line": 3, "symbol": "API_TOKEN"},
            "sink": {"file": "send.py", "line": 8, "symbol": "requests.post", "kind": "network"},
            "evidence_path": [],
        },
    }

    rendered = findings_from_capabilities(
        analyze_capabilities(findings=[finding]), subject="demo"
    )

    exfil = next(item for item in rendered if item.metadata.get("rule_id") == "CAP-EXFIL-001")
    assert exfil.level == "critical"
    assert [event["location"] for event in exfil.metadata["evidence_path"]] == [
        "read.py",
        "send.py",
    ]
