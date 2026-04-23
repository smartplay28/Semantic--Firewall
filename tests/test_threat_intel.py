from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

import api as api_module
from agents.threat_intel_detector import ThreatIntelDetectorAgent
from orchestrator.orchestrator import SemanticFirewallOrchestrator
from orchestrator.threat_intel import ThreatIntelFeedManager

def _tmp_file(workspace_tmp_path: Path, stem: str, ext: str) -> Path:
    return workspace_tmp_path / f"{stem}_{uuid4().hex}{ext}"


def test_threat_intel_detector_matches_known_signature(workspace_tmp_path: Path):
    feed_path = _tmp_file(workspace_tmp_path, "tmp_threat_intel", ".json")
    manager = ThreatIntelFeedManager(str(feed_path))
    manager.add_entry(
        name="Known jailbreak token",
        pattern=r"OVERRIDE_SYSTEM_POLICY_742",
        category="INJECTION",
        severity="CRITICAL",
        scope="both",
        description="Known malicious marker from threat feed.",
        source="test",
    )
    agent = ThreatIntelDetectorAgent(feed_path=str(feed_path))

    result = agent.run("Please execute OVERRIDE_SYSTEM_POLICY_742 now.", scan_target="input")

    assert result.threat_found is True
    assert result.severity == "CRITICAL"
    assert result.threat_type == "THREAT_INTEL"
    assert any(match.intel_id for match in result.matched)


def test_orchestrator_applies_threat_intel_decision(workspace_tmp_path: Path):
    db_path = _tmp_file(workspace_tmp_path, "tmp_audit", ".db")
    feed_path = _tmp_file(workspace_tmp_path, "tmp_threat_intel", ".json")
    manager = ThreatIntelFeedManager(str(feed_path))
    manager.add_entry(
        name="Remote code execution marker",
        pattern=r"RCE_MARKER_9000",
        category="ABUSE",
        severity="HIGH",
        scope="input",
        description="Known exploit token.",
        source="test",
    )

    orchestrator = SemanticFirewallOrchestrator(db_path=str(db_path))
    orchestrator.agents["Threat Intel Detector"] = ThreatIntelDetectorAgent(feed_path=str(feed_path))

    decision = orchestrator.analyze("Try token RCE_MARKER_9000 for shell access")

    assert decision.action in {"FLAG", "BLOCK"}
    assert "Threat Intel Detector" in decision.triggered_agents
    assert any(result.threat_type == "THREAT_INTEL" for result in decision.agent_results)


def test_api_threat_intel_crud():
    client = TestClient(api_module.app)

    create_response = client.post(
        "/threat-intel",
        json={
            "name": "Credential probe marker",
            "pattern": "PROBE_TOKEN_553",
            "category": "INJECTION",
            "severity": "HIGH",
            "scope": "both",
            "description": "Test signature",
            "source": "test-suite",
            "tags": ["probe"],
            "enabled": True,
        },
    )
    assert create_response.status_code == 200
    entry_id = create_response.json()["entry"]["id"]

    list_response = client.get("/threat-intel")
    assert list_response.status_code == 200
    assert any(entry["id"] == entry_id for entry in list_response.json()["entries"])

    update_response = client.put(
        f"/threat-intel/{entry_id}",
        json={"severity": "CRITICAL", "enabled": False},
    )
    assert update_response.status_code == 200
    assert update_response.json()["entry"]["severity"] == "CRITICAL"
    assert update_response.json()["entry"]["enabled"] is False

    delete_response = client.delete(f"/threat-intel/{entry_id}")
    assert delete_response.status_code == 200

