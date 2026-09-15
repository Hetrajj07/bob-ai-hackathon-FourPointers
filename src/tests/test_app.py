"""End-to-end contract checks for the analyst workspace API and document shell."""
from fastapi.testclient import TestClient

from src.app import app


client = TestClient(app)


def test_health_and_workspace_shell_are_available():
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    page = client.get("/")
    assert page.status_code == 200
    assert "Evidence-first investigation workspace" in page.text
    assert 'role="tablist"' in page.text
    assert "Skip to investigation workspace" in page.text


def test_promoted_case_has_grounded_evidence_and_all_mcp_previews_work():
    summary = client.get("/api/summary")
    assert summary.status_code == 200
    case = summary.json()["incidents"][0]
    assert case["promotion_checks"]
    assert all(case["promotion_checks"].values())

    detail = client.get(f"/api/incidents/{case['id']}")
    assert detail.status_code == 200
    evidence = detail.json()["evidence"]
    assert evidence and all(item["record_id"] for item in evidence)

    for tool in ("correlate_events", "get_incident", "explain_risk", "generate_bluf", "get_remediation_runbook", "get_detection_gaps", "search_indicators"):
        response = client.get("/api/mcp-query", params={"tool": tool, "incident_id": case["id"], "query": "asset context"})
        assert response.status_code == 200, tool
        payload = response.json()
        assert "error" not in payload or "Unknown tool" not in payload.get("error", ""), f"Tool '{tool}' returned an error: {payload}"


def test_unknown_incident_returns_a_clear_not_found_response():
    response = client.get("/api/incidents/INC-DOES-NOT-EXIST")
    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"
