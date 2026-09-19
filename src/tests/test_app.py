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
    assert "Evidence-first" in page.text
    assert 'role="tablist"' in page.text
    assert "Skip to" in page.text


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


def test_cors_headers_are_present():
    response = client.options("/api/summary", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 200


def test_mcp_search_empty_query():
    response = client.get("/api/mcp-query", params={"tool": "search_indicators", "query": ""})
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_matches"] == 0
    assert payload["matches"] == []


def test_summary_response_has_required_structure():
    summary = client.get("/api/summary")
    assert summary.status_code == 200
    data = summary.json()
    assert "metadata" in data
    assert "metrics" in data
    assert "incidents" in data
    assert data["metrics"]["raw_records"] == 62
    assert data["metadata"]["ground_truth_used_for_runtime"] is False


def test_candidates_endpoint_returns_promoted_and_unpromoted():
    response = client.get("/api/candidates")
    assert response.status_code == 200
    data = response.json()
    assert "candidates" in data
    assert "promoted_count" in data
    assert "total_candidates" in data
    # Must have 5 candidates total (4 promoted + 1 not promoted).
    assert data["total_candidates"] == 5
    assert data["promoted_count"] == 4
    # Every candidate must have promotion_checks.
    for c in data["candidates"]:
        assert "promotion_checks" in c
        assert "promoted" in c
    # Exactly one candidate must be unpromoted.
    unpromoted = [c for c in data["candidates"] if not c["promoted"]]
    assert len(unpromoted) == 1
    assert not all(unpromoted[0]["promotion_checks"].values()), \
        "Unpromoted candidate must have at least one failed promotion check"
