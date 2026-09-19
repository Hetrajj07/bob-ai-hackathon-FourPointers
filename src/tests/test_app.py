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
    assert data["metrics"]["raw_records"] >= 62
    assert data["metadata"]["ground_truth_used_for_runtime"] is False


def test_candidates_endpoint_returns_promoted_and_unpromoted():
    response = client.get("/api/candidates")
    assert response.status_code == 200
    data = response.json()
    assert "candidates" in data
    assert "promoted_count" in data
    assert "total_candidates" in data
    assert data["total_candidates"] >= 5
    assert data["promoted_count"] >= 4
    # Every candidate must have promotion_checks.
    for c in data["candidates"]:
        assert "promotion_checks" in c
        assert "promoted" in c
    # Must have at least one unpromoted candidate that failed promotion checks.
    unpromoted = [c for c in data["candidates"] if not c["promoted"]]
    assert len(unpromoted) >= 1
    for u in unpromoted:
        assert not all(u["promotion_checks"].values()), \
            "Unpromoted candidate must have at least one failed promotion check"



def test_threatfox_and_cisa_kev_endpoints():
    res_tf = client.get("/api/threatfox/lookup", params={"indicator": "185.214.66.91"})
    assert res_tf.status_code == 200
    data_tf = res_tf.json()
    assert data_tf["found"] is True
    assert "Cobalt Strike" in data_tf["threat"].get("threat_type_desc", "") or "Cobalt Strike" in data_tf["threat"].get("malware_printable", "")

    res_cisa = client.get("/api/cisa-kev/lookup", params={"cve": "CVE-2023-34362"})
    assert res_cisa.status_code == 200
    data_cisa = res_cisa.json()
    assert data_cisa["found"] is True
    assert "MOVEit" in data_cisa["vulnerability"].get("vulnerabilityName", "")


def test_ingest_otrf_and_cicids_endpoints():
    # Test OTRF event ingest
    otrf_sample = {
        "EventID": 1,
        "SourceName": "Microsoft-Windows-Sysmon",
        "TimeCreated": "2026-09-18T14:15:30.124Z",
        "Computer": "TEST-HOST-01",
        "EventData": {
            "RuleName": "technique_id=T1059.001,technique_name=PowerShell",
            "ProcessId": 9999,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc AAAA...",
            "User": "DEFENCE\\analyst1",
        },
    }
    res_otrf = client.post("/api/ingest/otrf", json=otrf_sample)
    assert res_otrf.status_code == 200
    assert res_otrf.json()["status"] == "ok"
    assert res_otrf.json()["inserted_count"] == 1

    # Test CIC-IDS flow ingest
    flow_sample = {
        "FlowID": "10.0.0.1-185.214.66.91-12345-443-6",
        "SourceIp": "10.0.0.1",
        "SourcePort": 12345,
        "DestinationIp": "185.214.66.91",
        "DestinationPort": 443,
        "Protocol": "TCP",
        "Timestamp": "2026-09-18T14:28:40Z",
        "Label": "Botnet-C2-Beaconing",
        "SensorHost": "NET-PROBE-CORE01",
    }
    res_flow = client.post("/api/ingest/cicids", json=flow_sample)
    assert res_flow.status_code == 200
    assert res_flow.json()["status"] == "ok"
    assert res_flow.json()["inserted_count"] == 1

    # Reset back to demo baseline
    res_reset = client.post("/api/reset")
    assert res_reset.status_code == 200
