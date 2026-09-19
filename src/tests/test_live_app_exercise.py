"""Exercise all endpoints and MCP tools against the live FastAPI application."""
from __future__ import annotations

import json
from pathlib import Path
from fastapi.testclient import TestClient

from src.app import app

client = TestClient(app)
ROOT = Path(__file__).resolve().parents[2]


def test_full_application_exercise():
    # 1. Default demo
    res = client.get("/api/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["metrics"]["raw_records"] == 62
    assert len(data["incidents"]) == 4

    # 2. OTRF Ingestion
    with (ROOT / "src" / "data" / "real" / "otrf_sample.json").open(encoding="utf-8") as f:
        otrf_records = json.load(f)
    res_otrf = client.post("/api/ingest/otrf", json=otrf_records[:2])
    assert res_otrf.status_code == 200
    assert res_otrf.json()["status"] == "ok"
    assert res_otrf.json()["inserted_count"] == 2

    # 3. CIC-IDS Ingestion
    with (ROOT / "src" / "data" / "real" / "cicids_sample.json").open(encoding="utf-8") as f:
        cic_records = json.load(f)
    res_cic = client.post("/api/ingest/cicids", json=cic_records[:2])
    assert res_cic.status_code == 200
    assert res_cic.json()["status"] == "ok"
    assert res_cic.json()["inserted_count"] == 2

    # 4. Satellite / SPARTA simulation feed
    res_sat = client.post("/api/simulate-feed", json={"scenario": "sparta_satellite_compromise"})
    assert res_sat.status_code == 200
    assert res_sat.json()["status"] == "ok"
    assert res_sat.json()["inserted_records"] >= 3

    # 5. ThreatFox Lookup
    res_tf = client.get("/api/threatfox/lookup", params={"indicator": "185.214.66.91"})
    assert res_tf.status_code == 200
    assert res_tf.json()["found"] is True

    # 6. CISA KEV Lookup
    res_kev = client.get("/api/cisa-kev/lookup", params={"cve": "CVE-2023-34362"})
    assert res_kev.status_code == 200
    assert res_kev.json()["found"] is True

    # 7. Custom observation ingestion
    custom_alert = {
        "_id": "CUSTOM-OBS-9999",
        "timestamp": "2026-09-18T16:00:00Z",
        "source": "satellite_sensor",
        "host": "SAT-GROUND-01",
        "event_type": "downlink_rf_anomaly",
        "detail": "High-altitude downlink carrier jamming detected on tactical S-band link.",
    }
    res_custom = client.post("/api/alerts", json=custom_alert)
    assert res_custom.status_code == 200
    assert res_custom.json()["status"] == "ok"

    # 8. MCP Tools exercise
    incident_id = data["incidents"][0]["id"]
    mcp_tools = [
        ("correlate_events", {}),
        ("get_incident", {"incident_id": incident_id}),
        ("explain_risk", {"incident_id": incident_id}),
        ("generate_bluf", {"incident_id": incident_id}),
        ("get_remediation_runbook", {"incident_id": incident_id}),
        ("get_detection_gaps", {"incident_id": incident_id}),
        ("search_indicators", {"query": "ENG-DB01"}),
    ]
    for tool_name, params in mcp_tools:
        mcp_res = client.get("/api/mcp-query", params={"tool": tool_name, **params})
        assert mcp_res.status_code == 200
        resp_data = mcp_res.json()
        assert "error" not in resp_data or "Unknown tool" not in resp_data.get("error", "")

    # 9. Reset Demo back to baseline
    res_reset = client.post("/api/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["raw_records"] == 62
