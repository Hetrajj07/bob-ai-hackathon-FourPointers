"""Integration tests for ThreatFusion dynamic backend API endpoints."""
from fastapi.testclient import TestClient
from src.app import app

client = TestClient(app)


def test_list_alerts_and_pagination():
    res = client.get("/api/alerts?limit=10&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert "total" in data
    assert len(data["alerts"]) <= 10
    assert data["total"] >= 62


def test_asset_crud_endpoints():
    # List assets
    list_res = client.get("/api/assets")
    assert list_res.status_code == 200
    assets = list_res.json()["assets"]
    assert "ENG-DB01" in assets

    # Create/Update asset
    upsert_res = client.post(
        "/api/assets",
        json={
            "host": "SAT-TEST-99",
            "criticality": 94,
            "mission_role": "Satellite ground uplink terminal",
            "zone": "mission-critical",
        },
    )
    assert upsert_res.status_code == 200
    assert upsert_res.json()["status"] == "ok"

    # Verify update
    check_res = client.get("/api/assets")
    assert "SAT-TEST-99" in check_res.json()["assets"]
    assert check_res.json()["assets"]["SAT-TEST-99"]["criticality"] == 94

    # Delete asset
    del_res = client.delete("/api/assets/SAT-TEST-99")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True


def test_dynamic_alert_ingestion_and_recorrelation():
    # Ingest a single alert
    new_alert = {
        "_id": "AL-DYN-001",
        "timestamp": "2026-09-19T10:15:00Z",
        "source": "satellite_sensor",
        "event_type": "downlink_telemetry_anomaly",
        "host": "SATCOM-GW02",
        "detail": "SATCOM ground terminal downlink telemetry anomaly",
    }
    ingest_res = client.post("/api/alerts", json=new_alert)
    assert ingest_res.status_code == 200
    data = ingest_res.json()
    assert data["status"] == "ok"
    assert data["total_alerts"] >= 63

    # Recorrelate
    recorr_res = client.post("/api/recorrelate")
    assert recorr_res.status_code == 200
    assert recorr_res.json()["status"] == "ok"


def test_bulk_alert_ingestion():
    batch = [
        {
            "_id": f"AL-BULK-{i}",
            "timestamp": "2026-09-19T10:20:00Z",
            "source": "network_sensor",
            "detail": f"Network telemetry probe {i}",
        }
        for i in range(3)
    ]
    res = client.post("/api/alerts/bulk", json=batch)
    assert res.status_code == 200
    assert res.json()["inserted_count"] == 3


def test_incident_triage_patch():
    # Fetch first incident ID
    summary_res = client.get("/api/summary")
    inc_id = summary_res.json()["incidents"][0]["id"]

    # Patch triage status & notes
    patch_res = client.patch(
        f"/api/incidents/{inc_id}",
        json={"status": "investigating", "analyst_notes": "Ground station telemetry under review."},
    )
    assert patch_res.status_code == 200
    updated = patch_res.json()["incident"]
    assert updated["status"] == "investigating"
    assert updated["analyst_notes"] == "Ground station telemetry under review."

    # Verify persistent retrieval
    get_res = client.get(f"/api/incidents/{inc_id}")
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "investigating"
    assert get_res.json()["analyst_notes"] == "Ground station telemetry under review."


def test_simulate_feed_and_reset():
    # Simulate satellite breach
    sat_res = client.post("/api/simulate-feed", json={"scenario": "satellite_ground_breach"})
    assert sat_res.status_code == 200
    assert sat_res.json()["status"] == "ok"
    assert sat_res.json()["inserted_records"] == 3

    # Reset demo baseline
    reset_res = client.post("/api/reset")
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "ok"
    assert reset_res.json()["raw_records"] == 62
    assert reset_res.json()["promoted_incidents"] == 4


def test_bob_ask_endpoint():
    summary = client.get("/api/summary").json()
    inc_id = summary["incidents"][0]["id"]

    for cmd in ("investigate", "explain", "bluf", "runbook", "gaps", "What is the priority score?"):
        res = client.post("/api/bob/ask", json={"incident_id": inc_id, "command": cmd})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["incident_id"] == inc_id
        assert len(data["response"]) > 20

