"""Unit tests for the new REST API routes (Search, Ingestion, Bob Ask, Simulation, Techniques)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient
from src.app import app

client = TestClient(app)


def test_api_incidents_list():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 4
    for inc in data:
        assert "id" in inc
        assert "priority" in inc
        assert "human_title" in inc


def test_api_rag_techniques_search():
    res = client.get("/api/rag/techniques", params={"query": "credential dumping"})
    assert res.status_code == 200
    data = res.json()
    assert "matches" in data
    assert len(data["matches"]) > 0
    assert any("T1003" in m["technique_id"] for m in data["matches"])


def test_api_bob_ask():
    # First get an incident ID
    summary = client.get("/api/summary").json()
    iid = summary["incidents"][0]["id"]

    res = client.post("/api/bob/ask", json={"incident_id": iid, "prompt": "Why is this case high priority?"})
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert "P1" in data["answer"] or "Priority" in data["answer"]


def test_api_search():
    # Test keyword search
    res = client.post("/api/search", json={"query": "powershell"})
    assert res.status_code == 200
    data = res.json()
    assert data["count"] > 0
    assert len(data["results"]) > 0

    # Test IP search
    res_ip = client.post("/api/search", json={"query": "185.214.66.91"})
    assert res_ip.status_code == 200
    assert res_ip.json()["count"] > 0


def test_api_demo_simulation():
    res = client.get("/api/demo/simulation")
    assert res.status_code == 200
    data = res.json()
    assert "steps" in data
    assert len(data["steps"]) == 7
    assert data["steps"][0]["step"] == 1
    assert data["steps"][-1]["step"] == 7


def test_api_events_ingestion_and_reset():
    # Test valid ingestion
    custom_records = [
        {
            "_id": "TEST-NEW-99",
            "timestamp": "2026-09-18T14:00:00Z",
            "source": "siem",
            "host": "TEST-WKS",
            "user": "testuser",
            "detail": "test alert event",
        }
    ]
    res = client.post("/api/events", json={"records": custom_records})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["ingested_count"] == 1

    # Test invalid ingestion (missing timestamp)
    bad_res = client.post("/api/events", json={"records": [{"_id": "NO-TIME"}]})
    assert bad_res.status_code == 422

    # Reset back to baseline
    reset_res = client.post("/api/analyze")
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "reset_to_baseline"
