"""Unit tests for ThreatFusion SQLite persistence layer."""
from pathlib import Path
from src.threatfusion.db import (
    delete_asset,
    get_all_alerts,
    get_assets,
    get_incident,
    get_incidents,
    init_db,
    insert_alert,
    insert_alerts_bulk,
    query_alerts,
    reset_db,
    save_incidents,
    update_incident_triage,
    upsert_asset,
)

ROOT = Path(__file__).resolve().parents[2]


def test_db_init_and_seeding():
    # Use in-memory database for isolated test
    conn_target = init_db(db_path=":memory:", seed_if_empty=True, root_dir=ROOT)
    assert conn_target == ":memory:"


def test_db_crud_operations(tmp_path):
    test_db = tmp_path / "test_tf.db"
    init_db(db_path=test_db, seed_if_empty=True, root_dir=ROOT)

    # Verify seeded alerts count
    alerts = get_all_alerts(db_path=test_db)
    assert len(alerts) == 62

    # Verify seeded assets
    assets = get_assets(db_path=test_db)
    assert "ENG-DB01" in assets
    assert assets["ENG-DB01"]["criticality"] == 95

    # Insert single new alert
    new_alert = {
        "_id": "AL-TEST-999",
        "timestamp": "2026-09-18T10:00:00Z",
        "source": "endpoint",
        "event_type": "process_creation",
        "host": "ENG-DB01",
        "process": "powershell.exe",
        "detail": "Test alert execution",
    }
    inserted = insert_alert(new_alert, db_path=test_db)
    assert inserted["_id"] == "AL-TEST-999"

    alerts_after = get_all_alerts(db_path=test_db)
    assert len(alerts_after) == 63

    # Query with filters
    filtered, count = query_alerts(db_path=test_db, host="ENG-DB01")
    assert count >= 1
    assert any(a["_id"] == "AL-TEST-999" for a in filtered)

    # Bulk insert
    batch = [
        {"_id": f"BULK-{i}", "timestamp": "2026-09-18T11:00:00Z", "source": "siem", "text": f"Batch event {i}"}
        for i in range(5)
    ]
    bulk_count = insert_alerts_bulk(batch, db_path=test_db)
    assert bulk_count == 5
    assert len(get_all_alerts(db_path=test_db)) == 68

    # Upsert asset
    upserted = upsert_asset("NEW-SRV01", 88, "Mission control server", "core-infra", db_path=test_db)
    assert upserted["criticality"] == 88
    updated_assets = get_assets(db_path=test_db)
    assert "NEW-SRV01" in updated_assets
    assert updated_assets["NEW-SRV01"]["criticality"] == 88

    # Delete asset
    assert delete_asset("NEW-SRV01", db_path=test_db) is True
    assert "NEW-SRV01" not in get_assets(db_path=test_db)

    # Incidents save & triage
    mock_incidents = [
        {
            "id": "INC-TEST-001",
            "promotable": True,
            "priority": "P1",
            "priority_score": 90,
            "confidence": 85.0,
            "severity": 88,
            "mission_impact": 95,
            "urgency": 90,
            "record_ids": ["AL-TEST-999"],
            "techniques": [],
        }
    ]
    save_incidents(mock_incidents, db_path=test_db)
    inc_list = get_incidents(db_path=test_db, promotable_only=True)
    assert len(inc_list) == 1
    assert inc_list[0]["id"] == "INC-TEST-001"
    assert inc_list[0]["status"] == "open"

    # Update triage
    updated_inc = update_incident_triage(
        "INC-TEST-001", status="investigating", analyst_notes="Analyst investigating memory artifact.", db_path=test_db
    )
    assert updated_inc is not None
    assert updated_inc["status"] == "investigating"
    assert updated_inc["analyst_notes"] == "Analyst investigating memory artifact."

    # Resave incidents without losing status/notes
    save_incidents(mock_incidents, db_path=test_db)
    retrieved = get_incident("INC-TEST-001", db_path=test_db)
    assert retrieved["status"] == "investigating"
    assert retrieved["analyst_notes"] == "Analyst investigating memory artifact."

    # Reset DB
    reset_db(root_dir=ROOT, db_path=test_db)
    assert len(get_all_alerts(db_path=test_db)) == 62
