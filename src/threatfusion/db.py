"""ThreatFusion SQLite persistence layer.

Provides relational storage for alerts, asset context, candidate hypotheses,
promoted incidents, analyst triage state, and audit logs.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = ROOT_DIR / "src" / "data" / "threatfusion.db"


def get_db_path(custom_path: Path | str | None = None) -> Path:
    if custom_path is not None:
        return Path(custom_path) if isinstance(custom_path, str) and custom_path != ":memory:" else custom_path
    return DEFAULT_DB_PATH


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    target = get_db_path(db_path)
    if target == ":memory:":
        conn = sqlite3.connect(":memory:")
    else:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(
    db_path: Path | str | None = None,
    seed_if_empty: bool = True,
    root_dir: Path | None = None,
) -> Path | str:
    """Initialize SQLite schema and optionally seed baseline demo data."""
    target = get_db_path(db_path)
    root = root_dir or ROOT_DIR
    conn = get_connection(target)

    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT,
                host TEXT,
                user TEXT,
                ip TEXT,
                raw_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
            CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);

            CREATE TABLE IF NOT EXISTS assets (
                host TEXT PRIMARY KEY,
                criticality INTEGER NOT NULL,
                mission_role TEXT,
                zone TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'open',
                analyst_notes TEXT DEFAULT '',
                promotable INTEGER NOT NULL,
                priority TEXT NOT NULL,
                priority_score INTEGER NOT NULL,
                confidence REAL NOT NULL,
                severity INTEGER NOT NULL,
                mission_impact INTEGER NOT NULL,
                urgency INTEGER NOT NULL,
                details_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT
            );
            """
        )

    if seed_if_empty:
        cursor = conn.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        if count == 0:
            seed_from_files(conn, root)

    conn.close()
    return target


def seed_from_files(conn: sqlite3.Connection, root: Path) -> None:
    """Seed alerts and assets from demo JSON files into the database."""
    data_dir = root / "src" / "data"
    alerts_file = data_dir / "demo_alerts.json"
    assets_file = data_dir / "assets.json"

    now_iso = datetime.now(timezone.utc).isoformat()

    if alerts_file.exists():
        with alerts_file.open(encoding="utf-8") as f:
            records = json.load(f)
        for r in records:
            _insert_alert_record(conn, r, now_iso)

    if assets_file.exists():
        with assets_file.open(encoding="utf-8") as f:
            assets = json.load(f)
        for host, meta in assets.items():
            conn.execute(
                """
                INSERT OR REPLACE INTO assets (host, criticality, mission_role, zone, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    host.strip().upper(),
                    int(meta.get("criticality", 50)),
                    meta.get("mission_role", "Standard system"),
                    meta.get("zone", "corporate"),
                    now_iso,
                ),
            )

    conn.execute(
        "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
        (now_iso, "seed_demo_data", f"Seeded demo data from {data_dir}"),
    )
    conn.commit()


def _extract_primary_fields(r: dict[str, Any]) -> tuple[str, str, str, str | None, str | None, str | None, str]:
    record_id = str(r.get("_id") or r.get("id"))
    ts = str(r.get("timestamp"))
    source = str(r.get("source", "unknown"))
    event_type = str(r.get("event_type")) if r.get("event_type") else None

    # Determine primary host/user/ip for quick indexing
    host = str(r.get("host") or r.get("src_host") or r.get("dst_host") or "").strip().upper() or None
    user = str(r.get("user") or "").strip().lower() or None
    ip = str(r.get("ip") or r.get("src_ip") or r.get("dst_ip") or "").strip() or None

    # Ensure _id is consistently populated in the raw dict
    raw = dict(r)
    if "_id" not in raw:
        raw["_id"] = record_id

    return record_id, ts, source, event_type, host, user, ip


def _insert_alert_record(conn: sqlite3.Connection, r: dict[str, Any], created_at: str) -> None:
    rid, ts, src, et, host, user, ip = _extract_primary_fields(r)
    raw = dict(r)
    raw["_id"] = rid
    conn.execute(
        """
        INSERT OR REPLACE INTO alerts (id, timestamp, source, event_type, host, user, ip, raw_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (rid, ts, src, et, host, user, ip, json.dumps(raw, ensure_ascii=False), created_at),
    )


def insert_alert(alert_dict: dict[str, Any], db_path: Path | str | None = None) -> dict[str, Any]:
    """Validate and insert a single alert record into the database."""
    rid = str(alert_dict.get("_id") or alert_dict.get("id") or "")
    if not rid:
        # Generate an alert id if missing
        rid = f"AL-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
        alert_dict["_id"] = rid

    if "timestamp" not in alert_dict:
        alert_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    if "source" not in alert_dict:
        alert_dict["source"] = "manual_ingest"

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        _insert_alert_record(conn, alert_dict, now_iso)
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (now_iso, "insert_alert", f"Alert {rid} inserted from source {alert_dict.get('source')}"),
        )
    conn.close()
    return alert_dict


def insert_alerts_bulk(alert_list: list[dict[str, Any]], db_path: Path | str | None = None) -> int:
    """Insert a batch of alerts in a single database transaction."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    inserted = 0
    with conn:
        for alert_dict in alert_list:
            rid = str(alert_dict.get("_id") or alert_dict.get("id") or "")
            if not rid:
                rid = f"AL-{int(datetime.now(timezone.utc).timestamp() * 1000)}-{inserted}"
                alert_dict["_id"] = rid
            if "timestamp" not in alert_dict:
                alert_dict["timestamp"] = now_iso
            _insert_alert_record(conn, alert_dict, now_iso)
            inserted += 1
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (now_iso, "bulk_insert_alerts", f"Inserted batch of {inserted} alerts"),
        )
    conn.close()
    return inserted


def get_all_alerts(db_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Retrieve all raw alert dictionaries, sorted by timestamp ascending."""
    conn = get_connection(db_path)
    cursor = conn.execute("SELECT raw_json FROM alerts ORDER BY timestamp ASC")
    results = [json.loads(row["raw_json"]) for row in cursor.fetchall()]
    conn.close()
    return results


def query_alerts(
    db_path: Path | str | None = None,
    limit: int = 50,
    offset: int = 0,
    source: str | None = None,
    host: str | None = None,
    search: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Query paginated alerts with filtering."""
    conn = get_connection(db_path)
    clauses = []
    params: list[Any] = []

    if source:
        clauses.append("source = ?")
        params.append(source)
    if host:
        clauses.append("host = ?")
        params.append(host.upper())
    if search:
        clauses.append("raw_json LIKE ?")
        params.append(f"%{search}%")

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    count_cur = conn.execute(f"SELECT COUNT(*) FROM alerts {where_sql}", params)
    total_count = count_cur.fetchone()[0]

    query_sql = f"SELECT raw_json FROM alerts {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    rows_cur = conn.execute(query_sql, params + [limit, offset])
    alerts = [json.loads(row["raw_json"]) for row in rows_cur.fetchall()]

    conn.close()
    return alerts, total_count


def get_assets(db_path: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Retrieve all registered assets mapped by uppercase hostname."""
    conn = get_connection(db_path)
    cursor = conn.execute("SELECT host, criticality, mission_role, zone FROM assets")
    out = {}
    for row in cursor.fetchall():
        out[row["host"]] = {
            "criticality": row["criticality"],
            "mission_role": row["mission_role"],
            "zone": row["zone"],
        }
    conn.close()
    return out


def upsert_asset(
    host: str,
    criticality: int,
    mission_role: str = "Standard system",
    zone: str = "corporate",
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Create or update an asset definition."""
    clean_host = host.strip().upper()
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            INSERT INTO assets (host, criticality, mission_role, zone, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                criticality = excluded.criticality,
                mission_role = excluded.mission_role,
                zone = excluded.zone,
                updated_at = excluded.updated_at
            """,
            (clean_host, int(criticality), mission_role, zone, now_iso),
        )
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (now_iso, "upsert_asset", f"Asset {clean_host} updated (criticality: {criticality})"),
        )
    conn.close()
    return {"host": clean_host, "criticality": criticality, "mission_role": mission_role, "zone": zone}


def delete_asset(host: str, db_path: Path | str | None = None) -> bool:
    """Delete an asset from the asset inventory."""
    clean_host = host.strip().upper()
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        cur = conn.execute("DELETE FROM assets WHERE host = ?", (clean_host,))
        deleted = cur.rowcount > 0
        if deleted:
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
                (now_iso, "delete_asset", f"Asset {clean_host} deleted"),
            )
    conn.close()
    return deleted


def save_incidents(incidents: list[dict[str, Any]], db_path: Path | str | None = None) -> None:
    """Save computed incidents while preserving analyst status and notes."""
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        for inc in incidents:
            iid = inc["id"]
            cur = conn.execute("SELECT status, analyst_notes FROM incidents WHERE id = ?", (iid,))
            existing = cur.fetchone()
            status = existing["status"] if existing else "open"
            notes = existing["analyst_notes"] if existing else ""

            # Inject stored triage state into details json for persistence
            enriched = dict(inc)
            enriched["status"] = status
            enriched["analyst_notes"] = notes

            conn.execute(
                """
                INSERT INTO incidents (
                    id, status, analyst_notes, promotable, priority, priority_score,
                    confidence, severity, mission_impact, urgency, details_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    promotable = excluded.promotable,
                    priority = excluded.priority,
                    priority_score = excluded.priority_score,
                    confidence = excluded.confidence,
                    severity = excluded.severity,
                    mission_impact = excluded.mission_impact,
                    urgency = excluded.urgency,
                    details_json = excluded.details_json,
                    updated_at = excluded.updated_at
                """,
                (
                    iid,
                    status,
                    notes,
                    1 if inc.get("promotable") else 0,
                    inc.get("priority", "P3"),
                    int(inc.get("priority_score", 50)),
                    float(inc.get("confidence", 50.0)),
                    int(inc.get("severity", 50)),
                    int(inc.get("mission_impact", 50)),
                    int(inc.get("urgency", 50)),
                    json.dumps(enriched, ensure_ascii=False),
                    now_iso,
                ),
            )
    conn.close()


def get_incidents(
    db_path: Path | str | None = None,
    promotable_only: bool = False,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve saved incidents with stored triage state."""
    conn = get_connection(db_path)
    clauses = []
    params: list[Any] = []

    if promotable_only:
        clauses.append("promotable = 1")
    if status:
        clauses.append("status = ?")
        params.append(status)

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT status, analyst_notes, details_json FROM incidents {where_sql} ORDER BY priority_score DESC"
    cursor = conn.execute(sql, params)
    out = []
    for row in cursor.fetchall():
        item = json.loads(row["details_json"])
        item["status"] = row["status"]
        item["analyst_notes"] = row["analyst_notes"]
        out.append(item)
    conn.close()
    return out


def get_incident(incident_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve a single incident by ID."""
    conn = get_connection(db_path)
    cur = conn.execute("SELECT status, analyst_notes, details_json FROM incidents WHERE id = ?", (incident_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    item = json.loads(row["details_json"])
    item["status"] = row["status"]
    item["analyst_notes"] = row["analyst_notes"]
    return item


def update_incident_triage(
    incident_id: str,
    status: str | None = None,
    analyst_notes: str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any] | None:
    """Update analyst status or notes for an incident."""
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        cur = conn.execute("SELECT status, analyst_notes, details_json FROM incidents WHERE id = ?", (incident_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return None

        new_status = status if status is not None else row["status"]
        new_notes = analyst_notes if analyst_notes is not None else row["analyst_notes"]

        item = json.loads(row["details_json"])
        item["status"] = new_status
        item["analyst_notes"] = new_notes

        conn.execute(
            """
            UPDATE incidents
            SET status = ?, analyst_notes = ?, details_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status, new_notes, json.dumps(item, ensure_ascii=False), now_iso, incident_id),
        )
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (now_iso, "update_triage", f"Incident {incident_id} updated: status={new_status}"),
        )
    conn.close()
    return item


def reset_db(root_dir: Path | None = None, db_path: Path | str | None = None) -> None:
    """Clear all dynamic database tables and reseed with default demo alerts and assets."""
    target = get_db_path(db_path)
    root = root_dir or ROOT_DIR
    conn = get_connection(target)
    with conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM assets")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM audit_log")
    seed_from_files(conn, root)
    conn.close()
