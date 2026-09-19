"""ThreatFusion SQLite persistence layer.

Provides relational storage for alerts, asset context, candidate hypotheses,
promoted incidents, analyst triage state, multi-domain situational awareness telemetry,
and audit logs.
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
                domain TEXT,
                latitude REAL,
                longitude REAL,
                sector TEXT,
                entity_type TEXT,
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

        # Graceful column migration for existing databases
        for col, col_type in [
            ("domain", "TEXT"),
            ("latitude", "REAL"),
            ("longitude", "REAL"),
            ("sector", "TEXT"),
            ("entity_type", "TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sector ON alerts(sector)")
        except sqlite3.OperationalError:
            pass

    if seed_if_empty:
        cursor = conn.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        if count == 0:
            seed_from_files(conn, root)

    conn.close()
    return target


def seed_from_files(conn: sqlite3.Connection, root: Path) -> None:
    """Seed baseline demo alerts and assets from demo JSON files into the database."""
    from src.threatfusion.enrichment import enrich_record

    data_dir = root / "src" / "data"
    alerts_file = data_dir / "demo_alerts.json"
    assets_file = data_dir / "assets.json"

    now_iso = datetime.now(timezone.utc).isoformat()

    if alerts_file.exists():
        with alerts_file.open(encoding="utf-8") as f:
            records = json.load(f)
        for r in records:
            _insert_alert_record(conn, enrich_record(r, root=root), now_iso)

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
        (now_iso, "seed_demo_data", f"Seeded demo baseline from {data_dir}"),
    )
    conn.commit()


def _extract_primary_fields(r: dict[str, Any]) -> tuple[str, str, str, str | None, str | None, str | None, str | None, str | None, float | None, float | None, str | None, str | None]:
    record_id = str(r.get("_id") or r.get("id"))
    ts = str(r.get("timestamp"))
    source = str(r.get("source", "unknown"))
    event_type = str(r.get("event_type")) if r.get("event_type") else None

    # Determine primary host/user/ip for quick indexing
    host = str(r.get("host") or r.get("src_host") or r.get("dst_host") or "").strip().upper() or None
    user = str(r.get("user") or "").strip().lower() or None
    ip = str(r.get("ip") or r.get("src_ip") or r.get("dst_ip") or "").strip() or None

    domain = r.get("domain")
    lat = float(r["latitude"]) if r.get("latitude") is not None else None
    lon = float(r["longitude"]) if r.get("longitude") is not None else None
    sector = r.get("sector")
    entity_type = r.get("entity_type")

    # Ensure _id is consistently populated in the raw dict
    raw = dict(r)
    if "_id" not in raw:
        raw["_id"] = record_id

    return record_id, ts, source, event_type, host, user, ip, domain, lat, lon, sector, entity_type


def _insert_alert_record(conn: sqlite3.Connection, r: dict[str, Any], created_at: str) -> None:
    rid, ts, src, et, host, user, ip, domain, lat, lon, sector, ent_type = _extract_primary_fields(r)
    raw = dict(r)
    raw["_id"] = rid
    conn.execute(
        """
        INSERT OR REPLACE INTO alerts (id, timestamp, source, event_type, host, user, ip, domain, latitude, longitude, sector, entity_type, raw_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (rid, ts, src, et, host, user, ip, domain, lat, lon, sector, ent_type, json.dumps(raw, ensure_ascii=False), created_at),
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
    domain: str | None = None,
    sector: str | None = None,
    search: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Query paginated alerts with filtering across domains and sectors."""
    conn = get_connection(db_path)
    clauses = []
    params: list[Any] = []

    if source:
        clauses.append("source = ?")
        params.append(source)
    if host:
        clauses.append("host = ?")
        params.append(host.upper())
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    if sector:
        clauses.append("sector = ?")
        params.append(sector)
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
            INSERT OR REPLACE INTO assets (host, criticality, mission_role, zone, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (clean_host, criticality, mission_role, zone, now_iso),
        )
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (now_iso, "upsert_asset", f"Asset {clean_host} updated with criticality {criticality}"),
        )
    conn.close()
    return {
        "host": clean_host,
        "criticality": criticality,
        "mission_role": mission_role,
        "zone": zone,
        "updated_at": now_iso,
    }


def delete_asset(host: str, db_path: Path | str | None = None) -> bool:
    """Remove an asset from inventory."""
    clean_host = host.strip().upper()
    conn = get_connection(db_path)
    with conn:
        cursor = conn.execute("DELETE FROM assets WHERE host = ?", (clean_host,))
        deleted = cursor.rowcount > 0
        if deleted:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
                (now_iso, "delete_asset", f"Asset {clean_host} deleted"),
            )
    conn.close()
    return deleted


def save_incidents(incidents_list: list[dict[str, Any]], db_path: Path | str | None = None) -> None:
    """Save or update analyzed candidate hypotheses & incidents into SQLite."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        for inc in incidents_list:
            inc_id = inc["id"]
            promotable = 1 if inc.get("promotable") else 0
            prio = str(inc.get("priority", "UNKNOWN"))
            prio_score = int(inc.get("priority_score", 0))
            conf = float(inc.get("confidence", 0.0))
            sev = int(inc.get("severity", 0))
            imp = int(inc.get("mission_impact", 0))
            urg = int(inc.get("urgency", 0))

            conn.execute(
                """
                INSERT INTO incidents (
                    id, promotable, priority, priority_score, confidence,
                    severity, mission_impact, urgency, details_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    inc_id,
                    promotable,
                    prio,
                    prio_score,
                    conf,
                    sev,
                    imp,
                    urg,
                    json.dumps(inc, ensure_ascii=False),
                    now_iso,
                ),
            )
    conn.close()


def get_incident(incident_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Fetch stored incident details by ID."""
    conn = get_connection(db_path)
    cursor = conn.execute("SELECT details_json, status, analyst_notes FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    data = json.loads(row["details_json"])
    data["status"] = row["status"]
    data["analyst_notes"] = row["analyst_notes"]
    return data


def get_incidents(db_path: Path | str | None = None, promotable_only: bool = False) -> list[dict[str, Any]]:
    """Fetch all stored incidents ordered by priority score descending."""
    conn = get_connection(db_path)
    sql = "SELECT details_json, status, analyst_notes FROM incidents"
    if promotable_only:
        sql += " WHERE promotable = 1"
    sql += " ORDER BY priority_score DESC"
    cursor = conn.execute(sql)
    out = []
    for row in cursor.fetchall():
        d = json.loads(row["details_json"])
        d["status"] = row["status"]
        d["analyst_notes"] = row["analyst_notes"]
        out.append(d)
    conn.close()
    return out


def update_incident_triage(
    incident_id: str,
    status: str | None = None,
    notes: str | None = None,
    analyst_notes: str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Update human analyst triage decision on an incident."""
    now_iso = datetime.now(timezone.utc).isoformat()
    final_notes = analyst_notes if analyst_notes is not None else (notes or "")
    conn = get_connection(db_path)
    with conn:
        if status is not None:
            conn.execute(
                """
                UPDATE incidents
                SET status = ?, analyst_notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, final_notes, now_iso, incident_id),
            )
        else:
            conn.execute(
                """
                UPDATE incidents
                SET analyst_notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (final_notes, now_iso, incident_id),
            )
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (now_iso, "update_incident_triage", f"Incident {incident_id} triaged as {status}"),
        )
    conn.close()
    return {
        "incident_id": incident_id,
        "status": status or "open",
        "notes": final_notes,
        "analyst_notes": final_notes,
        "updated_at": now_iso,
    }


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


def ingest_corpus_data(
    include_historical: bool = True,
    include_recent: bool = True,
    include_otrf: bool = True,
    include_cicids: bool = True,
    include_sparta_satellite: bool = True,
    include_opensky: bool = True,
    include_maritime_ais: bool = True,
    include_satellite_eo: bool = True,
    include_thermal_firms: bool = True,
    include_weather_imd: bool = True,
    include_bhuvan_geospatial: bool = True,
    include_emergency_usgs: bool = True,
    db_path: Path | str | None = None,
    root_dir: Path | None = None,
) -> dict[str, Any]:
    """Ingest historical archive, recent multi-source threats, and multi-domain public data feeds into SQLite."""
    from src.threatfusion.normalizer import (
        normalize_otrf,
        normalize_cicids,
        normalize_opensky,
        normalize_maritime_ais,
        normalize_sentinel,
        normalize_nasa_firms,
        normalize_imd_weather,
        normalize_isro_bhuvan,
        normalize_cems_usgs,
    )
    from src.threatfusion.enrichment import enrich_record

    target = get_db_path(db_path)
    root = root_dir or ROOT_DIR
    conn = get_connection(target)
    now_iso = datetime.now(timezone.utc).isoformat()

    stats = {
        "historical_ingested": 0,
        "recent_ingested": 0,
        "otrf_ingested": 0,
        "cicids_ingested": 0,
        "sparta_satellite_ingested": 0,
        "opensky_airspace_ingested": 0,
        "maritime_ais_ingested": 0,
        "satellite_eo_ingested": 0,
        "thermal_firms_ingested": 0,
        "weather_imd_ingested": 0,
        "bhuvan_geospatial_ingested": 0,
        "emergency_usgs_ingested": 0,
        "total_new_ingested": 0,
    }

    # First update asset inventory from assets.json and strategic infrastructure
    assets_file = root / "src" / "data" / "assets.json"
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

    all_records: list[dict[str, Any]] = []

    # 1. Historical Threats (Archive)
    if include_historical:
        hist_file = root / "src" / "data" / "historical" / "historical_threats.json"
        if hist_file.exists():
            with hist_file.open(encoding="utf-8") as f:
                hist_records = [enrich_record(r, root=root) for r in json.load(f)]
                stats["historical_ingested"] = len(hist_records)
                all_records.extend(hist_records)

    # 2. Recent Threats (September Active Telemetry)
    if include_recent:
        recent_file = root / "src" / "data" / "recent" / "recent_threats.json"
        if recent_file.exists():
            with recent_file.open(encoding="utf-8") as f:
                recent_records = [enrich_record(r, root=root) for r in json.load(f)]
                stats["recent_ingested"] = len(recent_records)
                all_records.extend(recent_records)

    # 3. Real OTRF Sysmon Events
    if include_otrf:
        otrf_file = root / "src" / "data" / "real" / "otrf_sample.json"
        if otrf_file.exists():
            with otrf_file.open(encoding="utf-8") as f:
                otrf_records = [enrich_record(normalize_otrf(ev), root=root) for ev in json.load(f)]
                stats["otrf_ingested"] = len(otrf_records)
                all_records.extend(otrf_records)

    # 4. Real CIC-IDS2017 Network Flows
    if include_cicids:
        cicids_file = root / "src" / "data" / "real" / "cicids_sample.json"
        if cicids_file.exists():
            with cicids_file.open(encoding="utf-8") as f:
                cicids_records = [enrich_record(normalize_cicids(fl), root=root) for fl in json.load(f)]
                stats["cicids_ingested"] = len(cicids_records)
                all_records.extend(cicids_records)

    # 5. SPARTA Satellite Telemetry Chain
    if include_sparta_satellite:
        sat_file = root / "src" / "data" / "space" / "satellite_demo.json"
        if sat_file.exists():
            with sat_file.open(encoding="utf-8") as f:
                sat_records = [enrich_record(r, root=root) for r in json.load(f)]
                stats["sparta_satellite_ingested"] = len(sat_records)
                all_records.extend(sat_records)

    # 6. OpenSky Airspace Telemetry
    if include_opensky:
        opensky_file = root / "src" / "data" / "multidomain" / "airspace_opensky.json"
        if opensky_file.exists():
            with opensky_file.open(encoding="utf-8") as f:
                os_records = [enrich_record(normalize_opensky(fl), root=root) for fl in json.load(f)]
                stats["opensky_airspace_ingested"] = len(os_records)
                all_records.extend(os_records)

    # 7. NOAA MarineCadastre AIS Maritime
    if include_maritime_ais:
        ais_file = root / "src" / "data" / "multidomain" / "maritime_ais.json"
        if ais_file.exists():
            with ais_file.open(encoding="utf-8") as f:
                ais_records = [enrich_record(normalize_maritime_ais(v), root=root) for v in json.load(f)]
                stats["maritime_ais_ingested"] = len(ais_records)
                all_records.extend(ais_records)

    # 8. Copernicus Sentinel SAR & Optical Satellite EO
    if include_satellite_eo:
        sentinel_file = root / "src" / "data" / "multidomain" / "satellite_copernicus_isro.json"
        if sentinel_file.exists():
            with sentinel_file.open(encoding="utf-8") as f:
                sat_eo_records = [enrich_record(normalize_sentinel(s), root=root) for s in json.load(f)]
                stats["satellite_eo_ingested"] = len(sat_eo_records)
                all_records.extend(sat_eo_records)

    # 9. NASA FIRMS Thermal IR Hotspots
    if include_thermal_firms:
        firms_file = root / "src" / "data" / "multidomain" / "thermal_nasa_firms.json"
        if firms_file.exists():
            with firms_file.open(encoding="utf-8") as f:
                firms_records = [enrich_record(normalize_nasa_firms(fm), root=root) for fm in json.load(f)]
                stats["thermal_firms_ingested"] = len(firms_records)
                all_records.extend(firms_records)

    # 10. IMD Indian Weather & Coastal Radar
    if include_weather_imd:
        imd_file = root / "src" / "data" / "multidomain" / "weather_imd.json"
        if imd_file.exists():
            with imd_file.open(encoding="utf-8") as f:
                imd_records = [enrich_record(normalize_imd_weather(w), root=root) for w in json.load(f)]
                stats["weather_imd_ingested"] = len(imd_records)
                all_records.extend(imd_records)

    # 11. ISRO Bhuvan / India OGD Strategic Infrastructure
    if include_bhuvan_geospatial:
        bhuvan_file = root / "src" / "data" / "multidomain" / "geospatial_bhuvan.json"
        if bhuvan_file.exists():
            with bhuvan_file.open(encoding="utf-8") as f:
                bhuvan_records = [enrich_record(normalize_isro_bhuvan(bg), root=root) for bg in json.load(f)]
                stats["bhuvan_geospatial_ingested"] = len(bhuvan_records)
                all_records.extend(bhuvan_records)
                for bg in bhuvan_records:
                    feat_host = bg.get("host", "").upper()
                    if feat_host:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO assets (host, criticality, mission_role, zone, updated_at)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                feat_host,
                                95,
                                bg.get("feature_name", "Strategic installation"),
                                bg.get("sector", "border-perimeter"),
                                now_iso,
                            ),
                        )

    # 12. Copernicus EMS & USGS Geophysical Feeds
    if include_emergency_usgs:
        usgs_file = root / "src" / "data" / "multidomain" / "emergency_cems_usgs.json"
        if usgs_file.exists():
            with usgs_file.open(encoding="utf-8") as f:
                usgs_records = [enrich_record(normalize_cems_usgs(u), root=root) for u in json.load(f)]
                stats["emergency_usgs_ingested"] = len(usgs_records)
                all_records.extend(usgs_records)

    with conn:
        for r in all_records:
            _insert_alert_record(conn, r, now_iso)
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (now_iso, "ingest_corpus_data", f"Ingested multi-domain corpus: {stats}"),
        )

    stats["total_new_ingested"] = len(all_records)
    total_in_db = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    stats["total_alerts_in_db"] = total_in_db
    conn.close()
    return stats
