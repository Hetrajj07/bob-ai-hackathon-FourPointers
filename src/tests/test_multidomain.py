"""Unit and integration tests for Multi-Domain Situational Awareness & Telemetry Feeds.

Covers:
- Spatial calculations, haversine distance, and sector classification
- Normalizers for OpenSky, AIS, Copernicus Sentinel, NASA FIRMS, IMD Weather, ISRO Bhuvan, Copernicus EMS/USGS
- Multi-domain database ingestion and schema migration
- Multi-domain API endpoints (/api/multidomain/sectors, domain-stats, radar-feed, simulate-multidomain)
- MCP server tools (get_domain_summary, get_geospatial_threats)
- IBM Bob grounded multi-domain commands (/defence, /airspace, /maritime, /satellite, /thermal, /weather)
"""
import pytest
from fastapi.testclient import TestClient

from src.app import app
from src.threatfusion.spatial import (
    haversine_distance,
    classify_sector,
    get_sector_info,
    STRATEGIC_SECTORS,
)
from src.threatfusion.normalizer import (
    normalize_opensky,
    normalize_maritime_ais,
    normalize_sentinel,
    normalize_nasa_firms,
    normalize_imd_weather,
    normalize_isro_bhuvan,
    normalize_cems_usgs,
    auto_normalize,
)
from src.threatfusion.db import ingest_corpus_data, reset_db
from src.mcp_server import execute_tool

client = TestClient(app)


def test_haversine_distance():
    # Distance between New Delhi (28.6139, 77.2090) and Mumbai (19.0760, 72.8777) ~ 1148 km
    dist = haversine_distance(28.6139, 77.2090, 19.0760, 72.8777)
    assert 1140 < dist < 1160
    # Zero distance
    assert haversine_distance(34.0, 78.0, 34.0, 78.0) == 0.0


def test_sector_classification():
    # Ladakh coords -> NORTHERN_LAC_LADAKH
    sec_ladakh = classify_sector(34.2, 78.5)
    assert sec_ladakh == "NORTHERN_LAC_LADAKH"

    # Gujarat Sir Creek -> WESTERN_BORDER_SIR_CREEK
    sec_creek = classify_sector(23.6, 68.4)
    assert sec_creek == "WESTERN_BORDER_SIR_CREEK"

    # Siliguri Corridor -> SILIGURI_CORRIDOR
    sec_sili = classify_sector(26.7, 88.3)
    assert sec_sili == "SILIGURI_CORRIDOR"

    # Andaman & Nicobar -> ANDAMAN_NICOBAR_EEZ
    sec_andaman = classify_sector(11.6, 92.7)
    assert sec_andaman == "ANDAMAN_NICOBAR_EEZ"

    # Default fallback
    sec_none = classify_sector(None, None)
    assert sec_none == "CENTRAL_COMMAND_CORRIDOR"


def test_sector_info_metadata():
    info = get_sector_info("NORTHERN_LAC_LADAKH")
    assert info is not None
    assert "name" in info
    assert "strategic_importance" in info
    assert "primary_sensors" in info
    assert len(info["primary_sensors"]) >= 3


def test_normalizer_opensky():
    raw = {
        "icao24": "8001fa",
        "callsign": "UAV-PATROL09",
        "time_position": 1789720000,
        "latitude": 34.25,
        "longitude": 78.45,
        "baro_altitude": 7800.0,
        "velocity": 120.5,
        "true_track": 85.0,
        "squawk": "7700",
    }
    norm = normalize_opensky(raw)
    assert norm["domain"] == "airspace"
    assert norm["source"] == "opensky_airspace"
    assert norm["callsign"] == "UAV-PATROL09"
    assert norm["sector"] == "NORTHERN_LAC_LADAKH"
    assert norm["squawk"] == "7700"
    assert norm["latitude"] == 34.25


def test_normalizer_maritime_ais():
    raw = {
        "MMSI": "419000123",
        "VesselName": "SURVEY-PROBE-04",
        "BaseDateTime": "2026-09-18T22:30:00Z",
        "LAT": 23.55,
        "LON": 68.35,
        "SOG": 4.2,
        "COG": 190.0,
        "VesselType": "Research/Survey",
    }
    norm = normalize_maritime_ais(raw)
    assert norm["domain"] == "maritime"
    assert norm["source"] == "maritime_ais"
    assert norm["vessel_name"] == "SURVEY-PROBE-04"
    assert norm["sector"] == "WESTERN_BORDER_SIR_CREEK"


def test_normalizer_sentinel():
    raw = {
        "mission": "Sentinel-1B-SAR",
        "timestamp": "2026-09-18T18:00:00Z",
        "latitude": 34.3,
        "longitude": 78.6,
        "change_type": "surface_coherence_loss",
        "coherence_drop_pct": 74.5,
    }
    norm = normalize_sentinel(raw)
    assert norm["domain"] == "satellite_eo"
    assert norm["source"] == "copernicus_sentinel"
    assert norm["sector"] == "NORTHERN_LAC_LADAKH"


def test_normalizer_nasa_firms():
    raw = {
        "satellite": "VIIRS-SNPP",
        "acq_date": "2026-09-18",
        "acq_time": "1945",
        "latitude": 34.15,
        "longitude": 78.25,
        "frp": 12.8,
        "confidence": "h",
    }
    norm = normalize_nasa_firms(raw)
    assert norm["domain"] == "thermal_ir"
    assert norm["source"] == "nasa_firms"
    assert norm["frp_mw"] == 12.8


def test_auto_normalize_multidomain():
    # OpenSky flight
    flight = {"icao24": "700abc", "callsign": "SURV-01", "latitude": 26.8, "longitude": 88.4}
    norm_flight = auto_normalize(flight)
    assert norm_flight["domain"] == "airspace"

    # AIS vessel
    vessel = {"MMSI": "123456789", "VesselName": "VESSEL-X", "LAT": 11.5, "LON": 92.5}
    norm_vessel = auto_normalize(vessel)
    assert norm_vessel["domain"] == "maritime"


def test_api_multidomain_sectors():
    res = client.get("/api/multidomain/sectors")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["total_sectors"] == len(STRATEGIC_SECTORS)
    sector_ids = [s["sector_id"] for s in data["sectors"]]
    assert "NORTHERN_LAC_LADAKH" in sector_ids
    assert "WESTERN_BORDER_SIR_CREEK" in sector_ids
    assert "ANDAMAN_NICOBAR_EEZ" in sector_ids


def test_api_multidomain_domain_stats():
    res = client.get("/api/multidomain/domain-stats")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "domain_breakdown" in data
    assert data["total_records"] > 0


def test_api_multidomain_radar_feed():
    res = client.get("/api/multidomain/radar-feed")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "feed" in data
    assert isinstance(data["feed"], list)

    # Sector filter
    res_sec = client.get("/api/multidomain/radar-feed?sector=NORTHERN_LAC_LADAKH")
    assert res_sec.status_code == 200
    for item in res_sec.json()["feed"]:
        assert item["sector"] == "NORTHERN_LAC_LADAKH"


def test_api_simulate_multidomain():
    res = client.post("/api/simulate-multidomain", json={"scenario": "airspace_border_incursion"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["scenario"] == "airspace_border_incursion"
    assert data["total_alerts"] > 0


def test_mcp_domain_summary_tool():
    summary = execute_tool("get_domain_summary", {})
    assert "domain_counts" in summary
    assert "active_strategic_sectors" in summary
    assert summary["total_records"] > 0


def test_mcp_geospatial_threats_tool():
    res = execute_tool("get_geospatial_threats", {"sector": "NORTHERN_LAC_LADAKH"})
    assert "sector" in res
    assert "observations" in res
    assert "correlated_candidate_clusters" in res


def test_bob_defence_briefings():
    # Test /defence briefing
    res_def = client.post("/api/bob/ask", json={"command": "defence"})
    assert res_def.status_code == 200
    data_def = res_def.json()
    assert "National Defence Situational Awareness Brief" in data_def["response"]
    assert "OpenSky Network" in data_def["response"]
    assert "Copernicus Sentinel" in data_def["response"]

    # Test /airspace briefing
    res_air = client.post("/api/bob/ask", json={"command": "airspace"})
    assert res_air.status_code == 200
    assert "Airspace Domain Briefing" in res_air.json()["response"]

    # Test /maritime briefing
    res_mar = client.post("/api/bob/ask", json={"command": "maritime"})
    assert res_mar.status_code == 200
    assert "Maritime Domain" in res_mar.json()["response"]

    # Test /satellite briefing
    res_sat = client.post("/api/bob/ask", json={"command": "satellite"})
    assert res_sat.status_code == 200
    assert "Earth Observation & Satellite Briefing" in res_sat.json()["response"]
