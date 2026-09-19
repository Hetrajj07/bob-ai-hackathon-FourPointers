"""Multi-source and multi-domain telemetry normalizer for ThreatFusion.

Normalizes raw feeds across:
1. ✈️ Airspace: OpenSky Network (live & historical flight state vectors)
2. 🚢 Maritime: NOAA MarineCadastre / Maritime AIS (vessel traffic & dark vessel gaps)
3. 🛰️ Satellite: Copernicus Sentinel-1 (SAR) / Sentinel-2 (Optical) & ISRO MOSDAC
4. 🔥 Thermal IR: NASA FIRMS (MODIS / VIIRS active fire & thermal hotspots)
5. 🌦️ Weather: IMD (India Meteorological Department observations & warnings)
6. 🇮🇳 Geospatial: ISRO Bhuvan / India OGD strategic infrastructure
7. 🌍 Geophysical: Copernicus EMS & USGS real-time seismic feeds
8. 💻 Cyber / C2: OTRF Sysmon, CIC-IDS2017 flow telemetry, SPARTA space telemetry
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from src.threatfusion.spatial import classify_sector

ATTACK_RULE_RE = re.compile(r"technique_id=(T\d{4}(?:\.\d{3})?)")


def _deterministic_id(prefix: str, content: str) -> str:
    h = hashlib.sha1(content.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{h}"


def normalize_otrf(event: dict[str, Any]) -> dict[str, Any]:
    """Convert an OTRF Sysmon or Windows Event Log record to canonical format."""
    event_id = event.get("EventID")
    data = event.get("EventData") or {}
    computer = (event.get("Computer") or data.get("SourceHostname") or "").strip().upper()
    ts_raw = event.get("TimeCreated") or data.get("UtcTime") or datetime.now(timezone.utc).isoformat()

    rule_name = str(data.get("RuleName", ""))
    attack_hint = None
    m = ATTACK_RULE_RE.search(rule_name)
    if m:
        attack_hint = m.group(1)

    rec_id = _deterministic_id("OTRF", f"{computer}-{event_id}-{ts_raw}-{data.get('ProcessId', '')}")

    user = data.get("User") or data.get("TargetUserName") or data.get("SourceUser")
    if user and "\\" in str(user):
        user = str(user).split("\\")[-1]

    src_ip = data.get("SourceIp") or data.get("IpAddress")
    dst_ip = data.get("DestinationIp")

    process = data.get("Image")
    if process and "\\" in str(process):
        process = str(process).split("\\")[-1]

    parent_process = data.get("ParentImage")
    if parent_process and "\\" in str(parent_process):
        parent_process = str(parent_process).split("\\")[-1]

    cmdline = data.get("CommandLine")
    target_img = data.get("TargetImage")
    if target_img and "\\" in str(target_img):
        target_img = str(target_img).split("\\")[-1]

    detail = ""
    event_type = "system_event"
    if event_id == 1:
        event_type = "process_creation"
        detail = f"Process {process} launched by {parent_process or 'system'}: {cmdline or ''}"
    elif event_id == 10:
        event_type = "process_access"
        detail = f"Process {process} accessed memory of target {target_img} (GrantedAccess {data.get('GrantedAccess', '0x1000')})"
    elif event_id == 3:
        event_type = "network_connection"
        detail = f"Process {process} established outbound connection to {dst_ip}:{data.get('DestinationPort', '')}"
    elif event_id == 4624:
        event_type = "user_logon"
        detail = f"User {user} logged on to {computer} via logon type {data.get('LogonType')} from {src_ip}"
    else:
        detail = f"Sysmon/Security event {event_id} on {computer}"

    canonical = {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "endpoint" if event.get("SourceName") == "Microsoft-Windows-Sysmon" else "siem",
        "domain": "cyber_c2",
        "event_type": event_type,
        "host": computer,
        "user": user,
        "process": process,
        "parent_process": parent_process,
        "cmdline": cmdline,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": data.get("DestinationPort"),
        "detail": detail.strip(),
        "origin": "OTRF Security Datasets",
        "provenance_type": "real_sample",
        "dataset_name": "OTRF Security Datasets",
    }
    if attack_hint:
        canonical["attack_id_hint"] = attack_hint
        canonical["rule_technique_hint"] = attack_hint
    return canonical


def normalize_cicids(flow: dict[str, Any]) -> dict[str, Any]:
    """Convert a CIC-IDS2017 network flow record to canonical format."""
    flow_id = str(flow.get("FlowID") or "")
    src_ip = flow.get("SourceIp") or flow.get("src_ip")
    dst_ip = flow.get("DestinationIp") or flow.get("dst_ip")
    src_port = flow.get("SourcePort") or flow.get("src_port")
    dst_port = flow.get("DestinationPort") or flow.get("dst_port")
    proto = str(flow.get("Protocol") or "TCP").upper()
    ts_raw = flow.get("Timestamp") or flow.get("timestamp") or datetime.now(timezone.utc).isoformat()
    label = flow.get("Label") or flow.get("label") or "Network-Flow"
    sensor = flow.get("SensorHost") or "NET-PROBE-01"

    rec_id = _deterministic_id("CICIDS", f"{flow_id}-{ts_raw}")
    detail = f"Network flow [{proto}] from {src_ip}:{src_port} to {dst_ip}:{dst_port} flagged as {label} ({flow.get('TotalFwdPackets', 0)} fwd packets)"

    canonical = {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "network_sensor",
        "domain": "cyber_c2",
        "event_type": "network_flow_alert",
        "host": sensor,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": "RDP" if dst_port == 3389 else ("SSH" if dst_port == 22 else proto),
        "detail": detail,
        "label": label,
        "dataset_label": label,
        "origin": "CIC-IDS2017 Dataset",
        "provenance_type": "real_sample",
        "dataset_name": "CIC-IDS2017",
    }
    return canonical


def normalize_opensky(flight: dict[str, Any]) -> dict[str, Any]:
    """Convert OpenSky Network aircraft telemetry into canonical ThreatFusion format."""
    callsign = (flight.get("callsign") or flight.get("icao24") or "UNKNOWN").strip().upper()
    icao24 = (flight.get("icao24") or "").strip().lower()
    lat = float(flight.get("latitude") or flight.get("lat") or 0.0)
    lon = float(flight.get("longitude") or flight.get("lon") or 0.0)
    alt = flight.get("baro_altitude") or flight.get("altitude") or 0
    vel = flight.get("velocity") or flight.get("speed") or 0
    track = flight.get("true_track") or flight.get("heading") or 0
    squawk = str(flight.get("squawk") or "")
    sector = flight.get("sector") or classify_sector(lat, lon)

    ts_raw = flight.get("timestamp")
    if not ts_raw and flight.get("time_position"):
        ts_raw = datetime.fromtimestamp(flight["time_position"], tz=timezone.utc).isoformat()
    elif not ts_raw:
        ts_raw = datetime.now(timezone.utc).isoformat()

    rec_id = _deterministic_id("OPENSKY", f"{callsign}-{icao24}-{ts_raw}")
    detail = flight.get("detail") or f"Aircraft {callsign} (ICAO {icao24}) tracked at {alt}ft, speed {vel}kts, squawk {squawk or 'nominal'} in {sector}."

    return {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "opensky_airspace",
        "domain": "airspace",
        "event_type": "airspace_track_observation",
        "entity_type": "aircraft",
        "callsign": callsign,
        "icao24": icao24,
        "host": f"AIR-TRACK-{callsign}",
        "latitude": lat,
        "longitude": lon,
        "altitude_ft": alt,
        "velocity_knots": vel,
        "heading_deg": track,
        "squawk": squawk,
        "sector": sector,
        "detail": detail,
        "origin": "OpenSky Network Civil Airspace API",
        "provenance_type": "real_api_feed",
        "dataset_name": "OpenSky Network",
    }


def normalize_maritime_ais(vessel: dict[str, Any]) -> dict[str, Any]:
    """Convert NOAA MarineCadastre / AIS vessel data into canonical ThreatFusion format."""
    mmsi = str(vessel.get("MMSI") or vessel.get("mmsi") or "UNKNOWN").strip()
    name = (vessel.get("VesselName") or vessel.get("vessel_name") or f"VESSEL-{mmsi}").strip().upper()
    lat = float(vessel.get("LAT") or vessel.get("latitude") or 0.0)
    lon = float(vessel.get("LON") or vessel.get("longitude") or 0.0)
    sog = float(vessel.get("SOG") or vessel.get("speed_knots") or 0.0)
    cog = float(vessel.get("COG") or vessel.get("heading") or 0.0)
    v_type = vessel.get("VesselType") or vessel.get("vessel_type") or "Unspecified Vessel"
    status = vessel.get("Status") or vessel.get("status") or "Under way"
    transponder = vessel.get("TransponderStatus") or vessel.get("transponder_status") or "Active"
    sector = vessel.get("sector") or classify_sector(lat, lon)

    ts_raw = vessel.get("BaseDateTime") or vessel.get("timestamp") or datetime.now(timezone.utc).isoformat()
    rec_id = _deterministic_id("AIS", f"{mmsi}-{name}-{ts_raw}")
    detail = vessel.get("detail") or f"Vessel {name} (MMSI: {mmsi}, Type: {v_type}) observed at {sog} kts, COG {cog}°, status: {status} ({transponder})."

    return {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "maritime_ais",
        "domain": "maritime",
        "event_type": "maritime_vessel_observation",
        "entity_type": "vessel",
        "vessel_name": name,
        "mmsi": mmsi,
        "host": f"MAR-VESSEL-{name.replace(' ', '_')}",
        "latitude": lat,
        "longitude": lon,
        "speed_knots": sog,
        "heading_deg": cog,
        "vessel_type": v_type,
        "transponder_status": transponder,
        "sector": sector,
        "detail": detail,
        "origin": "NOAA MarineCadastre AIS Dataset",
        "provenance_type": "real_dataset",
        "dataset_name": "NOAA MarineCadastre AIS",
    }


def normalize_sentinel(sat: dict[str, Any]) -> dict[str, Any]:
    """Convert Copernicus Sentinel-1 SAR & Sentinel-2 Optical earth observations into canonical format."""
    mission = sat.get("satellite_mission") or sat.get("mission") or "Sentinel-1A SAR"
    scene_id = sat.get("scene_id") or f"SCENE-{mission}"
    lat = float(sat.get("latitude") or 0.0)
    lon = float(sat.get("longitude") or 0.0)
    anomaly = sat.get("anomaly_type") or "Earth Observation Surface Anomaly"
    conf = float(sat.get("confidence") or 85.0)
    sector = sat.get("sector") or classify_sector(lat, lon)

    ts_raw = sat.get("sensing_time") or sat.get("timestamp") or datetime.now(timezone.utc).isoformat()
    rec_id = _deterministic_id("SENTINEL", f"{scene_id}-{ts_raw}")
    detail = sat.get("detail") or f"{mission} detected {anomaly} at ({lat}, {lon}) with confidence {conf}% in {sector}."

    return {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "copernicus_sentinel",
        "domain": "satellite_eo",
        "event_type": "satellite_earth_observation",
        "entity_type": "satellite",
        "satellite_mission": mission,
        "scene_id": scene_id,
        "host": f"SAT-EO-{mission.split()[0]}",
        "latitude": lat,
        "longitude": lon,
        "anomaly_type": anomaly,
        "confidence_score": conf,
        "sector": sector,
        "detail": detail,
        "origin": "Copernicus Data Space Ecosystem (Sentinel-1 SAR / Sentinel-2 Optical)",
        "provenance_type": "satellite_observation",
        "dataset_name": "Copernicus Sentinel Data Space",
    }


def normalize_nasa_firms(fire: dict[str, Any]) -> dict[str, Any]:
    """Convert NASA FIRMS MODIS / VIIRS active thermal hotspot data into canonical format."""
    sat = fire.get("satellite") or "VIIRS Suomi-NPP"
    lat = float(fire.get("latitude") or 0.0)
    lon = float(fire.get("longitude") or 0.0)
    frp = float(fire.get("frp") or 0.0)
    bright = float(fire.get("brightness") or fire.get("bright_t31") or 300.0)
    sector = fire.get("sector") or classify_sector(lat, lon)

    acq_date = fire.get("acq_date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    acq_time = str(fire.get("acq_time") or "0000").zfill(4)
    ts_raw = f"{acq_date}T{acq_time[:2]}:{acq_time[2:]}:00Z"

    rec_id = _deterministic_id("FIRMS", f"{sat}-{lat}-{lon}-{ts_raw}")
    detail = fire.get("detail") or f"NASA FIRMS thermal hotspot detected by {sat} (Brightness: {bright}K, FRP: {frp}MW) in {sector}."

    return {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "nasa_firms",
        "domain": "thermal_ir",
        "event_type": "thermal_anomaly_detection",
        "entity_type": "thermal_hotspot",
        "satellite": sat,
        "host": f"THERMAL-HOTSPOT-{sector}",
        "latitude": lat,
        "longitude": lon,
        "brightness_temp_k": bright,
        "frp_mw": frp,
        "sector": sector,
        "detail": detail,
        "origin": "NASA FIRMS Near-Real-Time Active Fire Telemetry",
        "provenance_type": "satellite_nrt",
        "dataset_name": "NASA FIRMS (MODIS/VIIRS)",
    }


def normalize_imd_weather(w: dict[str, Any]) -> dict[str, Any]:
    """Convert IMD (India Meteorological Department) weather observations & bulletins into canonical format."""
    station = w.get("station_name") or w.get("station_id") or "IMD-Station"
    lat = float(w.get("latitude") or 0.0)
    lon = float(w.get("longitude") or 0.0)
    warning = w.get("severe_warning_level") or "Standard Observation"
    vis = w.get("visibility_meters") or 5000
    temp = w.get("temperature_c") or 25.0
    sector = w.get("sector") or classify_sector(lat, lon)

    ts_raw = w.get("observation_time") or w.get("timestamp") or datetime.now(timezone.utc).isoformat()
    rec_id = _deterministic_id("IMD", f"{station}-{ts_raw}")
    detail = w.get("detail") or f"IMD Bulletin from {station}: {warning}, visibility {vis}m, temp {temp}°C in {sector}."

    return {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "imd_weather",
        "domain": "weather_env",
        "event_type": "meteorological_advisory",
        "entity_type": "weather_station",
        "station_name": station,
        "host": f"IMD-AWS-{station.split()[0].upper()}",
        "latitude": lat,
        "longitude": lon,
        "visibility_meters": vis,
        "temperature_c": temp,
        "warning_level": warning,
        "sector": sector,
        "detail": detail,
        "origin": "India Meteorological Department (IMD) API & Bulletins",
        "provenance_type": "government_meteorological_api",
        "dataset_name": "India Meteorological Department (IMD)",
    }


def normalize_isro_bhuvan(geo: dict[str, Any]) -> dict[str, Any]:
    """Convert ISRO Bhuvan / OGD strategic geospatial infrastructure metadata into canonical format."""
    feat_id = geo.get("feature_id") or "BHUVAN-01"
    name = geo.get("feature_name") or "Strategic Asset"
    f_type = geo.get("feature_type") or "strategic_infrastructure"
    lat = float(geo.get("latitude") or 0.0)
    lon = float(geo.get("longitude") or 0.0)
    tier = geo.get("strategic_tier") or "Tier-1 Strategic Installation"
    sector = geo.get("sector") or classify_sector(lat, lon)

    ts_raw = geo.get("timestamp") or datetime.now(timezone.utc).isoformat()
    rec_id = _deterministic_id("BHUVAN", f"{feat_id}-{name}")
    detail = geo.get("description") or f"ISRO Bhuvan mapped {name} ({f_type}, {tier}) located in {sector}."

    return {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "isro_bhuvan",
        "domain": "geospatial_infra",
        "event_type": "strategic_infrastructure_context",
        "entity_type": "strategic_infrastructure",
        "feature_id": feat_id,
        "feature_name": name,
        "host": f"BHUVAN-INFRA-{feat_id}",
        "latitude": lat,
        "longitude": lon,
        "strategic_tier": tier,
        "sector": sector,
        "detail": detail,
        "origin": "ISRO Bhuvan / India OGD Strategic Infrastructure Catalog",
        "provenance_type": "isro_bhuvan_geospatial",
        "dataset_name": "ISRO Bhuvan / MOSDAC Geospatial Layers",
    }


def normalize_cems_usgs(ev: dict[str, Any]) -> dict[str, Any]:
    """Convert Copernicus EMS / USGS geophysical events into canonical format."""
    ev_id = ev.get("event_id") or "GEO-EV-01"
    ev_type = ev.get("event_type") or "geophysical_event"
    lat = float(ev.get("latitude") or 0.0)
    lon = float(ev.get("longitude") or 0.0)
    mag = float(ev.get("magnitude") or 0.0)
    sector = ev.get("sector") or classify_sector(lat, lon)

    ts_raw = ev.get("timestamp") or datetime.now(timezone.utc).isoformat()
    rec_id = _deterministic_id("USGS", f"{ev_id}-{ts_raw}")
    detail = ev.get("detail") or f"Geophysical event {ev_id} ({ev_type}, M{mag}) in {sector}."

    return {
        "_id": rec_id,
        "timestamp": ts_raw,
        "source": "usgs_earthquake" if "USGS" in ev_id or mag > 0 else "copernicus_ems",
        "domain": "geophysical",
        "event_type": ev_type,
        "entity_type": "seismic_or_emergency_activation",
        "event_id": ev_id,
        "host": f"DISASTER-MAP-{ev_id}",
        "latitude": lat,
        "longitude": lon,
        "magnitude": mag,
        "sector": sector,
        "detail": detail,
        "origin": "USGS Real-time Earthquake Hazards / Copernicus EMS Rapid Mapping",
        "provenance_type": "usgs_realtime_feed",
        "dataset_name": "USGS & Copernicus EMS",
    }


def auto_normalize(record: dict[str, Any]) -> dict[str, Any]:
    """Automatically detect input record schema and convert to canonical ThreatFusion event."""
    if "EventID" in record and ("EventData" in record or "SourceName" in record):
        return normalize_otrf(record)
    if "FlowID" in record or ("TotalFwdPackets" in record and "DestinationIp" in record):
        return normalize_cicids(record)
    if "icao24" in record or "baro_altitude" in record or ("callsign" in record and "velocity" in record):
        return normalize_opensky(record)
    if "MMSI" in record or "mmsi" in record or "SOG" in record:
        return normalize_maritime_ais(record)
    if "satellite_mission" in record or "polarisation" in record or "scene_id" in record:
        return normalize_sentinel(record)
    if "frp" in record or "brightness" in record or ("bright_t31" in record and "scan" in record):
        return normalize_nasa_firms(record)
    if "station_id" in record or "severe_warning_level" in record or "visibility_meters" in record:
        return normalize_imd_weather(record)
    if "feature_id" in record or ("feature_type" in record and "strategic_tier" in record):
        return normalize_isro_bhuvan(record)
    if "event_id" in record and ("magnitude" in record or "depth_km" in record or "CEMS" in str(record.get("event_id"))):
        return normalize_cems_usgs(record)

    # Standard ThreatFusion format
    rec = dict(record)
    if "_id" not in rec and "id" in rec:
        rec["_id"] = str(rec["id"])
    elif "_id" not in rec:
        rec["_id"] = _deterministic_id("OBS", str(rec))
    if "timestamp" not in rec:
        rec["timestamp"] = datetime.now(timezone.utc).isoformat()
    if "source" not in rec:
        rec["source"] = "unknown"
    rec.setdefault("provenance_type", "synthetic")
    rec.setdefault("dataset_name", "Synthetic Benchmark")
    return rec
