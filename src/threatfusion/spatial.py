"""Spatial analytics, geofencing, and multi-domain sector intelligence for ThreatFusion.

Provides:
- Haversine great-circle distance computation (km)
- Strategic defence & border sector classification (LAC Ladakh, Sir Creek, Siliguri, Andaman EEZ)
- Proximity checks to critical infrastructure & air/maritime corridors
- Unified multi-domain provenance tracking
"""
from __future__ import annotations

import math
from typing import Any

# Strategic Indian Defence & Border Corridors (Centroid + Bounding Geofence)
STRATEGIC_SECTORS = {
    "NORTHERN_LAC_LADAKH": {
        "name": "Northern Sector — Line of Actual Control (Ladakh)",
        "domain_focus": ["airspace", "satellite_eo", "thermal_ir", "geospatial_infra", "weather_env"],
        "bounds": {"min_lat": 32.0, "max_lat": 36.0, "min_lon": 75.0, "max_lon": 81.0},
        "center": {"lat": 34.2, "lon": 78.5},
        "strategic_importance": "High-altitude border sector with strategic roads, forward airfields (Nyoma, Daulat Beg Oldi), and extreme weather constraints.",
        "primary_sensors": ["Sentinel-1 SAR Radar", "Sentinel-2 Optical", "OpenSky Airspace", "NASA FIRMS", "IMD High-Altitude AWS"],
    },
    "WESTERN_BORDER_SIR_CREEK": {
        "name": "Western Sector — Sir Creek & Gujarat Maritime Frontier",
        "domain_focus": ["maritime", "airspace", "thermal_ir", "weather_env"],
        "bounds": {"min_lat": 22.5, "max_lat": 25.0, "min_lon": 67.5, "max_lon": 70.5},
        "center": {"lat": 23.7, "lon": 68.7},
        "strategic_importance": "Tidal marshland border corridor, shallow delta navigation, offshore oil installations, and Exclusive Economic Zone (EEZ) patrol boundary.",
        "primary_sensors": ["NOAA/Indian AIS", "Coastal Radar", "OpenSky Patrol Tracks", "IMD Coastal Radar", "Sentinel-1 SAR"],
    },
    "SILIGURI_CORRIDOR": {
        "name": "Siliguri Corridor — Strategic Northeast Land Bridge",
        "domain_focus": ["airspace", "geospatial_infra", "geophysical", "weather_env"],
        "bounds": {"min_lat": 26.0, "max_lat": 27.5, "min_lon": 87.5, "max_lon": 89.5},
        "center": {"lat": 26.7, "lon": 88.4},
        "strategic_importance": "Narrow geostrategic bottleneck (~22km wide) linking mainland India to the North-Eastern states, highly vulnerable to transport disruption.",
        "primary_sensors": ["OpenSky Air Tracks", "Copernicus EMS Rapid Mapping", "IMD Flood Telemetry", "Bhuvan Infrastructure"],
    },
    "ANDAMAN_NICOBAR_EEZ": {
        "name": "Southern Maritime — Andaman & Nicobar Command / Malacca Approach",
        "domain_focus": ["maritime", "satellite_eo", "weather_env"],
        "bounds": {"min_lat": 6.5, "max_lat": 14.5, "min_lon": 91.5, "max_lon": 95.0},
        "center": {"lat": 11.5, "lon": 93.0},
        "strategic_importance": "Tri-Services Command theater overseeing global energy sea lines of communication (SLOCs) and Ten Degree Channel.",
        "primary_sensors": ["NOAA AIS Vessel Feeds", "ISRO MOSDAC OceanSat-3", "Sentinel-1 Maritime SAR", "IMD Cyclone Radar"],
    },
    "CENTRAL_COMMAND_CORRIDOR": {
        "name": "National Cyber & Space Command Network",
        "domain_focus": ["cyber_c2", "space_telemetry", "geospatial_infra"],
        "bounds": {"min_lat": 18.0, "max_lat": 29.0, "min_lon": 72.0, "max_lon": 85.0},
        "center": {"lat": 24.0, "lon": 77.0},
        "strategic_importance": "Strategic command centers, defense communication relays, satellite ground stations, and critical power infrastructure.",
        "primary_sensors": ["Satellite Ground Station Telemetry", "SPARTA Space TTPs", "OTRF Endpoint Logs", "CICIDS Network Probes"],
    },
}


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on the Earth (in kilometers)."""
    r_earth = 6371.0  # Earth radius in kilometers

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return round(r_earth * c, 2)


def classify_sector(lat: float | None, lon: float | None) -> str:
    """Determine the strategic defence / border sector for a given coordinate pair."""
    if lat is None or lon is None:
        return "CENTRAL_COMMAND_CORRIDOR"

    for sector_id, info in STRATEGIC_SECTORS.items():
        bounds = info["bounds"]
        if bounds["min_lat"] <= lat <= bounds["max_lat"] and bounds["min_lon"] <= lon <= bounds["max_lon"]:
            return sector_id

    # Fallback to nearest sector center
    closest_sector = "CENTRAL_COMMAND_CORRIDOR"
    min_dist = float("inf")
    for sector_id, info in STRATEGIC_SECTORS.items():
        center = info["center"]
        d = haversine_distance(lat, lon, center["lat"], center["lon"])
        if d < min_dist:
            min_dist = d
            closest_sector = sector_id

    return closest_sector


def get_sector_metadata(sector_id: str) -> dict[str, Any]:
    """Retrieve full descriptive metadata for a strategic sector."""
    return STRATEGIC_SECTORS.get(
        sector_id,
        {
            "name": sector_id,
            "domain_focus": ["multi_domain"],
            "strategic_importance": "General operational awareness sector.",
            "primary_sensors": ["Multi-sensor network"],
            "bounds": {"min_lat": 0, "max_lat": 0, "min_lon": 0, "max_lon": 0},
            "center": {"lat": 0, "lon": 0},
        },
    )


get_sector_info = get_sector_metadata

