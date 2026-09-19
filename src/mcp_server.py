#!/usr/bin/env python3
"""ThreatFusion Model Context Protocol (MCP) STDIO Server.

Provides a deterministic, read-only security analytics interface for IBM Bob.
Maintains strict separation:
- ThreatFusion = Deterministic analytics, correlation, scoring, and promotion engine.
- IBM Bob = Natural-language investigation, interpretation, and commander briefing layer.

Supported MCP Protocol Versions:
- 2026-07-28, 2025-06-18 (Default), 2024-11-05

Zero ground-truth access during runtime. All scores and evidence are auditable.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.threatfusion.db import get_all_alerts, get_assets, get_incident as db_get_incident
from src.threatfusion.engine import (
    ENGINE_VERSION,
    TACTIC_RANK,
    analyze,
    bluf,
    clear_context_cache,
    promoted_incidents,
    remediation_runbook,
)

SERVER_NAME = "threatfusion-mcp"
SERVER_VERSION = ENGINE_VERSION
SUPPORTED_PROTOCOL_VERSIONS = ["2026-07-28", "2025-06-18", "2024-11-05"]
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

_INCIDENT_ID_PARAM = {
    "type": "string",
    "description": (
        "ThreatFusion candidate or promoted incident identifier, e.g. 'INC-CAND-09226FFA'. "
        "Use correlate_events to discover available candidate and incident IDs."
    ),
}

TOOLS = [
    {
        "name": "correlate_events",
        "description": (
            "Run deterministic ThreatFusion correlation across all ingested observations. "
            "Returns a structured summary of candidate hypotheses, evidence relationships, "
            "4D risk scores, promotion status (CANDIDATE vs PROMOTED INCIDENT), and promotion gate checks. "
            "Call this first to discover active threat hypotheses and incident IDs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_all_candidates": {
                    "type": "boolean",
                    "description": "If true (default), returns both unpromoted candidate hypotheses and promoted incidents.",
                    "default": True,
                },
                "promoted_only": {
                    "type": "boolean",
                    "description": "If true, restricts results strictly to candidates that met all promotion requirements.",
                    "default": False,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_incident",
        "description": (
            "Retrieve a complete analyst-ready evidence package for a specific candidate or promoted incident. "
            "Includes candidate status (CANDIDATE vs PROMOTED INCIDENT), priority, 4D risk scores, "
            "observable MITRE ATT&CK / SPARTA techniques, attack-flow coherence, per-record provenance badges, "
            "affected asset criticality, contradictions/negative evidence, detection gaps, and grounded next steps. "
            "Use when you need the complete factual picture of a case."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": _INCIDENT_ID_PARAM,
            },
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "explain_risk",
        "description": (
            "Explain why a candidate or incident was prioritized across ThreatFusion's 4 separate risk dimensions: "
            "1. Confidence (how strongly available evidence supports the hypothesis), "
            "2. Severity (how harmful the observed behavior could be), "
            "3. Mission Impact (operational importance of affected assets), "
            "4. Urgency (how quickly the analyst should investigate). "
            "Explains key evidence drivers, cross-source corroboration, negative evidence penalties, and remaining uncertainty."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": _INCIDENT_ID_PARAM,
            },
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_detection_gaps",
        "description": (
            "Identify missing telemetry and unobserved intermediate tactics across the attack kill-chain for a candidate. "
            "Explicitly frames unobserved tactics as potential visibility/telemetry blindspots rather than proof of attacker absence. "
            "Use when answering 'What evidence are we missing?' or designing hunting queries."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": _INCIDENT_ID_PARAM,
            },
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "generate_bluf",
        "description": (
            "Generate a military-standard Bottom Line Up Front (BLUF) briefing for leadership from grounded ThreatFusion evidence. "
            "Includes: Bottom Line, Executive Commander Briefing, What Happened, Why It Matters, Supporting Evidence, "
            "Uncertainty & Boundaries (no unsupported attribution), and Grounded Next Steps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": _INCIDENT_ID_PARAM,
            },
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_remediation_runbook",
        "description": (
            "Retrieve prioritized, phased Incident Response runbooks for a candidate or incident. "
            "Separates Phase 1: Investigation & Telemetry Gathering (Immediate), Phase 2: Containment (Requires approval), "
            "Phase 3: Eradication (Requires approval), and Phase 4: Detection Engineering. "
            "Highlights prerequisites, target systems (Firewall, IAM, Endpoint), and operational impact."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": _INCIDENT_ID_PARAM,
            },
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_indicators",
        "description": (
            "Search for a specific IP address, hostname, username, CVE, IOC, or keyword across all raw observations "
            "and candidate hypotheses. Returns matching record IDs, timestamps, sources, provenance types, and associated candidate clusters."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "IP, hostname, username, CVE identifier, IOC, or keyword to search for (e.g. '185.214.66.91', 'ENG-DB01', 'CVE-2023-38831', 'powershell').",
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_domain_summary",
        "description": (
            "Retrieve multi-domain situational awareness telemetry breakdown across: "
            "1. Airspace (OpenSky flights & tracks), 2. Maritime (AIS vessels & dark vessels), "
            "3. Satellite EO (Copernicus Sentinel-1/2 SAR & Optical), 4. Thermal IR (NASA FIRMS hotspots), "
            "5. Weather/Environment (IMD observations & alerts), 6. Geospatial Infrastructure (ISRO Bhuvan), "
            "7. Geophysical (Copernicus EMS / USGS), 8. Cyber / C2 (SPARTA & OTRF). "
            "Provides counts, active sectors, and real-world provenance for Bob."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Optional specific domain filter ('airspace', 'maritime', 'satellite_eo', 'thermal_ir', 'weather_env', 'geospatial_infra', 'geophysical', 'cyber_c2').",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_geospatial_threats",
        "description": (
            "Query threats, tracks, and observations correlated within a specific strategic defence / border sector: "
            "'NORTHERN_LAC_LADAKH', 'WESTERN_BORDER_SIR_CREEK', 'SILIGURI_CORRIDOR', 'ANDAMAN_NICOBAR_EEZ', or 'CENTRAL_COMMAND_CORRIDOR'. "
            "Combines airspace tracks, maritime vessels, thermal anomalies, satellite SAR change scenes, and weather state."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sector": {
                    "type": "string",
                    "description": "Sector identifier (e.g. 'NORTHERN_LAC_LADAKH', 'WESTERN_BORDER_SIR_CREEK', 'SILIGURI_CORRIDOR', 'ANDAMAN_NICOBAR_EEZ').",
                },
            },
            "required": ["sector"],
            "additionalProperties": False,
        },
    },
]


def send_response(message: dict[str, Any]) -> None:
    """Write JSON-RPC message to stdout followed by newline."""
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def sanitize_output(obj: Any) -> Any:
    """Sanitize strings in tool output data to prevent prompt injection or markdown control sequence hijacking."""
    if isinstance(obj, str):
        cleaned = re.sub(r'(?i)<system>|</system>|<prompt>|</prompt>|```', '', obj)
        return cleaned.strip()
    if isinstance(obj, dict):
        return {k: sanitize_output(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_output(v) for v in obj]
    return obj


def load_engine_state() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load observations from persistent SQLite database or fall back to bundled demo data."""
    db_file = ROOT / "src" / "data" / "threatfusion.db"
    records = None
    assets = None
    if db_file.exists():
        try:
            records = get_all_alerts(db_file)
            assets = get_assets(db_file)
        except Exception:
            records = None
            assets = None
    analysis = analyze(ROOT, records=records, assets=assets)
    return analysis, analysis.get("incidents", [])


def find_candidate(candidate_id: str, all_candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Find a candidate hypothesis or promoted incident by ID, scenario label, or record ID."""
    if not all_candidates:
        return None
    clean_id = (candidate_id or "").strip().upper()
    if not clean_id:
        return None

    # 1. Exact match on candidate id
    for c in all_candidates:
        if c.get("id", "").upper() == clean_id:
            return c

    # 2. Scenario label match (e.g. INC-A, INC-B, INC-C, INC-D, INC-E or A, B, C, D, E)
    scenario_map = {
        "INC-A": "INC-CAND-09226FFA",
        "INC-B": "INC-CAND-6F2501EE",
        "INC-C": "INC-CAND-ED68597A",
        "INC-D": "INC-CAND-81F62494",
        "INC-E": "INC-CAND-B58A749C",
        "A": "INC-CAND-09226FFA",
        "B": "INC-CAND-6F2501EE",
        "C": "INC-CAND-ED68597A",
        "D": "INC-CAND-81F62494",
        "E": "INC-CAND-B58A749C",
    }
    if clean_id in scenario_map:
        mapped_id = scenario_map[clean_id]
        for c in all_candidates:
            if c.get("id", "").upper() == mapped_id.upper():
                return c

    # 3. Partial hash / substring match (only if length >= 4)
    if len(clean_id) >= 4 and not clean_id.startswith("INC-NONEXISTENT"):
        for c in all_candidates:
            cid = c.get("id", "").upper()
            if clean_id in cid or cid.endswith(clean_id):
                return c

    # 4. Check if candidate_id matches any record_id or entity inside the candidate
    for c in all_candidates:
        if clean_id in [str(r).upper() for r in c.get("record_ids", [])]:
            return c
        for a in c.get("assets", []):
            if clean_id == str(a.get("asset", "")).upper():
                return c

    return None


def _format_candidate_summary(c: dict[str, Any]) -> dict[str, Any]:
    """Format a compact, structured candidate summary for Bob."""
    is_promoted = bool(c.get("promotable"))
    checks = c.get("promotion_checks", {})
    reqs_met = [k for k, v in checks.items() if v]
    reqs_failed = [k for k, v in checks.items() if not v]

    techniques = [f"{t.get('technique')} {t.get('technique_name')}" for t in c.get("techniques", [])]
    assets = [a.get("asset") for a in c.get("assets", [])]

    return {
        "candidate_id": c.get("id"),
        "status": "promoted_incident" if is_promoted else "candidate",
        "promoted": is_promoted,
        "priority": c.get("priority"),
        "priority_score": c.get("priority_score"),
        "confidence": c.get("confidence"),
        "severity": c.get("severity"),
        "mission_impact": c.get("mission_impact"),
        "urgency": c.get("urgency"),
        "observation_count": len(c.get("record_ids", [])),
        "sources": c.get("sources", []),
        "frameworks": c.get("frameworks_present", ["MITRE ATT&CK"]),
        "top_techniques": techniques[:4],
        "affected_assets": assets,
        "promotion_summary": {
            "status": "PROMOTED INCIDENT" if is_promoted else "CANDIDATE HYPOTHESIS (NOT PROMOTED)",
            "requirements_met": reqs_met,
            "requirements_failed": reqs_failed,
        },
        "one_line_summary": (
            f"{c.get('priority')} incident on {', '.join(assets) if assets else 'corporate assets'} with {c.get('confidence')}% evidence confidence."
            if is_promoted else
            f"Unpromoted candidate on {', '.join(assets) if assets else 'endpoints'} (failed checks: {', '.join(reqs_failed) if reqs_failed else 'none'})."
        ),
    }


def execute_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute a registered MCP tool and return a structured dictionary."""
    analysis, all_candidates = load_engine_state()
    promoted_list = [c for c in all_candidates if c.get("promotable")]
    unpromoted_list = [c for c in all_candidates if not c.get("promotable")]

    # ── 1. correlate_events ──
    if name == "correlate_events":
        promoted_only = bool(args.get("promoted_only", False))
        target_candidates = promoted_list if promoted_only else all_candidates

        raw_count = len(analysis.get("records", []))
        cand_count = len(all_candidates)
        prom_count = len(promoted_list)
        unprom_count = len(unpromoted_list)
        compression = round(100 * (1 - cand_count / max(1, raw_count)), 1)

        return {
            "summary": (
                f"ThreatFusion correlated {raw_count} raw observations into {cand_count} candidate hypotheses "
                f"({prom_count} promoted incidents, {unprom_count} unpromoted candidates). "
                f"Alert reduction / compression ratio: {compression}%."
            ),
            "raw_observations_count": raw_count,
            "candidate_hypotheses_count": cand_count,
            "promoted_incidents_count": prom_count,
            "unpromoted_candidates_count": unprom_count,
            "compression_ratio_percent": compression,
            "candidates": [_format_candidate_summary(c) for c in target_candidates],
            "guidance_for_bob": (
                "For 'promoted_incident' items, report as verified incidents with supporting evidence. "
                "For 'candidate' items, explain that ThreatFusion kept them as hypotheses because they did not satisfy all promotion checks."
            ),
        }

    # ── 2. search_indicators ──
    if name == "search_indicators":
        query = str(args.get("query", "")).lower().strip()
        if not query:
            return {"query": "", "total_matches": 0, "matches": [], "message": "Please provide a non-empty search query."}

        record_to_candidate: dict[str, dict[str, Any]] = {}
        for c in all_candidates:
            cid = c.get("id")
            for rid in c.get("record_ids", []):
                record_to_candidate[rid] = {
                    "candidate_id": cid,
                    "promoted": c.get("promotable"),
                    "priority": c.get("priority"),
                }

        matches = []
        for r in analysis.get("records", []):
            raw_str = json.dumps(r).lower()
            if query in raw_str:
                rid = str(r.get("_id") or r.get("id"))
                cand_info = record_to_candidate.get(rid)
                matches.append({
                    "record_id": rid,
                    "timestamp": r.get("timestamp"),
                    "source": r.get("source"),
                    "host": r.get("host") or r.get("src_host") or r.get("dst_host"),
                    "user": r.get("user"),
                    "ip": r.get("ip") or r.get("src_ip") or r.get("dst_ip"),
                    "provenance_type": r.get("provenance_type", "synthetic"),
                    "dataset_name": r.get("dataset_name", "ThreatFusion Dataset"),
                    "summary": r.get("detail") or r.get("text") or r.get("event_type") or "Security event",
                    "associated_candidate": cand_info,
                })

        return {
            "query": query,
            "total_matches": len(matches),
            "matches": matches[:15],
            "note": f"Showing {min(15, len(matches))} of {len(matches)} matching observations across raw telemetry.",
        }

    # ── 3. get_domain_summary ──
    if name == "get_domain_summary":
        domain_filter = args.get("domain")
        from src.threatfusion.spatial import STRATEGIC_SECTORS

        records = analysis.get("records", [])
        domain_counts: dict[str, int] = {}
        sector_counts: dict[str, int] = {}
        domain_observations: dict[str, list[dict[str, Any]]] = {}

        for r in records:
            dom = r.get("domain") or ("cyber_c2" if r.get("source") in ("endpoint", "network_sensor", "siem", "threat_intel_report") else r.get("source", "other"))
            sec = r.get("sector") or "CENTRAL_COMMAND_CORRIDOR"
            domain_counts[dom] = domain_counts.get(dom, 0) + 1
            sector_counts[sec] = sector_counts.get(sec, 0) + 1

            if dom not in domain_observations:
                domain_observations[dom] = []
            if len(domain_observations[dom]) < 5:
                domain_observations[dom].append({
                    "record_id": str(r.get("_id") or r.get("id")),
                    "source": r.get("source"),
                    "domain": dom,
                    "event_type": r.get("event_type"),
                    "host": r.get("host"),
                    "latitude": r.get("latitude"),
                    "longitude": r.get("longitude"),
                    "sector": sec,
                    "summary": r.get("detail") or r.get("text") or "Multi-domain telemetry",
                    "dataset_name": r.get("dataset_name", "Public Data Source"),
                })

        return {
            "status": "ok",
            "total_records": len(records),
            "domain_counts": domain_counts,
            "sector_counts": sector_counts,
            "active_strategic_sectors": list(STRATEGIC_SECTORS.keys()),
            "domain_sample_observations": domain_observations if not domain_filter else {domain_filter: domain_observations.get(domain_filter, [])},
            "source_provenance_catalog": [
                {"domain": "airspace", "source": "OpenSky Network", "type": "Real civil ADS-B aircraft positions & squawks"},
                {"domain": "maritime", "source": "NOAA MarineCadastre AIS", "type": "Vessel traffic & dark vessel gaps"},
                {"domain": "satellite_eo", "source": "Copernicus Sentinel-1/2 & ISRO MOSDAC", "type": "SAR all-weather radar & multispectral optical"},
                {"domain": "thermal_ir", "source": "NASA FIRMS (MODIS/VIIRS)", "type": "Near-real-time active fire & thermal hotspots"},
                {"domain": "weather_env", "source": "India Meteorological Dept (IMD)", "type": "AWS radar observations, dense fog & sea-state bulletins"},
                {"domain": "geospatial_infra", "source": "ISRO Bhuvan / India OGD", "type": "Strategic forward airfields, naval bases, radar stations"},
                {"domain": "geophysical", "source": "USGS & Copernicus EMS", "type": "Real-time seismic feeds & rapid mapping activations"},
                {"domain": "cyber_c2", "source": "SPARTA / OTRF / CIC-IDS", "type": "Space TTPs, Sysmon, and network flow alerts"},
            ],
        }

    # ── 4. get_geospatial_threats ──
    if name == "get_geospatial_threats":
        target_sector = str(args.get("sector", "")).strip().upper()
        from src.threatfusion.spatial import get_sector_metadata, STRATEGIC_SECTORS

        if target_sector not in STRATEGIC_SECTORS:
            return {
                "error": f"Unknown sector '{target_sector}'.",
                "valid_sectors": list(STRATEGIC_SECTORS.keys()),
            }

        meta = get_sector_metadata(target_sector)
        matching_records = []
        for r in analysis.get("records", []):
            if r.get("sector") == target_sector or str(r.get("host", "")).find(target_sector) != -1:
                matching_records.append({
                    "record_id": str(r.get("_id") or r.get("id")),
                    "timestamp": r.get("timestamp"),
                    "source": r.get("source"),
                    "domain": r.get("domain", "multi_domain"),
                    "host": r.get("host"),
                    "latitude": r.get("latitude"),
                    "longitude": r.get("longitude"),
                    "summary": r.get("detail") or r.get("text") or "Sector observation",
                    "provenance": r.get("dataset_name", "Multi-domain feed"),
                })

        # Sector candidates
        sector_candidates = [
            _format_candidate_summary(c)
            for c in all_candidates
            if any(r.get("record_id") in c.get("record_ids", []) for r in matching_records)
        ]

        return {
            "sector": target_sector,
            "sector_name": meta.get("name"),
            "strategic_importance": meta.get("strategic_importance"),
            "primary_sensors": meta.get("primary_sensors"),
            "domain_focus": meta.get("domain_focus"),
            "coordinates_center": meta.get("center"),
            "matching_observations_count": len(matching_records),
            "observations": matching_records[:20],
            "correlated_candidate_clusters": sector_candidates,
        }

    # All subsequent tools require incident_id
    iid = str(args.get("incident_id", "")).strip()
    if not iid:
        return {"error": "Missing required argument 'incident_id'. Use correlate_events to discover active candidate IDs."}

    candidate = find_candidate(iid, all_candidates)
    if candidate is None:
        return {
            "error": f"Candidate or incident '{iid}' not found.",
            "available_candidate_ids": [c.get("id") for c in all_candidates[:8]],
            "guidance": "Call correlate_events to list all available candidate and incident IDs.",
        }

    # Enrich with database triage status if present
    db_item = None
    db_file = ROOT / "src" / "data" / "threatfusion.db"
    if db_file.exists():
        try:
            db_item = db_get_incident(iid, db_file)
        except Exception:
            db_item = None

    triage_status = db_item.get("status", "open") if db_item else "open"
    analyst_notes = db_item.get("analyst_notes", "") if db_item else ""
    is_promoted = bool(candidate.get("promotable"))
    checks = candidate.get("promotion_checks", {})
    reqs_met = [k for k, v in checks.items() if v]
    reqs_failed = [k for k, v in checks.items() if not v]

    # ── 3. get_incident ──
    if name == "get_incident":
        clean_techniques = [
            {
                "technique_id": t.get("technique"),
                "technique_name": t.get("technique_name"),
                "framework": t.get("framework", "MITRE ATT&CK"),
                "tactic": t.get("tactic"),
                "confidence": t.get("confidence"),
                "reason": t.get("reason"),
                "record_id": t.get("record_id"),
                "timestamp": t.get("timestamp"),
            }
            for t in candidate.get("techniques", [])
        ]

        clean_evidence = [
            {
                "record_id": ev.get("record_id"),
                "timestamp": ev.get("timestamp"),
                "source": ev.get("source"),
                "summary": ev.get("summary"),
                "technique": ev.get("technique"),
                "technique_name": ev.get("technique_name"),
                "framework": ev.get("framework"),
                "ioc_evidence": bool(ev.get("ioc_evidence")),
                "provenance_type": ev.get("provenance_type", "synthetic"),
                "dataset_name": ev.get("dataset_name", "ThreatFusion Dataset"),
                "threatfox_match": ev.get("threatfox_match"),
                "cisa_kev_match": ev.get("cisa_kev_match"),
            }
            for ev in candidate.get("evidence", [])
        ]

        return {
            "candidate_id": candidate.get("id"),
            "status": "promoted_incident" if is_promoted else "candidate",
            "triage_status": triage_status,
            "analyst_notes": analyst_notes,
            "priority": candidate.get("priority"),
            "priority_score": candidate.get("priority_score"),
            "human_summary": (
                f"{candidate.get('priority')} incident with {candidate.get('confidence')}% evidence confidence "
                f"targeting {', '.join(a.get('asset') for a in candidate.get('assets', [])) or 'corporate systems'}."
                if is_promoted else
                f"Candidate hypothesis (not promoted) on {', '.join(a.get('asset') for a in candidate.get('assets', [])) or 'endpoints'}."
            ),
            "affected_assets": candidate.get("assets", []),
            "observation_count": len(candidate.get("record_ids", [])),
            "sources": candidate.get("sources", []),
            "frameworks_present": candidate.get("frameworks_present", ["MITRE ATT&CK"]),
            "provenance_summary": candidate.get("provenance_summary", {}),
            "techniques": clean_techniques,
            "attack_flow": candidate.get("attack_flow", {}),
            "scoring": {
                "confidence": {
                    "score": candidate.get("confidence"),
                    "interpretation": "High confidence supported by multiple independent feeds and observable techniques." if candidate.get("confidence", 0) >= 80 else "Moderate/low confidence.",
                },
                "severity": {
                    "score": candidate.get("severity"),
                    "interpretation": "High behavioral severity." if candidate.get("severity", 0) >= 80 else "Moderate/low behavioral severity.",
                },
                "mission_impact": {
                    "score": candidate.get("mission_impact"),
                    "interpretation": f"Impacts mission-critical assets (score: {candidate.get('mission_impact')}/100)." if candidate.get("mission_impact", 0) >= 80 else "Standard corporate impact.",
                },
                "urgency": {
                    "score": candidate.get("urgency"),
                    "interpretation": "Immediate response recommended." if candidate.get("urgency", 0) >= 80 else "Standard priority investigation.",
                },
            },
            "promotion": {
                "promoted": is_promoted,
                "status_label": "PROMOTED INCIDENT" if is_promoted else "CANDIDATE HYPOTHESIS",
                "requirements_met": reqs_met,
                "requirements_failed": reqs_failed,
                "reason": (
                    "Passed all 4 promotion gates: behavioral evidence, progression coherence, confidence, and source independence."
                    if is_promoted else
                    f"Did not meet all promotion gates. Failed: {', '.join(reqs_failed)}."
                ),
            },
            "evidence_observations": clean_evidence,
            "negative_evidence": candidate.get("negative_evidence", []),
            "contradictions_found": len(candidate.get("negative_evidence", [])) > 0,
            "actor_similarity": {
                "top_matches": candidate.get("actor_similarity", []),
                "guidance": "Historical technique overlap is provided for behavioral context only and does NOT constitute actor attribution.",
            },
            "investigation_gaps": candidate.get("attack_flow", {}).get("unobserved_intermediate_tactics", []),
            "recommended_next_steps": (candidate.get("bluf") or bluf(candidate)).get("recommended_actions", []),
            "bluf": candidate.get("bluf") or bluf(candidate),
            "runbook": candidate.get("runbook") or remediation_runbook(candidate),
        }

    # ── 4. explain_risk ──
    if name == "explain_risk":
        assets_names = [a.get("asset") for a in candidate.get("assets", [])]
        rf = candidate.get("risk_factors", {})
        gaps = candidate.get("attack_flow", {}).get("unobserved_intermediate_tactics", [])

        return {
            "candidate_id": candidate.get("id"),
            "status": "promoted_incident" if is_promoted else "candidate",
            "overall_priority": {
                "priority": candidate.get("priority"),
                "priority_score": candidate.get("priority_score"),
                "explanation": (
                    f"Operational priority {candidate.get('priority')} (Score: {candidate.get('priority_score')}/100) "
                    f"derived deterministically from Confidence ({candidate.get('confidence')}%), Severity ({candidate.get('severity')}/100), "
                    f"Mission Impact ({candidate.get('mission_impact')}/100), and Urgency ({candidate.get('urgency')}/100)."
                ),
            },
            "dimensions": {
                "confidence": {
                    "score": candidate.get("confidence"),
                    "meaning": "How strongly the available evidence supports the hypothesis.",
                    "drivers": [
                        f"Behavior confidence: {rf.get('behavior_confidence', 0)}%",
                        f"Source corroboration: {rf.get('source_corroboration', 0)}% across {len(candidate.get('sources', []))} independent feeds",
                        f"Source quality score: {rf.get('source_quality', 0)}/100",
                        f"IOC specificity: {rf.get('ioc_specificity', 0)}%",
                    ],
                },
                "severity": {
                    "score": candidate.get("severity"),
                    "meaning": "How harmful the observed behavior could be.",
                    "drivers": [
                        f"Attack-flow coherence score: {rf.get('attack_flow_coherence', 0)}%",
                        f"Verified techniques present: {len(candidate.get('techniques', []))}",
                        f"Has CISA KEV exploit: {bool(candidate.get('has_cisa_kev_exploit'))}",
                        f"Has ThreatFox C2 corroboration: {bool(candidate.get('has_threatfox_corroboration'))}",
                    ],
                },
                "mission_impact": {
                    "score": candidate.get("mission_impact"),
                    "meaning": "How important the affected asset/environment is.",
                    "affected_assets": candidate.get("assets", []),
                    "criticality_summary": f"Highest asset criticality is {candidate.get('asset_criticality', 50)}/100 on {', '.join(assets_names) if assets_names else 'endpoints'}.",
                },
                "urgency": {
                    "score": candidate.get("urgency"),
                    "meaning": "How quickly the analyst should investigate based on the available evidence.",
                    "drivers": [
                        "Active kill-chain progression detected" if candidate.get("attack_flow", {}).get("progression", 0) > 0.5 else "Early stage activity",
                        f"Source independence: {round(candidate.get('source_independence', 0) * 100, 1)}%",
                    ],
                },
            },
            "negative_evidence_and_penalties": {
                "penalties_applied": rf.get("contradiction_penalty", 0),
                "negative_evidence_count": len(candidate.get("negative_evidence", [])),
                "items": candidate.get("negative_evidence", []),
            },
            "uncertainty_and_limitations": [
                f"Unobserved intermediate tactics: {', '.join(gaps)}" if gaps else "No intermediate tactic gaps in attack progression.",
                "Technique overlap with historical threat actors is not attribution.",
            ],
            "frameworks_present": candidate.get("frameworks_present", ["MITRE ATT&CK"]),
            "provenance_summary": candidate.get("provenance_summary", {}),
        }

    # ── 5. get_detection_gaps ──
    if name == "get_detection_gaps":
        observed_tactics = sorted({e["tactic"] for e in candidate.get("techniques", [])}, key=lambda t: TACTIC_RANK.get(t, 999))
        unobserved_gaps = candidate.get("attack_flow", {}).get("unobserved_intermediate_tactics", [])

        inferred_missing = []
        if "persistence" in unobserved_gaps:
            inferred_missing.append("Registry / Run-key persistence telemetry and scheduled task creation logs.")
        if "privilege-escalation" in unobserved_gaps:
            inferred_missing.append("Process token manipulation and local privilege elevation telemetry.")
        if "defense-evasion" in unobserved_gaps:
            inferred_missing.append("Log-clearing, binary tampering, or process injection detection telemetry.")
        if "credential-access" in unobserved_gaps:
            inferred_missing.append("LSASS memory access (Sysmon Event ID 10) and Kerberos ticket request logs.")
        if "discovery" in unobserved_gaps:
            inferred_missing.append("Account and network discovery command execution logs (whoami, net view).")

        return {
            "candidate_id": candidate.get("id"),
            "status": "promoted_incident" if is_promoted else "candidate",
            "observed_tactics": observed_tactics,
            "unobserved_intermediate_tactics": unobserved_gaps,
            "inferred_missing_telemetry_types": inferred_missing,
            "guidance_for_bob": (
                "Explicitly explain that unobserved tactics may indicate a telemetry visibility gap "
                "rather than evidence that the attacker skipped those phases."
            ),
        }

    # ── 6. generate_bluf ──
    if name == "generate_bluf":
        bluf_data = candidate.get("bluf") or bluf(candidate)
        assets_names = [a.get("asset") for a in candidate.get("assets", [])]
        fw_name = " & ".join(candidate.get("frameworks_present", ["MITRE ATT&CK"]))

        return {
            "candidate_id": candidate.get("id"),
            "status": "promoted_incident" if is_promoted else "candidate",
            "priority": candidate.get("priority"),
            "priority_score": candidate.get("priority_score"),
            "bottom_line": bluf_data.get("bottom_line"),
            "commander_briefing": bluf_data.get("commander_briefing"),
            "what_happened": (
                f"Correlated multi-stage security telemetry targeting {', '.join(assets_names) if assets_names else 'systems'} "
                f"across {len(candidate.get('sources', []))} independent feeds ({', '.join(candidate.get('sources', []))})."
            ),
            "why_it_matters": (
                f"Activity involves verified {fw_name} attacker techniques affecting an asset with mission criticality {candidate.get('mission_impact')}/100. "
                f"Evidence confidence is scored at {candidate.get('confidence')}% with threat severity {candidate.get('severity')}/100."
            ),
            "key_evidence": [
                f"{t.get('technique')} {t.get('technique_name')} ({t.get('tactic')})"
                for t in candidate.get("techniques", [])[:5]
            ],
            "uncertainty_and_boundaries": bluf_data.get("uncertainty"),
            "actor_assessment": bluf_data.get("actor_assessment"),
            "recommended_next_steps": bluf_data.get("recommended_actions", []),
        }

    # ── 7. get_remediation_runbook ──
    if name == "get_remediation_runbook":
        raw_steps = candidate.get("runbook") or remediation_runbook(candidate)
        assets_names = [a.get("asset") for a in candidate.get("assets", [])]

        phased_actions: dict[str, list[dict[str, Any]]] = {
            "Investigation & Telemetry Gathering": [
                {
                    "action": f"Collect memory dump, live process trees, and auth logs from {', '.join(assets_names) if assets_names else 'affected hosts'}.",
                    "priority": "Immediate",
                    "target": "Endpoint / EDR",
                    "requires_approval": False,
                }
            ],
            "Containment": [],
            "Eradication": [],
            "Detection Engineering": [],
        }

        for step in raw_steps:
            phase = step.get("phase", "Containment")
            if phase not in phased_actions:
                phased_actions[phase] = []
            phased_actions[phase].append({
                "action": step.get("action"),
                "priority": step.get("priority", "High"),
                "target": step.get("target", "Infrastructure"),
                "requires_approval": phase in ("Containment", "Eradication"),
            })

        return {
            "candidate_id": candidate.get("id"),
            "status": "promoted_incident" if is_promoted else "candidate",
            "priority": candidate.get("priority"),
            "operational_safety_notice": (
                "Remediation actions in Containment and Eradication require analyst review and authorization before execution. "
                "ThreatFusion does NOT execute disruptive containment autonomously."
            ),
            "phased_runbook": phased_actions,
        }

    return {"error": f"Unknown tool '{name}'"}


def tool_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Compatibility alias for execute_tool."""
    return execute_tool(name, args)


def main() -> None:
    """Main JSON-RPC stdio event loop."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            mid = req.get("id")
            method = req.get("method")

            if method == "initialize":
                client_ver = (req.get("params") or {}).get("protocolVersion")
                negotiated = client_ver if client_ver in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
                send_response({
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": negotiated,
                        "capabilities": {
                            "tools": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": SERVER_NAME,
                            "version": SERVER_VERSION,
                        },
                    },
                })
            elif method == "notifications/initialized":
                continue
            elif method == "ping":
                send_response({"jsonrpc": "2.0", "id": mid, "result": {}})
            elif method == "tools/list":
                send_response({
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"tools": TOOLS},
                })
            elif method == "tools/call":
                params = req.get("params") or {}
                tool_name = params.get("name")
                tool_args = params.get("arguments") or {}
                result_obj = execute_tool(tool_name, tool_args)
                sanitized_result = sanitize_output(result_obj)
                is_error = isinstance(sanitized_result, dict) and "error" in sanitized_result

                send_response({
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(sanitized_result, indent=2),
                            }
                        ],
                        "isError": is_error,
                    },
                })
            else:
                send_response({
                    "jsonrpc": "2.0",
                    "id": mid,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}",
                    },
                })
        except Exception as exc:
            send_response({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": f"Internal MCP server error: {exc}",
                },
            })


if __name__ == "__main__":
    main()
