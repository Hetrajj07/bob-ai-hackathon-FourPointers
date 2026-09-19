#!/usr/bin/env python3
"""Small MCP stdio server for ThreatFusion.

It exposes read-only investigation tools backed by the deterministic engine.
No ground-truth labels are used during tool execution.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Allow both `python src/mcp_server.py` and `python -m src.mcp_server`.
sys.path.insert(0, str(ROOT))

from src.threatfusion.db import get_all_alerts, get_assets, get_incident as db_get_incident, init_db  # noqa: E402
from src.threatfusion.engine import ENGINE_VERSION, TACTIC_RANK, analyze, bluf, clear_context_cache, promoted_incidents, remediation_runbook  # noqa: E402

SERVER_VERSION = ENGINE_VERSION
# Explicitly document and negotiate supported Model Context Protocol versions.
SUPPORTED_PROTOCOL_VERSIONS = ["2026-07-28", "2025-06-18", "2024-11-05"]
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

_INCIDENT_ID_PROP = {
    "incident_id": {
        "type": "string",
        "description": (
            "ThreatFusion promoted incident identifier returned by correlate_events, "
            "e.g. INC-CAND-ABC12345. Use correlate_events first if you do not have an ID."
        ),
    }
}

TOOLS = [
    {
        "name": "correlate_events",
        "description": (
            "Run the deterministic ThreatFusion analysis over the bundled demo telemetry. "
            "Returns promoted incident IDs, priority scores, confidence, mission impact, and "
            "raw/candidate/promoted counts. Call this first to discover incident IDs before "
            "using any other tool."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_incident",
        "description": (
            "Retrieve full grounded evidence, ATT&CK technique/tactic mapping, risk factors, "
            "per-record provenance, asset context, and a BLUF for one promoted incident. "
            "Use when you need the complete picture of a case."
        ),
        "inputSchema": {"type": "object", "properties": _INCIDENT_ID_PROP, "required": ["incident_id"], "additionalProperties": False},
    },
    {
        "name": "explain_risk",
        "description": (
            "Return the deterministic risk decomposition used to prioritize an incident: "
            "evidence confidence, threat severity, mission impact, urgency, source independence, "
            "and any negative evidence penalties. Use when an analyst asks why a case was scored high or low."
        ),
        "inputSchema": {"type": "object", "properties": _INCIDENT_ID_PROP, "required": ["incident_id"], "additionalProperties": False},
    },
    {
        "name": "get_detection_gaps",
        "description": (
            "Return observed ATT&CK tactics and any intermediate tactics not observed between "
            "the first and last observed tactic. Absence is explicitly treated as a possible "
            "telemetry gap, not proof the attacker did not perform that phase."
        ),
        "inputSchema": {"type": "object", "properties": _INCIDENT_ID_PROP, "required": ["incident_id"], "additionalProperties": False},
    },
    {
        "name": "generate_bluf",
        "description": (
            "Generate a commander-ready Bottom Line Up Front from grounded incident evidence "
            "and deterministic scores. Includes bottom line, assessment, actor context (not attribution), "
            "uncertainty, and recommended analyst actions."
        ),
        "inputSchema": {"type": "object", "properties": _INCIDENT_ID_PROP, "required": ["incident_id"], "additionalProperties": False},
    },
    {
        "name": "get_remediation_runbook",
        "description": (
            "Retrieve prioritized analyst-reviewed response steps for an incident, organised by phase "
            "(Containment, Eradication, Detection Engineering). Steps require analyst approval; "
            "ThreatFusion does not perform autonomous containment."
        ),
        "inputSchema": {"type": "object", "properties": _INCIDENT_ID_PROP, "required": ["incident_id"], "additionalProperties": False},
    },
    {
        "name": "search_indicators",
        "description": (
            "Search for a specific IP address, hostname, username, IOC, or keyword across all "
            "raw observations and correlated hypotheses. Returns matching record IDs, timestamps, "
            "sources, and snippets. Limit 10 results."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "IP address, hostname, username, IOC value, or keyword to search for, "
                        "e.g. '185.214.66.91', 'ENG-DB01', 'jsharma', 'powershell'."
                    ),
                }
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
]


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def promoted():
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
    d = analyze(ROOT, records=records, assets=assets)
    return d, promoted_incidents(d)


def find_incident(iid: str, incidents):
    return next((x for x in incidents if x["id"] == iid), None)


def tool_call(name: str, args: dict):
    d, incidents = promoted()
    if name == "correlate_events":
        return {
            "raw_observations": len(d["records"]),
            "candidate_hypotheses": len(d["incidents"]),
            "promoted_incidents": len(incidents),
            "incidents": [{k: x[k] for k in ("id", "priority", "priority_score", "confidence", "mission_impact", "urgency", "record_ids")} for x in incidents],
        }

    if name == "search_indicators":
        q = str(args.get("query", "")).lower().strip()
        if not q:
            return {"matches": [], "query": q, "total_matches": 0}
        matches = []
        for r in d["records"]:
            raw_str = json.dumps(r).lower()
            if q in raw_str:
                matches.append({
                    "record_id": r.get("_id") or r.get("id"),
                    "timestamp": r["timestamp"],
                    "source": r.get("source"),
                    "matched_snippet": r.get("detail") or r.get("text") or r.get("event_type") or "event",
                })
        return {"query": q, "total_matches": len(matches), "matches": matches[:10]}

    iid = args.get("incident_id")
    x = find_incident(iid, incidents) if iid else None
    if x is None:
        return {"error": f"Unknown incident {iid}"}

    db_item = None
    db_file = ROOT / "src" / "data" / "threatfusion.db"
    if db_file.exists():
        try:
            db_item = db_get_incident(iid, db_file)
        except Exception:
            db_item = None

    status = db_item.get("status", "open") if db_item else "open"
    notes = db_item.get("analyst_notes", "") if db_item else ""

    if name == "get_incident":
        return {**x, "status": status, "analyst_notes": notes, "bluf": bluf(x)}
    if name == "explain_risk":
        return {
            "priority": x["priority"],
            "priority_score": x["priority_score"],
            "confidence": x["confidence"],
            "severity": x["severity"],
            "mission_impact": x["mission_impact"],
            "urgency": x["urgency"],
            "risk_factors": x["risk_factors"],
            "source_independence": x["source_independence"],
            "negative_evidence": x["negative_evidence"],
        }
    if name == "get_detection_gaps":
        return {
            "observed_tactics": sorted({e["tactic"] for e in x["techniques"]}, key=lambda t: TACTIC_RANK.get(t, 999)),
            "unobserved_intermediate_tactics": x["attack_flow"].get("unobserved_intermediate_tactics", []),
            "note": "An unobserved tactic may indicate a telemetry gap; it is not proof that the adversary did not perform it.",
        }
    if name == "generate_bluf":
        return bluf(x)
    if name == "get_remediation_runbook":
        return {
            "incident_id": x["id"],
            "priority": x["priority"],
            "runbook": x.get("runbook") or remediation_runbook(x),
        }
    return {"error": f"Unknown tool {name}"}


def main() -> None:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        req = None
        try:
            req = json.loads(line)
            mid = req.get("id")
            method = req.get("method")
            if method == "initialize":
                client_ver = (req.get("params") or {}).get("protocolVersion")
                negotiated = client_ver if client_ver in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
                send({
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": negotiated,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "threatfusion-mcp", "version": SERVER_VERSION},
                    },
                })
            elif method == "notifications/initialized":
                continue
            elif method == "ping":
                send({"jsonrpc": "2.0", "id": mid, "result": {}})
            elif method == "tools/list":
                send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
            elif method == "tools/call":
                params = req.get("params") or {}
                obj = tool_call(params.get("name"), params.get("arguments") or {})
                is_error = isinstance(obj, dict) and "error" in obj
                send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": json.dumps(obj, indent=2)}], "isError": is_error}})
            else:
                send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}})
        except Exception as exc:
            send({"jsonrpc": "2.0", "id": req.get("id") if isinstance(req, dict) else None, "error": {"code": -32000, "message": str(exc)}})


if __name__ == "__main__":
    main()
