"""Multi-source telemetry normalizer for ThreatFusion.

Normalizes raw feeds from:
- OTRF Security Datasets (Sysmon / Windows Event Logs)
- CIC-IDS2017 (Network flow sensor telemetry)
- Space / Satellite Telemetry (SPARTA TTP mapped)
- Standard SIEM & CTI observation records
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

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
    }
    if attack_hint:
        canonical["attack_id_hint"] = attack_hint
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
        "event_type": "network_flow_alert",
        "host": sensor,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": "RDP" if dst_port == 3389 else ("SSH" if dst_port == 22 else proto),
        "detail": detail,
        "label": label,
        "origin": "CIC-IDS2017 Dataset",
    }
    return canonical


def auto_normalize(record: dict[str, Any]) -> dict[str, Any]:
    """Automatically detect input record schema and convert to canonical ThreatFusion event."""
    if "EventID" in record and ("EventData" in record or "SourceName" in record):
        return normalize_otrf(record)
    if "FlowID" in record or ("TotalFwdPackets" in record and "DestinationIp" in record):
        return normalize_cicids(record)

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
    return rec
