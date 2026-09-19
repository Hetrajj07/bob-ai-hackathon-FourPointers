"""Generate realistic but synthetic telemetry for the defense-console demo.

This is not captured customer telemetry. Fields mirror common SIEM, EDR, NDR,
and CTI exports so the ingestion route can be demonstrated safely and locally.

Run from the repository root:
    python src/data/generate_defense_telemetry.py
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


OUTPUT = Path(__file__).with_name("defense_telemetry.json")
BASE = datetime(2026, 9, 19, 8, 30, tzinfo=timezone.utc)


def stamp(minute: int) -> str:
    return (BASE + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z")


def record(number: int, minute: int, **fields: object) -> dict[str, object]:
    return {"_id": f"DEF-20260919-{number:03d}", "timestamp": stamp(minute), **fields}


def build_dataset() -> list[dict[str, object]]:
    """Return a multi-source intrusion chain plus unrelated operational noise."""
    ioc, host, user = "203.0.113.77", "FIN-SRV01", "a.kapoor"
    attack = [
        record(1, 0, source="threat_intel_report", format="stix", ioc=ioc,
               text=f"High-confidence CTI indicator {ioc} associated with credential-phishing and C2 activity.",
               attack_id_hint="T1566.001"),
        record(2, 2, source="siem", format="cef", host=host, user=user,
               event_type="email_attachment_opened", detail="winword.exe opened Benefits_Update_2026.docm attachment"),
        record(3, 3, source="endpoint", format="edr", host=host, user=user,
               process="powershell.exe", parent_process="winword.exe", cmdline="-enc JAB3AGMAPQAi..."),
        record(4, 5, source="network_sensor", format="zeek", host=host, src_ip="10.42.18.25",
               dst_ip=ioc, dst_port=443, protocol="HTTPS", detail="new outbound TLS session with low-prevalence destination"),
        record(5, 9, source="endpoint", format="edr", host=host, user=user,
               process="rundll32.exe", parent_process="powershell.exe", detail="suspicious DLL execution after encoded PowerShell"),
        record(6, 12, source="endpoint", format="edr", host=host, user=user,
               process="procdump64.exe", detail="credential access attempt against lsass.exe"),
        record(7, 16, source="siem", format="cef", src_host=host, dst_host="ENG-DB01", user="svc_finops",
               event_type="remote_logon", protocol="RDP", dst_port=3389,
               detail="remote desktop logon outside approved change window"),
        record(8, 18, source="network_sensor", format="zeek", host="ENG-DB01", src_ip="10.42.18.25",
               dst_ip=ioc, dst_port=443, protocol="HTTPS", detail="follow-on encrypted connection to CTI-matched infrastructure"),
        record(9, 20, source="threat_intel_report", format="stix", ioc=ioc,
               text=f"Indicator {ioc} reputation updated: command-and-control infrastructure, confidence high."),
    ]
    normal = [
        record(10, -12, source="siem", host="HR-WKS03", user="m.ross", event_type="password_reset", detail="self-service password reset completed"),
        record(11, -7, source="endpoint", host="HR-WKS03", process="teams.exe", parent_process="explorer.exe"),
        record(12, -3, source="network_sensor", src_ip="10.42.5.14", dst_ip="198.51.100.20", dst_port=443, protocol="HTTPS", detail="approved SaaS traffic"),
        record(13, 7, source="siem", host="CORP-114", user="n.singh", event_type="vpn_connect", detail="MFA verified remote access"),
        record(14, 10, source="endpoint", host="CORP-209", process="excel.exe", parent_process="explorer.exe"),
        record(15, 13, source="siem", host="CORE-SW01", event_type="antivirus_scan_clean", detail="scheduled scan completed clean"),
        record(16, 15, source="network_sensor", src_ip="10.42.7.31", dst_ip="192.0.2.44", dst_port=443, protocol="TCP", detail="software update download"),
        record(17, 22, source="siem", host="CORP-301", user="p.iyer", event_type="badge_swipe_anomaly", detail="resolved by facilities team"),
        record(18, 27, source="endpoint", host="CORP-118", process="outlook.exe", parent_process="explorer.exe"),
    ]
    return attack + normal


if __name__ == "__main__":
    records = build_dataset()
    OUTPUT.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(records)} synthetic defense telemetry records to {OUTPUT}")
