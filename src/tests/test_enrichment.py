from __future__ import annotations

from pathlib import Path
import pytest

from src.threatfusion.enrichment import lookup_threatfox, check_cisa_kev, enrich_record

ROOT = Path(__file__).resolve().parents[2]


def test_lookup_threatfox():
    match = lookup_threatfox("185.214.66.91", root=ROOT)
    assert match is not None
    assert "Cobalt Strike" in match.get("malware_printable", "") or "Cobalt Strike" in match.get("threat_type_desc", "")
    assert match.get("confidence_level") == 100

    no_match = lookup_threatfox("127.0.0.1", root=ROOT)
    assert no_match is None


def test_check_cisa_kev():
    match = check_cisa_kev("CVE-2023-34362", root=ROOT)
    assert match is not None
    assert "MOVEit" in match.get("vulnerabilityName", "") or "MOVEit" in match.get("shortDescription", "")

    no_match = check_cisa_kev("CVE-1999-000000", root=ROOT)
    assert no_match is None


def test_enrich_record():
    record = {
        "_id": "TEST-REC-01",
        "timestamp": "2026-09-18T14:30:00Z",
        "source": "network_sensor",
        "dst_ip": "185.214.66.91",
        "detail": "Outbound connection to known C2 node",
    }
    enriched = enrich_record(record, root=ROOT)
    assert enriched.get("threatfox_match") is not None
    assert enriched.get("threat_actor_hint") == "Cobalt Strike"
