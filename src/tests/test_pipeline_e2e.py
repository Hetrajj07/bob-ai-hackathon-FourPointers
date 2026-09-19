"""End-to-end pipeline verification for all telemetry types and CTI feeds."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from src.threatfusion.normalizer import normalize_otrf, normalize_cicids, auto_normalize
from src.threatfusion.enrichment import enrich_record
from src.threatfusion.engine import analyze, clear_context_cache, promoted_incidents

ROOT = Path(__file__).resolve().parents[2]


def test_otrf_pipeline_end_to_end():
    otrf_file = ROOT / "src" / "data" / "real" / "otrf_sample.json"
    assert otrf_file.exists()
    with otrf_file.open(encoding="utf-8") as f:
        raw_events = json.load(f)

    # 1. Normalize and enrich all sample events
    normalized = []
    for ev in raw_events:
        norm = normalize_otrf(ev)
        assert norm["provenance_type"] == "real_sample"
        assert norm["dataset_name"] == "OTRF Security Datasets"
        enriched = enrich_record(norm, root=ROOT)
        assert enriched["provenance_type"] == "real_sample"  # Provenance preserved
        normalized.append(enriched)

    # 2. Correlate through ThreatFusion engine
    analysis = analyze(ROOT, records=normalized)
    assert len(analysis["incidents"]) >= 1
    cand = analysis["incidents"][0]

    # 3. Provenance preserved in cluster
    assert cand["provenance_summary"]["real_sample_count"] == len(normalized)
    assert cand["provenance_summary"]["synthetic_count"] == 0
    assert "OTRF Security Datasets" in cand["provenance_summary"]["datasets"]

    # 4. Scoring & Promotion checks
    assert cand["confidence"] > 0
    assert cand["priority"] in ("P1", "P2", "P3", "P4")
    assert cand["techniques"][0]["framework"] == "MITRE ATT&CK"


def test_cicids_pipeline_end_to_end():
    # 1. Raw CIC-IDS flow with C2 IP
    raw_flow = {
        "FlowID": "10.40.2.15-185.214.66.91-51234-443-6",
        "SourceIp": "10.40.2.15",
        "SourcePort": 51234,
        "DestinationIp": "185.214.66.91",
        "DestinationPort": 443,
        "Protocol": "TCP",
        "Timestamp": "2026-09-18T14:28:40Z",
        "Label": "Botnet-C2-Beaconing",
        "SensorHost": "NET-PROBE-CORE01",
    }
    # 2. Normalization & Provenance
    norm = normalize_cicids(raw_flow)
    assert norm["provenance_type"] == "real_sample"
    assert norm["dataset_name"] == "CIC-IDS2017"
    assert norm["dataset_label"] == "Botnet-C2-Beaconing"

    # 3. Enrichment against local curated ThreatFox CTI snapshot
    enriched = enrich_record(norm, root=ROOT)
    assert enriched["provenance_type"] == "real_sample"
    assert enriched.get("threatfox_match") is not None
    assert enriched["threatfox_match"]["provenance"] == "curated_snapshot"
    assert enriched["threatfox_match"]["malware"] == "Cobalt Strike"


def test_sparta_satellite_pipeline_end_to_end():
    sat_file = ROOT / "src" / "data" / "space" / "satellite_demo.json"
    assert sat_file.exists()
    with sat_file.open(encoding="utf-8") as f:
        records = json.load(f)

    for r in records:
        assert r["provenance_type"] == "synthetic"
        assert "SPARTA" in r["dataset_name"]

    analysis = analyze(ROOT, records=records)
    assert len(analysis["incidents"]) >= 1
    sparta_cluster = analysis["incidents"][0]
    assert sparta_cluster["has_sparta_taxonomy"] is True
    assert "SPARTA" in sparta_cluster["frameworks_present"]
    assert sparta_cluster["provenance_summary"]["synthetic_count"] == len(records)
    assert sparta_cluster["provenance_summary"]["real_sample_count"] == 0
