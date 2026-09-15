import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ROOT = Path(__file__).resolve().parents[1]
from threatfusion.engine import (
    analyze, normalize, tag_technique, promoted_incidents, bluf,
    remediation_runbook, temporal_decay, negative_evidence, extract_entities,
    actor_assessment, actor_similarity, attack_flow, edge_strength,
    text_of, _as_string_list, asset_criticality, clear_context_cache,
    candidate_clusters, score_cluster, _canonical_entity_value,
)


def test_runtime_does_not_promote_from_ground_truth():
    d = analyze(ROOT.parent)
    assert d["metadata"]["ground_truth_used_for_runtime"] is False
    assert len(promoted_incidents(d)) == 1


def test_real_incident_uses_precise_attack_subtechniques():
    d = analyze(ROOT.parent)
    incident = promoted_incidents(d)[0]
    tids = [e["technique"] for e in incident["techniques"]]
    assert "T1566.001" in tids
    assert "T1059.001" in tids
    assert "T1003.001" in tids
    assert "T1021.001" in tids


def test_public_ip_is_not_automatically_an_ioc():
    raw = {"_id":"X", "timestamp":"2026-09-15T00:00:00Z", "source":"network_sensor", "dst_ip":"52.55.10.23"}
    n = normalize(raw)
    assert ("ioc", "52.55.10.23") not in n["entities"]
    assert ("ip", "52.55.10.23") in n["entities"]


def test_entity_keys_normalize_casing_and_indicator_strings():
    raw = {"_id": "X", "timestamp": "2026-09-15T00:00:00Z", "source": "siem", "host": "eng-wks17.", "user": "JSharma", "ioc": "185.214.66.91"}
    entities = extract_entities(raw)
    assert ("host", "ENG-WKS17") in entities
    assert ("user", "jsharma") in entities
    assert ("ioc", "185.214.66.91") in entities


def test_evidence_includes_the_resolved_attack_technique_name():
    d = analyze(ROOT.parent)
    incident = promoted_incidents(d)[0]
    mapped = [record for record in incident["evidence"] if record["technique"]]
    assert mapped
    assert all(record["technique_name"] for record in mapped)


def test_normalize_rejects_malformed_observations():
    try:
        normalize({"_id": "broken", "timestamp": "not-a-timestamp"})
    except ValueError as exc:
        assert "invalid timestamp" in str(exc)
    else:
        raise AssertionError("Malformed timestamps must fail clearly")


def test_rdp_requires_rdp_evidence():
    techniques = {"T1021.001":{"name":"Remote Desktop Protocol","tactics":["lateral-movement"]}}
    bad = {"timestamp":"2026-09-15T00:00:00Z","source":"siem","event_type":"remote_logon","detail":"unexpected login"}
    good = {"timestamp":"2026-09-15T00:00:00Z","source":"siem","event_type":"remote_logon","protocol":"RDP","dst_port":3389}
    assert tag_technique(bad, techniques)[0] is None
    assert tag_technique(good, techniques)[0] == "T1021.001"


def test_bluf_has_uncertainty_language():
    d = analyze(ROOT.parent)
    b = bluf(promoted_incidents(d)[0])
    assert "not attribution" in b["actor_assessment"]
    assert b["recommended_actions"]


def test_actor_assessment_does_not_select_an_arbitrary_tied_group():
    assessment = actor_assessment([
        {"group": "APT-A", "similarity": 70.0},
        {"group": "APT-B", "similarity": 70.0},
    ])
    assert "multiple historical groups" in assessment
    assert "not attribution" in assessment


def test_remediation_runbook_contains_phased_actions():
    d = analyze(ROOT.parent)
    incident = promoted_incidents(d)[0]
    rb = incident.get("runbook") or remediation_runbook(incident)
    assert len(rb) >= 3
    phases = {step["phase"] for step in rb}
    assert "Containment" in phases
    assert "Eradication" in phases


def test_runbook_lists_each_affected_asset_once():
    d = analyze(ROOT.parent)
    incident = promoted_incidents(d)[0]
    containment = next(step for step in incident["runbook"] if step["phase"] == "Containment")
    assert containment["action"].count("ENG-WKS17") == 1
    assert containment["action"].count("ENG-DB01") == 1


def test_temporal_decay_continuous_curve():
    assert temporal_decay(0.0) == 1.0
    assert 0.35 < temporal_decay(30.0, tau=30.0) < 0.38
    assert temporal_decay(90.0, tau=30.0) < 0.06


def test_negative_evidence_penalties():
    cluster = [
        {"id": "TEST-01", "raw": {"event_type": "antivirus_scan_clean"}},
        {"id": "TEST-02", "raw": {"detail": "routine maintenance by known admin"}},
    ]
    negs = negative_evidence(cluster)
    assert len(negs) == 2
    factors = [n["factor"] for n in negs]
    assert "clean antivirus result" in factors
    assert "approved administrative context" in factors


def test_text_of_excludes_structural_keys():
    """A record ID containing a technique keyword must not trigger a false match."""
    raw = {
        "_id": "lsass_benign_test",
        "timestamp": "2026-09-15T00:00:00Z",
        "source": "endpoint",
        "format": "json",
        "event_type": "normal_process_start",
        "process": "notepad.exe",
    }
    t = text_of(raw)
    # _id is excluded, so "lsass" should NOT appear in the text
    assert "lsass" not in t
    # But semantic fields are preserved
    assert "notepad" in t
    techniques = {"T1003.001": {"name": "LSASS Memory", "tactics": ["credential-access"]}}
    tid, _, _ = tag_technique(raw, techniques)
    assert tid is None, "Record ID 'lsass_benign_test' should not trigger T1003.001"


def test_identical_timestamps_edge_strength():
    """Two events at exactly the same time with a shared entity should get full decay."""
    a = normalize({"_id": "A", "timestamp": "2026-09-15T08:00:00Z", "source": "siem", "host": "SRV01"})
    b = normalize({"_id": "B", "timestamp": "2026-09-15T08:00:00Z", "source": "endpoint", "host": "SRV01"})
    strength, reasons = edge_strength(a, b)
    assert strength > 0.0
    assert "shared:host" in reasons


def test_plural_iocs_field():
    """The engine handles the plural 'iocs' field alongside singular 'ioc'."""
    raw = {
        "_id": "MULTI",
        "timestamp": "2026-09-15T00:00:00Z",
        "source": "threat_intel_report",
        "text": "Campaign alert",
        "iocs": ["10.20.30.40", "evil.example.com"],
    }
    entities = extract_entities(raw)
    assert ("ioc", "10.20.30.40") in entities
    assert ("ioc", "evil.example.com") in entities


def test_attack_flow_single_event():
    """A single technique event returns score 0 with sane defaults."""
    events = [{"technique": "T1566.001", "tactic": "initial-access", "tactic_rank": 2, "timestamp": "2026-09-15T08:00:00Z"}]
    flow = attack_flow(events)
    assert flow["score"] == 0.0
    assert flow["depth"] == 0.25
    assert flow["transitions"] == []


def test_attack_flow_empty_events():
    """Zero technique events returns score 0 with depth 0."""
    flow = attack_flow([])
    assert flow["score"] == 0.0
    assert flow["depth"] == 0.0
    assert flow["transitions"] == []


def test_actor_similarity_empty_observed():
    """No observed techniques returns an empty match list."""
    result = actor_similarity([], [{"group": "APT-X", "technique_id": "T1566.001"}])
    assert result == []


def test_asset_criticality_lowercase_host_in_raw():
    """A lowercase host in raw data should still match the uppercased asset registry."""
    cluster = [{
        "hosts": [],
        "raw": {"src_host": "eng-db01", "dst_host": None},
    }]
    assets = {"ENG-DB01": {"criticality": 95, "mission_role": "Engineering database", "zone": "mission-critical"}}
    score, hits = asset_criticality(cluster, assets)
    assert score == 95
    assert len(hits) == 1
    assert hits[0]["asset"] == "ENG-DB01"


def test_normalize_rejects_falsy_id():
    """Records with _id=0, _id='', or missing _id should be rejected."""
    for bad_id in [0, "", None]:
        try:
            normalize({"_id": bad_id, "timestamp": "2026-09-15T00:00:00Z"})
        except ValueError as exc:
            assert "missing" in str(exc).lower()
        else:
            raise AssertionError(f"_id={bad_id!r} should have been rejected")


def test_clear_context_cache():
    """Clearing the cache does not raise and allows re-analysis."""
    clear_context_cache()
    d = analyze(ROOT.parent)
    assert d["metadata"]["engine_version"]
    clear_context_cache()  # should not raise
