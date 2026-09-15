import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ROOT = Path(__file__).resolve().parents[1]
from threatfusion.engine import analyze, normalize, tag_technique, promoted_incidents, bluf, remediation_runbook, temporal_decay, negative_evidence, extract_entities, actor_assessment


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
