"""Unit tests for the MITRE ATT&CK RAG Vector Store and Hybrid Mapping."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.threatfusion.vector_store import AttackVectorStore, get_vector_store
from src.threatfusion.engine import hybrid_tag_technique, load_context


def test_vector_store_initialization():
    vs = get_vector_store()
    assert vs.count() == 697
    assert vs.get_technique("T1059.001") is not None
    assert vs.get_technique("T1059.001")["name"] == "PowerShell"


def test_vector_store_semantic_search():
    vs = get_vector_store()
    
    # PowerShell search
    ps_matches = vs.search("encoded powershell script execution with winword parent", top_k=3)
    assert ps_matches
    assert ps_matches[0]["technique_id"] == "T1059.001"
    assert ps_matches[0]["score"] > 0.15

    # Phishing search
    phish_matches = vs.search("spearphishing email attachment invoice docm", top_k=3)
    assert phish_matches
    assert any("T1566" in m["technique_id"] for m in phish_matches)

    # Credential dumping search
    cred_matches = vs.search("lsass process memory credential dumping attempt", top_k=3)
    assert cred_matches
    assert any("T1003" in m["technique_id"] for m in cred_matches)

    # Empty query
    assert vs.search("") == []
    assert vs.search("   ") == []


def test_vector_store_tactic_filter():
    vs = get_vector_store()
    matches = vs.search("remote desktop protocol connection", top_k=5, tactic_filter="lateral-movement")
    assert matches
    for m in matches:
        assert "lateral-movement" in [t.lower() for t in m["tactics"]]


def test_hybrid_tag_technique_agreement():
    _, techniques, _, _, _ = load_context(str(ROOT))
    vs = get_vector_store()

    # Rule and semantic agree on PowerShell
    raw_ps = {
        "source": "endpoint",
        "process": "powershell.exe",
        "parent_process": "winword.exe",
        "cmdline": "-enc JAB... encoded powershell command",
    }
    tid, conf, why, meta = hybrid_tag_technique(raw_ps, techniques, vs)
    assert tid == "T1059.001"
    assert meta["agreement"] == "confirmed"
    assert "Supported by retrieved ATT&CK description" in why
    assert conf >= 0.94


def test_hybrid_tag_technique_semantic_discovery():
    _, techniques, _, _, _ = load_context(str(ROOT))
    vs = get_vector_store()

    # Telemetry with no matching explicit rule, but clear semantic description
    raw_desc = {
        "source": "threat_intel_report",
        "text": "adversaries abusing living off the land binaries and powershell scripts to automate tasks",
    }
    tid, conf, why, meta = hybrid_tag_technique(raw_desc, techniques, vs)
    assert tid is not None
    assert meta["semantic_technique"] is not None
