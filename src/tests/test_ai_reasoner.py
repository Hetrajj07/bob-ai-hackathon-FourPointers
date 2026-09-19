"""Unit tests for the Grounded AI Reasoner and IBM Bob assistant."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.threatfusion.ai_reasoner import get_ai_reasoner


def _sample_incident():
    return {
        "id": "INC-TEST-99",
        "priority": "P1",
        "priority_score": 93,
        "confidence": 92.1,
        "severity": 92,
        "mission_impact": 95,
        "urgency": 97,
        "sources": ["endpoint", "network_sensor", "siem", "threat_intel_report"],
        "record_ids": ["REC-0001", "REC-0002", "REC-0003", "REC-0004"],
        "assets": [{"asset": "ENG-DB01", "criticality": 95}],
        "techniques": [
            {"technique": "T1566.001", "technique_name": "Spearphishing Attachment", "reason": "phishing attachment opened"},
            {"technique": "T1059.001", "technique_name": "PowerShell", "reason": "encoded command"},
            {"technique": "T1003.001", "technique_name": "LSASS Memory", "reason": "credential dumping detected"},
        ],
        "risk_factors": {"attack_flow_coherence": 87.8},
        "negative_evidence": [],
        "attack_flow": {"unobserved_intermediate_tactics": ["persistence"]},
        "runbook": [
            {"phase": "Containment", "priority": "Immediate", "action": "Isolate ENG-DB01", "target": "Firewall"}
        ],
    }


def test_ai_reasoner_explain_priority():
    reasoner = get_ai_reasoner()
    inc = _sample_incident()
    res = reasoner.ask(inc, "Why is this case high priority?")
    assert "P1" in res["answer"]
    assert "93/100" in res["answer"]
    assert "92.1%" in res["answer"]
    assert "ENG-DB01" in res["answer"]
    assert len(res["grounded_facts"]) > 0


def test_ai_reasoner_explain_evidence():
    reasoner = get_ai_reasoner()
    inc = _sample_incident()
    res = reasoner.ask(inc, "What evidence supports this attack?")
    assert "Spearphishing Attachment" in res["answer"]
    assert "PowerShell" in res["answer"]
    assert "4 correlated alerts" in res["answer"]


def test_ai_reasoner_explain_contradictions():
    reasoner = get_ai_reasoner()
    inc = _sample_incident()
    res = reasoner.ask(inc, "What evidence is weak or contradictory?")
    assert "persistence" in res["answer"]
    assert "sensor visibility gap" in res["answer"]


def test_ai_reasoner_suggest_next_steps():
    reasoner = get_ai_reasoner()
    inc = _sample_incident()
    res = reasoner.ask(inc, "What should I investigate next?")
    assert "ENG-DB01" in res["answer"]
    assert "Isolate ENG-DB01" in res["answer"]


def test_ai_reasoner_explain_simple():
    reasoner = get_ai_reasoner()
    inc = _sample_incident()
    res = reasoner.ask(inc, "Explain this incident in simple language.")
    assert "ENG-DB01" in res["answer"]
    assert "P1 High-Confidence Case" in res["answer"]


def test_ai_reasoner_empty_incident():
    reasoner = get_ai_reasoner()
    res = reasoner.ask({}, "Why priority?")
    assert "No incident data provided" in res["answer"]


def test_ai_reasoner_answers_common_free_text_questions_from_case_facts():
    reasoner = get_ai_reasoner()
    inc = _sample_incident()
    assert "ENG-DB01" in reasoner.ask(inc, "Which asset is affected?")["answer"]
    assert "4 correlated alerts" in reasoner.ask(inc, "How many alerts are there?")["answer"]
    assert "endpoint" in reasoner.ask(inc, "Which telemetry sources support it?")["answer"]
    assert "cannot answer" in reasoner.ask(inc, "Who is the attacker?")["answer"]
