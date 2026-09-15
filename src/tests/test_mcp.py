import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_server import tool_call, TOOLS


def test_mcp_tool_definitions():
    tool_names = [t["name"] for t in TOOLS]
    assert "correlate_events" in tool_names
    assert "get_incident" in tool_names
    assert "explain_risk" in tool_names
    assert "get_detection_gaps" in tool_names
    assert "generate_bluf" in tool_names
    assert "get_remediation_runbook" in tool_names
    assert "search_indicators" in tool_names


def test_mcp_correlate_and_investigate():
    res = tool_call("correlate_events", {})
    assert res["raw_observations"] == 62
    assert res["promoted_incidents"] >= 1
    iid = res["incidents"][0]["id"]

    inc_res = tool_call("get_incident", {"incident_id": iid})
    assert inc_res["id"] == iid
    assert "bluf" in inc_res

    risk_res = tool_call("explain_risk", {"incident_id": iid})
    assert "confidence" in risk_res
    assert "severity" in risk_res
    assert "mission_impact" in risk_res

    gap_res = tool_call("get_detection_gaps", {"incident_id": iid})
    assert "observed_tactics" in gap_res

    rb_res = tool_call("get_remediation_runbook", {"incident_id": iid})
    assert len(rb_res["runbook"]) > 0


def test_mcp_indicator_search():
    res = tool_call("search_indicators", {"query": "185.214.66.91"})
    assert res["total_matches"] > 0
    assert any("REC-0004" == m["record_id"] for m in res["matches"])
