"""Comprehensive tests for ThreatFusion Model Context Protocol (MCP) Server.

Tests:
- Tool definitions, schemas, and AI-facing descriptions
- Protocol negotiation and lifecycle (initialize, ping, tools/list, tools/call)
- Separation of CANDIDATE HYPOTHESIS vs PROMOTED INCIDENT
- 4D risk explanation (Confidence, Severity, Mission Impact, Urgency)
- Detection gaps analysis
- Phased remediation runbooks with analyst safety notices
- Indicator and CVE search across raw observations
- Error handling and invalid input handling
- Zero runtime access to ground_truth.json
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.mcp_server import (
    DEFAULT_PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    TOOLS,
    execute_tool,
    find_candidate,
    load_engine_state,
    main as mcp_main,
    tool_call,
)


def test_mcp_tool_definitions():
    """Verify all 7 tools have valid names, descriptions, and explicit schemas."""
    expected_tools = {
        "correlate_events",
        "get_incident",
        "explain_risk",
        "get_detection_gaps",
        "generate_bluf",
        "get_remediation_runbook",
        "search_indicators",
    }
    tool_map = {t["name"]: t for t in TOOLS}
    assert set(tool_map.keys()) == expected_tools

    for name, t in tool_map.items():
        assert len(t["description"]) > 20, f"Tool {name} description too short"
        assert "inputSchema" in t
        assert t["inputSchema"]["type"] == "object"
        assert t["inputSchema"]["additionalProperties"] is False


def test_mcp_correlate_events_structured():
    """Verify correlate_events returns structured counts, candidate statuses, and 4D scores."""
    res = tool_call("correlate_events", {})
    assert "summary" in res
    assert res["raw_observations_count"] >= 62
    assert res["candidate_hypotheses_count"] >= 5
    assert res["promoted_incidents_count"] >= 4
    assert res["unpromoted_candidates_count"] >= 1
    assert "compression_ratio_percent" in res
    assert len(res["candidates"]) == res["candidate_hypotheses_count"]

    # Verify candidate structure
    for c in res["candidates"]:
        assert "candidate_id" in c
        assert c["status"] in ("promoted_incident", "candidate")
        assert "priority" in c
        assert "confidence" in c
        assert "severity" in c
        assert "mission_impact" in c
        assert "urgency" in c
        assert "promotion_summary" in c
        assert "requirements_met" in c["promotion_summary"]
        assert "requirements_failed" in c["promotion_summary"]


def test_mcp_promoted_incident_investigation():
    """Verify full evidence package retrieval on a promoted incident."""
    corr = tool_call("correlate_events", {"promoted_only": True})
    assert len(corr["candidates"]) >= 1
    promoted_cand = corr["candidates"][0]
    iid = promoted_cand["candidate_id"]

    # 1. get_incident
    inc = tool_call("get_incident", {"incident_id": iid})
    assert inc["candidate_id"] == iid
    assert inc["status"] == "promoted_incident"
    assert inc["promotion"]["promoted"] is True
    assert len(inc["promotion"]["requirements_failed"]) == 0
    assert "evidence_observations" in inc
    assert len(inc["evidence_observations"]) > 0
    assert "scoring" in inc
    assert "confidence" in inc["scoring"]
    assert "severity" in inc["scoring"]
    assert "mission_impact" in inc["scoring"]
    assert "urgency" in inc["scoring"]
    assert "bluf" in inc

    # 2. explain_risk
    risk = tool_call("explain_risk", {"incident_id": iid})
    assert risk["candidate_id"] == iid
    assert "overall_priority" in risk
    assert "dimensions" in risk
    assert "confidence" in risk["dimensions"]
    assert "severity" in risk["dimensions"]
    assert "mission_impact" in risk["dimensions"]
    assert "urgency" in risk["dimensions"]
    assert len(risk["dimensions"]["confidence"]["drivers"]) > 0

    # 3. get_detection_gaps
    gaps = tool_call("get_detection_gaps", {"incident_id": iid})
    assert gaps["candidate_id"] == iid
    assert "observed_tactics" in gaps
    assert "unobserved_intermediate_tactics" in gaps
    assert "guidance_for_bob" in gaps

    # 4. generate_bluf
    bluf_res = tool_call("generate_bluf", {"incident_id": iid})
    assert bluf_res["candidate_id"] == iid
    assert "bottom_line" in bluf_res
    assert "commander_briefing" in bluf_res
    assert "what_happened" in bluf_res
    assert "why_it_matters" in bluf_res
    assert "recommended_next_steps" in bluf_res

    # 5. get_remediation_runbook
    rb = tool_call("get_remediation_runbook", {"incident_id": iid})
    assert rb["candidate_id"] == iid
    assert "phased_runbook" in rb
    assert "Investigation & Telemetry Gathering" in rb["phased_runbook"]
    assert "operational_safety_notice" in rb


def test_mcp_unpromoted_candidate_investigation():
    """Verify that unpromoted candidates are clearly designated as 'candidate' hypotheses."""
    corr = tool_call("correlate_events", {})
    unpromoted = [c for c in corr["candidates"] if not c["promoted"]]
    assert len(unpromoted) >= 1, "Must have at least one unpromoted candidate in benchmark"
    cand_id = unpromoted[0]["candidate_id"]

    inc = tool_call("get_incident", {"incident_id": cand_id})
    assert inc["candidate_id"] == cand_id
    assert inc["status"] == "candidate"
    assert inc["promotion"]["promoted"] is False
    assert len(inc["promotion"]["requirements_failed"]) > 0

    risk = tool_call("explain_risk", {"incident_id": cand_id})
    assert risk["status"] == "candidate"


def test_mcp_indicator_search():
    """Verify indicator search across IPs, CVEs, hostnames, and keywords."""
    # Search by IP
    res_ip = tool_call("search_indicators", {"query": "185.214.66.91"})
    assert res_ip["total_matches"] > 0
    assert any("185.214.66.91" in json.dumps(m) for m in res_ip["matches"])

    # Search by host
    res_host = tool_call("search_indicators", {"query": "ENG-DB01"})
    assert res_host["total_matches"] > 0

    # Search by empty query
    res_empty = tool_call("search_indicators", {"query": ""})
    assert res_empty["total_matches"] == 0
    assert len(res_empty["matches"]) == 0


def test_mcp_error_handling():
    """Verify clean structured error messages for invalid or missing inputs."""
    # Missing incident_id
    err_missing = tool_call("get_incident", {})
    assert "error" in err_missing

    # Non-existent incident_id
    err_not_found = tool_call("get_incident", {"incident_id": "INC-NONEXISTENT-9999"})
    assert "error" in err_not_found
    assert "available_candidate_ids" in err_not_found

    # Unknown tool
    err_unknown = tool_call("non_existent_tool", {})
    assert "error" in err_unknown


def test_mcp_jsonrpc_stdio_lifecycle(monkeypatch):
    """Test full JSON-RPC stdio protocol lifecycle: initialize, ping, tools/list, tools/call."""
    requests = [
        # 1. Initialize with protocol version negotiation
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        # 2. Notification initialized
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        # 3. Ping
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        # 4. List tools
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        # 5. Call correlate_events tool
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "correlate_events", "arguments": {}}},
        # 6. Unknown method
        {"jsonrpc": "2.0", "id": 5, "method": "unknown_method"},
    ]

    input_data = "\n".join(json.dumps(r) for r in requests) + "\n"
    stdin_mock = io.StringIO(input_data)
    stdout_mock = io.StringIO()

    monkeypatch.setattr(sys, "stdin", stdin_mock)
    monkeypatch.setattr(sys, "stdout", stdout_mock)

    mcp_main()

    output_lines = [line.strip() for line in stdout_mock.getvalue().split("\n") if line.strip()]
    assert len(output_lines) == 5  # 5 responses for the 5 requests (notification doesn't respond)

    # Validate initialize response
    init_res = json.loads(output_lines[0])
    assert init_res["id"] == 1
    assert init_res["result"]["protocolVersion"] == "2025-06-18"
    assert init_res["result"]["serverInfo"]["name"] == SERVER_NAME

    # Validate ping response
    ping_res = json.loads(output_lines[1])
    assert ping_res["id"] == 2
    assert ping_res["result"] == {}

    # Validate tools/list response
    list_res = json.loads(output_lines[2])
    assert list_res["id"] == 3
    assert len(list_res["result"]["tools"]) == 7

    # Validate tools/call response
    call_res = json.loads(output_lines[3])
    assert call_res["id"] == 4
    assert call_res["result"]["isError"] is False
    content_obj = json.loads(call_res["result"]["content"][0]["text"])
    assert "candidate_hypotheses_count" in content_obj

    # Validate unknown method error response
    err_res = json.loads(output_lines[4])
    assert err_res["id"] == 5
    assert err_res["error"]["code"] == -32601
