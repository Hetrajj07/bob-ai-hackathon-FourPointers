# ThreatFusion source

`src/` contains the runnable D2 vertical slice.

- `app.py` — FastAPI dashboard and read-only API.
- `mcp_server.py` — local STDIO MCP server for IBM Bob.
- `evaluate.py` — offline benchmark; never used by runtime promotion.
- `threatfusion/engine.py` — normalization, candidate clustering, ATT&CK mapping, attack-flow analysis, risk and BLUF.
- `data/` — synthetic telemetry, benchmark labels, and demo asset context.
- `reference/` — bundled ATT&CK/group extracts.
- `tests/` — deterministic regression tests.

The runtime path does **not** load `ground_truth.json`. It is intentionally isolated to the offline evaluation script.
