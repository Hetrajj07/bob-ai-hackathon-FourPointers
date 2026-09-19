# Setup Guide

## Prerequisites

- Python 3.11 or newer
- Git
- IBM Bob (only needed for the optional MCP workflow)

## Install

From the repository root:

```bash
git clone https://github.com/Hetrajj07/bob-ai-hackathon-FourPointers.git
cd bob-ai-hackathon-FourPointers
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r src/requirements.txt
```

## Run the dashboard

```bash
python -m uvicorn src.app:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000.

## Run tests

```bash
python -m pytest -q src/tests
```

Expected result: **35 passed**.

## Run the offline evaluation

The benchmark uses `src/data/ground_truth.json` only in this offline script. Runtime application and MCP promotion never read those labels.

```bash
python src/evaluate.py
```

The output is a small synthetic-dataset evaluation and must not be interpreted as a production accuracy claim.

## IBM Bob + MCP

IBM Bob supports project-level MCP configuration in `.bob/mcp.json`. The included configuration uses local STDIO transport and sets the project root as the working directory.

1. Open this repository as the workspace in IBM Bob.
2. Open Bob settings → MCP and ensure MCP servers are enabled.
3. Confirm the `threatfusion` server appears.
4. Try `/investigate INC-CAND-...` using the incident ID shown by the dashboard.
5. Try `/explain INC-CAND-...` and `/bluf INC-CAND-...`.

The MCP server is read-only and exposes `correlate_events`, `get_incident`, `explain_risk`, `get_detection_gaps`, `generate_bluf`, `get_remediation_runbook`, and `search_indicators`.

## Troubleshooting

| Issue | Fix |
|---|---|
| `ModuleNotFoundError` | Activate `.venv` and run `python -m pip install -r src/requirements.txt`. |
| Dashboard does not load | Confirm port 8000 is free, then retry the uvicorn command. |
| Bob cannot start MCP | Open the repository root as the Bob workspace and check `.bob/mcp.json`; use `python` available on PATH. |
| Bob sees no tools | Enable MCP servers in Bob settings, then restart/reload the workspace. |
| No promoted incident | Run the offline test suite; inspect `src/data/demo_alerts.json` and the technique mappings. |
