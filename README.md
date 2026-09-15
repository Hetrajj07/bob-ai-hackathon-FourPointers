# ThreatFusion — Evidence-Backed Threat Intelligence Correlation

> **IBM BoB AI Innovation Hackathon 2026 · D2 — Threat Intelligence Correlation & Alert Prioritisation Assistant**

ThreatFusion turns fragmented cyber observations into evidence-backed attack hypotheses, prioritizes them by evidence confidence, threat severity, mission impact and urgency, and lets IBM Bob investigate the same grounded evidence through MCP.

## Team

| Field | Value |
|---|---|
| Team Name | Four-Pointers |
| Track | AI |
| Team Lead | Hetraj Rana — ranahetraj@gmail.com |
| Members | Aaryan Patel (patel.aaryan336@gmail.com) · Dhruv Gajera (dhruvgajera39@gmail.com) · Hit Goyani (hitgoyani01@gmai.com) |

## Problem Statement

Defence analysts receive heterogeneous SIEM, endpoint, network-sensor and intelligence observations that are difficult to correlate without over-grouping routine activity. The operational gap is not a lack of alerts; it is the difficulty of turning many observations into a small number of evidence-backed threat hypotheses and commander-ready decisions.

## Solution

ThreatFusion first creates **candidate hypotheses** using weighted entity relationships and temporal decay. It then validates those candidates with ATT&CK technique/sub-technique evidence, attack-flow coherence, source independence, negative evidence and asset context before promoting only the strongest hypotheses to incidents. IBM Bob accesses the resulting evidence through MCP and generates investigation explanations and BLUFs without inventing the underlying score.

## Key Features

- **Evidence-first correlation:** entity-specific weights, temporal decay and source diversity.
- **ATT&CK-aware inference:** auditable sub-technique mapping with per-record rationale and provenance.
- **Attack-flow reasoning:** progression/depth/backtrack analysis rather than simple alert counting.
- **Explainable prioritization:** confidence, threat severity, mission impact and urgency are separate dimensions.
- **IBM Bob investigation:** project MCP server plus `/investigate`, `/explain`, `/bluf` and `/runbook` workflows.

## Demo Dataset & ATT&CK Reference

The bundled demo contains **37 synthetic observations** from four source types (SIEM, endpoint sensor, network telemetry, and CTI advisory) and produces **2 candidate hypotheses**; the engine promotes **1** evidence-backed incident. The second candidate is deliberately weak and is not promoted.
The bundled MITRE ATT&CK reference data is sourced from the **MITRE ATT&CK v19.2** release (August 2026 update), providing structured techniques, tactics, groups, and sub-technique mappings.

## Tech Stack

| Category | Technologies |
|---|---|
| Languages | Python, JavaScript, HTML/CSS |
| Frameworks | FastAPI, Uvicorn |
| IBM Technologies | IBM Bob, project-level MCP workflow |
| Knowledge | MITRE ATT&CK v19.2 reference snapshot |
| Other | pytest, JSON-RPC 2.0 over STDIO, Mermaid |

## Repository Structure

```text
├── .bob/                       # Bob MCP config, commands and skill
├── src/
│   ├── app.py                 # FastAPI dashboard/API
│   ├── mcp_server.py          # Bob MCP server
│   ├── evaluate.py            # Offline benchmark; never used by runtime
│   ├── threatfusion/engine.py # Core intelligence engine
│   ├── data/                  # Synthetic telemetry + asset context
│   ├── reference/             # ATT&CK/group extracts
│   └── tests/                 # Deterministic tests
├── docs/                      # Problem, solution, architecture, setup, evaluation
├── demo/                      # Screenshots + local demo video
├── presentation/              # Slide deck
└── submission.yaml            # Evaluator metadata
```

## How to Run

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r src/requirements.txt
python -m pytest -q src/tests
python -m uvicorn src.app:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

For Bob/MCP setup, see [`docs/setup-guide.md`](docs/setup-guide.md).

## Demo

- Demo video: [`demo/demo-video-link.txt`](demo/demo-video-link.txt)
- Live demo: [`demo/live-demo-url.txt`](demo/live-demo-url.txt)
- Screenshots: [`demo/screenshots/`](demo/screenshots/)
- Presentation: [`presentation/ThreatFusion_D2.pptx`](presentation/ThreatFusion_D2.pptx)

## Validation

The repository is structurally compliant with all automated GitHub Actions checks (`.github/workflows/validate.yml`), which verify required files, valid YAML schema, non-empty source code in `src/`, non-placeholder demo link format, and replacement of all template placeholders.

## Known Limitations

This is an evidence-backed hackathon prototype with production-oriented architecture using synthetic multi-source telemetry and a bundled ATT&CK reference snapshot. It is not a production SOC, does not perform autonomous containment, and does not claim real threat-actor attribution. The local walk-through video is included in `demo/ThreatFusion_demo.mp4` for local reproducibility; a public hosted link is pending external hosting upload prior to final submission.

## What We're Most Proud Of

The core innovation is the separation of **candidate clustering** from **incident promotion**. A shared entity creates a hypothesis; ATT&CK evidence, behavior coherence, corroboration, contradictions and asset context determine whether it deserves escalation. Runtime never reads the benchmark truth labels, and IBM Bob can interrogate the grounded result through MCP.

## Research Notes

See [`docs/research-notes.md`](docs/research-notes.md) for the design references and [`docs/evaluation.md`](docs/evaluation.md) for the reproducible synthetic benchmark.
