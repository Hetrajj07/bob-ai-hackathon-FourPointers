# ThreatFusion — Evidence-Backed Threat Intelligence Correlation

> **IBM BoB AI Innovation Hackathon 2026 · D2 — Threat Intelligence Correlation & Alert Prioritisation Assistant**

ThreatFusion turns fragmented cyber observations into evidence-backed attack hypotheses, prioritizes them by evidence confidence, threat severity, mission impact and urgency, and lets IBM Bob investigate the same grounded evidence through MCP.

## Team

| Field | Value |
|---|---|
| Team Name | Four-Pointers |
| Track | AI |
| Team Lead | Hetraj Rana — ranahetraj@gmail.com |
| Members | Aaryan Patel (patel.aaryan336@gmail.com) · Dhruv Gajera (dhruvgajera39@gmail.com) · Hit Goyani (hitgoyani01@gmail.com) |

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

The bundled demo contains **62 synthetic observations** from four source types (SIEM, endpoint sensor, network telemetry, and CTI advisory) spanning three attack days. The engine produces **5 candidate hypotheses** and promotes **4** evidence-backed incidents (3× P1, 1× P2). The fifth candidate is deliberately weak and is not promoted.
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

## Defense Telemetry Ingestion

Use **Load Defense Feed** in the dashboard to ingest the bundled 18-record
production-shaped telemetry feed. It contains CTI, SIEM, EDR, and network
sensor records, including a correlated intrusion sequence and benign traffic.
The feed is intentionally synthetic and safe to share; it is not customer or
live security data. Regenerate it with:

```bash
python src/data/generate_defense_telemetry.py
```

It can also be loaded programmatically with:

```bash
curl -X POST http://127.0.0.1:8000/api/datasets/defense-telemetry
```

For Bob/MCP setup, see [`docs/setup-guide.md`](docs/setup-guide.md).

## Demo

- Demo video: [`demo/demo-video-link.txt`](demo/demo-video-link.txt) — replace the local-only value with a real 3–5 minute hosted URL before submission
- Live demo: [`demo/live-demo-url.txt`](demo/live-demo-url.txt)
- Screenshots: [`demo/screenshots/`](demo/screenshots/)
- Presentation: [`presentation/ThreatFusion.pptx`](presentation/ThreatFusion.pptx)

## Validation

The repository passes the structural GitHub Actions checks in [`.github/workflows/validate.yml`](.github/workflows/validate.yml): required files, valid YAML, non-empty source code, and basic template replacement. The workflow does **not** verify that the demo link is publicly accessible, that the video is 3–5 minutes, or that screenshots match the current build; those are manual final-submission checks.

## Known Limitations

This is an evidence-backed hackathon prototype with production-oriented architecture using synthetic multi-source telemetry and a bundled ATT&CK reference snapshot. It is not a production SOC, does not perform autonomous containment, and does not claim real threat-actor attribution. The local preview in `demo/ThreatFusion_demo.mp4` is for local reproducibility only; record and host the final walkthrough described in `demo/demo-video-script.md` before submission.

## What We're Most Proud Of

The core innovation is the separation of **candidate clustering** from **incident promotion**. A shared entity creates a hypothesis; ATT&CK evidence, behavior coherence, corroboration, contradictions and asset context determine whether it deserves escalation. Runtime never reads the benchmark truth labels, and IBM Bob can interrogate the grounded result through MCP.

## Research Notes

See [`docs/research-notes.md`](docs/research-notes.md) for the design references and [`docs/evaluation.md`](docs/evaluation.md) for the reproducible synthetic benchmark.
