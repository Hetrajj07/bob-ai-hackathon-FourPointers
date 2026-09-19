# ThreatFusion — Evidence-Backed Threat Intelligence Correlation

> **IBM BoB AI Innovation Hackathon 2026 · Challenge: Threat Intelligence Correlation & Alert Prioritisation Assistant**

ThreatFusion turns heterogeneous security alerts across SIEM systems, satellite feeds, cyber sensors, and intelligence reports into evidence-backed attack hypotheses, eliminates false positives, maps behaviors to MITRE ATT&CK, prioritizes incidents across 4 risk dimensions, and empowers IBM Bob to generate structured commander-ready BLUF briefings through MCP.

## Team

| Field | Value |
|---|---|
| Team Name | Four-Pointers |
| Track | AI |
| Team Lead | Hetraj Rana — ranahetraj@gmail.com |
| Members | Aaryan Patel (patel.aaryan336@gmail.com) · Dhruv Gajera (dhruvgajera39@gmail.com) · Hit Goyani (hitgoyani01@gmail.com) |

## Problem Statement

> *"Defence analysts receive thousands of alerts daily from SIEM systems, satellite feeds, cyber sensors, and intelligence reports — all in different formats. No human team can read them all. Missing a genuine threat is catastrophic; chasing false positives wastes critical resources. Threat assessments must also be produced in structured BLUF (Bottom Line Up Front) format so commanders get a clear picture in minutes.*
>
> **Your Challenge**: *Build a Bob solution that ingests multi-source threat feeds, correlates alerts to separate genuine threats from false positives, maps attacker techniques to the MITRE ATT&CK framework, and generates prioritised BLUF investigation summaries for commanders."*

## Solution

ThreatFusion ingests heterogeneous feeds (SIEM, satellite downlink/telemetry feeds, endpoint/network cyber sensors, CTI advisories) into an embedded persistent SQLite database. It forms **candidate hypotheses** using an inverted entity index, relationship-weighted edge scoring, and continuous temporal decay. It then rigorously tests candidates against observable MITRE ATT&CK v19.2 sub-technique evidence, multi-stage attack-flow coherence, source independence, and negative evidence—promoting only confirmed threats into incidents while filtering out false positives. IBM Bob queries this persistent evidence base through MCP to produce structured, commander-ready BLUFs.

## Key Features

- **Multi-Source Feed Ingestion:** Ingests and normalizes SIEM, satellite ground/downlink sensors, cyber sensors, and CTI feeds with persistent SQLite storage.
- **Evidence-First Correlation:** Inverted entity index with relationship-specific weights, temporal decay, and cross-source independence.
- **False-Positive Elimination:** Strict separation between candidate clustering and incident promotion; negative evidence checks suppress routine noise.
- **ATT&CK v19.2 Inference:** Auditable sub-technique mapping (e.g. `T1003.001` LSASS, `T1059.001` PowerShell, `T1566.001` Phishing) with full provenance.
- **Attack-Flow Coherence:** Progression/depth/backtrack analysis ensuring multi-stage campaign validity.
- **Structured Commander BLUFs:** Bottom Line Up Front briefings with prioritized decision recommendations.
- **IBM Bob MCP Workflows:** Grounded `/bluf`, `/investigate`, `/explain`, and `/runbook` commands without hallucinated scores.

## Demo Dataset & ATT&CK Reference

The bundled demo contains **62 synthetic observations** spanning SIEM, satellite sensor feeds, cyber sensors, and CTI advisories. The engine produces **5 candidate hypotheses** and promotes **4** evidence-backed incidents (3× P1, 1× P2). The fifth candidate is deliberately weak/benign and is rejected by promotion checks.
The bundled MITRE ATT&CK reference data is sourced from the **MITRE ATT&CK v19.2** release, providing structured techniques, tactics, groups, and sub-technique mappings.

## Tech Stack

| Category | Technologies |
|---|---|
| Languages | Python, JavaScript, HTML/CSS |
| Frameworks | FastAPI, Uvicorn |
| Database | SQLite (persistent relational backend) |
| IBM Technologies | IBM Bob, Project-level MCP Server (JSON-RPC 2.0 over STDIO) |
| Knowledge | MITRE ATT&CK v19.2 reference snapshot |
| Testing & Validation | pytest, Inverted Entity Index, Mermaid |

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
