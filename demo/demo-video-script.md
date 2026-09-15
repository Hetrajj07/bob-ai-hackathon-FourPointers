# Final 3–5 minute demo script

Use this sequence to record the final hosted demo. The bundled local MP4 is only a short preview and must not be used as the final evidence.

| Time | Screen / action | What to say |
|---|---|---|
| 0:00–0:25 | Open the dashboard overview. | “ThreatFusion helps defence analysts decide whether scattered observations are one credible attack story. The demo uses synthetic telemetry, so we do not claim production detection accuracy.” |
| 0:25–0:55 | Point to the four KPI values: 37 observations, 2 candidates, 1 promoted incident. | “A shared host or IP first creates a candidate hypothesis. It is promoted only after evidence and behavior support it.” |
| 0:55–1:45 | Select `INC-CAND-09226FFA` and walk the timeline. | “The chain is CTI context, an attachment on ENG-WKS17, Office-launched PowerShell, C2 communication, LSASS credential access, RDP to ENG-DB01, then independent IOC corroboration.” |
| 1:45–2:20 | Show ATT&CK flow and risk factors. | “The engine maps evidence to ATT&CK sub-techniques, checks tactic progression, and separates confidence, severity, mission impact, and urgency. Current values are 92.1%, 92, 95, and 97.” |
| 2:20–2:45 | Open BLUF and runbook. | “The commander receives a grounded summary, clear uncertainty, and phased containment and detection-engineering actions. Actor similarity is context only, never attribution.” |
| 2:45–3:25 | Open IBM Bob and run `/investigate INC-CAND-09226FFA`. | “Bob calls our local, read-only MCP server. It receives the same deterministic evidence rather than inventing a threat score.” |
| 3:25–3:50 | Run `/explain` and `/bluf`; show returned evidence and uncertainty. | “Bob can explain the prioritisation and produce a commander-ready brief while preserving provenance and telemetry-gap language.” |
| 3:50–4:10 | Open the baseline-comparison tab. | “On this small synthetic benchmark, naive grouping forms four clusters and flags the benign case. ThreatFusion forms two candidates and promotes only the evidence-backed incident.” |
| 4:10–4:25 | End on the overview or deck title. | “ThreatFusion prioritizes evidence-backed attack stories, not individual alerts.” |

## Recording rules

- Record the final build after running `python -m pytest -q src/tests`.
- Keep the dashboard values, screenshots, video, and slide deck synchronized.
- Upload a 3–5 minute recording to YouTube (unlisted), Loom, Box, or Google Drive with view access enabled.
- Put only the final hosted URL on line 1 of `demo-video-link.txt`.
- State clearly that the benchmark is synthetic and that the prototype performs neither actor attribution nor autonomous containment.
