---
name: threat-investigation
description: Evidence-first investigation workflow for ThreatFusion D2 incidents. Use when the user asks why an incident is suspicious, how it was prioritized, what ATT&CK behaviors are present, or what to brief a commander.
---

# ThreatFusion investigation workflow

## Rules
- Evidence first: use MCP results as the source of truth.
- Never turn technique overlap into actor attribution.
- Preserve uncertainty and negative evidence.
- Keep confidence, severity, mission impact and urgency separate.
- When telemetry is absent, label it as a possible visibility gap rather than proof of absence.

## Output
1. Bottom line.
2. Evidence chain.
3. ATT&CK techniques and attack-flow coherence.
4. Risk decomposition.
5. Uncertainty / detection gaps.
6. Recommended investigation and containment actions.
