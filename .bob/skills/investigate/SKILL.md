---
name: investigate
description: Investigate a ThreatFusion incident using grounded MCP evidence
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: <incident-id>
---

# /investigate

Investigate a ThreatFusion incident using the MCP tools.

Workflow:
1. Call `get_incident` for the requested incident ID.
2. Call `explain_risk` and `get_detection_gaps`.
3. Explain the conclusion only from returned evidence; do not invent telemetry.
4. Distinguish evidence confidence, threat severity and mission impact.
5. End with a concise analyst next-step plan.

Never claim threat-actor attribution from technique overlap. Use “behaviorally consistent with” instead.
