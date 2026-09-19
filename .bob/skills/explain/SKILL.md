---
name: explain
description: Explain why a ThreatFusion incident was prioritized
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: <incident-id>
---

# /explain

Explain why an incident was prioritized. Use `get_incident` and `explain_risk`.

Structure: evidence → ATT&CK behavior → attack-flow coherence → confidence → severity → mission impact → uncertainty.
