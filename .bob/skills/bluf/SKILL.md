---
name: bluf
description: Generate a commander-ready BLUF for a ThreatFusion incident
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: <incident-id>
---

# /bluf

Generate a commander-ready BLUF for a ThreatFusion incident.

Use `get_incident` then `generate_bluf`. Preserve the tool output's uncertainty language and action recommendations.
