---
name: bluf
description: Generate a commander-ready Bottom Line Up Front (BLUF) briefing for leadership from ThreatFusion evidence
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: <candidate-or-incident-id>
---

# /bluf

Generate a commander-ready Bottom Line Up Front briefing using `generate_bluf(incident_id=...)`.

## Output Structure
1. **BOTTOM LINE:** 1-sentence executive summary.
2. **COMMANDER BRIEFING:** Decision-ready situational brief.
3. **WHAT HAPPENED & WHY IT MATTERS:** Factual threat narrative.
4. **SUPPORTING EVIDENCE:** ATT&CK / SPARTA techniques & independent feeds.
5. **RECOMMENDED NEXT STEPS:** Immediate actions for analyst/commander.
6. **UNCERTAINTY:** Explicit telemetry gaps (no unsupported threat-actor attribution).
