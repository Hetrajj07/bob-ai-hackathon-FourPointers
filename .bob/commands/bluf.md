---
description: Generate a commander-ready Bottom Line Up Front (BLUF) briefing for a ThreatFusion incident
argument-hint: <candidate-or-incident-id>
---

# /bluf

Generate a military-standard Bottom Line Up Front (BLUF) briefing for leadership.

## Briefing Flow

1. Call `generate_bluf(incident_id=...)` for the requested ID.
2. Format the response clearly for commanders:
   - **BOTTOM LINE:** 1-sentence executive priority and confidence statement.
   - **COMMANDER BRIEFING:** Decision-oriented situational summary.
   - **WHAT HAPPENED & WHY IT MATTERS:** Plain-language threat narrative.
   - **KEY EVIDENCE:** Observable ATT&CK / SPARTA techniques and independent sources.
   - **WHAT TO DO NEXT:** Prioritized immediate actions.
   - **UNCERTAINTY & BOUNDARIES:** Explicit statement of unobserved tactics (no unsupported attribution).
