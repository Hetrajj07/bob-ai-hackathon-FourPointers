---
name: investigate
description: Investigate a ThreatFusion candidate hypothesis or promoted incident using grounded MCP evidence
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: <candidate-or-incident-id>
---

# /investigate

Produce a concise, human-readable intelligence brief (100–250 words) for a threat using `get_incident(incident_id=...)`.

## Output Structure
1. **THREAT / CANDIDATE:** ID, Status (`PROMOTED INCIDENT` vs `CANDIDATE`), Priority.
2. **WHAT HAPPENED:** 1–3 sentence event summary.
3. **WHY IT MATTERS:** Practical security significance.
4. **WHY IT WAS PRIORITIZED:** Key evidence drivers and cross-source corroboration.
5. **EVIDENCE:** Key ATT&CK / SPARTA techniques, sources, IOC matches.
6. **CONFIDENCE & IMPACT:** Plain-language interpretation.
7. **WHAT TO DO NEXT:** 2–5 prioritized next steps.
8. **UNKNOWN / LIMITATIONS:** Explicitly mention unobserved intermediate tactics.
