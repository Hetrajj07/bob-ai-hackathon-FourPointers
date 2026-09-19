---
description: Investigate a ThreatFusion candidate hypothesis or promoted incident using grounded MCP evidence
argument-hint: <candidate-or-incident-id>
---

# /investigate

Investigate a ThreatFusion candidate hypothesis or promoted incident using MCP tools.

## Investigation Flow

1. Call `get_incident(incident_id=...)` for the requested ID. (If none provided, call `correlate_events()` first).
2. Check `status` to determine whether this is a **PROMOTED INCIDENT** or a **CANDIDATE HYPOTHESIS**.
3. Generate a structured 100–250 word Human-Readable Threat Brief:
   - **THREAT / CANDIDATE:** ID, Status, Priority
   - **WHAT HAPPENED:** 1–3 sentence event summary
   - **WHY IT MATTERS:** Practical security significance
   - **WHY IT WAS PRIORITIZED:** Key evidence drivers and cross-source corroboration
   - **EVIDENCE:** Key ATT&CK / SPARTA techniques, sources, IOC matches
   - **CONFIDENCE & IMPACT:** Plain-language interpretation of 4D risk scores
   - **WHAT TO DO NEXT:** 2–5 prioritized investigation and response actions
   - **UNKNOWN / LIMITATIONS:** Explicitly mention unobserved intermediate tactics
4. Preserve factual boundaries: Never claim nation-state attribution without verifiable intelligence.
