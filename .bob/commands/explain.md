---
description: Explain why a ThreatFusion candidate or incident was prioritized across 4 risk dimensions
argument-hint: <candidate-or-incident-id>
---

# /explain

Explain why a ThreatFusion threat hypothesis was prioritized and scored.

## Explanation Flow

1. Call `explain_risk(incident_id=...)` for the requested ID.
2. Clearly explain why the activity is important:
   - **Confidence:** How strongly available evidence supports the hypothesis.
   - **Severity:** How harmful the observed behavior could be.
   - **Mission Impact:** Importance of affected assets.
   - **Urgency:** How quickly the analyst should investigate.
   - **Priority:** Resulting operational priority (P1/P2/P3/P4).
3. Call out key corroborating evidence, IOC matches (ThreatFox), and KEV exploits (CISA KEV).
4. Highlight any negative evidence or contradiction penalties applied.
5. Note remaining uncertainty and telemetry gaps.
