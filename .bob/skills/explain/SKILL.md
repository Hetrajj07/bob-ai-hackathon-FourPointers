---
name: explain
description: Explain why a ThreatFusion candidate or incident was prioritized across 4 risk dimensions
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: <candidate-or-incident-id>
---

# /explain

Explain why a ThreatFusion threat hypothesis was prioritized using `explain_risk(incident_id=...)`.

## Output Structure
1. **THREAT IDENTIFIER & STATUS:** Candidate vs. Promoted Incident.
2. **OPERATIONAL PRIORITY:** Overall score (e.g. P1 / 96) and executive rationale.
3. **FOUR RISK DIMENSIONS:**
   - **Confidence:** Support from independent feeds, IOC specificity, and verified behaviors.
   - **Severity:** Harm potential, attack-flow depth, dangerous capabilities.
   - **Mission Impact:** Asset criticality and mission role.
   - **Urgency:** Progression speed and active risk.
4. **KEY EVIDENCE DRIVERS:** ThreatFox CTI, CISA KEV, or cross-source corroboration.
5. **UNCERTAINTY & PENALTIES:** Negative evidence, contradictions, and visibility gaps.
