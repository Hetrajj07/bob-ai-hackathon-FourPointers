---
description: Retrieve prioritized, phased incident response runbooks with explicit analyst safety controls
argument-hint: <candidate-or-incident-id>
---

# /runbook

Retrieve prioritized Incident Response containment, eradication, and detection engineering runbooks.

## Runbook Flow

1. Call `get_remediation_runbook(incident_id=...)` for the requested ID.
2. Group recommended actions into clear phases:
   - **Phase 1: Investigation & Telemetry Gathering** (Immediate, Non-disruptive)
   - **Phase 2: Containment** (Immediate/High · Requires Analyst Authorization)
   - **Phase 3: Eradication** (High · Requires Analyst Authorization)
   - **Phase 4: Detection Engineering** (Medium · Proactive hunting queries & rules)
3. Explicitly note target infrastructure systems (Firewall, IAM, Endpoint, SIEM).
4. Include the operational safety notice that ThreatFusion does NOT autonomously execute disruptive containment.
