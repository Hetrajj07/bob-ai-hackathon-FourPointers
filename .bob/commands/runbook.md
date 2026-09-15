---
description: Retrieve prioritized Incident Response containment and remediation runbooks for a ThreatFusion incident
argument-hint: <incident-id>
---

# /runbook

Retrieve the prioritized Incident Response containment, eradication, and detection engineering runbook for an incident.

Workflow:
1. Call `get_remediation_runbook` for the requested incident ID.
2. Group recommended actions by phase (Containment, Eradication, Detection Engineering).
3. Clearly highlight Immediate vs. High priority actions.
4. Specify the target systems (Firewall, IAM, Endpoint Policy, Email Security).
