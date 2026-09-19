---
name: runbook
description: Retrieve prioritized, phased incident response runbooks with explicit analyst safety controls
metadata:
  user-invocable: true
  disable-model-invocation: true
  argument-hint: <candidate-or-incident-id>
---

# /runbook

Retrieve prioritized Incident Response containment, eradication, and detection engineering runbooks using `get_remediation_runbook(incident_id=...)`.

## Output Structure
1. **OPERATIONAL SAFETY BANNER:** Actions require analyst authorization; no autonomous containment.
2. **PHASE 1: INVESTIGATION & TELEMETRY GATHERING** (Immediate, Non-disruptive)
3. **PHASE 2: CONTAINMENT** (Immediate/High · Requires Authorization)
4. **PHASE 3: ERADICATION** (High · Requires Authorization)
5. **PHASE 4: DETECTION ENGINEERING** (Medium · Proactive hunting queries & rules)
