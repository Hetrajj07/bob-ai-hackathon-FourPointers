# Solution Overview

## What We Built

**ThreatFusion** is an evidence-backed D2 intelligence assistant that turns fragmented observations into prioritized incident hypotheses. It is designed around a simple rule: a correlation is not automatically an incident; an incident must earn promotion through corroborated behavioral evidence.

## How It Works

1. **Normalize** SIEM, endpoint, network-sensor and threat-intelligence records into one canonical event shape.
2. **Cluster candidates** with relationship-specific entity weights and continuous temporal decay.
3. **Enrich evidence** with ATT&CK technique/sub-technique inference and source provenance.
4. **Validate behavior** with tactic progression, technique depth, source independence and explicit contradiction/negative evidence.
5. **Assess decision dimensions** separately: evidence confidence, threat severity, mission impact and urgency.
6. **Promote only evidence-backed hypotheses** to incidents; runtime never reads benchmark labels.
7. **Brief the analyst/commander** through the web dashboard and IBM Bob MCP tools.

## What Makes It Different

A naïve implementation treats a shared host/IP/time window as an incident. ThreatFusion treats that as a **candidate hypothesis** and then asks whether the evidence forms a coherent attack story. This reduces the risk of promoting normal shared infrastructure activity merely because it is temporally close.

## Example

```text
37 observations
   ↓
2 candidate hypotheses
   ↓
ATT&CK + attack-flow validation
   ↓
1 promoted incident
   ↓
P1 decision brief
```

These numbers describe the bundled synthetic demo only.

## IBM Bob Integration

IBM Bob is not used to invent the threat score. Bob retrieves grounded incident evidence through the project MCP server and can execute the D2 investigation workflow through `/investigate`, `/explain` and `/bluf`. The deterministic engine remains the source of truth for scores and evidence.

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Candidate clustering before promotion | Prevents shared-entity over-correlation from becoming an incident automatically. |
| Explicit IOC semantics | Prevents every public IP from being treated as malicious. |
| ATT&CK sub-techniques | Provides finer behavioral precision and avoids over-broad labels. |
| Separate confidence/severity/impact/urgency | Makes prioritization explainable and reflects different dimensions of operational risk. |
| Negative evidence + uncertainty | Lets the system express “not enough evidence” rather than forcing benign/malicious certainty. |
| Actor similarity, not attribution | Historical technique overlap is useful context but is insufficient for definitive attribution. |

## Limitations

The prototype uses synthetic telemetry and a bundled ATT&CK snapshot. The correlation stage is intentionally designed for a small reproducible dataset. It is not a production detection platform and does not autonomously execute defensive actions.
