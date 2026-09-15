# Architecture

## System Architecture

```mermaid
graph TD
    A[SIEM] --> N[Normalization]
    B[Endpoint] --> N
    C[Network Sensor] --> N
    D[Threat Intel] --> N
    N --> E[Candidate Evidence Clustering]
    E --> F[Weighted Relationship Graph]
    F --> G[ATT&CK Technique / Sub-technique Inference]
    G --> H[Attack-flow Coherence]
    H --> I[Confidence + Severity + Mission Impact + Urgency]
    I --> J[Incident Promotion]
    J --> K[Dashboard]
    J --> L[MCP Server]
    L --> M[IBM Bob]
    J --> N2[Grounded BLUF + Investigation Plan]
```

## Components

| Component | Technology | Responsibility |
|---|---|---|
| Dashboard/API | FastAPI + vanilla JavaScript | Read-only incident, attack flow graph, timeline, and runbook views |
| Candidate clustering | Python (inverted entity index) | High-performance weighted entity links + continuous temporal decay |
| ATT&CK inference | Python + bundled ATT&CK reference | Sub-technique mapping with rationale/provenance |
| Attack-flow engine | Python | Tactic progression, depth and backtrack analysis |
| Risk engine | Python | Confidence, severity, mission impact and urgency |
| Runbook engine | Python | ATT&CK-mapped phased containment, eradication, and detection engineering |
| MCP server | JSON-RPC 2.0 over STDIO | Exposes grounded read-only investigation and runbook tools to Bob |
| Bob workflow | `.bob/mcp.json`, commands, skill | Analyst interaction, command triggers, and narrative synthesis |

## Key Design Guardrails

1. **Candidate ≠ incident.** Shared entities create hypotheses; promotion requires behavioral and corroborating evidence.
2. **Ground truth is offline-only.** `ground_truth.json` is consumed only by `src/evaluate.py`. It is never used by runtime promotion, the dashboard, or MCP.
3. **IOC semantics are explicit.** Public IP addresses remain ordinary IP entities unless an explicit threat-intelligence or indicator field identifies them as an IOC.
4. **ATT&CK mappings are evidence-backed.** RDP requires RDP evidence; LSASS behavior maps to T1003.001 rather than the broader T1003.
5. **Actor similarity is not attribution.** Historical ATT&CK technique overlap is presented only as behavioral consistency.

## Data Flow

Input records arrive in four intentionally different schemas. The normalizer extracts common entities and preserves provenance. Candidate edges combine relationship-specific weights, source separation and temporal decay. The resulting clusters are enriched with ATT&CK behavior. Attack-flow coherence, source independence, IOC specificity, negative evidence and asset criticality are then used to calculate separate decision dimensions. Only clusters that satisfy the promotion rules are shown as incidents.

## Security Considerations

- No credentials are stored in the repository.
- MCP uses local STDIO rather than exposing a network listener.
- The prototype is read-only and has no autonomous containment action.
- Synthetic telemetry is used for the demo.
- Production use would require enterprise identity, secrets management, authorization, logging and data-governance controls.

## Scalability & Performance Optimization

The candidate clustering engine implements an **inverted entity index** (`entity -> list[record_indices]`) before evaluating pairwise edge strengths. Rather than executing a naive $O(N^2)$ comparison across all raw observations, it restricts temporal decay and weight calculations exclusively to record pairs sharing at least one common entity. On the demo dataset, this reduces pair evaluations from 666 down to 23 (a 96.5% reduction) while producing mathematically identical cluster boundaries. For enterprise-scale telemetry, the same graph model seamlessly operates over streaming sliding windows or distributed indices. STIX/TAXII 2.1 can be added at the ingestion boundary without altering internal representations.
