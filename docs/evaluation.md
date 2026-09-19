# Evaluation

## Bundled synthetic benchmark

The repository ships **62 synthetic observations** across four source types (SIEM, endpoint, network sensor, threat intelligence). Five ground-truth scenarios are labeled:

| Scenario | Type    | Records |
|----------|---------|---------|
| INC-A    | Attack  | 7       |
| INC-B    | Benign  | 2       |
| INC-C    | Attack  | 9       |
| INC-D    | Attack  | 9       |
| INC-E    | Attack  | 7       |

The benchmark is **offline only**. The runtime dashboard and Bob MCP server do not load the truth labels at any point.

Run:

```bash
python src/evaluate.py
```

Current result:

```text
Dataset: 62 records, 5 labeled scenarios (4 attack, 1 benign)

Metric Comparison:
┌─────────────────────────┬───────────┬──────────────┐
│ Metric                  │ Baseline  │ ThreatFusion │
├─────────────────────────┼───────────┼──────────────┤
│ Formed Clusters         │ 7         │ 5 (hypotheses)│
│ Promoted Incidents      │ 7         │ 4            │
│ True Positives (TP)     │ 4         │ 4            │
│ False Positives (FP)    │ 1         │ 0            │
│ False Negatives (FN)    │ 0         │ 0            │
│ True Negatives (TN)     │ 0         │ 1            │
│ Precision               │ 0.800     │ 1.000        │
│ Recall                  │ 1.000     │ 1.000        │
│ F1 Score                │ 0.889     │ 1.000        │
│ False Positive Rate     │ 1.000     │ 0.000        │
└─────────────────────────┴───────────┴──────────────┘
```

The baseline recovers all 4 attack scenarios but also flags the benign cluster as an incident.
ThreatFusion produces the same attack recall while suppressing the benign cluster.

This is intentionally a small reproducibility benchmark, not a production accuracy claim.
A production evaluation should use a larger labeled corpus, multiple attack families,
missing telemetry, duplicated source events and analyst-reviewed ground truth.

## Why the benchmark is useful

The dataset includes a convincing benign PowerShell/new-location-login pair (INC-B).
The engine must therefore distinguish "shared time/entity context" from an
evidence-backed multi-stage attack flow with independent source corroboration.

## Baseline comparison

| Method      | Candidates | Promoted | Benign promoted |
|-------------|:----------:|:--------:|:---------------:|
| Naïve       | 7          | 7        | 1               |
| ThreatFusion| 5          | 4        | 0               |

The naïve baseline uses shared entity + hard time window only; it has no ATT&CK validation,
no attack-flow coherence check, no source independence requirement, and no negative-evidence
penalty. Every cluster above minimum size is implicitly an incident.

ThreatFusion applies four explicit promotion checks before escalation:

1. **Minimum behavior evidence** — at least two ATT&CK-backed observations.
2. **Multi-tactic progression** — the case crosses multiple tactics with sufficient attack-flow coherence.
3. **Evidence confidence** — quality and corroboration clear the promotion threshold.
4. **Source independence** — the story is supported across sufficiently independent telemetry sources.

A candidate that fails any check stays in the queue as a hypothesis, not an incident.

## Separation of runtime and evaluation

`ground_truth.json` is read **only** by `src/evaluate.py`. The runtime engine
(`src/threatfusion/engine.py`), the FastAPI dashboard (`src/app.py`), and the MCP server
(`src/mcp_server.py`) never import or read that file. This is verified by the test:

```python
assert d["metadata"]["ground_truth_used_for_runtime"] is False
```
