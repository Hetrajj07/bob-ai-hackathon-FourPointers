# Evaluation

## Bundled synthetic benchmark

The repository ships 37 synthetic observations. `INC-A` is the seeded positive incident; `INC-B` is a benign/ambiguous cluster used to test false-positive suppression.

The benchmark is **offline only**. The runtime dashboard and Bob MCP server do not load the truth labels.

Run:

```bash
python src/evaluate.py
```

Current result:

```text
raw observations:             37
candidate hypotheses:          2
promoted incidents:            1
true incident promoted:        1
benign cluster promoted:       0
```

This is intentionally a small reproducibility benchmark, not a production accuracy claim. A production evaluation should use a larger labeled corpus, multiple attack families, missing telemetry, duplicated source events and analyst-reviewed ground truth.

## Why the benchmark is useful

The dataset is deliberately heterogeneous and includes a convincing benign PowerShell/new-location-login pair. The engine must therefore distinguish “shared time/entity context” from an evidence-backed multi-stage attack flow.

## Baseline comparison

The same 37-record dataset produces **4 clusters** under a naïve shared-entity + hard-time-window baseline. One of those clusters overlaps the benign/ambiguous `INC-B` case. ThreatFusion produces **2 candidate hypotheses** and promotes only the evidence-backed `INC-A`; the benign cluster is not promoted.

This is a demonstration of the decision boundary, not a generalized false-positive-rate claim.
