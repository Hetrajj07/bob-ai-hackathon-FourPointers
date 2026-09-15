"""Offline evaluation only. This module never influences runtime incident promotion."""
from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path

try:
    from src.threatfusion.engine import analyze, normalize, parse_ts, promoted_incidents
except ImportError:
    from threatfusion.engine import analyze, normalize, parse_ts, promoted_incidents

ROOT = Path(__file__).resolve().parents[1]


def naive_clusters(norm, max_minutes=90):
    """Baseline: connect any pair sharing any entity inside a hard time window."""
    parent = {r["id"]: r["id"] for r in norm}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[b] = a

    for i, a in enumerate(norm):
        for b in norm[i + 1 :]:
            dt = abs((parse_ts(a["timestamp"]) - parse_ts(b["timestamp"])).total_seconds()) / 60
            if dt <= max_minutes and set(a["entities"]) & set(b["entities"]):
                union(a["id"], b["id"])
    out = defaultdict(list)
    for r in norm:
        out[find(r["id"])].append(r)
    return [v for v in out.values() if len(v) > 1]


def overlap(a, b):
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if a | b else 0.0


def evaluate():
    d = analyze(ROOT)
    norm = [normalize(r) for r in d["records"]]
    baseline = naive_clusters(norm)
    enhanced_candidates = d["incidents"]
    enhanced_promoted = promoted_incidents(d)
    with (ROOT / "src" / "data" / "ground_truth.json").open(encoding="utf-8") as f:
        ground_truth = json.load(f)
    truth_positive = set(ground_truth["INC-A"])
    benign = set(ground_truth["INC-B"])

    baseline_fp = sum(1 for c in baseline if overlap([r["id"] for r in c], benign) >= 0.70)
    baseline_tp = sum(1 for c in baseline if overlap([r["id"] for r in c], truth_positive) >= 0.70)
    enhanced_tp = sum(1 for c in enhanced_promoted if overlap(c["record_ids"], truth_positive) >= 0.70)
    enhanced_fp = sum(1 for c in enhanced_promoted if overlap(c["record_ids"], benign) >= 0.70)

    return {
        "dataset": {"records": len(d["records"]), "true_incident": "INC-A", "benign_cluster": "INC-B"},
        "baseline": {"clusters": len(baseline), "true_incidents_found": baseline_tp, "benign_clusters_flagged": baseline_fp},
        "enhanced": {"candidate_hypotheses": len(enhanced_candidates), "promoted_incidents": len(enhanced_promoted), "true_incidents_found": enhanced_tp, "benign_clusters_promoted": enhanced_fp},
        "runtime_checks": {
            "ground_truth_used_for_runtime": d["metadata"]["ground_truth_used_for_runtime"],
            "engine_version": d["metadata"]["engine_version"],
            "attack_kb_version": d["metadata"]["attack_kb_version"],
        },
        "note": "This is a small synthetic benchmark, not a production effectiveness claim.",
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
