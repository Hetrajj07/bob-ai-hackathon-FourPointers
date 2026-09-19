"""Offline evaluation only. This module never influences runtime incident promotion."""
from __future__ import annotations

import json
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
        for b in norm[i + 1:]:
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

    # All labeled attack scenarios (anything that is not INC-B benign).
    benign_keys = {"INC-B"}
    attack_keys = [k for k in ground_truth if k not in benign_keys]
    benign_records: set[str] = set()
    for k in benign_keys:
        benign_records.update(ground_truth.get(k, []))
    attack_scenarios: list[tuple[str, set[str]]] = [
        (k, set(ground_truth[k])) for k in attack_keys
    ]

    # Per-scenario detection results.
    scenario_results = []
    for label, truth_ids in attack_scenarios:
        promoted_match = any(overlap(c["record_ids"], truth_ids) >= 0.70 for c in enhanced_promoted)
        baseline_match = any(overlap([r["id"] for r in c], truth_ids) >= 0.70 for c in baseline)
        scenario_results.append({
            "scenario": label,
            "type": "attack",
            "promoted_by_threatfusion": promoted_match,
            "recovered_by_baseline": baseline_match,
        })
    # Benign scenario: we want it NOT promoted.
    benign_promoted = any(overlap(c["record_ids"], benign_records) >= 0.70 for c in enhanced_promoted)
    benign_baseline_fp = any(overlap([r["id"] for r in c], benign_records) >= 0.70 for c in baseline)
    scenario_results.append({
        "scenario": "INC-B",
        "type": "benign",
        "promoted_by_threatfusion": benign_promoted,
        "recovered_by_baseline": benign_baseline_fp,
    })

    # Aggregate metrics.
    tf_attack_promoted = sum(1 for s in scenario_results if s["type"] == "attack" and s["promoted_by_threatfusion"])
    tf_benign_promoted = sum(1 for s in scenario_results if s["type"] == "benign" and s["promoted_by_threatfusion"])
    bl_attack_recovered = sum(1 for s in scenario_results if s["type"] == "attack" and s["recovered_by_baseline"])
    bl_benign_fp = sum(1 for s in scenario_results if s["type"] == "benign" and s["recovered_by_baseline"])
    total_attack = len(attack_keys)

    return {
        "dataset": {
            "records": len(d["records"]),
            "labeled_scenarios": len(ground_truth),
            "attack_scenarios": total_attack,
            "benign_scenarios": len(benign_keys),
        },
        "baseline": {
            "clusters": len(baseline),
            "attack_scenarios_recovered": bl_attack_recovered,
            "benign_scenarios_flagged": bl_benign_fp,
        },
        "threatfusion": {
            "candidate_hypotheses": len(enhanced_candidates),
            "promoted_incidents": len(enhanced_promoted),
            "attack_scenarios_promoted": tf_attack_promoted,
            "benign_scenarios_promoted": tf_benign_promoted,
            "incident_recall": round(tf_attack_promoted / max(1, total_attack), 3),
            "false_positive_rate": round(tf_benign_promoted / max(1, len(benign_keys)), 3),
        },
        "scenario_breakdown": scenario_results,
        "runtime_checks": {
            "ground_truth_used_for_runtime": d["metadata"]["ground_truth_used_for_runtime"],
            "engine_version": d["metadata"]["engine_version"],
            "attack_kb_version": d["metadata"]["attack_kb_version"],
        },
        "note": "Synthetic benchmark only. Not a production accuracy claim.",
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
