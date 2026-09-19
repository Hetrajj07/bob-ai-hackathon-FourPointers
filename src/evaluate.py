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
    total_benign = len(benign_keys)

    # Confusion matrix & standard classification metrics
    tp = tf_attack_promoted
    fp = tf_benign_promoted
    fn = total_attack - tf_attack_promoted
    tn = total_benign - tf_benign_promoted
    precision = round(tp / max(1, tp + fp), 3)
    recall = round(tp / max(1, tp + fn), 3)
    f1 = round(2 * precision * recall / max(1e-6, precision + recall), 3)
    fpr = round(fp / max(1, fp + tn), 3)

    bl_tp = bl_attack_recovered
    bl_fp = bl_benign_fp
    bl_fn = total_attack - bl_attack_recovered
    bl_tn = total_benign - bl_benign_fp
    bl_prec = round(bl_tp / max(1, bl_tp + bl_fp), 3)
    bl_rec = round(bl_tp / max(1, bl_tp + bl_fn), 3)
    bl_f1 = round(2 * bl_prec * bl_rec / max(1e-6, bl_prec + bl_rec), 3)
    bl_fpr = round(bl_fp / max(1, bl_fp + bl_tn), 3)

    return {
        "dataset": {
            "records": len(d["records"]),
            "labeled_scenarios": len(ground_truth),
            "attack_scenarios": total_attack,
            "benign_scenarios": total_benign,
        },
        "baseline": {
            "clusters": len(baseline),
            "attack_scenarios_recovered": bl_attack_recovered,
            "benign_scenarios_flagged": bl_benign_fp,
            "true_positives": bl_tp,
            "false_positives": bl_fp,
            "false_negatives": bl_fn,
            "true_negatives": bl_tn,
            "precision": bl_prec,
            "recall": bl_rec,
            "f1_score": bl_f1,
            "false_positive_rate": bl_fpr,
        },
        "threatfusion": {
            "candidate_hypotheses": len(enhanced_candidates),
            "promoted_incidents": len(enhanced_promoted),
            "attack_scenarios_promoted": tp,
            "benign_scenarios_promoted": fp,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "incident_recall": recall,
            "precision": precision,
            "f1_score": f1,
            "false_positive_rate": fpr,
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
