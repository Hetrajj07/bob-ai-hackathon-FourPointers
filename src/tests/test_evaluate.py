from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluate import evaluate


def test_offline_benchmark_distinguishes_benign_cluster():
    r = evaluate()
    # Dataset
    assert r['dataset']['records'] == 62
    assert r['dataset']['attack_scenarios'] == 4
    assert r['dataset']['benign_scenarios'] == 1

    # ThreatFusion must promote all 4 attack scenarios and suppress the benign one.
    assert r['threatfusion']['attack_scenarios_promoted'] == 4
    assert r['threatfusion']['benign_scenarios_promoted'] == 0
    assert r['threatfusion']['incident_recall'] == 1.0
    assert r['threatfusion']['false_positive_rate'] == 0.0

    # Baseline flags the benign cluster (demonstrating the decision boundary value).
    assert r['baseline']['benign_scenarios_flagged'] == 1

    # Runtime must never read ground truth.
    assert r['runtime_checks']['ground_truth_used_for_runtime'] is False

    # Per-scenario breakdown must cover all 5 labeled scenarios.
    scenarios = {s['scenario'] for s in r['scenario_breakdown']}
    assert {'INC-A', 'INC-B', 'INC-C', 'INC-D', 'INC-E'} == scenarios
