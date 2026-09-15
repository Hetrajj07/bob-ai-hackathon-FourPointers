from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluate import evaluate


def test_offline_benchmark_distinguishes_benign_cluster():
    r = evaluate()
    assert r['dataset']['records'] == 37
    assert r['baseline']['benign_clusters_flagged'] == 1
    assert r['enhanced']['benign_clusters_promoted'] == 0
    assert r['enhanced']['true_incidents_found'] == 1
