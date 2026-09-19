"""ThreatFusion Corpus Ingestion Utility.

Ingests historical threat archives and recent multi-source telemetry
into the persistent SQLite database (threatfusion.db).

Usage:
    python src/ingest_data.py --all
    python src/ingest_data.py --historical
    python src/ingest_data.py --recent
    python src/ingest_data.py --reset
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.threatfusion.db import get_all_alerts, ingest_corpus_data, reset_db
from src.threatfusion.engine import analyze, clear_context_cache, promoted_incidents


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatFusion Multi-Source Data Ingestion CLI")
    parser.add_argument("--all", action="store_true", help="Ingest both historical archive and recent threats")
    parser.add_argument("--historical", action="store_true", help="Ingest historical threat campaigns (August - early September)")
    parser.add_argument("--recent", action="store_true", help="Ingest recent threats (September 18-19, 2026)")
    parser.add_argument("--reset", action="store_true", help="Reset database to the baseline 62 demo alerts")

    args = parser.parse_args()

    if args.reset:
        print("[*] Resetting database to baseline demo telemetry...")
        reset_db(root_dir=ROOT)
        clear_context_cache()
        records = get_all_alerts()
        print(f"[+] Database reset complete. Total alerts: {len(records)}")
        return

    # Default to --all if no specific flag is given
    do_all = args.all or (not args.historical and not args.recent)
    include_hist = do_all or args.historical
    include_rec = do_all or args.recent

    print(f"[*] Starting ingestion into ThreatFusion SQLite database...")
    print(f"    - Historical Archive: {include_hist}")
    print(f"    - Recent Telemetry:   {include_rec}")

    stats = ingest_corpus_data(
        include_historical=include_hist,
        include_recent=include_rec,
        include_otrf=True,
        include_cicids=True,
        include_sparta_satellite=True,
        root_dir=ROOT,
    )
    clear_context_cache()

    print("[+] Ingestion successful:")
    for k, v in stats.items():
        print(f"    {k}: {v}")

    print("[*] Running dynamic correlation across all ingested observations...")
    db_records = get_all_alerts()
    analysis = analyze(ROOT, records=db_records)
    promoted = promoted_incidents(analysis)
    print(f"[+] Dynamic correlation complete:")
    print(f"    Total raw alerts:       {len(analysis['records'])}")
    print(f"    Candidate hypotheses:   {len(analysis['incidents'])}")
    print(f"    Promoted incidents:     {len(promoted)}")
    print(f"    Compression ratio:      {round(100 * (1 - len(analysis['incidents']) / max(1, len(analysis['records']))), 1)}%")


if __name__ == "__main__":
    main()
