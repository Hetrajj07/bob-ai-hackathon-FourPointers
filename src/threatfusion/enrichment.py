"""Threat Intelligence and IOC enrichment module for ThreatFusion.

Integrates real CTI feeds:
- ThreatFox / abuse.ch community IOC database
- CISA Known Exploited Vulnerabilities (KEV) catalog
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("threatfusion.enrichment")
ROOT_DIR = Path(__file__).resolve().parents[2]

_threatfox_cache: dict[str, dict[str, Any]] | None = None
_cisa_kev_cache: dict[str, dict[str, Any]] | None = None


def _load_threatfox_db(root: Path | None = None) -> dict[str, dict[str, Any]]:
    global _threatfox_cache
    if _threatfox_cache is not None:
        return _threatfox_cache

    base = root or ROOT_DIR
    tf_file = base / "src" / "data" / "real" / "threatfox_sample.json"
    cache: dict[str, dict[str, Any]] = {}
    if tf_file.exists():
        try:
            with tf_file.open(encoding="utf-8") as f:
                items = json.load(f)
            for item in items:
                val = str(item.get("ioc_value", "")).strip().lower()
                # Store both exact value and ip stripped of port
                cache[val] = item
                if ":" in val and not val.startswith("http"):
                    ip_only = val.split(":")[0]
                    cache[ip_only] = item
        except Exception as exc:
            logger.warning(f"Error loading ThreatFox sample: {exc}")
    _threatfox_cache = cache
    return _threatfox_cache


def _load_cisa_kev(root: Path | None = None) -> dict[str, dict[str, Any]]:
    global _cisa_kev_cache
    if _cisa_kev_cache is not None:
        return _cisa_kev_cache

    base = root or ROOT_DIR
    kev_file = base / "src" / "data" / "real" / "cisa_kev_sample.json"
    cache: dict[str, dict[str, Any]] = {}
    if kev_file.exists():
        try:
            with kev_file.open(encoding="utf-8") as f:
                items = json.load(f)
            for item in items:
                cve = str(item.get("cveID", "")).strip().upper()
                cache[cve] = item
        except Exception as exc:
            logger.warning(f"Error loading CISA KEV sample: {exc}")
    _cisa_kev_cache = cache
    return _cisa_kev_cache


def lookup_threatfox(indicator: str, root: Path | None = None) -> dict[str, Any] | None:
    """Check an IP, domain, or IOC against the ThreatFox intelligence database."""
    db = _load_threatfox_db(root)
    clean_val = indicator.strip().lower()
    if clean_val in db:
        return db[clean_val]
    # Check IP without port
    if ":" in clean_val:
        ip_only = clean_val.split(":")[0]
        if ip_only in db:
            return db[ip_only]
    return None


def check_cisa_kev(cve_id: str, root: Path | None = None) -> dict[str, Any] | None:
    """Check a CVE identifier against the CISA Known Exploited Vulnerabilities catalog."""
    db = _load_cisa_kev(root)
    clean_cve = cve_id.strip().upper()
    return db.get(clean_cve)


def enrich_record(record: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    """Enrich an observation record with ThreatFox CTI and CISA KEV context.

    If an IP or domain matches a known ThreatFox IOC, explicitly promotes it to an
    IOC entity and attaches the malware attribution.
    """
    enriched = dict(record)
    candidates = []

    for key in ("dst_ip", "src_ip", "ip", "ioc"):
        val = record.get(key)
        if val:
            candidates.append(str(val))

    for indicator in candidates:
        match = lookup_threatfox(indicator, root)
        if match:
            malware_name = match.get("malware_printable") or match.get("malware")
            enriched["threatfox_match"] = {
                "ioc": match["ioc_value"],
                "malware": malware_name,
                "threat_type": match.get("threat_type"),
                "confidence": match.get("confidence_level", 90),
                "tags": match.get("tags", []),
            }
            enriched["threat_actor_hint"] = malware_name
            # Explicitly elevate matched IP to IOC status in the record
            current_iocs = enriched.get("iocs", [])
            if isinstance(current_iocs, list):
                if match["ioc_value"] not in current_iocs:
                    enriched["iocs"] = current_iocs + [match["ioc_value"]]
            break

    return enriched
