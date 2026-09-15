"""ThreatFusion D2 intelligence engine.

Design goals:
- Candidate clustering is only hypothesis generation, never incident truth.
- Correlation uses relationship-specific weights + continuous temporal decay.
- IOC evidence is explicit; ordinary public IPs are not automatically IOCs.
- ATT&CK mapping is rule-backed and sub-technique-aware.
- Incident promotion is evidence-based and independent of ground truth.
- Risk is decomposed into confidence, severity, mission impact and urgency.
- Every score keeps provenance so IBM Bob can explain it without inventing evidence.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

ENGINE_VERSION = "2.1.0"

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]
TACTIC_RANK = {t: i for i, t in enumerate(TACTIC_ORDER)}

SOURCE_CREDIBILITY = {
    "threat_intel_report": 0.92,
    "endpoint": 0.90,
    "network_sensor": 0.84,
    "siem": 0.78,
}

# Relationship weights are deliberately interpretable.
ENTITY_WEIGHTS = {
    "ioc": 1.00,
    "ip": 0.82,
    "host": 0.65,
    "user": 0.58,
}

# Demonstration asset registry. In a real deployment this would come from CMDB/asset inventory.
ASSET_DEFAULTS = {
    "ENG-DB01": {"criticality": 95, "mission_role": "Engineering database", "zone": "mission-critical"},
    "ENG-WKS17": {"criticality": 82, "mission_role": "Engineering workstation", "zone": "engineering"},
    "VPN-GW01": {"criticality": 90, "mission_role": "Remote access gateway", "zone": "perimeter"},
    "FIN-LT22": {"criticality": 58, "mission_role": "Finance endpoint", "zone": "corporate"},
}

TECHNIQUE_RISK = {
    "T1566.001": 72,  # Spearphishing Attachment
    "T1059.001": 80,  # PowerShell
    "T1003.001": 92,  # LSASS Memory
    "T1021.001": 86,  # RDP
    "T1021.002": 82,  # SMB / Windows Admin Shares
    "T1021.004": 74,  # SSH
}

IOC_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class DSU:
    def __init__(self) -> None:
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        if self.p[x] != x:
            self.p[x] = self.find(self.p[x])
        return self.p[x]

    def union(self, a: str, b: str) -> None:
        a, b = self.find(a), self.find(b)
        if a != b:
            self.p[b] = a


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=4)
def load_context(root_str: str):
    root = Path(root_str)
    data = root / "src" / "data"
    ref = root / "src" / "reference"
    records = load_json(data / "demo_alerts.json")
    assets_path = data / "assets.json"
    assets = load_json(assets_path) if assets_path.exists() else ASSET_DEFAULTS
    techniques = {x["id"]: x for x in load_json(ref / "techniques.json")}
    groups = load_json(ref / "groups.json")
    edges = load_json(ref / "group_technique_edges.json")
    return records, techniques, groups, edges, assets


def text_of(r: dict[str, Any]) -> str:
    return json.dumps(r, sort_keys=True, ensure_ascii=False).lower()


def _canonical_entity_value(entity_type: str, value: Any) -> str:
    """Return a stable correlation key without losing the source record.

    Endpoint and identity systems commonly disagree only in casing or whitespace.
    Canonicalising at the entity boundary prevents those harmless schema differences
    from fragmenting an otherwise coherent candidate hypothesis.
    """
    cleaned = str(value).strip()
    if entity_type == "host":
        return cleaned.upper().rstrip(".")
    if entity_type in {"user", "ip", "ioc"}:
        return cleaned.lower().rstrip(".")
    return cleaned


def _as_string_list(value: Any) -> list[str]:
    """Normalize optional indicator fields without accidentally iterating a string."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def extract_entities(r: dict[str, Any]) -> list[tuple[str, str]]:
    """Extract correlation entities.

    IMPORTANT: public IPs are only treated as *IP* entities by default. They become
    IOC entities only when explicitly observed in threat-intel evidence or an
    indicator field. This prevents the previous false-positive bug where every
    cloud/public IP became an IOC automatically.
    """
    ents: list[tuple[str, str]] = []
    for k in ("host", "src_host", "dst_host"):
        if r.get(k):
            ents.append(("host", _canonical_entity_value("host", r[k])))
    if r.get("user"):
        ents.append(("user", _canonical_entity_value("user", r["user"])))
    for k in ("src_ip", "dst_ip"):
        if r.get(k):
            ents.append(("ip", _canonical_entity_value("ip", r[k])))

    t = text_of(r)
    for token in IOC_RE.findall(r.get("text", "")):
        ents.append(("ip", _canonical_entity_value("ip", token)))

    explicit_iocs = {
        _canonical_entity_value("ioc", indicator)
        for key in ("ioc", "iocs")
        for indicator in _as_string_list(r.get(key))
    }
    for indicator in explicit_iocs:
        ents.append(("ioc", indicator))
    for token in IOC_RE.findall(t):
        canonical = _canonical_entity_value("ioc", token)
        if canonical in explicit_iocs:
            ents.append(("ioc", canonical))

    # Threat-intel reports are authoritative only for the indicators they explicitly mention.
    if r.get("source") == "threat_intel_report":
        for token in IOC_RE.findall(r.get("text", "")):
            ents.append(("ioc", _canonical_entity_value("ioc", token)))

    return list(dict.fromkeys(ents))


def normalize(r: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in ("_id", "timestamp") if not r.get(field)]
    if missing:
        raise ValueError(f"Record is missing required field(s): {', '.join(missing)}")
    try:
        parse_ts(str(r["timestamp"]))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Record {r['_id']} has an invalid timestamp: {r['timestamp']!r}") from exc

    ents = extract_entities(r)
    hosts = [v for k, v in ents if k == "host"]
    users = [v for k, v in ents if k == "user"]
    ips = [v for k, v in ents if k in ("ip", "ioc")]
    return {
        "id": r["_id"],
        "timestamp": r["timestamp"],
        "source": r.get("source", "unknown"),
        "event_type": r.get("event_type"),
        "host": hosts[0] if hosts else None,
        "hosts": hosts,
        "users": users,
        "ips": ips,
        "raw": r,
        "entities": ents,
        "source_credibility": SOURCE_CREDIBILITY.get(r.get("source"), 0.60),
    }


def temporal_decay(minutes: float, tau: float = 30.0) -> float:
    return math.exp(-max(minutes, 0.0) / tau)


def _shared_indicator(a: dict[str, Any], b: dict[str, Any]) -> bool:
    a_ips = {v for k, v in a["entities"] if k in {"ip", "ioc"}}
    b_ips = {v for k, v in b["entities"] if k in {"ip", "ioc"}}
    shared_ip = a_ips & b_ips
    a_ioc = {v for k, v in a["entities"] if k == "ioc"}
    b_ioc = {v for k, v in b["entities"] if k == "ioc"}
    return bool(shared_ip & (a_ioc | b_ioc))


def edge_strength(a: dict[str, Any], b: dict[str, Any], max_minutes: float = 90.0) -> tuple[float, list[str]]:
    ta, tb = parse_ts(a["timestamp"]), parse_ts(b["timestamp"])
    dt = abs((tb - ta).total_seconds()) / 60.0
    if dt > max_minutes:
        return 0.0, []

    shared = set(a["entities"]) & set(b["entities"])
    if not shared:
        return 0.0, []

    # Use the strongest relationship, but reward multiple corroborating relationships modestly.
    weights = [ENTITY_WEIGHTS.get(typ, 0.2) for typ, _ in shared]
    relationship = max(weights) + min(0.20, 0.08 * (len(weights) - 1))

    # Cross-source corroboration is more valuable than same-source chaining.
    source_factor = 1.0 if a["source"] != b["source"] else 0.72
    decay = temporal_decay(dt)
    strength = min(1.0, relationship * source_factor * decay)
    reasons = [f"shared:{typ}" for typ, _ in shared]
    if _shared_indicator(a, b):
        strength = min(1.0, strength + 0.12)
        reasons.append("explicit-IOC-corroboration")
    return strength, reasons


def candidate_clusters(norm: list[dict[str, Any]], threshold: float = 0.38) -> list[list[dict[str, Any]]]:
    d = DSU()
    for r in norm:
        d.find(r["id"])

    # High-performance candidate pairing: invert index by entities so only pairs
    # with shared entities are evaluated. Skips disjoint pairs in O(1) without
    # altering the mathematical threshold or edge weights.
    entity_to_indices: dict[tuple[str, str], list[int]] = defaultdict(list)
    for idx, r in enumerate(norm):
        for ent in r["entities"]:
            entity_to_indices[ent].append(idx)

    candidate_pairs: set[tuple[int, int]] = set()
    for indices in entity_to_indices.values():
        if len(indices) > 1:
            for i in range(len(indices)):
                for j in range(i + 1, len(indices)):
                    candidate_pairs.add((min(indices[i], indices[j]), max(indices[i], indices[j])))

    for i, j in sorted(candidate_pairs):
        strength, _ = edge_strength(norm[i], norm[j])
        if strength >= threshold:
            d.union(norm[i]["id"], norm[j]["id"])

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in norm:
        groups[d.find(r["id"])].append(r)
    return [sorted(v, key=lambda x: x["timestamp"]) for v in groups.values() if len(v) > 1]


def tag_technique(r: dict[str, Any], techniques: dict[str, Any]) -> tuple[str | None, float, str | None]:
    t = text_of(r)
    hinted = r.get("attack_id_hint")
    if hinted in techniques:
        return hinted, 0.95, "explicit CTI technique reference"
    if "spearphishing attachment" in t or r.get("event_type") == "email_attachment_opened" or ("attachment" in t and "winword" in t):
        return "T1566.001", 0.90, "attachment-based phishing behavior"
    if r.get("process") == "powershell.exe" and r.get("parent_process") in {"winword.exe", "excel.exe", "outlook.exe"}:
        return "T1059.001", 0.94, "PowerShell launched by Office/document process"
    if r.get("process") == "powershell.exe" and re.search(r"(^|\s)-enc(odedcommand)?(\s|$)", t):
        return "T1059.001", 0.92, "encoded PowerShell command line"
    if "lsass" in t or "credential dumping" in t or "credential access attempt" in t:
        return "T1003.001", 0.93, "LSASS credential-access behavior"
    if r.get("protocol", "").upper() == "RDP" and r.get("dst_port") == 3389:
        return "T1021.001", 0.92, "Remote Desktop Protocol evidence"
    if "admin share" in t or (r.get("protocol", "").upper() == "SMB"):
        return "T1021.002", 0.86, "SMB/admin-share evidence"
    if r.get("protocol", "").upper() == "SSH" or (r.get("dst_port") == 22 and r.get("source") == "network_sensor"):
        return "T1021.004", 0.82, "SSH transport evidence"
    return None, 0.0, None


def technique_events(cluster: list[dict[str, Any]], techniques: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    seen: set[tuple[str, str]] = set()
    for r in cluster:
        tid, conf, why = tag_technique(r["raw"], techniques)
        if not tid or tid not in techniques:
            continue
        tactics = [t for t in techniques[tid].get("tactics", []) if t in TACTIC_RANK]
        if not tactics:
            continue
        tactic = min(tactics, key=lambda t: TACTIC_RANK[t])
        key = (r["id"], tid)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "record_id": r["id"],
            "timestamp": r["timestamp"],
            "technique": tid,
            "technique_name": techniques[tid].get("name", tid),
            "tactic": tactic,
            "tactic_rank": TACTIC_RANK[tactic],
            "confidence": conf,
            "reason": why,
        })
    return sorted(out, key=lambda x: x["timestamp"])


def attack_flow(tech_events: list[dict[str, Any]]) -> dict[str, Any]:
    if len(tech_events) < 2:
        return {"score": 0.0, "progression": 0.0, "depth": min(1.0, len(tech_events) / 4), "transitions": [], "unobserved_intermediate_tactics": []}

    strict_up = 0
    same = 0
    backtracks = 0
    transitions = []
    observed_ranks = []
    for prev, cur in zip(tech_events, tech_events[1:]):
        delta = cur["tactic_rank"] - prev["tactic_rank"]
        if delta > 0:
            strict_up += 1
            label = "progression"
        elif delta == 0:
            same += 1
            label = "same-tactic-repeat"
        else:
            backtracks += 1
            label = "backtrack"
        transitions.append({"from": prev["tactic"], "to": cur["tactic"], "label": label})
        observed_ranks.extend([prev["tactic_rank"], cur["tactic_rank"]])

    total = max(1, len(transitions))
    progression = max(0.0, (strict_up + 0.25 * same - 0.75 * backtracks) / total)
    distinct = len({e["technique"] for e in tech_events})
    depth = min(1.0, distinct / 4.0)

    # These are intermediate tactics not observed between the minimum and maximum observed ranks.
    unobserved = []
    ranks = sorted(set(observed_ranks))
    if len(ranks) >= 2:
        for rank in range(ranks[0] + 1, ranks[-1]):
            tactic = next((t for t, idx in TACTIC_RANK.items() if idx == rank), None)
            if tactic and tactic not in {e["tactic"] for e in tech_events}:
                unobserved.append(tactic)

    score = round(0.65 * progression + 0.35 * depth, 3)
    return {
        "score": score,
        "progression": round(progression, 3),
        "depth": round(depth, 3),
        "strict_progressions": strict_up,
        "backtracks": backtracks,
        "transitions": transitions,
        "unobserved_intermediate_tactics": unobserved,
    }


def _semantic_fingerprint(raw: dict[str, Any]) -> str:
    keys = ("event_type", "process", "parent_process", "cmdline", "dst_ip", "dst_host", "src_host", "host", "user", "protocol", "dst_port")
    values = {k: raw.get(k) for k in keys if raw.get(k) is not None}
    return json.dumps(values, sort_keys=True, separators=(",", ":"))


def source_independence(cluster: list[dict[str, Any]]) -> float:
    """Estimate corroboration diversity while discounting duplicate semantic observations."""
    source_set = {r["source"] for r in cluster}
    unique_fps = {_semantic_fingerprint(r["raw"]) for r in cluster}
    # Independent source contribution has diminishing returns; semantic diversity prevents
    # a batch of duplicate events from being mistaken for independent evidence.
    source_diversity = min(1.0, len(source_set) / 3.0)
    semantic_diversity = min(1.0, len(unique_fps) / max(1, len(cluster)))
    return round(0.70 * source_diversity + 0.30 * semantic_diversity, 3)


def asset_criticality(cluster: list[dict[str, Any]], assets: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    hits = []
    seen_assets: set[str] = set()
    for r in cluster:
        candidates = list(r["hosts"])
        candidates += [r["raw"].get("src_host"), r["raw"].get("dst_host")]
        for host in candidates:
            if host and host in assets and host not in seen_assets:
                meta = assets[host]
                hits.append({"asset": host, **meta})
                seen_assets.add(host)
    if not hits:
        return 45, []
    return max(int(x.get("criticality", 45)) for x in hits), hits


def negative_evidence(cluster: list[dict[str, Any]]) -> list[dict[str, Any]]:
    negatives = []
    for r in cluster:
        raw = r["raw"]
        t = text_of(raw)
        if raw.get("event_type") == "antivirus_scan_clean":
            negatives.append({"factor": "clean antivirus result", "penalty": 0.12, "record_id": r["id"]})
        if "approved" in t or "known admin" in t:
            negatives.append({"factor": "approved administrative context", "penalty": 0.15, "record_id": r["id"]})
        if raw.get("parent_process") == "explorer.exe" and raw.get("process") == "powershell.exe" and "-enc" not in t:
            negatives.append({"factor": "interactive PowerShell without suspicious parent", "penalty": 0.07, "record_id": r["id"]})
    return negatives


def _independent_source_coverage(cluster: list[dict[str, Any]]) -> float:
    return min(1.0, len({r["source"] for r in cluster}) / 3.0)


def actor_similarity(observed: list[str], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gtech: dict[str, set[str]] = defaultdict(set)
    counts: Counter[str] = Counter()
    groups = set()
    for e in edges:
        g, tid = e.get("group"), e.get("technique_id")
        if g and tid:
            gtech[g].add(tid)
            counts[tid] += 1
            groups.add(g)
    N = max(1, len(groups))
    obs = set(observed)
    out = []
    for g, tids in gtech.items():
        shared = tids & obs
        if not shared:
            continue
        specificity = sum(math.log((N + 1) / max(1, counts[tid])) for tid in shared)
        coverage = len(shared) / max(1, len(obs))
        norm = specificity / (specificity + 3.5)
        similarity = 100 * (0.72 * norm + 0.28 * coverage)
        out.append({"group": g, "similarity": round(similarity, 1), "shared_techniques": sorted(shared)})
    return sorted(out, key=lambda x: -x["similarity"])[:5]


def actor_assessment(matches: list[dict[str, Any]]) -> str:
    """Describe historical technique overlap without implying actor attribution.

    A tied similarity score is not a meaningful discriminator. Present it as an
    ambiguity rather than letting source-file order select an arbitrary actor name.
    """
    if not matches:
        return "No sufficiently distinctive historical behavior profile was identified; this is not attribution."
    best = matches[0]
    close_matches = [m for m in matches if abs(m["similarity"] - best["similarity"]) < 5]
    if len(close_matches) > 1:
        names = ", ".join(m["group"] for m in close_matches[:3])
        return (
            f"Observed techniques overlap with multiple historical groups ({names}); "
            "the available evidence does not differentiate an actor and is not attribution."
        )
    if best["similarity"] < 60:
        return "Technique overlap is too weak for a useful historical behavior comparison; this is not attribution."
    return (
        f"Observed behavior has the strongest historical overlap with {best['group']} "
        f"({best['similarity']} similarity); this is context, not attribution."
    )


def _ioc_specificity(cluster: list[dict[str, Any]]) -> float:
    ioc_count = sum(1 for r in cluster if any(k == "ioc" for k, _ in r["entities"]))
    return min(1.0, ioc_count / 2.0)


def score_cluster(cluster: list[dict[str, Any]], techniques: dict[str, Any], edges: list[dict[str, Any]], assets: dict[str, Any]) -> dict[str, Any]:
    tech_events = technique_events(cluster, techniques)
    flow = attack_flow(tech_events)
    src_ind = source_independence(cluster)
    neg = negative_evidence(cluster)
    impact, asset_hits = asset_criticality(cluster, assets)
    ioc_specificity = _ioc_specificity(cluster)
    source_coverage = _independent_source_coverage(cluster)

    tech_conf = (sum(e["confidence"] for e in tech_events) / len(tech_events)) if tech_events else 0.0
    behavior_severity = max([TECHNIQUE_RISK.get(e["technique"], 55) for e in tech_events] or [35])
    source_quality = sum(max(r["source_credibility"] for r in cluster if r["source"] == src) for src in {r["source"] for r in cluster}) / max(1, len({r["source"] for r in cluster}))
    corroboration = 0.45 * src_ind + 0.30 * source_coverage + 0.25 * source_quality
    # Explainable confidence: behavior + corroboration + IOC specificity - contradiction.
    raw_conf = 0.45 * tech_conf + 0.30 * flow["score"] + 0.18 * corroboration + 0.07 * ioc_specificity
    contradiction_penalty = min(0.35, sum(n["penalty"] for n in neg))
    confidence = max(0.0, min(1.0, raw_conf - contradiction_penalty))

    severity = min(100, round(0.55 * behavior_severity + 30 * flow["score"] + 15 * ioc_specificity))
    urgency = min(100, round(45 + 22 * flow["score"] + 18 * source_coverage + 15 * (1 if impact >= 80 else 0)))
    priority_score = round(100 * (0.45 * confidence + 0.25 * severity / 100 + 0.20 * impact / 100 + 0.10 * urgency / 100))
    priority = "P1" if priority_score >= 82 else ("P2" if priority_score >= 65 else ("P3" if priority_score >= 45 else "P4"))

    evidence = []
    for r in cluster:
        tid, tc, why = tag_technique(r["raw"], techniques)
        provenance = {
            "record_id": r["id"],
            "timestamp": r["timestamp"],
            "source": r["source"],
            "summary": summarize_record(r["raw"]),
            "technique": tid,
            "technique_name": techniques[tid].get("name", tid) if tid else None,
            "technique_confidence": tc,
            "technique_reason": why,
            "source_credibility": r["source_credibility"],
        }
        if any(k == "ioc" for k, _ in r["entities"]):
            provenance["ioc_evidence"] = True
        evidence.append(provenance)

    iid = "INC-CAND-" + hashlib.sha1("|".join(sorted(r["id"] for r in cluster)).encode()).hexdigest()[:8].upper()
    distinct_tactics = {event["tactic"] for event in tech_events}
    promotion_checks = {
        "minimum_behavior_evidence": len(tech_events) >= 2,
        "multi_tactic_progression": len(distinct_tactics) >= 2 and flow["score"] >= 0.50,
        "evidence_confidence": confidence >= 0.55,
        "source_independence": src_ind >= 0.50,
    }
    return {
        "id": iid,
        "record_ids": [r["id"] for r in cluster],
        "sources": sorted({r["source"] for r in cluster}),
        "confidence": round(confidence * 100, 1),
        "severity": severity,
        "mission_impact": impact,
        "urgency": urgency,
        "priority_score": priority_score,
        "priority": priority,
        "promotable": all(promotion_checks.values()),
        "promotion_checks": promotion_checks,
        "technique_count": len(tech_events),
        "techniques": tech_events,
        "attack_flow": flow,
        "evidence": evidence,
        "negative_evidence": neg,
        "actor_similarity": actor_similarity([e["technique"] for e in tech_events], edges),
        "asset_criticality": impact,
        "assets": asset_hits,
        "source_independence": src_ind,
        "risk_factors": {
            "behavior_confidence": round(tech_conf * 100, 1),
            "attack_flow_coherence": round(flow["score"] * 100, 1),
            "source_corroboration": round(corroboration * 100, 1),
            "source_quality": round(source_quality * 100, 1),
            "ioc_specificity": round(ioc_specificity * 100, 1),
            "contradiction_penalty": round(contradiction_penalty * 100, 1),
        },
        "runbook": remediation_runbook({
            "mission_impact": impact,
            "assets": asset_hits,
            "techniques": tech_events,
            "attack_flow": flow,
        }),
    }


def summarize_record(raw: dict[str, Any]) -> str:
    s = raw.get("detail") or raw.get("text") or raw.get("event_type") or raw.get("process") or "event"
    return str(s)[:220]


def analyze(root: Path) -> dict[str, Any]:
    records, techniques, groups, edges, assets = load_context(str(root.resolve()))
    if not isinstance(records, list):
        raise ValueError("demo_alerts.json must contain a JSON list of observations")
    record_ids = [record.get("_id") for record in records]
    if len(record_ids) != len(set(record_ids)):
        raise ValueError("demo_alerts.json contains duplicate observation IDs")
    norm = [normalize(r) for r in records]
    clusters = candidate_clusters(norm)
    incidents = [score_cluster(c, techniques, edges, assets) for c in clusters]
    incidents.sort(key=lambda x: (-int(x["promotable"]), -x["priority_score"]))
    return {
        "records": records,
        "incidents": incidents,
        "candidate_clusters": clusters,
        "techniques": techniques,
        "groups": groups,
        "edges": edges,
        "assets": assets,
        "metadata": {
            "engine_version": ENGINE_VERSION,
            "attack_kb_version": "v19.2",
            "ground_truth_used_for_runtime": False,
        },
    }


def promoted_incidents(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    return [x for x in analysis["incidents"] if x["promotable"]]


def remediation_runbook(inc: dict[str, Any]) -> list[dict[str, Any]]:
    steps = []
    if inc.get("mission_impact", 0) >= 80:
        affected = [a["asset"] for a in inc.get("assets", [])]
        steps.append({
            "phase": "Containment",
            "action": f"Isolate critical host(s) {', '.join(affected) if affected else 'affected mission assets'} from production VLAN.",
            "priority": "Immediate",
            "target": "Network / Firewall",
        })
    if any(e["technique"] == "T1003.001" for e in inc.get("techniques", [])):
        steps.append({
            "phase": "Eradication",
            "action": "Force global credential reset and Kerberos ticket revocation for compromised service/admin accounts.",
            "priority": "Immediate",
            "target": "Active Directory / IAM",
        })
    if any(e["technique"] == "T1021.001" for e in inc.get("techniques", [])):
        steps.append({
            "phase": "Containment",
            "action": "Disable remote desktop protocol (RDP 3389) laterally across non-jumpbox workstations.",
            "priority": "High",
            "target": "Endpoint Policy / GPO",
        })
    if any(e["technique"] == "T1566.001" for e in inc.get("techniques", [])):
        steps.append({
            "phase": "Eradication",
            "action": "Purge malicious invoice attachment from mailboxes across enterprise Exchange/M365.",
            "priority": "High",
            "target": "Email Security Gateway",
        })
    gaps = inc.get("attack_flow", {}).get("unobserved_intermediate_tactics", [])
    if gaps:
        steps.append({
            "phase": "Detection Engineering",
            "action": f"Deploy targeted hunting queries and sysmon audit rules for unobserved intermediate tactics: {', '.join(gaps)}.",
            "priority": "Medium",
            "target": "SIEM / Detection Rules",
        })
    return steps


def bluf(inc: dict[str, Any]) -> dict[str, Any]:
    techniques = ", ".join(dict.fromkeys(e["technique"] + " " + e["technique_name"] for e in inc["techniques"])) or "No high-confidence ATT&CK technique"
    actor_line = actor_assessment(inc["actor_similarity"])
    actions = []
    if inc["mission_impact"] >= 80:
        actions.append("Prioritize containment of the affected mission-critical asset.")
    if any(e["technique"] == "T1003.001" for e in inc["techniques"]):
        actions.append("Validate credential exposure and rotate affected privileged credentials.")
    if any(e["technique"] == "T1021.001" for e in inc["techniques"]):
        actions.append("Review RDP authentication and lateral-movement telemetry.")
    if not actions:
        actions.append("Collect additional endpoint and identity telemetry before escalation.")
    gaps = inc["attack_flow"].get("unobserved_intermediate_tactics", [])
    return {
        "bottom_line": f"{inc['priority']} incident with {inc['confidence']}% evidence confidence, {inc['severity']}/100 threat severity and {inc['mission_impact']}/100 mission impact.",
        "assessment": f"Observed activity forms a {'coherent' if inc['attack_flow']['score'] >= 0.55 else 'weak'} multi-stage behavior pattern. ATT&CK evidence: {techniques}.",
        "actor_assessment": actor_line,
        "uncertainty": (
            "Unobserved intermediate tactics: " + ", ".join(gaps) + ". Absence may be a telemetry gap rather than absence of attacker activity."
            if gaps else
            "No material contradicting evidence was identified in the available demo telemetry."
        ),
        "recommended_actions": actions[:4],
        "runbook": remediation_runbook(inc),
    }
