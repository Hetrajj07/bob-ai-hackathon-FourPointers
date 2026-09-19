# Solution Overview

> **IBM BoB AI Innovation Hackathon 2026 · Challenge: Threat Intelligence Correlation & Alert Prioritisation Assistant**

## What We Built

**ThreatFusion** is an evidence-backed intelligence assistant and dynamic backend that ingests multi-source threat feeds (SIEM systems, satellite feeds, cyber sensors, and intelligence reports), correlates observations into candidate hypotheses, eliminates false positives, maps behaviors to MITRE ATT&CK, and produces structured, commander-ready Bottom Line Up Front (BLUF) briefings through IBM Bob.

---

## The End-to-End Pipeline

1. **Heterogeneous Multi-Source Ingestion & Persistence:**
   - Ingests SIEM logs, satellite downlink/telemetry feeds, endpoint & network cyber sensors, and CTI advisories into a persistent **SQLite relational database**.
   - Normalizes disparate schemas into a canonical representation while preserving complete original provenance.

2. **Inverted Entity Index Candidate Clustering:**
   - Evaluates shared entity pairs (`ioc`: 1.0, `ip`: 0.82, `host`: 0.65, `user`: 0.58) using continuous temporal decay ($\tau = 30$ min).
   - The inverted index reduces pairwise comparisons by **96.5%** ($O(N^2) \rightarrow O(k)$) compared to naive all-pairs scanning.

3. **MITRE ATT&CK v19.2 Behavioral Inference:**
   - Tags specific sub-techniques (e.g. `T1003.001` LSASS memory dump, `T1059.001` PowerShell execution, `T1566.001` Spearphishing attachment, `T1021.001` RDP lateral movement).
   - Generates explicit audit rationales for every tagged event.

4. **Attack-Flow Coherence & False-Positive Elimination:**
   - Measures tactic progression, depth, and backtracks across the kill-chain.
   - Evaluates cross-source independence and incorporates **negative evidence** (clean AV scans, routine administrative explorer-powershell execution) to suppress benign noise.

5. **Explainable 4D Risk Scoring:**
   - Decomposes priority into 4 distinct dimensions: **Evidence Confidence**, **Threat Severity**, **Mission Impact**, and **Urgency**.
   - Applies strict promotion checks so that weak or uncorroborated clusters remain candidate hypotheses rather than polluting the active incident queue.

6. **Structured Commander BLUF & Response Actions:**
   - Generates military-standard **Bottom Line Up Front (BLUF)** summaries for operational commanders in minutes.
   - Provides staged containment, eradication, and detection engineering runbooks requiring analyst sign-off.

7. **IBM Bob MCP Server:**
   - Exposes read-only JSON-RPC 2.0 stdio tools (`correlate_events`, `get_incident`, `explain_risk`, `get_detection_gaps`, `generate_bluf`, `get_remediation_runbook`, `search_indicators`) directly to IBM Bob.
   - Bob synthesizes executive briefings without inventing scores or hallucinating evidence.

---

## Comparison: Naïve SIEM vs. ThreatFusion

| Capability | Naïve Correlation / Static SIEM | ThreatFusion Engine |
|---|---|---|
| **Feed Sources** | Single SIEM or endpoint silo | Multi-source: SIEM, satellite feeds, cyber sensors, CTI |
| **Storage & State** | Static or heavy external infra | Lightweight, zero-dependency persistent SQLite backend |
| **Clustering Logic** | Blind "same host + time window" | Inverted entity index + relationship weights + temporal decay |
| **False-Positive Handling** | Alert inflation; high analyst fatigue | Strict candidate vs. incident promotion + negative evidence |
| **ATT&CK Mapping** | Generic tactic keyword hits | Specific sub-technique mapping with per-record provenance |
| **Prioritization** | Single opaque 1-100 severity number | 4D decomposition: Confidence, Severity, Impact, Urgency |
| **Commander Briefing** | Raw log dumps and tickets | Structured, decision-ready BLUF in plain language |
| **AI Assistant** | Uncontrolled LLM prompt hallucination | Grounded IBM Bob MCP server with isolated scores |
