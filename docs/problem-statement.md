# Problem Statement

> **IBM BoB AI Innovation Hackathon 2026 · Challenge: Threat Intelligence Correlation & Alert Prioritisation Assistant**

## Official Challenge Statement

> *"Defence analysts receive thousands of alerts daily from SIEM systems, satellite feeds, cyber sensors, and intelligence reports — all in different formats. No human team can read them all. Missing a genuine threat is catastrophic; chasing false positives wastes critical resources. Threat assessments must also be produced in structured BLUF (Bottom Line Up Front) format so commanders get a clear picture in minutes.*
>
> **Your Challenge**: *Build a Bob solution that ingests multi-source threat feeds, correlates alerts to separate genuine threats from false positives, maps attacker techniques to the MITRE ATT&CK framework, and generates prioritised BLUF investigation summaries for commanders."*

---

## The Core Operational Challenges

1. **Massive Heterogeneity Across Multi-Source Feeds:**
   - Ingesting disparate formats across SIEM logs, satellite downlink/telemetry feeds, endpoint and network cyber sensors, and CTI advisory reports.
   - Preserving entity provenance and timestamps without flattening essential contextual metadata.

2. **The Dual Catastrophe: Missed Threats vs. False Positive Exhaustion:**
   - Missing a coordinated multi-stage campaign targeting mission-critical assets (e.g. satellite ground control stations or core engineering databases) is catastrophic.
   - Alert fatigue caused by over-correlating routine IT noise (antivirus clean scans, routine administrative PowerShell) exhausts limited analyst resources.

3. **Attack-Flow Coherence vs. Naive Entity Over-Grouping:**
   - A single adversary action manifests as weak, temporally separated signals across independent systems.
   - Simply grouping by "same host + time window" creates alert inflation and false positives. ThreatFusion creates **candidate hypotheses first**, and promotes only those backed by ATT&CK technique progression and multi-source corroboration.

4. **Commander Decision Velocity (Structured BLUF):**
   - Commanders do not have time to parse 100-page alert logs or opaque AI scores.
   - Assessments must be delivered in military-standard **Bottom Line Up Front (BLUF)** format within minutes, clearly stating the priority, confidence, asset impact, adversary tactics, and immediate containment decisions.

---

## Who is Affected

- **Defence & SOC Analysts:** Triaging thousands of daily alerts across SIEM, satellite, cyber, and intelligence feeds.
- **Incident Responders:** Executing prioritized containment and eradication actions without causing unintended mission disruptions.
- **Operational Commanders:** Requiring executive-level, evidence-backed decision briefings to authorize cyber defence measures.
