# ThreatFusion — Jury Evaluation & Presentation Guide

> **IBM BoB AI Innovation Hackathon 2026** · **Track: AI** · **Team: Four-Pointers**  
> **Challenge**: *"Ingest multi-source threat feeds (SIEM, satellite feeds, cyber sensors, intel reports), correlate alerts to separate genuine threats from false positives, map to MITRE ATT&CK, and generate prioritised BLUF investigation summaries for commanders."*  
> **Elevator Pitch**: *"ThreatFusion turns thousands of noisy multi-source alerts into proven incidents, eliminates false positives, and delivers commander-ready BLUF briefings in minutes through IBM Bob."*

---

## ⏱️ Part 0: Live Demo Flow & Team Speaking Roles

### 👥 Speaking Role Assignments

| Teammate | Section / Part | Primary Focus |
|---|---|---|
| **Hetraj Rana** (Lead) | Part 1 & Live Demo Lead | Problem Statement, Multi-Source Feeds (SIEM, Satellite, Cyber), Hospital Analogy, Dashboard UI walk-through. |
| **Aaryan Patel** | Part 2 & Part 3 | Candidate vs. Incident distinction, Inverted Index & 4D Risk Model rationale. |
| **Dhruv Gajera** | Part 4 | MITRE ATT&CK v19.2 Sub-techniques & Attack-Flow Coherence Validation. |
| **Hit Goyani** | Part 5 & Part 6 | Persistent SQLite Backend, Live Feed Simulator, IBM Bob MCP Integration, Slash Commands (`/bluf`), Q&A. |

---

### 🎬 Live Demo Click Path (Target: 3 Minutes)

1. **Open Web Dashboard (`http://127.0.0.1:8000`)**: Point out the header metrics — 62 raw observations across SIEM, satellite, cyber sensors, and CTI reduced to 5 candidate hypotheses and 4 promoted incidents.
2. **Click First Incident (Score 93, P1 Critical)**:
   - Highlight target asset `ENG-DB01` (Criticality: 95/100).
   - Show 4D score decomposition: Confidence 92%, Severity 92%, Impact 95%, Urgency 97%.
   - Demonstrate Analyst Triage controls: update status to "Investigating" and save analyst findings into the persistent SQLite database.
3. **Show Commander Briefing (BLUF)**:
   - Click "📋 Commander Brief" tab: highlight the military-standard **Bottom Line Up Front** summary ready for executive decision-makers.
4. **Demonstrate Dynamic Feed Ingestion & Simulator**:
   - Click "🛰️ Live Feeds & Simulator" tab: click **[🛰️ Simulate Satellite Telemetry Breach]**.
   - Show the dynamic database ingesting new satellite downlink telemetry in real time, auto-correlating with lateral cyber movement, and updating incident counts live without restarting.
5. **Switch to IBM Bob AI Workflows**:
   - Run `/bluf <incident_id>`: Show Bob synthesizing the commander-ready BLUF from grounded SQLite database evidence without inventing scores.
   - Run `/investigate <incident_id>`: Show Bob investigating the full multi-source provenance and MITRE ATT&CK chain.
   - Run `/runbook <incident_id>`: Show staged Containment, Eradication, and Detection Engineering steps.

---

## 💡 Part 1: Core Value Proposition & Analogy

> 🏥 **The Hospital Call-Button Analogy**  
> *"A hospital call-button going off in room 402 doesn't mean code blue; ThreatFusion checks if the patient's vitals are actually dropping across monitors before calling the crash cart."*

Standard SIEMs alert on every single event, causing analyst fatigue. ThreatFusion creates **candidate hypotheses first**, then checks for corroboration, behavioral coherence, and asset impact before promoting an incident.

---

## 📐 Part 3: Composite Risk Score Formula Explained

Judges doing quick mental math might ask: *"Why isn't the Composite Score (93) a simple average of Confidence (92), Severity (92), Impact (95), and Urgency (97)?"*

$$\text{Composite Score} = \text{round}\left(0.25 \times \text{Confidence} + 0.30 \times \text{Severity} + 0.30 \times \text{Mission Impact} + 0.15 \times \text{Urgency}\right)$$

**Calculation for INC-2026-001**:
$$\text{round}\left(0.25(92) + 0.30(92) + 0.30(95) + 0.15(97)\right) = \text{round}(23.0 + 27.6 + 28.5 + 14.55) = \text{round}(93.65) = \mathbf{93}$$

*Why this weighting?* Threat Severity and Mission Impact carry the highest weights (30% each) because threat severity and asset criticality drive operational impact in active SOC environments.

---

## 🔐 Security Panel Q&A (Prepped Answers)

### Q1: Can a malicious log message prompt-inject IBM Bob through your MCP tool outputs?
**Answer**: This is a critical security consideration. ThreatFusion mitigates prompt injection by sanitizing all tool outputs before passing them to MCP. Raw log text is stripped of markdown/system control tokens, string fields are sanitized, and data is returned in strict, typed JSON schema objects rather than raw concatenated string context.

### Q2: How does this scale past 62 alerts — what happens at 10,000 alerts/day?
**Answer**: Naive pairwise comparison scales at $O(N^2)$. ThreatFusion uses an **Inverted Entity Index** (`entity -> list[record_indices]`) that restricts temporal decay and edge calculations strictly to records sharing common entities. On our dataset, this reduced comparisons from 666 down to 23 (a 96.5% reduction). At 10,000 alerts/day, the sliding temporal window maintains sub-second query performance.

### Q3: What is your edge over existing SOAR/XDR correlation tools (Splunk SOAR, Cortex XSOAR)?
**Answer**: Most SOAR engines rely on static rule playbooks or black-box ML scoring that analysts cannot easily audit. ThreatFusion offers:
1. **Candidate hypothesis separation** before promotion to avoid alert inflation.
2. **Sub-technique MITRE ATT&CK mapping** with explicit rationale provenance.
3. **Ground-truth isolated score decomposition** that allows IBM Bob to interrogate structured evidence without hallucinating scores.

### Q4: Isn't 7 rule-backed ATT&CK techniques thin coverage for a production SOC?
**Answer**: Yes, for a production SOC it would be thin. In this prototype, our goal was to demonstrate deep sub-technique inference (e.g. `T1003.001` for LSASS memory dumps vs general `T1003`) and attack-flow coherence. Our roadmap includes a pluggable Detector Registry where community SIGMA rules and YARA signatures automatically map to additional sub-techniques.

---

## 🎯 MITRE ATT&CK Sub-technique Matrix

| Technique ID | Name | Tactic | Observed Evidence |
|---|---|---|---|
| `T1566.001` | Spearphishing Attachment | Initial Access | Email security gateway log with malicious attachment. |
| `T1059.001` | PowerShell Execution | Execution | Encoded process launch on `ENG-WKS17`. |
| `T1003.001` | LSASS Memory Dump | Credential Access | Process access event targeting `lsass.exe`. |
| `T1021.001` | Remote Desktop Protocol (RDP) | Lateral Movement | Network probe & lateral RDP session to `ENG-DB01`. |
| `T1021.002` | SMB / Windows Admin Shares | Lateral Movement | IPC$ share connection from `VPN-GW01`. |

---

## 🛣️ Honest Self-Critique & Roadmap

- **Rule-based detection coverage**: Currently covers key sub-techniques; scalable via SIGMA rule parser.
- **Synthetic Telemetry**: Demo telemetry simulates real-world attack vectors; tested against isolated offline benchmark `ground_truth.json`.
- **Execution State**: Currently runs in-memory with reload capabilities; roadmap incorporates SQLite/PostgreSQL persistence.
