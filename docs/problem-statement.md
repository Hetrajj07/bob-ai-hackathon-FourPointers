# Problem Statement

## Background

D2 asks teams to address a defence-intelligence problem: analysts receive large volumes of security alerts, cyber-sensor observations, satellite/intelligence feeds and intelligence reports in different formats. The challenge is not merely to display those alerts, but to correlate evidence, reduce false positives, map adversary behavior to MITRE ATT&CK and produce a prioritised BLUF for commanders.

## The Problem

A single attacker action may appear as several weak signals across independent systems. Conversely, ordinary administrative activity can share common entities such as a host, user or process and look connected when it is not. A useful assistant must therefore form **candidate hypotheses first**, then promote only those supported by coherent behavioral evidence and corroboration.

## Who is Affected

- Defence/SOC analysts triaging high-volume heterogeneous telemetry.
- Threat-intelligence analysts connecting indicators and adversary behavior.
- Commanders who need a decision-ready summary rather than a raw alert queue.

## Why It Matters

The official D2 statement highlights the operational cost of thousands of daily alerts and the danger of both missed genuine threats and wasted investigation effort. Our prototype focuses on the decision point immediately before escalation: which observations form a credible incident, why, and what should happen next.

## Why Existing Approaches Fall Short

Simple rules such as “same host + same time window” over-correlate noisy activity. A single opaque AI score is also difficult to audit. ThreatFusion separates candidate clustering from incident promotion and decomposes priority into evidence confidence, threat severity, mission impact and urgency.
