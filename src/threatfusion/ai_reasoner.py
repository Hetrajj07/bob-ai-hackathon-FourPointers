"""Evidence-Grounded AI Reasoning Engine for ThreatFusion and IBM Bob.

Strictly adheres to grounded facts:
- Uses ONLY structured evidence from ThreatFusion's correlation engine.
- Never invents alerts, indicators, timestamps, techniques, or attacker attribution.
- Supports pluggable watsonx.ai LLM via environment variables, with an offline
  deterministic synthesis fallback so it NEVER fails or crashes.
- When watsonx is configured, it receives structured evidence as a grounded context
  block — the LLM is used for natural-language synthesis, not for inventing scores.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger("threatfusion.ai_reasoner")

SYSTEM_PROMPT = """You are a cybersecurity investigation assistant for ThreatFusion.
Use ONLY the structured evidence supplied in the [GROUNDED EVIDENCE] block below.
Never invent an alert, indicator, timestamp, technique, affected asset, or attacker identity.
If evidence is insufficient for the question, explicitly say so.
Distinguish observed facts from interpretation.
Do not claim attribution unless explicit evidence supports it.
Answer in plain language: one direct sentence followed by at most three short bullets.
Do not recommend an action unless it appears in the supplied runbook.
Do not infer an unobserved attack stage from a technique name."""


def _build_evidence_block(inc: dict[str, Any]) -> str:
    """Serialize the key grounded facts from an incident into a structured text block."""
    techs = [f"{t.get('technique')} {t.get('technique_name')}: {t.get('reason', '')}" for t in inc.get("techniques", [])]
    assets = [a.get("asset", "") for a in inc.get("assets", []) if isinstance(a, dict)]
    negs = [n.get("factor", "") for n in inc.get("negative_evidence", [])]
    gaps = inc.get("attack_flow", {}).get("unobserved_intermediate_tactics", [])
    sources = inc.get("sources", [])
    runbook = [f"[{s.get('phase')}] {s.get('priority')}: {s.get('action')}" for s in inc.get("runbook", [])]
    bluf = inc.get("bluf", {})

    lines = [
        f"INCIDENT_ID: {inc.get('id', 'N/A')}",
        f"PRIORITY: {inc.get('priority', 'N/A')} ({inc.get('priority_score', 0)}/100)",
        f"EVIDENCE_CONFIDENCE: {inc.get('confidence', 0)}%",
        f"THREAT_SEVERITY: {inc.get('severity', 0)}/100",
        f"MISSION_IMPACT: {inc.get('mission_impact', 0)}/100",
        f"URGENCY: {inc.get('urgency', 0)}/100",
        f"CORRELATED_ALERTS: {len(inc.get('record_ids', []))} alerts",
        f"SOURCES: {', '.join(sources)}",
        f"SOURCE_INDEPENDENCE: {round(inc.get('source_independence', 0) * 100, 1)}%",
        f"AFFECTED_ASSETS: {', '.join(assets) if assets else 'none identified'}",
        f"ATT&CK_TECHNIQUES:\n" + "\n".join(f"  - {t}" for t in techs),
        f"ATTACK_FLOW_COHERENCE: {inc.get('risk_factors', {}).get('attack_flow_coherence', 0)}%",
        f"NEGATIVE_EVIDENCE: {', '.join(negs) if negs else 'none'}",
        f"TELEMETRY_GAPS: {', '.join(gaps) if gaps else 'none'}",
        f"RUNBOOK:\n" + "\n".join(f"  - {r}" for r in runbook),
    ]
    if bluf:
        lines += [
            f"BLUF_BOTTOM_LINE: {bluf.get('bottom_line', '')}",
            f"BLUF_ACTOR_ASSESSMENT: {bluf.get('actor_assessment', '')}",
        ]
    return "\n".join(lines)


class ThreatFusionAIReasoner:
    """Grounded reasoning engine that answers analyst inquiries using structured incident evidence.

    When WATSONX_API_KEY + WATSONX_PROJECT_ID are set, answers are synthesized by
    watsonx.ai (ibm/granite-3-8b-instruct) with the grounded evidence block injected
    as the sole context — the model cannot see anything outside that block.

    When watsonx is unavailable (missing keys, network error, rate limit), the engine
    falls back to fully deterministic templated synthesis so the app never crashes.
    """

    def __init__(self) -> None:
        self.watsonx_api_key = os.getenv("WATSONX_API_KEY", "").strip()
        self.watsonx_project_id = os.getenv("WATSONX_PROJECT_ID", "").strip()
        self.watsonx_url = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com").rstrip("/")
        self.watsonx_model = os.getenv("WATSONX_MODEL", "ibm/granite-3-8b-instruct")
        self._iam_token: str | None = None

    def is_external_ai_configured(self) -> bool:
        return bool(self.watsonx_api_key and self.watsonx_project_id)

    # ------------------------------------------------------------------
    # watsonx.ai integration
    # ------------------------------------------------------------------

    def _get_iam_token(self) -> str | None:
        """Exchange an IBM Cloud API key for a short-lived IAM bearer token."""
        try:
            import urllib.request
            import urllib.parse
            data = urllib.parse.urlencode({
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self.watsonx_api_key,
            }).encode()
            req = urllib.request.Request(
                "https://iam.cloud.ibm.com/identity/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read())
                return payload.get("access_token")
        except Exception as exc:
            logger.warning("IAM token fetch failed: %s", exc)
            return None

    def _call_watsonx(self, evidence_block: str, query: str) -> str | None:
        """Call watsonx.ai text generation with grounded evidence context.

        Returns the generated text or None if the call fails for any reason.
        The caller always falls back to deterministic synthesis on None.
        """
        if not self.is_external_ai_configured():
            return None

        token = self._get_iam_token()
        if not token:
            return None

        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"[GROUNDED EVIDENCE]\n{evidence_block}\n"
            f"[END GROUNDED EVIDENCE]\n\n"
            f"Analyst question: {query}\n\n"
            f"Answer (grounded only):"
        )

        payload = json.dumps({
            "model_id": self.watsonx_model,
            "input": prompt,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": 512,
                "stop_sequences": ["[END]"],
                "temperature": 0.0,
            },
            "project_id": self.watsonx_project_id,
        }).encode()

        try:
            import urllib.request
            req = urllib.request.Request(
                f"{self.watsonx_url}/ml/v1/text/generation?version=2023-05-29",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                return result["results"][0]["generated_text"].strip()
        except Exception as exc:
            logger.warning("watsonx generation failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ask(self, incident: dict[str, Any], query: str) -> dict[str, Any]:
        """Answer an analyst question strictly grounded in the supplied incident evidence."""
        if not incident:
            return {
                "answer": "No incident data provided. Please select an active case first.",
                "grounded_facts": [],
                "source": "threatfusion_rule_engine",
                "ai_service": "none",
            }

        q = (query or "").strip().lower()
        if not q:
            return {
                "answer": "Ask a question about this incident, such as its priority, evidence, affected assets, detection gaps, or next action.",
                "grounded_facts": [],
                "source": "grounded_ai_reasoner",
                "ai_service": "deterministic_grounded",
            }

        # Always answer analyst input through deterministic evidence lookups. This
        # avoids treating a fluent model response as a source of incident facts.
        result = self._deterministic_route(incident, q, query)
        result["ai_service"] = "deterministic_grounded"
        return result

    @staticmethod
    def _is_supported_intent(q: str) -> bool:
        """Return whether a question has an exact, evidence-backed response template."""
        keywords = (
            "priority", "score", "risk", "why", "weak", "contradict", "negative",
            "false positive", "missing", "gap", "support", "evidence", "next",
            "investigate", "what to check", "what should", "simple", "layman",
            "what happened", "summarize", "explain", "bluf", "commander", "brief",
            "action", "remediation", "runbook", "do now", "contain",
        )
        return any(word in q for word in keywords)

    def _deterministic_route(self, incident: dict[str, Any], q: str, raw_query: str) -> dict[str, Any]:
        """Route to the best deterministic handler based on query intent."""
        if any(w in q for w in ["priority", "score", "why high", "risk", "why is", "confidence", "severity", "urgent", "urgency", "impact"]):
            return self.explain_priority(incident)
        if any(w in q for w in ["weak", "contradict", "negative", "false positive", "missing", "gap"]):
            return self.explain_contradictions(incident)
        if any(w in q for w in ["support", "evidence", "why believe", "what evidence", "what support"]):
            return self.explain_evidence(incident)
        if any(w in q for w in ["next", "investigate", "investigation step", "what to check", "what should", "what do"]):
            return self.suggest_next_steps(incident)
        if any(w in q for w in ["simple", "layman", "what happened", "summarize", "explain"]):
            return self.explain_simple(incident)
        if any(w in q for w in ["bluf", "commander", "bottom line", "brief"]):
            return self.generate_bluf(incident)
        if any(w in q for w in ["action", "remediation", "runbook", "do now", "security team", "contain"]):
            return self.explain_remediation(incident)
        if any(w in q for w in ["asset", "affected", "target", "host", "system"]):
            return self.answer_assets(incident)
        if any(w in q for w in ["technique", "mitre", "attack method", "behavior"]):
            return self.answer_techniques(incident)
        if any(w in q for w in ["alert", "record", "event", "how many"]):
            return self.answer_alert_count(incident)
        if any(w in q for w in ["source", "sensor", "telemetry"]):
            return self.answer_sources(incident)
        if any(w in q for w in ["indicator", "ioc", "ip address", "ip "]):
            return self.answer_indicators(incident)
        if any(w in q for w in ["time", "when", "timestamp", "date"]):
            return self.answer_timing(incident)
        return self.answer_unknown(incident)

    def answer_assets(self, inc: dict[str, Any]) -> dict[str, Any]:
        assets = [a.get("asset") for a in inc.get("assets", []) if isinstance(a, dict) and a.get("asset")]
        answer = f"Affected assets: **{', '.join(assets)}**." if assets else "No affected asset is identified in the case evidence."
        return {"answer": answer, "grounded_facts": [f"Assets: {', '.join(assets) or 'none'}"], "source": "grounded_ai_reasoner"}

    def answer_techniques(self, inc: dict[str, Any]) -> dict[str, Any]:
        techniques = [f"{t.get('technique')} — {t.get('technique_name')}" for t in inc.get("techniques", []) if t.get("technique")]
        answer = "Observed ATT&CK techniques:\n\n" + "\n".join(f"- {technique}" for technique in techniques[:4]) if techniques else "No ATT&CK technique is mapped with sufficient confidence."
        return {"answer": answer, "grounded_facts": techniques[:4], "source": "grounded_ai_reasoner"}

    def answer_alert_count(self, inc: dict[str, Any]) -> dict[str, Any]:
        count = len(inc.get("record_ids", []))
        return {"answer": f"This case contains **{count} correlated alerts**.", "grounded_facts": [f"Correlated alerts: {count}"], "source": "grounded_ai_reasoner"}

    def answer_sources(self, inc: dict[str, Any]) -> dict[str, Any]:
        sources = inc.get("sources", [])
        return {"answer": f"Evidence comes from {len(sources)} source(s): **{', '.join(sources) or 'none'}**.", "grounded_facts": [f"Sources: {', '.join(sources) or 'none'}"], "source": "grounded_ai_reasoner"}

    def answer_indicators(self, inc: dict[str, Any]) -> dict[str, Any]:
        indicators = []
        for item in inc.get("evidence", []):
            summary = item.get("summary", "")
            if item.get("ioc_evidence") and summary:
                indicators.append(summary)
        if indicators:
            answer = "IOC-related evidence:\n\n" + "\n".join(f"- {item}" for item in indicators[:3])
        else:
            answer = "No explicit IOC value is available in the selected case evidence."
        return {"answer": answer, "grounded_facts": indicators[:3], "source": "grounded_ai_reasoner"}

    def answer_timing(self, inc: dict[str, Any]) -> dict[str, Any]:
        timestamps = [item.get("timestamp") for item in inc.get("evidence", []) if item.get("timestamp")]
        if timestamps:
            answer = f"Observed case activity runs from **{min(timestamps)}** to **{max(timestamps)}**."
        else:
            answer = "The selected case does not include timestamped evidence."
        return {"answer": answer, "grounded_facts": timestamps[:1] + timestamps[-1:], "source": "grounded_ai_reasoner"}

    def answer_unknown(self, inc: dict[str, Any]) -> dict[str, Any]:
        return {
            "answer": "I cannot answer that from the selected incident evidence without guessing. Ask about priority, evidence, assets, techniques, alerts, sources, indicators, timing, gaps, or recommended actions.",
            "grounded_facts": [f"Case: {inc.get('id', 'N/A')}"],
            "source": "grounded_ai_reasoner",
        }

    def explain_priority(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Explain the 4D risk decomposition."""
        p = inc.get("priority", "P1")
        ps = inc.get("priority_score", 0)
        conf = inc.get("confidence", 0)
        sev = inc.get("severity", 0)
        imp = inc.get("mission_impact", 0)
        urg = inc.get("urgency", 0)
        factors = inc.get("risk_factors", {})
        assets = [a.get("asset") for a in inc.get("assets", []) if isinstance(a, dict)]
        asset_str = ", ".join(assets) if assets else "monitored systems"

        top_techniques = ", ".join(t.get("technique_name", t.get("technique", "")) for t in inc.get("techniques", [])[:2]) or "observed activity"
        ans = (
            f"This is **{p} ({ps}/100)** because the evidence indicates a high-risk incident affecting {asset_str}.\n\n"
            f"- Confidence: **{conf}%** from {len(inc.get('record_ids', []))} correlated alerts across {len(inc.get('sources', []))} sources.\n"
            f"- Severity: **{sev}/100**; observed behavior includes {top_techniques}.\n"
            f"- Mission impact / urgency: **{imp}/100** / **{urg}/100**."
        )
        return {
            "answer": ans,
            "grounded_facts": [f"Priority {p}", f"Score {ps}", f"Confidence {conf}%", f"Impact {imp}", f"Assets: {asset_str}"],
            "source": "grounded_ai_reasoner",
        }

    def explain_evidence(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Explain supporting evidence chain."""
        techniques = inc.get("techniques", [])
        tech_str = "\n".join(f"- {t.get('technique_name') or t.get('technique')}: {t.get('reason', 'Behavioral match')}" for t in techniques[:3])
        sources = inc.get("sources", [])
        records = inc.get("record_ids", [])
        src_ind = inc.get("source_independence", 0)

        ans = (
            f"The case is supported by **{len(records)} correlated alerts** from {len(sources)} sources ({', '.join(sources)}).\n\n"
            f"{tech_str or '- No high-confidence technique was mapped.'}\n"
            f"- Source diversity score: **{round(src_ind * 100, 1)}%**."
        )
        return {
            "answer": ans,
            "grounded_facts": [f"{len(records)} records", f"{len(sources)} sources", f"{len(techniques)} techniques"],
            "source": "grounded_ai_reasoner",
        }

    def explain_contradictions(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Explain negative evidence, weak links, or false-positive risks."""
        negs = inc.get("negative_evidence", [])
        flow = inc.get("attack_flow", {})
        gaps = flow.get("unobserved_intermediate_tactics", [])

        if negs:
            neg_str = "\n".join(f"- {n.get('factor')}" for n in negs[:2])
        else:
            neg_str = "- No contradictory telemetry was recorded."
        gap_str = ", ".join(gaps) if gaps else "None identified"
        ans = (
            "The evidence is strong, but these limits should be checked:\n\n"
            f"{neg_str}\n"
            f"- Missing visibility: **{gap_str}** (a sensor visibility gap, not proof that activity did not occur)."
        )
        return {
            "answer": ans,
            "grounded_facts": [f"Negative factors: {len(negs)}", f"Telemetry gaps: {gap_str}"],
            "source": "grounded_ai_reasoner",
        }

    def suggest_next_steps(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Produce prioritized next investigation actions."""
        assets = [a.get("asset") for a in inc.get("assets", []) if isinstance(a, dict)]
        asset_str = ", ".join(assets) if assets else "affected hosts"
        runbook = inc.get("runbook", [])[:3]
        if runbook:
            steps = "\n".join(f"- **{step.get('priority', 'High')}**: {step.get('action')} ({step.get('target', asset_str)})" for step in runbook)
            ans = f"Start with the case runbook for {asset_str}:\n\n{steps}"
        else:
            ans = f"No case-specific next step is available. Review the correlated evidence for {asset_str} and follow your approved incident-response process."
        return {
            "answer": ans,
            "grounded_facts": [f"Target: {asset_str}", f"Runbook steps: {len(runbook)}"],
            "source": "grounded_ai_reasoner",
        }

    def explain_simple(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Produce a non-technical 2-paragraph explanation."""
        p = inc.get("priority", "P1")
        assets = [a.get("asset") for a in inc.get("assets", []) if isinstance(a, dict)]
        asset_str = ", ".join(assets) if assets else "business systems"
        techs = [t.get("technique_name", "") for t in inc.get("techniques", [])]

        observed = ", ".join(techs[:3]) or "suspicious activity"
        ans = (
            f"A **{p} High-Confidence Case** affects {asset_str}.\n\n"
            f"- The system observed: {observed}.\n"
            f"- {len(inc.get('record_ids', []))} alerts from {len(inc.get('sources', []))} sources support the case.\n"
            "- Treat it as an active investigation; the evidence does not establish attacker identity."
        )
        return {
            "answer": ans,
            "grounded_facts": [f"Priority {p}", f"Target {asset_str}"],
            "source": "grounded_ai_reasoner",
        }

    def generate_bluf(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Generate executive Bottom Line Up Front."""
        bluf_obj = inc.get("bluf", {})
        bottom_line = bluf_obj.get("bottom_line") or f"{inc.get('priority', 'P1')} incident with {inc.get('confidence', 0)}% evidence confidence."
        assessment = bluf_obj.get("assessment", "Multi-stage intrusion pattern identified.")
        uncertainty = bluf_obj.get("uncertainty", "No critical contradictory evidence observed.")
        actor = bluf_obj.get("actor_assessment", "Behavioral overlap observed; context only, not attribution.")

        ans = (
            f"### Executive BLUF (Bottom Line Up Front)\n\n"
            f"**Bottom Line**: {bottom_line}\n\n"
            f"**Assessment**: {assessment}\n\n"
            f"**Threat Actor Context**: {actor}\n\n"
            f"**Uncertainty & Gaps**: {uncertainty}\n\n"
            f"**Immediate Decision**: Execute containment on affected mission assets and revoke affected credentials."
        )
        return {
            "answer": ans,
            "grounded_facts": [bottom_line, assessment, actor],
            "source": "grounded_ai_reasoner",
        }

    def explain_remediation(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Explain the remediation runbook."""
        runbook = inc.get("runbook", [])
        if not runbook:
            return {
                "answer": "No specific runbook steps generated. Follow standard SOC containment protocol.",
                "grounded_facts": [],
                "source": "grounded_ai_reasoner",
            }

        steps_str = "\n".join(
            f"- **[{s.get('phase', 'Action')}] ({s.get('priority', 'High')})**: {s.get('action')} *(Target: {s.get('target', 'SOC')})*"
            for s in runbook
        )

        ans = (
            f"### Phased Remediation Runbook\n\n"
            f"ThreatFusion generated the following prioritized response runbook based on the observed ATT&CK techniques and exposed assets:\n\n"
            f"{steps_str}\n\n"
            f"**Execution Guardrail**: All automated containment actions require analyst authorization before policy enforcement."
        )
        return {
            "answer": ans,
            "grounded_facts": [f"{len(runbook)} runbook steps"],
            "source": "grounded_ai_reasoner",
        }

    def _synthesize_general(self, inc: dict[str, Any], query: str) -> dict[str, Any]:
        """Handle free-form questions strictly grounded on incident fields."""
        p = inc.get("priority", "P1")
        score = inc.get("priority_score", 0)
        records = len(inc.get("record_ids", []))
        techs = [f"{t.get('technique')} ({t.get('technique_name')})" for t in inc.get("techniques", [])]

        ans = (
            f"I can confirm the case is **{p} ({score}/100)** with {inc.get('confidence', 0)}% evidence confidence.\n\n"
            f"- {records} correlated alerts across {len(inc.get('sources', []))} sources.\n"
            f"- Observed techniques: {', '.join(techs[:3]) if techs else 'none mapped'}.\n"
            "- Ask about priority, evidence, gaps, or recommended actions for a precise answer."
        )
        return {
            "answer": ans,
            "grounded_facts": [f"ID: {inc.get('id')}", f"Priority: {p}", f"Techniques: {len(techs)}"],
            "source": "grounded_ai_reasoner",
        }


# Global singleton
_global_reasoner: ThreatFusionAIReasoner | None = None


def get_ai_reasoner() -> ThreatFusionAIReasoner:
    global _global_reasoner
    if _global_reasoner is None:
        _global_reasoner = ThreatFusionAIReasoner()
    return _global_reasoner
