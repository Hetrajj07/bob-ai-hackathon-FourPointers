# 3–5 minute demo script

1. Start the local FastAPI dashboard and show **37 observations → 2 candidate hypotheses → 1 promoted incident**.
2. Select `INC-CAND-09226FFA`.
3. Walk the evidence timeline: CTI report → attachment → PowerShell → C2 IOC → LSASS credential access → RDP to `ENG-DB01`.
4. Show the separate decision dimensions: **92.1% confidence, 92 severity, 95 mission impact, 97 urgency**.
5. Show the attack-flow coherence, provenance, actor-consistency disclaimer and unobserved intermediate tactics.
6. In IBM Bob, run `/investigate INC-CAND-09226FFA` and let Bob retrieve the same grounded evidence through MCP.
7. Run `/explain INC-CAND-09226FFA`, then `/bluf INC-CAND-09226FFA`.
8. Close with: **“We prioritize attack stories, not individual alerts.”**

Important: describe the benchmark as synthetic and do not claim that the demo proves production detection accuracy or actor attribution.
