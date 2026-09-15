from __future__ import annotations

import json
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from src.threatfusion.engine import analyze, bluf, promoted_incidents, remediation_runbook, TACTIC_RANK

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="ThreatFusion — Evidence-Backed Threat Intelligence", version="2.0.0")

INDEX = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ThreatFusion — Defense Threat Intelligence Correlation & BLUF Prioritisation</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #050b14;
      --bg-card: rgba(13, 27, 42, 0.85);
      --bg-card-hover: rgba(18, 38, 58, 0.95);
      --panel: #0d1b2a;
      --panel2: #11253a;
      --text: #f0f6fc;
      --text-muted: #8b9bb4;
      --border: #1e3a5a;
      --border-focus: #38bdf8;
      --cyan: #38bdf8;
      --indigo: #818cf8;
      --green: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --p1-bg: rgba(244, 63, 94, 0.2);
      --p1-border: #f43f5e;
      --p2-bg: rgba(245, 158, 11, 0.2);
      --p2-border: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, #0d2238 0%, #050b14 70%);
      color: var(--text);
      font-family: 'Inter', -apple-system, sans-serif;
      min-height: 100vh;
      line-height: 1.5;
    }
    .container { max-width: 1440px; margin: 0 auto; padding: 24px; }
    
    /* Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .brand-group { display: flex; align-items: center; gap: 14px; }
    .brand-icon {
      width: 44px; height: 44px; border-radius: 12px;
      background: linear-gradient(135deg, #0284c7, #6366f1);
      display: flex; align-items: center; justify-content: center;
      font-weight: 900; font-size: 22px; color: #fff;
      box-shadow: 0 0 24px rgba(56, 189, 248, 0.4);
    }
    .brand-title { font-size: 26px; font-weight: 800; letter-spacing: -0.5px; }
    .brand-title span { color: var(--cyan); }
    .brand-sub { font-size: 13px; color: var(--text-muted); font-weight: 400; }
    .badge-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .badge {
      font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
      padding: 5px 10px; border-radius: 9999px; background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.25); color: var(--cyan);
    }
    .pulse-dot {
      width: 8px; height: 8px; border-radius: 50%; background: var(--green);
      display: inline-block; margin-right: 6px; box-shadow: 0 0 8px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.9); } 100% { opacity: 1; transform: scale(1); } }
    
    /* Top KPIs */
    .kpi-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px; margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--bg-card); backdrop-filter: blur(12px);
      border: 1px solid var(--border); border-radius: 14px;
      padding: 18px 20px; transition: transform 0.2s, border-color 0.2s;
    }
    .kpi-card:hover { transform: translateY(-2px); border-color: rgba(56, 189, 248, 0.4); }
    .kpi-label { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; }
    .kpi-value { font-size: 32px; font-weight: 800; margin: 4px 0; color: #fff; font-family: 'JetBrains Mono', monospace; }
    .kpi-desc { font-size: 12px; color: var(--text-muted); }
    
    /* Tab Navigation */
    .tab-bar {
      display: flex; gap: 8px; border-bottom: 1px solid var(--border);
      margin-bottom: 24px; overflow-x: auto; padding-bottom: 2px;
    }
    .tab-btn {
      background: transparent; border: none; color: var(--text-muted);
      padding: 10px 18px; font-size: 14px; font-weight: 600; cursor: pointer;
      border-radius: 8px 8px 0 0; transition: all 0.2s; display: flex; align-items: center; gap: 8px;
    }
    .tab-btn:hover { color: var(--text); background: rgba(255, 255, 255, 0.04); }
    .tab-btn.active {
      color: var(--cyan); background: rgba(56, 189, 248, 0.08);
      border-bottom: 2px solid var(--cyan);
    }
    
    /* Layouts */
    .split-layout { display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 24px; }
    @media (max-width: 1080px) { .split-layout { grid-template-columns: 1fr; } }
    
    .panel {
      background: var(--bg-card); backdrop-filter: blur(12px);
      border: 1px solid var(--border); border-radius: 14px; padding: 22px; margin-bottom: 24px;
    }
    .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .panel-title { font-size: 17px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
    
    /* Table */
    .incident-table { width: 100%; border-collapse: collapse; }
    .incident-table th { text-align: left; padding: 10px 12px; font-size: 11px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); font-weight: 600; }
    .incident-table td { padding: 14px 12px; font-size: 13px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
    .incident-table tr { cursor: pointer; transition: background 0.15s; }
    .incident-table tr:hover { background: rgba(56, 189, 248, 0.05); }
    .incident-table tr.selected { background: rgba(56, 189, 248, 0.12); border-left: 3px solid var(--cyan); }
    
    /* Badges & Pills */
    .pill { display: inline-flex; align-items: center; padding: 3px 8px; border-radius: 6px; font-weight: 700; font-size: 11px; text-transform: uppercase; }
    .pill.p1 { background: var(--p1-bg); color: #fda4af; border: 1px solid var(--p1-border); }
    .pill.p2 { background: var(--p2-bg); color: #fde68a; border: 1px solid var(--p2-border); }
    .pill.source { background: rgba(99, 102, 241, 0.15); color: #c7d2fe; border: 1px solid rgba(99, 102, 241, 0.3); font-family: 'JetBrains Mono', monospace; font-size: 11px; }
    
    /* Attack Kill Chain Visualizer */
    .kill-chain { display: flex; align-items: stretch; gap: 10px; margin: 20px 0; overflow-x: auto; padding-bottom: 8px; }
    .chain-node {
      flex: 1; min-width: 140px; background: rgba(17, 37, 58, 0.8); border: 1px solid var(--border);
      border-radius: 10px; padding: 12px; text-align: center; position: relative;
    }
    .chain-node.active { border-color: var(--cyan); background: rgba(14, 43, 70, 0.9); box-shadow: 0 0 12px rgba(56, 189, 248, 0.2); }
    .chain-phase { font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--cyan); letter-spacing: 0.5px; }
    .chain-tech { font-size: 13px; font-weight: 700; margin: 4px 0; font-family: 'JetBrains Mono', monospace; }
    .chain-name { font-size: 11px; color: var(--text-muted); line-height: 1.2; }
    .chain-arrow { align-self: center; color: var(--text-muted); font-size: 16px; font-weight: bold; }
    
    /* 4-Quadrant Priority Decomposition */
    .metric-quad { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
    @media (max-width: 680px) { .metric-quad { grid-template-columns: repeat(2, 1fr); } }
    .quad-box { background: rgba(17, 37, 58, 0.6); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
    .quad-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
    .quad-val { font-size: 24px; font-weight: 800; margin: 4px 0; font-family: 'JetBrains Mono', monospace; }
    .quad-bar { height: 4px; background: rgba(255, 255, 255, 0.1); border-radius: 2px; overflow: hidden; margin-top: 6px; }
    .quad-fill { height: 100%; border-radius: 2px; }
    
    /* Timeline */
    .timeline { position: relative; padding-left: 24px; border-left: 2px solid var(--border); margin: 16px 0; }
    .timeline-item { position: relative; margin-bottom: 18px; }
    .timeline-dot {
      position: absolute; left: -31px; top: 3px; width: 12px; height: 12px;
      border-radius: 50%; background: var(--cyan); border: 2px solid #050b14;
    }
    .timeline-time { font-size: 11px; font-family: 'JetBrains Mono', monospace; color: var(--cyan); font-weight: 600; }
    .timeline-title { font-size: 13px; font-weight: 700; margin: 2px 0; }
    .timeline-body { font-size: 12px; color: var(--text-muted); line-height: 1.4; }
    .timeline-meta { display: flex; gap: 8px; align-items: center; margin-top: 4px; flex-wrap: wrap; }
    
    /* BLUF Block */
    .bluf-card {
      background: #08111d; border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px;
      padding: 18px; position: relative; margin-bottom: 18px;
    }
    .bluf-section { margin-bottom: 14px; }
    .bluf-section:last-child { margin-bottom: 0; }
    .bluf-heading { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: var(--cyan); margin-bottom: 4px; }
    .bluf-text { font-size: 13px; line-height: 1.6; color: #e2e8f0; }
    
    /* Runbook */
    .runbook-step {
      background: rgba(17, 37, 58, 0.5); border-left: 3px solid var(--cyan);
      border-radius: 0 8px 8px 0; padding: 12px 14px; margin-bottom: 10px; font-size: 13px;
    }
    .step-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
    .step-phase { font-weight: 700; color: var(--cyan); font-size: 12px; text-transform: uppercase; }
    .step-target { font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
    
    /* Buttons */
    .btn {
      background: #0369a1; border: 1px solid #38bdf8; color: #fff;
      padding: 8px 14px; font-size: 12px; font-weight: 600; border-radius: 8px;
      cursor: pointer; display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s;
    }
    .btn:hover { background: #0284c7; box-shadow: 0 0 12px rgba(56, 189, 248, 0.4); }
    .btn-secondary { background: rgba(255, 255, 255, 0.06); border: 1px solid var(--border); color: var(--text); }
    .btn-secondary:hover { background: rgba(255, 255, 255, 0.12); }
    
    /* Toast */
    .toast {
      position: fixed; bottom: 24px; right: 24px; background: #0c4a6e;
      border: 1px solid var(--cyan); color: #fff; padding: 12px 20px;
      border-radius: 10px; font-size: 13px; font-weight: 600; box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      transform: translateY(100px); opacity: 0; transition: all 0.3s; z-index: 9999;
    }
    .toast.show { transform: translateY(0); opacity: 1; }
    
    /* Terminal Preview */
    .terminal {
      background: #04080f; border: 1px solid #1e3a5a; border-radius: 10px;
      padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
      color: #a5f3fc; max-height: 420px; overflow-y: auto; white-space: pre-wrap; line-height: 1.5;
    }
    .mono { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand-group">
        <div class="brand-icon">TF</div>
        <div>
          <div class="brand-title">Threat<span>Fusion</span></div>
          <div class="brand-sub">D2 · Evidence-Backed Threat Intelligence Correlation & Alert Prioritisation Assistant</div>
        </div>
      </div>
      <div class="badge-bar">
        <div class="badge"><span class="pulse-dot"></span>Active Telemetry Pipeline</div>
        <div class="badge">ATT&CK v19.2</div>
        <div class="badge">IBM Bob MCP Ready</div>
        <button class="btn" onclick="copyBobCommand('/investigate INC-CAND-09226FFA')">📋 Copy /investigate</button>
      </div>
    </header>

    <!-- KPI Summary Row -->
    <div class="kpi-grid" id="kpi-row">
      <div class="kpi-card"><div class="kpi-label">Raw Observations</div><div class="kpi-value" id="kpi-raw">37</div><div class="kpi-desc">Multi-source heterogeneous feeds</div></div>
      <div class="kpi-card"><div class="kpi-label">Candidate Hypotheses</div><div class="kpi-value" id="kpi-cand">2</div><div class="kpi-desc">Formed via entity-temporal graphs</div></div>
      <div class="kpi-card"><div class="kpi-label">Promoted Incidents</div><div class="kpi-value" id="kpi-prom" style="color:var(--rose)">1</div><div class="kpi-desc">Validated multi-stage attack story</div></div>
      <div class="kpi-card"><div class="kpi-label">False-Positive Suppression</div><div class="kpi-value" id="kpi-fp" style="color:var(--green)">100%</div><div class="kpi-desc">Ambiguous routine admin suppressed</div></div>
      <div class="kpi-card"><div class="kpi-label">Candidate Compression</div><div class="kpi-value" id="kpi-comp" style="color:var(--cyan)">94.6%</div><div class="kpi-desc">Cognitive alert load reduction</div></div>
    </div>

    <!-- Tab Bar -->
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('triage')">🛡️ Incident Triage & Attack Flow</button>
      <button class="tab-btn" onclick="switchTab('bluf')">📑 Commander BLUF & IR Runbook</button>
      <button class="tab-btn" onclick="switchTab('timeline')">⏱️ Grounded Evidence Timeline</button>
      <button class="tab-btn" onclick="switchTab('baseline')">⚖️ ThreatFusion vs. Naive Baseline</button>
      <button class="tab-btn" onclick="switchTab('mcp')">🤖 IBM Bob MCP Terminal</button>
    </div>

    <!-- TAB 1: Triage & Attack Flow -->
    <div id="tab-triage" class="tab-content">
      <div class="split-layout">
        <div>
          <div class="panel">
            <div class="panel-header">
              <div class="panel-title">Prioritized Incident Candidates</div>
              <span class="badge">Evidence Promotion Gate</span>
            </div>
            <table class="incident-table">
              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Priority</th>
                  <th>Score</th>
                  <th>Confidence</th>
                  <th>Impact</th>
                  <th>Attack Flow</th>
                  <th>Sources</th>
                </tr>
              </thead>
              <tbody id="incident-rows"></tbody>
            </table>
          </div>

          <!-- Attack Flow Kill Chain Graph -->
          <div class="panel">
            <div class="panel-header">
              <div class="panel-title">Attack-Flow Coherence Graph</div>
              <span id="flow-score-badge" class="badge">Coherence: --</span>
            </div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
              Reconstructs adversary campaign sequence from multi-source observations. Measures tactic progression, depth, and backtracks.
            </p>
            <div class="kill-chain" id="kill-chain-nodes"></div>
            <div style="font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between; border-top: 1px solid var(--border); padding-top: 10px;">
              <span id="flow-stat-progressions">Strict Progressions: --</span>
              <span id="flow-stat-backtracks">Backtracks: --</span>
              <span id="flow-stat-unobserved">Unobserved Tactics: --</span>
            </div>
          </div>
        </div>

        <!-- Right Side: Deep Inspection & Decision Dimensions -->
        <div>
          <div class="panel" id="incident-detail-panel">
            <div class="panel-header">
              <div>
                <div id="sel-id" class="panel-title mono">Loading...</div>
                <div id="sel-summary" style="font-size: 12px; color: var(--text-muted);"></div>
              </div>
              <div id="sel-priority-pill"></div>
            </div>

            <!-- 4-Quadrant Prioritization Score -->
            <div class="metric-quad">
              <div class="quad-box">
                <div class="quad-label">Confidence</div>
                <div class="quad-val" id="sel-conf" style="color:var(--cyan)">--%</div>
                <div class="quad-bar"><div id="sel-conf-bar" class="quad-fill" style="background:var(--cyan)"></div></div>
              </div>
              <div class="quad-box">
                <div class="quad-label">Threat Severity</div>
                <div class="quad-val" id="sel-sev" style="color:var(--rose)">--</div>
                <div class="quad-bar"><div id="sel-sev-bar" class="quad-fill" style="background:var(--rose)"></div></div>
              </div>
              <div class="quad-box">
                <div class="quad-label">Mission Impact</div>
                <div class="quad-val" id="sel-imp" style="color:var(--amber)">--</div>
                <div class="quad-bar"><div id="sel-imp-bar" class="quad-fill" style="background:var(--amber)"></div></div>
              </div>
              <div class="quad-box">
                <div class="quad-label">Urgency</div>
                <div class="quad-val" id="sel-urg" style="color:var(--indigo)">--</div>
                <div class="quad-bar"><div id="sel-urg-bar" class="quad-fill" style="background:var(--indigo)"></div></div>
              </div>
            </div>

            <div style="margin-bottom: 16px;">
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px;">Grounded Risk Factor Decomposition</div>
              <div id="risk-factors-bars"></div>
            </div>

            <div style="margin-bottom: 16px;">
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Affected Mission Assets</div>
              <div id="asset-context-list" style="font-size: 12px; color: #cbd5e1;"></div>
            </div>

            <div>
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Adversary Technique Consistency</div>
              <div id="actor-context" style="font-size: 12px; color: var(--text-muted);"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: BLUF & IR Runbook -->
    <div id="tab-bluf" class="tab-content" style="display:none;">
      <div class="split-layout">
        <div>
          <div class="panel">
            <div class="panel-header">
              <div class="panel-title">Commander Bottom Line Up Front (BLUF)</div>
              <div style="display:flex; gap:8px;">
                <button class="btn btn-secondary" onclick="copyBlufText()">📋 Copy BLUF</button>
                <button class="btn" onclick="exportReport()">📥 Export Brief</button>
              </div>
            </div>
            <div class="bluf-card" id="bluf-container">
              <div class="bluf-section">
                <div class="bluf-heading">1. Bottom Line</div>
                <div class="bluf-text" id="bluf-bottom-line">Loading...</div>
              </div>
              <div class="bluf-section">
                <div class="bluf-heading">2. Strategic Assessment</div>
                <div class="bluf-text" id="bluf-assessment">Loading...</div>
              </div>
              <div class="bluf-section">
                <div class="bluf-heading">3. Actor Behavioral Consistency</div>
                <div class="bluf-text" id="bluf-actor">Loading...</div>
              </div>
              <div class="bluf-section">
                <div class="bluf-heading">4. Telemetry Gaps & Uncertainty</div>
                <div class="bluf-text" id="bluf-uncertainty">Loading...</div>
              </div>
            </div>
          </div>
        </div>
        <div>
          <div class="panel">
            <div class="panel-header">
              <div class="panel-title">Incident Response & Remediation Runbook</div>
              <span class="badge">Mapped to ATT&CK</span>
            </div>
            <div id="runbook-steps"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: Evidence Timeline -->
    <div id="tab-timeline" class="tab-content" style="display:none;">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Multi-Source Evidence Timeline</div>
          <div style="display:flex; gap:8px;">
            <button class="btn btn-secondary" onclick="filterTimeline('all')">All Sources</button>
            <button class="btn btn-secondary" onclick="filterTimeline('siem')">SIEM</button>
            <button class="btn btn-secondary" onclick="filterTimeline('endpoint')">Endpoint</button>
            <button class="btn btn-secondary" onclick="filterTimeline('network_sensor')">Network</button>
            <button class="btn btn-secondary" onclick="filterTimeline('threat_intel_report')">Threat Intel</button>
          </div>
        </div>
        <div class="timeline" id="timeline-container"></div>
      </div>
    </div>

    <!-- TAB 4: Baseline Comparison -->
    <div id="tab-baseline" class="tab-content" style="display:none;">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Baseline Comparison: Why Naive Correlation Fails</div>
          <span class="badge">Offline Benchmark Data</span>
        </div>
        <div class="split-layout" style="margin-top: 16px;">
          <div style="background: rgba(244, 63, 94, 0.08); border: 1px solid rgba(244, 63, 94, 0.25); border-radius: 12px; padding: 18px;">
            <h3 style="color:#fda4af; margin-bottom: 8px;">❌ Naive Time + Entity Clustering</h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
              Simple rules ("same host within 90 minutes") cluster all shared administrative activity together without behavioral validation.
            </p>
            <ul style="font-size: 13px; line-height: 1.8; color: #cbd5e1; padding-left: 20px;">
              <li>Generates <b>4 alert clusters</b> from 37 records.</li>
              <li>Flags <b>INC-B</b> (routine admin login + clean scan) as an incident.</li>
              <li>Causes severe analyst alert fatigue and false escalations.</li>
              <li>No ATT&CK sub-technique mapping or attack-flow verification.</li>
            </ul>
          </div>
          <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 12px; padding: 18px;">
            <h3 style="color:#6ee7b7; margin-bottom: 8px;">✅ ThreatFusion Evidence-Backed Model</h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
              Separates candidate hypotheses from incident promotion. Validates tactic progression, corroboration, and negative evidence.
            </p>
            <ul style="font-size: 13px; line-height: 1.8; color: #cbd5e1; padding-left: 20px;">
              <li>Forms <b>2 candidate hypotheses</b> with weighted temporal decay.</li>
              <li>Promotes <b>1 high-confidence incident</b> (INC-A).</li>
              <li>Suppresses <b>INC-B</b> due to clean AV scan and lack of coherent attack flow.</li>
              <li><b>100% false-positive suppression</b> on synthetic benchmark.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 5: Bob MCP Terminal -->
    <div id="tab-mcp" class="tab-content" style="display:none;">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">IBM Bob MCP Interactive Sandbox</div>
          <div style="display:flex; gap:8px;">
            <button class="btn btn-secondary" onclick="runMcpTool('correlate_events')">correlate_events</button>
            <button class="btn btn-secondary" onclick="runMcpTool('get_incident')">get_incident</button>
            <button class="btn btn-secondary" onclick="runMcpTool('explain_risk')">explain_risk</button>
            <button class="btn btn-secondary" onclick="runMcpTool('get_detection_gaps')">get_detection_gaps</button>
            <button class="btn btn-secondary" onclick="runMcpTool('get_remediation_runbook')">get_remediation_runbook</button>
            <button class="btn btn-secondary" onclick="runMcpTool('generate_bluf')">generate_bluf</button>
          </div>
        </div>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
          This terminal queries the exact JSON-RPC tools exposed via <code class="mono">src/mcp_server.py</code> to IBM Bob.
        </p>
        <div class="terminal" id="terminal-out">// Select an MCP tool above to inspect live JSON-RPC response payload...</div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast">Command copied to clipboard</div>

  <script>
    let DATA = null;
    let SELECTED_INCIDENT = null;
    let CURRENT_TIMELINE = [];

    function esc(s) {
      return (s ?? '').toString().replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
    }

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2400);
    }

    function switchTab(tab) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
      document.getElementById('tab-' + tab).style.display = 'block';
      event.currentTarget.classList.add('active');
    }

    async function init() {
      try {
        const res = await fetch('/api/summary');
        if (!res.ok) throw new Error('API request failed');
        DATA = await res.json();
        renderSummary();
      } catch (err) {
        document.getElementById('sel-id').textContent = 'Error loading telemetry: ' + err.message;
      }
    }

    function renderSummary() {
      const d = DATA;
      document.getElementById('kpi-raw').textContent = d.metrics.raw_records;
      document.getElementById('kpi-cand').textContent = d.metrics.candidate_clusters;
      document.getElementById('kpi-prom').textContent = d.metrics.promoted_incidents;
      document.getElementById('kpi-comp').textContent = d.metrics.candidate_compression + '%';

      let rows = '';
      d.incidents.forEach((inc, idx) => {
        const isSel = idx === 0 ? 'selected' : '';
        rows += `
          <tr class="${isSel}" onclick="selectIncident('${inc.id}', this)">
            <td class="mono" style="font-weight:700;">${esc(inc.id)}</td>
            <td><span class="pill ${inc.priority.toLowerCase()}">${esc(inc.priority)}</span></td>
            <td class="mono">${inc.priority_score}</td>
            <td class="mono">${inc.confidence}%</td>
            <td class="mono">${inc.mission_impact}</td>
            <td class="mono">${inc.attack_flow.score}</td>
            <td>${inc.sources.map(s => `<span class="pill source">${esc(s.replace('_',' '))}</span>`).join(' ')}</td>
          </tr>
        `;
      });
      document.getElementById('incident-rows').innerHTML = rows;

      if (d.incidents.length > 0) {
        loadIncidentDetail(d.incidents[0].id);
      }
    }

    async function selectIncident(id, tr) {
      document.querySelectorAll('.incident-table tr').forEach(r => r.classList.remove('selected'));
      tr.classList.add('selected');
      loadIncidentDetail(id);
    }

    async function loadIncidentDetail(id) {
      try {
        const res = await fetch('/api/incidents/' + id);
        if (!res.ok) throw new Error('Failed to fetch incident');
        SELECTED_INCIDENT = await res.json();
        renderIncidentView();
      } catch (err) {
        console.error(err);
      }
    }

    function renderIncidentView() {
      const inc = SELECTED_INCIDENT;
      if (!inc) return;

      document.getElementById('sel-id').textContent = inc.id;
      document.getElementById('sel-summary').textContent = `${inc.record_ids.length} Correlated Events · ${inc.sources.join(', ')}`;
      document.getElementById('sel-priority-pill').innerHTML = `<span class="pill ${inc.priority.toLowerCase()}" style="font-size:13px; padding:6px 12px;">${inc.priority} PRIORITY</span>`;

      // Metrics
      document.getElementById('sel-conf').textContent = inc.confidence + '%';
      document.getElementById('sel-conf-bar').style.width = inc.confidence + '%';
      document.getElementById('sel-sev').textContent = inc.severity + '/100';
      document.getElementById('sel-sev-bar').style.width = inc.severity + '%';
      document.getElementById('sel-imp').textContent = inc.mission_impact + '/100';
      document.getElementById('sel-imp-bar').style.width = inc.mission_impact + '%';
      document.getElementById('sel-urg').textContent = inc.urgency + '/100';
      document.getElementById('sel-urg-bar').style.width = inc.urgency + '%';

      // Risk factors
      let rfHtml = '';
      for (const [k, v] of Object.entries(inc.risk_factors)) {
        rfHtml += `
          <div style="margin-bottom:8px;">
            <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:2px;">
              <span>${esc(k.replaceAll('_',' '))}</span>
              <span class="mono">${v}%</span>
            </div>
            <div style="height:4px; background:rgba(255,255,255,0.08); border-radius:2px;">
              <div style="height:100%; width:${Math.min(100, v)}%; background:var(--cyan); border-radius:2px;"></div>
            </div>
          </div>
        `;
      }
      document.getElementById('risk-factors-bars').innerHTML = rfHtml;

      // Assets
      let assetHtml = inc.assets && inc.assets.length ? inc.assets.map(a => 
        `<div>🎯 <b>${esc(a.asset)}</b> (Criticality: ${a.criticality}/100) — ${esc(a.mission_role)} [${esc(a.zone)}]</div>`
      ).join('') : '<span style="color:var(--text-muted)">No registered critical asset in cluster</span>';
      document.getElementById('asset-context-list').innerHTML = assetHtml;

      // Actor
      let actorHtml = inc.actor_similarity && inc.actor_similarity.length ? inc.actor_similarity.slice(0, 2).map(act =>
        `<div>Historical behavioral consistency: <b>${esc(act.group)}</b> (${act.similarity}% similarity, shared: ${act.shared_techniques.join(', ')}). <i>Note: Not attribution.</i></div>`
      ).join('') : 'No distinctive historical threat actor technique profile.';
      document.getElementById('actor-context').innerHTML = actorHtml;

      // Attack flow
      document.getElementById('flow-score-badge').textContent = 'Coherence Score: ' + inc.attack_flow.score;
      document.getElementById('flow-stat-progressions').textContent = 'Strict Progressions: ' + inc.attack_flow.strict_progressions;
      document.getElementById('flow-stat-backtracks').textContent = 'Backtracks: ' + inc.attack_flow.backtracks;
      document.getElementById('flow-stat-unobserved').textContent = 'Unobserved Tactics: ' + (inc.attack_flow.unobserved_intermediate_tactics.length ? inc.attack_flow.unobserved_intermediate_tactics.join(', ') : 'None');

      let killHtml = '';
      inc.techniques.forEach((t, i) => {
        killHtml += `
          <div class="chain-node active">
            <div class="chain-phase">${esc(t.tactic)}</div>
            <div class="chain-tech">${esc(t.technique)}</div>
            <div class="chain-name">${esc(t.technique_name)}</div>
          </div>
        `;
        if (i < inc.techniques.length - 1) {
          killHtml += '<div class="chain-arrow">➔</div>';
        }
      });
      document.getElementById('kill-chain-nodes').innerHTML = killHtml || '<div style="color:var(--text-muted)">No technique progression</div>';

      // BLUF
      const b = inc.bluf;
      document.getElementById('bluf-bottom-line').textContent = b.bottom_line;
      document.getElementById('bluf-assessment').textContent = b.assessment;
      document.getElementById('bluf-actor').textContent = b.actor_assessment;
      document.getElementById('bluf-uncertainty').textContent = b.uncertainty;

      // Runbook
      let rbHtml = '';
      (inc.runbook || []).forEach((step, idx) => {
        rbHtml += `
          <div class="runbook-step">
            <div class="step-header">
              <span class="step-phase">${idx+1}. ${esc(step.phase)}</span>
              <span class="pill ${step.priority === 'Immediate' ? 'p1' : 'p2'}">${esc(step.priority)}</span>
            </div>
            <div style="font-weight:600; margin-bottom:4px;">${esc(step.action)}</div>
            <div class="step-target">Target: ${esc(step.target)}</div>
          </div>
        `;
      });
      document.getElementById('runbook-steps').innerHTML = rbHtml || '<div style="color:var(--text-muted)">No action steps</div>';

      // Timeline
      CURRENT_TIMELINE = inc.evidence;
      renderTimeline(CURRENT_TIMELINE);
    }

    function renderTimeline(evts) {
      let tHtml = '';
      evts.forEach(e => {
        tHtml += `
          <div class="timeline-item">
            <div class="timeline-dot"></div>
            <div class="timeline-time">${esc(e.timestamp.replace('T', ' ').replace('Z', ' UTC'))}</div>
            <div class="timeline-title">${esc(e.summary)}</div>
            <div class="timeline-meta">
              <span class="pill source">${esc(e.source)}</span>
              <span class="mono" style="font-size:11px; color:var(--text-muted);">${esc(e.record_id)}</span>
              ${e.technique ? `<span class="badge" style="font-size:10px;">${esc(e.technique)} (${Math.round(e.technique_confidence*100)}%)</span>` : ''}
              ${e.ioc_evidence ? `<span class="pill p1" style="font-size:10px;">IOC CORROBORATED</span>` : ''}
            </div>
            ${e.technique_reason ? `<div class="timeline-body" style="margin-top:4px;">${esc(e.technique_reason)}</div>` : ''}
          </div>
        `;
      });
      document.getElementById('timeline-container').innerHTML = tHtml;
    }

    function filterTimeline(source) {
      if (source === 'all') {
        renderTimeline(CURRENT_TIMELINE);
      } else {
        renderTimeline(CURRENT_TIMELINE.filter(e => e.source === source));
      }
    }

    function copyBobCommand(cmd) {
      navigator.clipboard.writeText(cmd);
      showToast('Copied: ' + cmd);
    }

    function copyBlufText() {
      if (!SELECTED_INCIDENT) return;
      const b = SELECTED_INCIDENT.bluf;
      const text = `COMMANDER BLUF — ${SELECTED_INCIDENT.id}\n\nBOTTOM LINE:\n${b.bottom_line}\n\nASSESSMENT:\n${b.assessment}\n\nACTOR CONSISTENCY:\n${b.actor_assessment}\n\nUNCERTAINTY / GAPS:\n${b.uncertainty}\n\nACTIONS:\n${b.recommended_actions.map((a,i)=>`${i+1}. ${a}`).join('\n')}`;
      navigator.clipboard.writeText(text);
      showToast('Commander BLUF copied to clipboard');
    }

    function exportReport() {
      if (!SELECTED_INCIDENT) return;
      const b = SELECTED_INCIDENT.bluf;
      const text = `# COMMANDER INCIDENT BRIEFING — ${SELECTED_INCIDENT.id}\n\n**Generated:** ${new Date().toISOString()}\n**Priority:** ${SELECTED_INCIDENT.priority} (Score: ${SELECTED_INCIDENT.priority_score}/100)\n**Evidence Confidence:** ${SELECTED_INCIDENT.confidence}%\n**Mission Impact:** ${SELECTED_INCIDENT.mission_impact}/100\n\n## Bottom Line\n${b.bottom_line}\n\n## Assessment\n${b.assessment}\n\n## Actor Consistency\n${b.actor_assessment}\n\n## Uncertainty & Detection Gaps\n${b.uncertainty}\n\n## Remediation Runbook\n${(SELECTED_INCIDENT.runbook || []).map((s, i) => `### ${i+1}. [${s.phase}] ${s.action}\n- **Priority:** ${s.priority}\n- **Target System:** ${s.target}`).join('\n\n')}\n`;
      const blob = new Blob([text], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${SELECTED_INCIDENT.id}_BLUF_Report.md`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Report exported successfully');
    }

    async function runMcpTool(toolName) {
      const out = document.getElementById('terminal-out');
      out.textContent = `Executing MCP tool "${toolName}" over JSON-RPC stdio simulation...\n`;
      try {
        const iid = SELECTED_INCIDENT ? SELECTED_INCIDENT.id : 'INC-CAND-09226FFA';
        const res = await fetch(`/api/mcp-query?tool=${toolName}&incident_id=${iid}`);
        const data = await res.json();
        out.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        out.textContent = `Error executing MCP tool: ${err.message}`;
      }
    }

    window.addEventListener('DOMContentLoaded', init);
  </script>
</body>
</html>
'''


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX


@app.get("/api/summary")
def summary() -> dict:
    d = analyze(ROOT)
    promoted = promoted_incidents(d)
    for x in promoted:
        x["bluf"] = bluf(x)
        x["runbook"] = remediation_runbook(x)
    raw = len(d["records"])
    candidate_count = len(d["incidents"])
    compression = round(100 * (1 - candidate_count / max(1, raw)), 1)
    return {
        "metadata": d["metadata"],
        "metrics": {
            "raw_records": raw,
            "candidate_clusters": candidate_count,
            "promoted_incidents": len(promoted),
            "candidate_compression": compression,
        },
        "incidents": promoted[:12],
    }


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str) -> dict:
    d = analyze(ROOT)
    for x in promoted_incidents(d):
        if x["id"] == incident_id:
            x["bluf"] = bluf(x)
            x["runbook"] = remediation_runbook(x)
            return x
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/evaluation")
def evaluation() -> dict:
    # Kept separate from runtime promotion: does not expose ground-truth records
    d = analyze(ROOT)
    return {
        "engine_version": d["metadata"]["engine_version"],
        "attack_kb_version": d["metadata"]["attack_kb_version"],
        "candidate_clusters": len(d["incidents"]),
        "promoted_incidents": len(promoted_incidents(d)),
    }


@app.get("/api/mcp-query")
def mcp_query(tool: str = Query(...), incident_id: str = Query(None), query: str = Query(None)) -> dict:
    from src.mcp_server import tool_call
    args = {}
    if incident_id:
        args["incident_id"] = incident_id
    if query:
        args["query"] = query
    return tool_call(tool, args)
