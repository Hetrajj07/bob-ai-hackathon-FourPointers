"""ThreatFusion analyst workspace and read-only API.

The UI deliberately presents a case review workflow instead of an alert-counting
dashboard: understand the case, inspect evidence, decide on next actions, and
hand the grounded facts to IBM Bob when narrative assistance is useful.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from src.threatfusion.engine import ENGINE_VERSION, analyze, bluf, clear_context_cache, promoted_incidents, remediation_runbook

logger = logging.getLogger("threatfusion")
ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="ThreatFusion - Analyst Workspace", version=ENGINE_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

INDEX = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0a0f1e">
  <title>ThreatFusion — Analyst Workspace</title>
  <style>
    :root {
      --bg: #0a0f1e;
      --bg2: #0e1629;
      --bg3: #121d36;
      --surface: #16213e;
      --surface2: #1a2850;
      --border: #1e2e52;
      --border2: #243460;
      --text: #e8f0ff;
      --text2: #a0b4d6;
      --muted: #6a82a8;
      --faint: #3d5278;
      --cyan: #00d4ff;
      --cyan-dim: rgba(0,212,255,.15);
      --cyan-glow: 0 0 18px rgba(0,212,255,.4);
      --purple: #a855f7;
      --purple-dim: rgba(168,85,247,.15);
      --purple-glow: 0 0 18px rgba(168,85,247,.4);
      --amber: #fbbf24;
      --amber-dim: rgba(251,191,36,.12);
      --green: #10b981;
      --green-dim: rgba(16,185,129,.15);
      --red: #f43f5e;
      --red-dim: rgba(244,63,94,.15);
      --blue: #3b82f6;
      --blue-dim: rgba(59,130,246,.15);
      --p1-color: #f43f5e;
      --p1-bg: rgba(244,63,94,.18);
      --p2-color: #fbbf24;
      --p2-bg: rgba(251,191,36,.18);
      --p3-color: #10b981;
      --p3-bg: rgba(16,185,129,.18);
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, sans-serif; font-size: 14px; line-height: 1.6; }
    button, input { font: inherit; }
    button { cursor: pointer; }
    button:focus-visible, a:focus-visible { outline: 2px solid var(--cyan); outline-offset: 3px; }
    .skip-link { position: fixed; left: 16px; top: -80px; z-index: 9999; padding: 10px 16px; border-radius: 8px; background: var(--surface); color: var(--cyan); border: 1px solid var(--cyan); }
    .skip-link:focus { top: 16px; }

    /* ── TOPBAR ── */
    .topbar {
      position: sticky; top: 0; z-index: 100;
      height: 64px; padding: 0 clamp(16px,3vw,48px);
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
      background: rgba(10,15,30,.92); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
    }
    .brand { display: flex; align-items: center; gap: 12px; text-decoration: none; }
    .brand-mark {
      width: 36px; height: 36px; border-radius: 10px;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      display: grid; place-items: center;
      font-size: 18px; font-weight: 900; color: #fff;
      box-shadow: var(--cyan-glow);
    }
    .brand-name { font-size: 18px; font-weight: 800; color: var(--text); letter-spacing: -.02em; }
    .brand-sub { font-size: 11px; color: var(--muted); letter-spacing: .04em; }
    .topbar-right { display: flex; align-items: center; gap: 16px; }
    .topbar-badge {
      padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700;
      background: var(--cyan-dim); color: var(--cyan); border: 1px solid rgba(0,212,255,.3);
    }
    .topbar-meta { font-size: 11px; color: var(--muted); text-align: right; }

    /* ── SEARCH BAR ── */
    .search-bar-wrap {
      padding: 10px clamp(16px,3vw,48px);
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 10px;
    }
    .search-input-wrap { position: relative; flex: 1; max-width: 480px; }
    .search-icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--muted); font-size: 14px; pointer-events: none; }
    .search-input {
      width: 100%; padding: 9px 12px 9px 36px;
      background: var(--surface); border: 1px solid var(--border2);
      border-radius: 8px; color: var(--text); font-size: 13px;
      transition: border-color .2s, box-shadow .2s;
    }
    .search-input::placeholder { color: var(--muted); }
    .search-input:focus { outline: none; border-color: var(--cyan); box-shadow: 0 0 0 3px rgba(0,212,255,.12); }
    .search-btn {
      padding: 9px 18px; border-radius: 8px; font-size: 13px; font-weight: 700;
      background: linear-gradient(135deg, var(--cyan), #0098cc);
      color: #000; border: none; white-space: nowrap;
      transition: opacity .2s, transform .1s;
    }
    .search-btn:hover { opacity: .88; transform: translateY(-1px); }
    .search-results {
      display: none; position: absolute; top: calc(100% + 6px); left: 0; right: 0;
      background: var(--surface2); border: 1px solid var(--border2);
      border-radius: 10px; z-index: 200; max-height: 280px; overflow-y: auto;
      box-shadow: 0 16px 40px rgba(0,0,0,.5);
    }
    .search-results.open { display: block; }
    .search-result-item { padding: 10px 14px; border-bottom: 1px solid var(--border); cursor: pointer; transition: background .15s; }
    .search-result-item:last-child { border-bottom: none; }
    .search-result-item:hover { background: var(--border); }
    .search-result-id { font-family: ui-monospace, monospace; font-size: 11px; color: var(--cyan); font-weight: 700; }
    .search-result-snippet { font-size: 12px; color: var(--text2); margin-top: 2px; }
    .search-result-ts { font-size: 11px; color: var(--muted); }
    .search-no-results { padding: 16px; text-align: center; color: var(--muted); font-size: 13px; }

    /* ── LAYOUT ── */
    .layout { display: grid; grid-template-columns: minmax(240px, 280px) minmax(0, 1fr); max-width: 1600px; margin: 0 auto; min-height: calc(100vh - 104px); }

    /* ── SIDEBAR ── */
    .case-rail { background: var(--bg2); border-right: 1px solid var(--border); padding: 24px 16px; display: flex; flex-direction: column; gap: 0; }
    .rail-header { margin-bottom: 16px; }
    .eyebrow { font-size: 10px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--cyan); margin-bottom: 6px; }
    .rail-title { font-size: 16px; font-weight: 800; color: var(--text); margin-bottom: 4px; }
    .rail-copy { font-size: 12px; color: var(--muted); margin-bottom: 16px; }

    /* Funnel banner inside sidebar */
    .funnel-banner { display: flex; align-items: center; justify-content: space-between; gap: 2px; background: var(--surface); border: 1px solid var(--border2); border-radius: 10px; padding: 10px 8px; margin-bottom: 16px; }
    .funnel-step { text-align: center; flex: 1; }
    .funnel-num { font-size: 20px; font-weight: 900; line-height: 1; }
    .funnel-num.raw { color: var(--text2); }
    .funnel-num.cand { color: var(--amber); }
    .funnel-num.prom { color: var(--green); text-shadow: 0 0 12px rgba(16,185,129,.6); }
    .funnel-label { font-size: 10px; color: var(--muted); margin-top: 2px; }
    .funnel-arrow { color: var(--faint); font-size: 16px; }

    .case-list { display: grid; gap: 8px; flex: 1; }
    .case-item {
      width: 100%; padding: 13px 14px; text-align: left;
      border: 1px solid var(--border); border-radius: 10px;
      color: var(--text); background: var(--surface);
      transition: border-color .18s, background .18s, box-shadow .18s;
    }
    .case-item:hover { border-color: var(--border2); background: var(--surface2); }
    .case-item[aria-current="true"] {
      border-color: var(--cyan);
      background: rgba(0,212,255,.06);
      box-shadow: 0 0 0 1px rgba(0,212,255,.2), inset 0 0 24px rgba(0,212,255,.04);
    }
    .case-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px; }
    .case-id { font-family: ui-monospace, monospace; font-size: 11px; font-weight: 700; color: var(--cyan); }
    .priority {
      display: inline-flex; align-items: center; gap: 4px;
      padding: 2px 8px; border-radius: 999px; font-size: 10px; font-weight: 800;
    }
    .priority.p1 { color: var(--p1-color); background: var(--p1-bg); box-shadow: 0 0 8px rgba(244,63,94,.3); }
    .priority.p2 { color: var(--p2-color); background: var(--p2-bg); box-shadow: 0 0 8px rgba(251,191,36,.3); }
    .priority.p3 { color: var(--p3-color); background: var(--p3-bg); }
    .case-techniques { font-size: 11px; color: var(--text2); margin-bottom: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .case-foot { display: flex; gap: 8px; }
    .case-stat { font-size: 10px; color: var(--muted); background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 2px 6px; }

    .rail-divider { border: none; border-top: 1px solid var(--border); margin: 16px 0; }
    .rail-note { font-size: 11px; color: var(--muted); padding: 10px 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }
    .rail-note strong { color: var(--text2); }

    /* ── MAIN AREA ── */
    main { min-width: 0; display: flex; flex-direction: column; }

    /* Case header */
    .case-header {
      padding: 24px clamp(18px,3vw,40px) 0;
      display: flex; align-items: flex-start; justify-content: space-between; gap: 20px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 18px;
    }
    .case-header-left { flex: 1; min-width: 0; }
    .case-title { font-size: clamp(20px,2.5vw,30px); font-weight: 900; color: var(--text); letter-spacing: -.03em; margin-bottom: 6px; font-family: ui-monospace, monospace; }
    .case-summary-text { font-size: 13px; color: var(--text2); }
    .case-signal {
      flex-shrink: 0; padding: 12px 18px; border-radius: 12px;
      background: var(--surface); border: 1px solid var(--border2);
      text-align: center; min-width: 140px;
    }
    .case-signal-label { font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
    .case-signal-value { font-size: 22px; font-weight: 900; color: var(--cyan); }

    /* Status strip */
    #status {
      padding: 6px clamp(18px,3vw,40px);
      font-size: 12px; color: var(--green); min-height: 30px;
      border-bottom: 1px solid var(--border);
      background: var(--bg2);
    }

    /* ── TABS ── */
    .tabbar {
      display: flex; gap: 2px; overflow-x: auto; padding: 0 clamp(18px,3vw,40px);
      background: var(--bg2); border-bottom: 1px solid var(--border);
      scrollbar-width: none;
    }
    .tabbar::-webkit-scrollbar { display: none; }
    .tab {
      min-height: 46px; padding: 0 16px; border: none; border-bottom: 3px solid transparent;
      background: transparent; color: var(--muted); white-space: nowrap;
      font-size: 13px; font-weight: 700; transition: color .18s, border-color .18s;
      display: flex; align-items: center; gap: 6px;
    }
    .tab:hover { color: var(--text); }
    .tab[aria-selected="true"] { color: var(--cyan); border-bottom-color: var(--cyan); }
    .tab-icon { font-size: 15px; }

    /* ── PANELS ── */
    .panel { display: none; padding: clamp(18px,3vw,36px) clamp(18px,3vw,40px); }
    .panel.active { display: block; }

    /* ── GRID HELPERS ── */
    .split { display: grid; grid-template-columns: minmax(0,1.4fr) minmax(280px,.8fr); gap: 20px; }
    .stack { display: flex; flex-direction: column; gap: 20px; }

    /* ── CARDS ── */
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; padding: 20px 22px;
    }
    .card-glow-cyan { border-color: rgba(0,212,255,.3); box-shadow: 0 0 24px rgba(0,212,255,.08); }
    .card-glow-red { border-color: rgba(244,63,94,.3); box-shadow: 0 0 24px rgba(244,63,94,.06); }
    .card h2 { font-size: 16px; font-weight: 800; color: var(--text); margin-bottom: 4px; }
    .card h3 { font-size: 13px; font-weight: 700; color: var(--text2); margin-bottom: 6px; }
    .card p { font-size: 13px; color: var(--muted); margin-bottom: 0; }
    .decision-copy { font-size: 15px; color: var(--text); line-height: 1.65; }

    /* ── METRIC GRID ── */
    .metric-grid { display: grid; grid-template-columns: repeat(2,1fr); gap: 10px; margin-top: 12px; }
    .metric {
      padding: 14px; border-radius: 10px;
      background: var(--bg3); border: 1px solid var(--border);
    }
    .metric-label { display: block; font-size: 10px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
    .metric-value { display: block; font-size: 28px; font-weight: 900; line-height: 1; }
    .metric-value.conf { color: var(--cyan); }
    .metric-value.sev { color: var(--p1-color); }
    .metric-value.impact { color: var(--purple); }
    .metric-value.urgency { color: var(--amber); }
    .metric-note { display: block; font-size: 11px; color: var(--muted); margin-top: 4px; }

    /* ── PROMOTION CHECKS ── */
    .check-list { list-style: none; display: grid; gap: 10px; margin-top: 12px; }
    .check-list li { display: flex; align-items: flex-start; gap: 10px; }
    .check-mark {
      flex-shrink: 0; width: 20px; height: 20px; border-radius: 50%;
      display: grid; place-items: center; font-size: 11px; font-weight: 900; margin-top: 1px;
    }
    .check-mark.pass { background: var(--green-dim); color: var(--green); border: 1px solid rgba(16,185,129,.4); }
    .check-mark.fail { background: var(--red-dim); color: var(--red); border: 1px solid rgba(244,63,94,.4); }
    .check-label { font-size: 13px; font-weight: 700; color: var(--text); }
    .check-detail { font-size: 12px; color: var(--muted); margin-top: 2px; }

    /* ── SOURCE BADGES ── */
    .source-badge {
      display: inline-block; padding: 2px 7px; border-radius: 4px;
      font-size: 10px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
    }
    .src-siem { background: rgba(59,130,246,.2); color: #60a5fa; border: 1px solid rgba(59,130,246,.3); }
    .src-endpoint { background: rgba(168,85,247,.2); color: #c084fc; border: 1px solid rgba(168,85,247,.3); }
    .src-network_sensor { background: rgba(0,212,255,.15); color: var(--cyan); border: 1px solid rgba(0,212,255,.3); }
    .src-threat_intel_report { background: rgba(251,191,36,.15); color: var(--amber); border: 1px solid rgba(251,191,36,.3); }

    /* ── TIMELINE ── */
    .timeline { position: relative; display: grid; gap: 0; margin-top: 12px; }
    .timeline-item { display: grid; grid-template-columns: 64px minmax(0,1fr); gap: 14px; padding-bottom: 18px; position: relative; }
    .timeline-item:not(:last-child)::before { content:""; position:absolute; left: 65px; top: 28px; bottom: 0; width: 1px; background: var(--border); }
    .ttime { color: var(--cyan); font-family: ui-monospace, monospace; font-size: 11px; font-weight: 700; padding-top: 6px; }
    .evidence {
      position: relative; padding: 12px 14px;
      background: var(--bg3); border: 1px solid var(--border);
      border-radius: 10px; transition: border-color .2s;
    }
    .evidence:hover { border-color: var(--border2); }
    .evidence::before {
      content: ""; position: absolute; top: 14px; left: -7px;
      width: 12px; height: 12px; border-radius: 50%;
      background: var(--bg); border: 2px solid var(--cyan);
    }
    .evidence-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; margin-bottom: 6px; }
    .evidence-title { font-size: 13px; font-weight: 700; color: var(--text); }
    .technique-tag { margin-top: 4px; font-family: ui-monospace, monospace; font-size: 11px; color: var(--green); background: var(--green-dim); border: 1px solid rgba(16,185,129,.3); border-radius: 4px; display: inline-block; padding: 1px 7px; }
    .evidence-reason { font-size: 12px; color: var(--text2); margin-top: 5px; }

    /* ── FILTERS ── */
    .filters { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }
    .filter {
      padding: 6px 12px; border-radius: 999px; font-size: 12px; font-weight: 700;
      border: 1px solid var(--border); background: var(--surface); color: var(--text2);
      transition: all .18s;
    }
    .filter:hover { border-color: var(--cyan); color: var(--cyan); }
    .filter[aria-pressed="true"] { background: var(--cyan); border-color: var(--cyan); color: #000; }

    /* ── ASSETS ── */
    .asset-list { display: grid; gap: 8px; margin-top: 10px; }
    .asset-card { padding: 10px 12px; background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; }
    .asset-name { font-family: ui-monospace, monospace; font-size: 12px; font-weight: 700; color: var(--purple); }
    .asset-role { font-size: 12px; color: var(--text2); margin-top: 2px; }
    .asset-crit { font-size: 11px; color: var(--muted); margin-top: 2px; }
    .crit-bar { height: 4px; border-radius: 2px; background: var(--border); margin-top: 6px; overflow: hidden; }
    .crit-fill { height: 100%; border-radius: 2px; background: linear-gradient(90deg, var(--green), var(--amber), var(--red)); }

    /* ── UNCERTAINTY NOTICE ── */
    .notice { padding: 12px 14px; border-radius: 10px; background: rgba(251,191,36,.08); border: 1px solid rgba(251,191,36,.25); color: var(--amber); font-size: 13px; margin-top: 12px; }

    /* ── BRIEF ── */
    .brief-section { padding: 14px 0; border-bottom: 1px solid var(--border); }
    .brief-section:last-of-type { border-bottom: none; }
    .brief-label { font-size: 10px; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; color: var(--cyan); margin-bottom: 6px; }
    .brief-text { font-size: 14px; color: var(--text); line-height: 1.65; }
    .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }
    .button {
      min-height: 40px; padding: 8px 18px; border-radius: 8px;
      font-size: 13px; font-weight: 700; border: none;
      background: linear-gradient(135deg, var(--cyan), #0098cc);
      color: #000; transition: opacity .2s, transform .1s;
    }
    .button:hover { opacity: .85; transform: translateY(-1px); }
    .button.secondary {
      background: transparent; color: var(--cyan);
      border: 1px solid rgba(0,212,255,.4);
    }
    .button.secondary:hover { background: var(--cyan-dim); }

    /* ── ACTION LIST (runbook) ── */
    .action-list { list-style: none; display: grid; gap: 10px; margin-top: 12px; }
    .action-item { padding: 14px; border-radius: 10px; background: var(--bg3); border: 1px solid var(--border); border-left: 3px solid var(--amber); }
    .action-phase { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: .06em; margin-bottom: 6px; }
    .phase-Containment { background: rgba(244,63,94,.15); color: var(--red); border: 1px solid rgba(244,63,94,.3); }
    .phase-Eradication { background: rgba(168,85,247,.15); color: var(--purple); border: 1px solid rgba(168,85,247,.3); }
    .phase-Detection { background: rgba(59,130,246,.15); color: #60a5fa; border: 1px solid rgba(59,130,246,.3); }
    .action-priority { display: inline-block; margin-left: 6px; font-size: 10px; font-weight: 700; color: var(--amber); }
    .action-text { font-size: 13px; color: var(--text); line-height: 1.55; }
    .action-target { font-size: 11px; color: var(--muted); margin-top: 4px; }

    /* ── COMPARE PANEL ── */
    .compare-funnel { display: flex; align-items: center; justify-content: center; gap: 0; margin: 20px 0; }
    .funnel-box { text-align: center; padding: 16px 24px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; min-width: 130px; }
    .funnel-big { font-size: 48px; font-weight: 900; line-height: 1; display: block; }
    .funnel-big.raw { color: var(--text2); }
    .funnel-big.cand { color: var(--amber); }
    .funnel-big.prom { color: var(--green); text-shadow: 0 0 20px rgba(16,185,129,.6); }
    .funnel-desc { font-size: 12px; color: var(--muted); margin-top: 6px; }
    .funnel-big-arrow { font-size: 28px; color: var(--faint); padding: 0 12px; }
    .compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; }
    .compare-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }
    .compare-card.bad { border-color: rgba(244,63,94,.3); }
    .compare-card.good { border-color: rgba(16,185,129,.3); }
    .compare-card-title { font-size: 13px; font-weight: 800; margin-bottom: 12px; }
    .compare-card.bad .compare-card-title { color: var(--red); }
    .compare-card.good .compare-card-title { color: var(--green); }
    .plain-list { list-style: none; display: grid; gap: 7px; }
    .plain-list li { font-size: 13px; color: var(--text2); padding-left: 14px; position: relative; }
    .plain-list li::before { content: "•"; position: absolute; left: 0; color: var(--muted); }

    /* ── BOB PANEL ── */
    .mcp-command { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; background: var(--bg3); border: 1px solid var(--border); border-radius: 10px; transition: border-color .18s; }
    .mcp-command:hover { border-color: var(--border2); }
    .mcp-cmd-code { font-family: ui-monospace, monospace; font-size: 13px; color: var(--cyan); font-weight: 700; }
    .mcp-cmd-desc { font-size: 12px; color: var(--muted); margin-top: 3px; }
    .mcp-tools-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
    .tool-btn {
      padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 700;
      background: var(--surface2); border: 1px solid var(--border2); color: var(--text2);
      transition: all .18s;
    }
    .tool-btn:hover { border-color: var(--cyan); color: var(--cyan); background: var(--cyan-dim); }
    .tool-output {
      min-height: 160px; max-height: 400px; overflow-y: auto;
      padding: 14px; border-radius: 10px;
      background: #050b18; border: 1px solid var(--border);
      color: #7dd3a8; font-family: ui-monospace, monospace; font-size: 12px;
      line-height: 1.6; white-space: pre-wrap;
    }

    /* ── EMPTY / LOADING ── */
    .empty { padding: 28px; text-align: center; color: var(--muted); font-size: 13px; }
    .loading-pulse { animation: pulse 1.4s ease-in-out infinite; }
    @keyframes pulse { 0%,100%{opacity:.4} 50%{opacity:1} }

    /* ── RESPONSIVE ── */
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      .case-rail { border-right: none; border-bottom: 1px solid var(--border); }
      .case-list { grid-template-columns: repeat(auto-fill, minmax(220px,1fr)); display: grid; }
      .split { grid-template-columns: 1fr; }
    }
    @media (max-width: 600px) {
      .topbar { height: auto; padding: 12px 16px; flex-wrap: wrap; }
      .tabbar { padding: 0 12px; }
      .panel { padding: 16px; }
      .metric-grid { grid-template-columns: 1fr; }
      .compare-grid { grid-template-columns: 1fr; }
      .timeline-item { grid-template-columns: 1fr; gap: 4px; }
      .timeline-item::before { display: none; }
      .evidence::before { display: none; }
      .compare-funnel { flex-direction: column; gap: 8px; }
      .funnel-big-arrow { transform: rotate(90deg); }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#workspace">Skip to workspace</a>
  <div class="shell">

    <!-- TOPBAR -->
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">T</div>
        <div>
          <div class="brand-name">ThreatFusion</div>
          <div class="brand-sub">Evidence-first intelligence workspace</div>
        </div>
      </div>
      <div class="topbar-right">
        <span class="topbar-badge" id="engine-badge">Loading…</span>
        <div class="topbar-meta">ATT&CK v19.2 · IBM Bob MCP</div>
      </div>
    </header>

    <!-- SEARCH BAR -->
    <div class="search-bar-wrap">
      <div class="search-input-wrap">
        <span class="search-icon">🔍</span>
        <input id="search-input" class="search-input" type="text" placeholder="Search indicators — IP, host, user, IOC, keyword…" autocomplete="off">
        <div id="search-results" class="search-results"></div>
      </div>
      <button id="search-btn" class="search-btn">Search</button>
    </div>

    <div class="layout">

      <!-- SIDEBAR -->
      <aside class="case-rail" aria-label="Incident queue">
        <div class="rail-header">
          <p class="eyebrow">Investigation queue</p>
          <div class="rail-title">Active Cases</div>
          <p class="rail-copy">Only evidence-backed hypotheses reach this list.</p>
        </div>

        <!-- Funnel numbers -->
        <div class="funnel-banner" id="funnel-banner">
          <div class="funnel-step"><div class="funnel-num raw" id="f-raw">—</div><div class="funnel-label">Raw alerts</div></div>
          <div class="funnel-arrow">›</div>
          <div class="funnel-step"><div class="funnel-num cand" id="f-cand">—</div><div class="funnel-label">Candidates</div></div>
          <div class="funnel-arrow">›</div>
          <div class="funnel-step"><div class="funnel-num prom" id="f-prom">—</div><div class="funnel-label">Promoted</div></div>
        </div>

        <div id="case-list" class="case-list" aria-live="polite">
          <div class="empty loading-pulse">Loading cases…</div>
        </div>

        <hr class="rail-divider">
        <div class="rail-note">
          <strong>How promotion works:</strong><br>
          A shared entity creates a hypothesis. ATT&CK behavior, corroboration and source independence determine if it becomes a case.
        </div>
      </aside>

      <!-- MAIN -->
      <main id="workspace">

        <!-- Case header -->
        <div class="case-header">
          <div class="case-header-left">
            <p class="eyebrow">Active investigation</p>
            <div id="case-title" class="case-title loading-pulse">Loading…</div>
            <div id="case-summary" class="case-summary-text">Preparing evidence narrative…</div>
          </div>
          <div class="case-signal">
            <div class="case-signal-label">Priority</div>
            <div id="case-priority" class="case-signal-value">—</div>
          </div>
        </div>

        <!-- Status strip -->
        <div id="status" aria-live="polite"></div>

        <!-- Tabs -->
        <nav class="tabbar" role="tablist" aria-label="Case workspace views">
          <button class="tab" id="tab-overview"  role="tab" aria-controls="panel-overview"  aria-selected="true"  data-tab="overview">
            <span class="tab-icon">🔎</span> Case Overview
          </button>
          <button class="tab" id="tab-evidence"  role="tab" aria-controls="panel-evidence"  aria-selected="false" data-tab="evidence">
            <span class="tab-icon">🧾</span> Evidence Sequence
          </button>
          <button class="tab" id="tab-response"  role="tab" aria-controls="panel-response"  aria-selected="false" data-tab="response">
            <span class="tab-icon">📋</span> Commander Brief
          </button>
          <button class="tab" id="tab-compare"   role="tab" aria-controls="panel-compare"   aria-selected="false" data-tab="compare">
            <span class="tab-icon">📊</span> Alert Reduction
          </button>
          <button class="tab" id="tab-bob"        role="tab" aria-controls="panel-bob"       aria-selected="false" data-tab="bob">
            <span class="tab-icon">🤖</span> IBM Bob Handoff
          </button>
        </nav>

        <!-- ── PANEL: OVERVIEW ── -->
        <section id="panel-overview" class="panel active" role="tabpanel" aria-labelledby="tab-overview">
          <div class="split">
            <div class="stack">
              <article class="card card-glow-cyan">
                <p class="eyebrow">Decision in plain language</p>
                <h2>Why this needs attention</h2>
                <p id="decision-copy" class="decision-copy loading-pulse">Loading…</p>
              </article>
              <article class="card">
                <p class="eyebrow">Evidence path</p>
                <h2>What happened (first 5 events)</h2>
                <p style="font-size:12px;color:var(--muted);margin-bottom:12px;">Time-ordered chain across independent sources. See <em>Evidence Sequence</em> for the full list.</p>
                <div id="overview-timeline" class="timeline"></div>
              </article>
            </div>
            <div class="stack">
              <article class="card">
                <p class="eyebrow">Risk dimensions</p>
                <h2>Four separate scores</h2>
                <p style="font-size:12px;color:var(--muted);">Each dimension answers a different question. No single opaque number.</p>
                <div id="metric-grid" class="metric-grid"></div>
              </article>
              <article class="card">
                <p class="eyebrow">Promotion boundary</p>
                <h2>Why this became a case</h2>
                <ul id="promotion-checks" class="check-list"></ul>
              </article>
              <article class="card">
                <p class="eyebrow">Affected assets &amp; uncertainty</p>
                <h2>Context to preserve</h2>
                <div id="asset-context" class="asset-list"></div>
                <div id="uncertainty-context" class="notice"></div>
              </article>
            </div>
          </div>
        </section>

        <!-- ── PANEL: EVIDENCE ── -->
        <section id="panel-evidence" class="panel" role="tabpanel" aria-labelledby="tab-evidence">
          <article class="card">
            <p class="eyebrow">Grounded chronology</p>
            <h2>Full evidence sequence</h2>
            <p style="font-size:12px;color:var(--muted);margin-bottom:14px;">Every inference links to a source record. Filter by source type — this does not affect the case score.</p>
            <div id="source-filters" class="filters" aria-label="Filter by source"></div>
            <div id="full-timeline" class="timeline"></div>
          </article>
        </section>

        <!-- ── PANEL: COMMANDER BRIEF ── -->
        <section id="panel-response" class="panel" role="tabpanel" aria-labelledby="tab-response">
          <div class="split">
            <article class="card card-glow-cyan">
              <p class="eyebrow">Commander brief · BLUF</p>
              <h2>Bottom line up front</h2>
              <p style="font-size:12px;color:var(--muted);margin-bottom:14px;">Grounded in deterministic engine evidence. Nothing is invented.</p>
              <div id="brief-content"></div>
              <div class="btn-row">
                <button id="copy-brief" class="button">📋 Copy Brief</button>
                <button id="export-brief" class="button secondary">⬇ Export Markdown</button>
              </div>
            </article>
            <article class="card">
              <p class="eyebrow">Recommended response</p>
              <h2>Actions — not automation</h2>
              <p style="font-size:12px;color:var(--muted);margin-bottom:0;">Analyst-reviewed steps. The system never acts autonomously.</p>
              <ol id="response-actions" class="action-list"></ol>
            </article>
          </div>
        </section>

        <!-- ── PANEL: ALERT REDUCTION ── -->
        <section id="panel-compare" class="panel" role="tabpanel" aria-labelledby="tab-compare">
          <article class="card">
            <p class="eyebrow">False-positive reduction</p>
            <h2>From raw alerts to a defensible case</h2>
            <p style="font-size:13px;color:var(--muted);">The bundled benchmark is a reproducible synthetic demonstration. These numbers reflect the demo dataset.</p>
            <div class="compare-funnel">
              <div class="funnel-box">
                <span class="funnel-big raw" id="c-raw">37</span>
                <div class="funnel-desc">Raw observations<br><span style="font-size:11px;color:var(--muted);">4 source schemas</span></div>
              </div>
              <span class="funnel-big-arrow">→</span>
              <div class="funnel-box">
                <span class="funnel-big cand">2</span>
                <div class="funnel-desc">Candidate hypotheses<br><span style="font-size:11px;color:var(--muted);">Entity + time links</span></div>
              </div>
              <span class="funnel-big-arrow">→</span>
              <div class="funnel-box">
                <span class="funnel-big prom">1</span>
                <div class="funnel-desc">Promoted incident<br><span style="font-size:11px;color:var(--muted);">All 4 checks passed</span></div>
              </div>
            </div>
          </article>
          <div class="compare-grid" style="margin-top:0;">
            <article class="card compare-card bad">
              <div class="compare-card-title">❌ Naïve approach — what it gets wrong</div>
              <ul class="plain-list">
                <li>Treats shared entities as proof</li>
                <li>Fixed time window is the only filter</li>
                <li>Hides contradictory &amp; missing evidence</li>
                <li>Promotes routine admin activity as threats</li>
                <li>One opaque score — impossible to audit</li>
              </ul>
            </article>
            <article class="card compare-card good">
              <div class="compare-card-title">✅ ThreatFusion — what changes</div>
              <ul class="plain-list">
                <li>Checks observable ATT&CK behavior first</li>
                <li>Confidence scored separately from impact</li>
                <li>Telemetry gaps are kept explicit</li>
                <li>Ambiguous clusters stay below promotion</li>
                <li>Every score has provenance Bob can read</li>
              </ul>
            </article>
          </div>
        </section>

        <!-- ── PANEL: IBM BOB ── -->
        <section id="panel-bob" class="panel" role="tabpanel" aria-labelledby="tab-bob">
          <div class="split">
            <article class="card">
              <p class="eyebrow">Grounded handoff</p>
              <h2>Ask IBM Bob with the case in view</h2>
              <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">Bob reads from the local read-only MCP server. It explains the deterministic result — it never manufactures a score or attribution.</p>
              <div id="bob-commands" class="stack" style="gap:8px;"></div>
            </article>
            <article class="card">
              <p class="eyebrow">Live tool preview</p>
              <h2>Inspect the same facts Bob sees</h2>
              <p style="font-size:13px;color:var(--muted);margin-bottom:14px;">These call the same MCP implementation — dashboard and Bob stay consistent.</p>
              <div id="mcp-tools" class="mcp-tools-row"></div>
              <pre id="tool-output" class="tool-output">Choose a tool above to inspect its grounded output.</pre>
            </article>
          </div>
        </section>

      </main>
    </div>
  </div>

  <script>
    let summary = null;
    let selected = null;
    let activeSource = 'all';

    const SOURCE_LABELS = {
      siem: 'SIEM',
      endpoint: 'Endpoint',
      network_sensor: 'Network Sensor',
      threat_intel_report: 'Threat Intel'
    };
    const SOURCE_CLASS = {
      siem: 'src-siem',
      endpoint: 'src-endpoint',
      network_sensor: 'src-network_sensor',
      threat_intel_report: 'src-threat_intel_report'
    };
    const CHECK_LABELS = {
      minimum_behavior_evidence: ['Multiple behavior observations', 'At least two ATT&CK-backed behavior observations were found.'],
      multi_tactic_progression: ['Coherent tactic progression', 'The case crosses multiple tactics with sufficient attack-flow coherence.'],
      evidence_confidence: ['Sufficient evidence confidence', 'Evidence quality and corroboration cleared the promotion threshold.'],
      source_independence: ['Independent source support', 'The story is corroborated across sufficiently independent telemetry sources.']
    };

    function esc(v) {
      return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function sourceLabel(s) { return SOURCE_LABELS[s] || s.replaceAll('_', ' '); }
    function sourceBadge(s) {
      const cls = SOURCE_CLASS[s] || 'src-siem';
      return `<span class="source-badge ${cls}">${esc(sourceLabel(s))}</span>`;
    }
    function timeLabel(ts) { return ts ? ts.slice(11, 16) + ' UTC' : '—'; }
    function setStatus(msg, isError = false) {
      const el = document.getElementById('status');
      el.textContent = msg;
      el.style.color = isError ? 'var(--red)' : 'var(--green)';
    }
    function switchTab(next) {
      document.querySelectorAll('[role="tab"]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === next)));
      document.querySelectorAll('[role="tabpanel"]').forEach(p => p.classList.toggle('active', p.id === 'panel-' + next));
    }

    function renderQueue() {
      const list = document.getElementById('case-list');
      if (!summary.incidents.length) {
        list.innerHTML = '<div class="empty">No cases currently meet the promotion boundary.</div>';
        return;
      }
      list.innerHTML = summary.incidents.map(inc => {
        const techNames = inc.techniques.map(t => t.technique_name).filter((n, i, a) => a.indexOf(n) === i).slice(0, 2).join(' · ');
        return `<button class="case-item" data-case-id="${esc(inc.id)}" aria-current="${inc.id === selected?.id ? 'true' : 'false'}">
          <div class="case-row">
            <span class="case-id">${esc(inc.id)}</span>
            <span class="priority ${inc.priority.toLowerCase()}">${esc(inc.priority)}</span>
          </div>
          <div class="case-techniques">${esc(techNames) || '—'}</div>
          <div class="case-foot">
            <span class="case-stat">${esc(inc.confidence)}% conf</span>
            <span class="case-stat">${esc(inc.mission_impact)}/100 impact</span>
            <span class="case-stat">${sourceBadge(inc.sources[0] || '')}</span>
          </div>
        </button>`;
      }).join('');
      list.querySelectorAll('[data-case-id]').forEach(b => b.addEventListener('click', () => loadCase(b.dataset.caseId)));
    }

    async function boot() {
      try {
        const res = await fetch('/api/summary');
        if (!res.ok) throw new Error('Unable to load analysis');
        summary = await res.json();
        // Funnel numbers
        document.getElementById('f-raw').textContent = summary.metrics.raw_records;
        document.getElementById('f-cand').textContent = summary.metrics.candidate_clusters;
        document.getElementById('f-prom').textContent = summary.metrics.promoted_incidents;
        document.getElementById('c-raw').textContent = summary.metrics.raw_records;
        document.getElementById('engine-badge').textContent = `Engine ${summary.metadata.engine_version}`;
        if (summary.incidents.length) await loadCase(summary.incidents[0].id, false);
        else renderQueue();
        setStatus(`Engine ${summary.metadata.engine_version} · ATT&CK ${summary.metadata.attack_kb_version} · ground truth excluded from runtime`);
      } catch (e) {
        setStatus(e.message, true);
        document.getElementById('case-title').textContent = 'Analysis unavailable';
        document.getElementById('case-title').classList.remove('loading-pulse');
      }
    }

    async function loadCase(id, announce = true) {
      try {
        const res = await fetch('/api/incidents/' + encodeURIComponent(id));
        if (!res.ok) throw new Error('Unable to load this case');
        selected = await res.json();
        activeSource = 'all';
        renderQueue();
        renderCase();
        if (announce) setStatus(`Loaded case ${selected.id}.`);
      } catch (e) {
        setStatus(e.message, true);
      }
    }

    function renderCase() {
      const inc = selected, brief = inc.bluf;
      const titleEl = document.getElementById('case-title');
      titleEl.textContent = inc.id;
      titleEl.classList.remove('loading-pulse');
      document.getElementById('case-summary').textContent =
        `${inc.record_ids.length} observations · ${inc.sources.length} source types · ${inc.promotable ? 'Ready for analyst review' : 'Still a hypothesis'}`;
      document.getElementById('case-priority').textContent = `${inc.priority} · ${inc.priority_score}/100`;

      const decisionEl = document.getElementById('decision-copy');
      decisionEl.textContent = brief.assessment;
      decisionEl.classList.remove('loading-pulse');

      // Metrics
      const metrics = [
        ['Evidence Confidence', `${inc.confidence}%`, 'conf', 'How well evidence supports this story.'],
        ['Threat Severity',     `${inc.severity}/100`, 'sev',  'Harm potential of observed behavior.'],
        ['Mission Impact',      `${inc.mission_impact}/100`, 'impact', 'Criticality of affected assets.'],
        ['Urgency',             `${inc.urgency}/100`, 'urgency', 'How quickly a decision is needed.'],
      ];
      document.getElementById('metric-grid').innerHTML = metrics.map(([label, val, cls, note]) =>
        `<div class="metric">
          <span class="metric-label">${esc(label)}</span>
          <strong class="metric-value ${cls}">${esc(val)}</strong>
          <span class="metric-note">${esc(note)}</span>
        </div>`).join('');

      // Promotion checks
      document.getElementById('promotion-checks').innerHTML = Object.entries(inc.promotion_checks || {}).map(([key, passed]) => {
        const [label, detail] = CHECK_LABELS[key] || [key.replaceAll('_', ' '), 'Promotion check'];
        return `<li>
          <span class="check-mark ${passed ? 'pass' : 'fail'}">${passed ? '✓' : '✗'}</span>
          <span><div class="check-label">${esc(label)}</div><div class="check-detail">${esc(detail)}</div></span>
        </li>`;
      }).join('');

      // Assets
      const assets = [...new Map((inc.assets || []).map(a => [a.asset, a])).values()];
      document.getElementById('asset-context').innerHTML = assets.length
        ? assets.map(a => `<div class="asset-card">
            <div class="asset-name">${esc(a.asset)}</div>
            <div class="asset-role">${esc(a.mission_role)}</div>
            <div class="asset-crit">Criticality ${esc(a.criticality)}/100 · ${esc(a.zone)}</div>
            <div class="crit-bar"><div class="crit-fill" style="width:${esc(a.criticality)}%"></div></div>
          </div>`).join('')
        : '<p>No registered asset context available.</p>';

      document.getElementById('uncertainty-context').textContent = brief.uncertainty;

      renderTimeline('overview-timeline', inc.evidence.slice(0, 5));
      renderFilters();
      renderTimeline('full-timeline', inc.evidence);
      renderBrief();
      renderBob();
    }

    function renderTimeline(targetId, records) {
      const target = document.getElementById(targetId);
      const filtered = activeSource === 'all' ? records : records.filter(r => r.source === activeSource);
      if (!filtered.length) { target.innerHTML = '<div class="empty">No evidence from this source in the selected case.</div>'; return; }
      target.innerHTML = filtered.map(r =>
        `<div class="timeline-item">
          <div class="ttime">${esc(timeLabel(r.timestamp))}</div>
          <div class="evidence">
            <div class="evidence-head">
              <strong class="evidence-title">${esc(r.summary)}</strong>
              ${sourceBadge(r.source)}
            </div>
            ${r.technique ? `<span class="technique-tag">${esc(r.technique)} · ${esc(r.technique_name || '')}</span>` : ''}
            ${r.technique_reason ? `<p class="evidence-reason">💡 ${esc(r.technique_reason)}</p>` : ''}
          </div>
        </div>`).join('');
    }

    function renderFilters() {
      const sources = [...new Set(selected.evidence.map(r => r.source))];
      const filters = ['all', ...sources];
      const target = document.getElementById('source-filters');
      target.innerHTML = filters.map(s =>
        `<button class="filter" data-source="${esc(s)}" aria-pressed="${s === activeSource}">
          ${s === 'all' ? 'All evidence' : esc(sourceLabel(s))}
        </button>`).join('');
      target.querySelectorAll('[data-source]').forEach(b => b.addEventListener('click', () => {
        activeSource = b.dataset.source;
        renderFilters();
        renderTimeline('full-timeline', selected.evidence);
      }));
    }

    function renderBrief() {
      const brief = selected.bluf;
      const sections = [
        ['Bottom line', brief.bottom_line],
        ['Assessment',  brief.assessment],
        ['Actor context', brief.actor_assessment],
        ['Uncertainty & visibility gaps', brief.uncertainty],
      ];
      document.getElementById('brief-content').innerHTML = sections.map(([label, value]) =>
        `<section class="brief-section">
          <div class="brief-label">${esc(label)}</div>
          <div class="brief-text">${esc(value)}</div>
        </section>`).join('');

      document.getElementById('response-actions').innerHTML = (selected.runbook || []).map(step => {
        const phaseKey = step.phase.replace(/\s+/g, '');
        return `<li class="action-item">
          <span class="action-phase phase-${esc(phaseKey)}">${esc(step.phase)}</span>
          <span class="action-priority">· ${esc(step.priority)}</span>
          <div class="action-text">${esc(step.action)}</div>
          <div class="action-target">🎯 Target: ${esc(step.target)}</div>
        </li>`;
      }).join('');
    }

    function briefText() {
      const brief = selected.bluf;
      return `# Commander Brief — ${selected.id}\n\n## Bottom line\n${brief.bottom_line}\n\n## Assessment\n${brief.assessment}\n\n## Actor context\n${brief.actor_assessment}\n\n## Uncertainty\n${brief.uncertainty}\n\n## Recommended actions\n${brief.recommended_actions.map((a, i) => `${i + 1}. ${a}`).join('\n')}`;
    }

    async function copyText(text, success) {
      try { await navigator.clipboard.writeText(text); setStatus(success); }
      catch { setStatus('Clipboard access unavailable — select and copy manually.', true); }
    }

    function exportBrief() {
      const blob = new Blob([briefText()], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${selected.id}_commander_brief.md`; a.click();
      URL.revokeObjectURL(url);
      setStatus('Commander brief exported.');
    }

    function renderBob() {
      const commands = [
        ['/investigate', 'Retrieve the evidence chain, risk factors, gaps, and analyst next steps.'],
        ['/explain',     'Explain why the case was prioritised without changing the deterministic score.'],
        ['/bluf',        'Turn grounded case facts into a commander-ready summary.'],
        ['/runbook',     'Retrieve staged containment, eradication, and detection-engineering actions.'],
      ];
      document.getElementById('bob-commands').innerHTML = commands.map(([cmd, desc]) =>
        `<div class="mcp-command">
          <div>
            <div class="mcp-cmd-code">${esc(cmd)} ${esc(selected.id)}</div>
            <div class="mcp-cmd-desc">${esc(desc)}</div>
          </div>
          <button class="button secondary" data-copy-command="${esc(cmd)} ${esc(selected.id)}">Copy</button>
        </div>`).join('');
      document.querySelectorAll('[data-copy-command]').forEach(b =>
        b.addEventListener('click', () => copyText(b.dataset.copyCommand, 'Bob command copied.')));

      const tools = [
        ['get_incident', 'Case facts'],
        ['explain_risk', 'Risk rationale'],
        ['get_detection_gaps', 'Visibility gaps'],
        ['generate_bluf', 'Brief'],
        ['get_remediation_runbook', 'Runbook'],
      ];
      document.getElementById('mcp-tools').innerHTML = tools.map(([tool, label]) =>
        `<button class="tool-btn" data-tool="${esc(tool)}">${esc(label)}</button>`).join('');
      document.querySelectorAll('[data-tool]').forEach(b =>
        b.addEventListener('click', () => runTool(b.dataset.tool)));
    }

    async function runTool(tool) {
      const output = document.getElementById('tool-output');
      output.textContent = `Retrieving ${tool}…`;
      try {
        const params = new URLSearchParams({ tool, incident_id: selected.id });
        const res = await fetch('/api/mcp-query?' + params.toString());
        const payload = await res.json();
        output.textContent = JSON.stringify(payload, null, 2);
      } catch (e) {
        output.textContent = `Unable to retrieve tool output: ${e.message}`;
      }
    }

    // ── SEARCH ──
    async function runSearch() {
      const q = document.getElementById('search-input').value.trim();
      if (!q) return;
      const resultsEl = document.getElementById('search-results');
      resultsEl.innerHTML = '<div class="search-no-results loading-pulse">Searching…</div>';
      resultsEl.classList.add('open');
      try {
        const params = new URLSearchParams({ tool: 'search_indicators', query: q });
        const res = await fetch('/api/mcp-query?' + params.toString());
        const data = await res.json();
        if (!data.matches || !data.matches.length) {
          resultsEl.innerHTML = `<div class="search-no-results">No matches found for "${esc(q)}"</div>`;
          return;
        }
        resultsEl.innerHTML = data.matches.map(m =>
          `<div class="search-result-item">
            <div class="search-result-id">${esc(m.record_id)}</div>
            <div class="search-result-snippet">${esc(m.matched_snippet)}</div>
            <div class="search-result-ts">${esc(m.timestamp || '')} · ${sourceBadge(m.source || '')}</div>
          </div>`).join('') +
          (data.total_matches > data.matches.length
            ? `<div class="search-no-results">Showing ${data.matches.length} of ${data.total_matches} matches</div>`
            : '');
      } catch (e) {
        resultsEl.innerHTML = `<div class="search-no-results">Search error: ${esc(e.message)}</div>`;
      }
    }

    document.getElementById('search-btn').addEventListener('click', runSearch);
    document.getElementById('search-input').addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(); });
    document.addEventListener('click', e => {
      if (!e.target.closest('.search-input-wrap') && !e.target.closest('#search-btn')) {
        document.getElementById('search-results').classList.remove('open');
      }
    });

    // ── TABS ──
    document.querySelectorAll('[role="tab"]').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
    document.getElementById('copy-brief').addEventListener('click', () => copyText(briefText(), 'Commander brief copied.'));
    document.getElementById('export-brief').addEventListener('click', exportBrief);

    boot();
  </script>
</body>
</html>'''


def _with_presentation_fields(incident: dict) -> dict:
    """Add derived read-only presentation fields without changing engine state."""
    incident["bluf"] = bluf(incident)
    incident["runbook"] = remediation_runbook(incident)
    return incident


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "threatfusion", "version": app.version}


@app.get("/api/summary")
def summary() -> dict:
    try:
        analysis = analyze(ROOT)
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}") from exc
    promoted = [_with_presentation_fields(incident) for incident in promoted_incidents(analysis)]
    raw_count = len(analysis["records"])
    candidate_count = len(analysis["incidents"])
    return {
        "metadata": analysis["metadata"],
        "metrics": {
            "raw_records": raw_count,
            "candidate_clusters": candidate_count,
            "promoted_incidents": len(promoted),
            "candidate_compression": round(100 * (1 - candidate_count / max(1, raw_count)), 1),
        },
        "incidents": promoted[:12],
    }


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str) -> dict:
    try:
        analysis = analyze(ROOT)
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}") from exc
    for candidate in promoted_incidents(analysis):
        if candidate["id"] == incident_id:
            return _with_presentation_fields(candidate)
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/evaluation")
def evaluation() -> dict:
    analysis = analyze(ROOT)
    return {
        "engine_version": analysis["metadata"]["engine_version"],
        "attack_kb_version": analysis["metadata"]["attack_kb_version"],
        "candidate_clusters": len(analysis["incidents"]),
        "promoted_incidents": len(promoted_incidents(analysis)),
    }


@app.get("/api/mcp-query")
def mcp_query(tool: str = Query(...), incident_id: str | None = Query(None), query: str | None = Query(None)) -> dict:
    from src.mcp_server import tool_call

    arguments: dict[str, str] = {}
    if incident_id:
        arguments["incident_id"] = incident_id
    if query:
        arguments["query"] = query
    return tool_call(tool, arguments)
