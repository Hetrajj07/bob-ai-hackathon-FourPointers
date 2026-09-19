"""ThreatFusion analyst workspace and read-only API.

The UI deliberately presents a case review workflow instead of an alert-counting
dashboard: understand the case, inspect evidence, decide on next actions, and
hand the grounded facts to IBM Bob when narrative assistance is useful.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from src.threatfusion.db import (
    delete_asset,
    get_all_alerts,
    get_assets,
    get_incident as db_get_incident,
    init_db,
    insert_alert,
    insert_alerts_bulk,
    query_alerts,
    reset_db,
    save_incidents,
    update_incident_triage,
    upsert_asset,
)
from src.threatfusion.engine import ENGINE_VERSION, analyze, bluf, clear_context_cache, promoted_incidents, remediation_runbook
from src.threatfusion.normalizer import normalize_otrf, normalize_cicids, auto_normalize
from src.threatfusion.enrichment import lookup_threatfox, check_cisa_kev, enrich_record

logger = logging.getLogger("threatfusion")
ROOT = Path(__file__).resolve().parents[1]

# Ensure SQLite database is initialized and seeded
init_db(seed_if_empty=True, root_dir=ROOT)

app = FastAPI(title="ThreatFusion - Analyst Workspace", version=ENGINE_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

INDEX = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0b0e14">
  <title>ThreatFusion — Analyst Workspace</title>
  <style>
    :root {
      --bg-base: #090c10;
      --bg-surface: #0e131b;
      --bg-surface-elevated: #151c27;
      --bg-surface-highlight: #1c2636;
      --border-subtle: #1c2533;
      --border-default: #263346;
      --border-strong: #3b4d66;
      
      --text-primary: #f0f6fc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --text-faint: #334155;

      --tactical-blue: #38bdf8;
      --tactical-blue-dim: rgba(56, 189, 248, 0.12);
      --tactical-blue-border: rgba(56, 189, 248, 0.35);

      --danger-red: #f43f5e;
      --danger-red-dim: rgba(244, 63, 94, 0.12);
      --danger-red-border: rgba(244, 63, 94, 0.35);

      --warning-amber: #f59e0b;
      --warning-amber-dim: rgba(245, 158, 11, 0.12);
      --warning-amber-border: rgba(245, 158, 11, 0.35);

      --success-green: #10b981;
      --success-green-dim: rgba(16, 185, 129, 0.12);
      --success-green-border: rgba(16, 185, 129, 0.35);

      --purple-intel: #818cf8;
      --purple-intel-dim: rgba(129, 140, 248, 0.12);

      --p1-color: #f43f5e;
      --p1-bg: rgba(244, 63, 94, 0.15);
      --p2-color: #f59e0b;
      --p2-bg: rgba(245, 158, 11, 0.15);
      --p3-color: #10b981;
      --p3-bg: rgba(16, 185, 129, 0.15);
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--bg-base);
      color: var(--text-primary);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 13px;
      line-height: 1.55;
      letter-spacing: -0.01em;
      -webkit-font-smoothing: antialiased;
    }
    button, input, textarea, select { font: inherit; }
    button { cursor: pointer; }
    button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible {
      outline: 2px solid var(--tactical-blue);
      outline-offset: 2px;
    }
    .skip-link {
      position: fixed; left: 16px; top: -80px; z-index: 9999;
      padding: 8px 14px; border-radius: 4px;
      background: var(--bg-surface-elevated); color: var(--tactical-blue);
      border: 1px solid var(--tactical-blue); font-weight: 700;
      transition: top 0.2s ease;
    }
    .skip-link:focus { top: 16px; }

    /* ── ANIMATIONS ── */
    @keyframes panelFadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulseLive {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.15); opacity: 1; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }
    @keyframes radarSweep {
      0% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.6); }
      70% { box-shadow: 0 0 0 6px rgba(56, 189, 248, 0); }
      100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0); }
    }

    /* ── TOPBAR ── */
    .topbar {
      position: sticky; top: 0; z-index: 100;
      height: 56px; padding: 0 24px;
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
      background: rgba(14, 19, 27, 0.95); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-subtle);
    }
    .brand { display: flex; align-items: center; gap: 12px; text-decoration: none; }
    .brand-mark {
      width: 30px; height: 30px; border-radius: 6px;
      background: #1e293b; border: 1px solid var(--border-strong);
      display: grid; place-items: center;
      font-size: 14px; font-weight: 900; color: var(--tactical-blue);
      font-family: ui-monospace, monospace;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.1);
    }
    .brand-name {
      font-size: 15px; font-weight: 800; color: var(--text-primary);
      letter-spacing: -0.02em; display: flex; align-items: center; gap: 8px;
    }
    .brand-tag {
      font-size: 9px; font-weight: 800; letter-spacing: 0.1em;
      text-transform: uppercase; padding: 2px 6px; border-radius: 3px;
      background: var(--tactical-blue-dim); color: var(--tactical-blue);
      border: 1px solid var(--tactical-blue-border);
    }
    .brand-sub { font-size: 11px; color: var(--text-muted); }
    .topbar-right { display: flex; align-items: center; gap: 10px; }
    .topbar-btn {
      padding: 6px 12px; border-radius: 5px; font-size: 12px; font-weight: 600;
      background: var(--bg-surface-elevated); color: var(--text-primary);
      border: 1px solid var(--border-default);
      display: inline-flex; align-items: center; gap: 6px;
      transition: all 0.15s ease;
    }
    .topbar-btn:hover {
      background: var(--bg-surface-highlight);
      border-color: var(--border-strong);
      color: #fff;
    }
    .topbar-btn.primary {
      background: var(--tactical-blue-dim);
      color: var(--tactical-blue);
      border-color: var(--tactical-blue-border);
    }
    .topbar-btn.primary:hover {
      background: var(--tactical-blue);
      color: #000;
      border-color: var(--tactical-blue);
    }
    .topbar-badge {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 9px; border-radius: 4px; font-size: 11px; font-weight: 700;
      font-family: ui-monospace, monospace;
      background: var(--bg-surface); color: var(--text-secondary);
      border: 1px solid var(--border-default);
    }
    .live-dot {
      width: 7px; height: 7px; border-radius: 50%;
      background: var(--success-green);
      display: inline-block;
      animation: pulseLive 2s infinite ease-in-out;
    }
    .topbar-meta { font-size: 11px; color: var(--text-muted); font-family: ui-monospace, monospace; }

    /* ── SEARCH BAR ── */
    .search-bar-wrap {
      padding: 8px 24px;
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-subtle);
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
    }
    .search-input-wrap { position: relative; flex: 1; max-width: 540px; }
    .search-icon {
      position: absolute; left: 12px; top: 50%; transform: translateY(-50%);
      color: var(--text-muted); font-size: 12px; pointer-events: none;
    }
    .search-input {
      width: 100%; padding: 7px 12px 7px 34px;
      background: var(--bg-base); border: 1px solid var(--border-default);
      border-radius: 5px; color: var(--text-primary); font-size: 12px;
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    .search-input::placeholder { color: var(--text-muted); }
    .search-input:focus {
      outline: none; border-color: var(--tactical-blue);
      box-shadow: 0 0 0 2px var(--tactical-blue-dim);
    }
    .search-btn {
      padding: 7px 14px; border-radius: 5px; font-size: 12px; font-weight: 600;
      background: var(--bg-surface-elevated); color: var(--text-primary);
      border: 1px solid var(--border-default);
      transition: all 0.15s ease;
    }
    .search-btn:hover {
      background: var(--bg-surface-highlight);
      border-color: var(--tactical-blue);
      color: var(--tactical-blue);
    }
    .search-results {
      display: none; position: absolute; top: calc(100% + 4px); left: 0; right: 0;
      background: var(--bg-surface-elevated); border: 1px solid var(--border-strong);
      border-radius: 6px; z-index: 200; max-height: 320px; overflow-y: auto;
      box-shadow: 0 12px 32px rgba(0,0,0,0.6);
    }
    .search-results.open { display: block; animation: panelFadeIn 0.15s ease; }
    .search-result-item {
      padding: 9px 12px; border-bottom: 1px solid var(--border-subtle);
      cursor: pointer; transition: background 0.1s;
    }
    .search-result-item:last-child { border-bottom: none; }
    .search-result-item:hover { background: var(--bg-surface-highlight); }
    .search-result-id { font-family: ui-monospace, monospace; font-size: 11px; color: var(--tactical-blue); font-weight: 700; }
    .search-result-snippet { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
    .search-result-ts { font-size: 10px; color: var(--text-muted); font-family: ui-monospace, monospace; margin-top: 3px; }
    .search-no-results { padding: 14px; text-align: center; color: var(--text-muted); font-size: 12px; }

    /* ── LAYOUT ── */
    .layout {
      display: grid;
      grid-template-columns: 290px minmax(0, 1fr);
      max-width: 1720px; margin: 0 auto;
      min-height: calc(100vh - 96px);
    }

    /* ── SIDEBAR QUEUE ── */
    .case-rail {
      background: var(--bg-surface);
      border-right: 1px solid var(--border-subtle);
      padding: 16px;
      display: flex; flex-direction: column; gap: 0;
    }
    .rail-header { margin-bottom: 12px; }
    .eyebrow {
      font-size: 10px; font-weight: 800; letter-spacing: 0.1em;
      text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;
      font-family: ui-monospace, monospace;
    }
    .rail-title { font-size: 14px; font-weight: 800; color: var(--text-primary); letter-spacing: -0.01em; }
    .rail-copy { font-size: 11px; color: var(--text-muted); margin-top: 2px; }

    /* Funnel summary */
    .funnel-banner {
      display: flex; align-items: center; justify-content: space-between;
      background: var(--bg-base); border: 1px solid var(--border-default);
      border-radius: 6px; padding: 8px 6px; margin: 12px 0 14px;
    }
    .funnel-step { text-align: center; flex: 1; }
    .funnel-num { font-size: 17px; font-weight: 800; line-height: 1; font-family: ui-monospace, monospace; }
    .funnel-num.raw { color: var(--text-secondary); }
    .funnel-num.cand { color: var(--warning-amber); }
    .funnel-num.prom { color: var(--success-green); }
    .funnel-label { font-size: 9px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; margin-top: 4px; }
    .funnel-arrow { color: var(--text-faint); font-size: 14px; font-weight: 900; }

    .case-list { display: grid; gap: 6px; flex: 1; align-content: flex-start; }
    .case-item {
      width: 100%; padding: 10px 12px; text-align: left;
      border: 1px solid var(--border-default); border-radius: 6px;
      color: var(--text-primary); background: var(--bg-surface-elevated);
      transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative;
    }
    .case-item:hover {
      border-color: var(--border-strong);
      background: var(--bg-surface-highlight);
      transform: translateX(2px);
    }
    .case-item[aria-current="true"] {
      border-color: var(--tactical-blue);
      background: var(--bg-surface-highlight);
      box-shadow: inset 3px 0 0 var(--tactical-blue);
    }
    .case-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; margin-bottom: 4px; }
    .case-id {
      font-family: ui-monospace, monospace; font-size: 11px; font-weight: 800;
      color: var(--text-primary); letter-spacing: 0.02em;
    }
    .case-item[aria-current="true"] .case-id { color: var(--tactical-blue); }
    .priority {
      display: inline-flex; align-items: center; gap: 4px;
      padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 800;
      font-family: ui-monospace, monospace; text-transform: uppercase;
    }
    .priority.p1 { color: var(--p1-color); background: var(--p1-bg); border: 1px solid var(--danger-red-border); }
    .priority.p2 { color: var(--p2-color); background: var(--p2-bg); border: 1px solid var(--warning-amber-border); }
    .priority.p3 { color: var(--p3-color); background: var(--p3-bg); border: 1px solid var(--success-green-border); }
    .case-techniques {
      font-size: 11px; color: var(--text-secondary); margin-bottom: 6px;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .case-foot { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
    .case-stat {
      font-size: 10px; color: var(--text-muted); font-family: ui-monospace, monospace;
      background: var(--bg-base); border: 1px solid var(--border-subtle);
      border-radius: 3px; padding: 1px 5px;
    }

    .rail-divider { border: none; border-top: 1px solid var(--border-subtle); margin: 14px 0; }
    .rail-note {
      font-size: 11px; color: var(--text-muted); padding: 10px;
      background: var(--bg-base); border: 1px solid var(--border-subtle);
      border-radius: 5px; line-height: 1.5;
    }
    .rail-note strong { color: var(--text-secondary); }

    /* ── MAIN WORKSPACE ── */
    main { min-width: 0; display: flex; flex-direction: column; background: var(--bg-base); }

    /* Case header */
    .case-header {
      padding: 18px 28px;
      display: flex; align-items: flex-start; justify-content: space-between; gap: 20px;
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-surface);
    }
    .case-header-left { flex: 1; min-width: 0; }
    .case-title {
      font-size: 22px; font-weight: 800; color: var(--text-primary);
      letter-spacing: -0.02em; margin-bottom: 4px;
      font-family: ui-monospace, monospace;
    }
    .case-summary-text { font-size: 12px; color: var(--text-secondary); }
    
    .case-signal {
      padding: 8px 14px; border-radius: 6px;
      background: var(--bg-surface-elevated); border: 1px solid var(--border-default);
      text-align: center; min-width: 130px;
    }
    .case-signal-label {
      font-size: 9px; font-weight: 800; letter-spacing: 0.1em;
      text-transform: uppercase; color: var(--text-muted); margin-bottom: 2px;
      font-family: ui-monospace, monospace;
    }
    .case-signal-value { font-size: 16px; font-weight: 800; font-family: ui-monospace, monospace; color: var(--tactical-blue); }

    .triage-select {
      background: var(--bg-surface-elevated); border: 1px solid var(--border-default);
      color: var(--text-primary); border-radius: 4px; padding: 4px 8px;
      font-size: 11px; font-weight: 600;
    }
    .btn-sm {
      background: var(--bg-surface-highlight); color: var(--text-primary);
      border: 1px solid var(--border-default);
      padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
      transition: all 0.15s;
    }
    .btn-sm:hover { background: var(--tactical-blue); color: #000; border-color: var(--tactical-blue); }

    .action-btn {
      background: var(--bg-surface-elevated); color: var(--text-primary);
      border: 1px solid var(--border-default);
      padding: 7px 12px; border-radius: 5px; font-size: 12px; font-weight: 600;
      transition: all 0.15s ease;
    }
    .action-btn:hover {
      background: var(--bg-surface-highlight);
      border-color: var(--border-strong);
      color: #fff;
    }
    .action-btn.primary {
      background: var(--tactical-blue-dim); color: var(--tactical-blue);
      border-color: var(--tactical-blue-border);
    }
    .action-btn.primary:hover {
      background: var(--tactical-blue); color: #000; border-color: var(--tactical-blue);
    }

    /* Status strip */
    #status {
      padding: 5px 28px;
      font-size: 11px; color: var(--success-green); min-height: 26px;
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-base); font-family: ui-monospace, monospace;
      display: flex; align-items: center;
    }

    /* ── TABS ── */
    .tabbar {
      display: flex; gap: 2px; overflow-x: auto; padding: 0 24px;
      background: var(--bg-surface); border-bottom: 1px solid var(--border-subtle);
      scrollbar-width: none;
    }
    .tabbar::-webkit-scrollbar { display: none; }
    .tab {
      min-height: 42px; padding: 0 14px; border: none;
      border-bottom: 2px solid transparent;
      background: transparent; color: var(--text-muted);
      white-space: nowrap; font-size: 12px; font-weight: 600;
      transition: all 0.15s ease;
      display: flex; align-items: center; gap: 6px;
    }
    .tab:hover { color: var(--text-primary); }
    .tab[aria-selected="true"] {
      color: var(--tactical-blue);
      border-bottom-color: var(--tactical-blue);
      background: rgba(56, 189, 248, 0.04);
    }
    .tab-icon { font-size: 13px; }

    /* ── PANELS ── */
    .panel { display: none; padding: 24px 28px; }
    .panel.active { display: block; animation: panelFadeIn 0.2s cubic-bezier(0.16, 1, 0.3, 1); }

    /* ── GRID HELPERS ── */
    .split { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(300px, 0.85fr); gap: 18px; }
    .stack { display: flex; flex-direction: column; gap: 16px; }

    /* ── CARDS ── */
    .card {
      background: var(--bg-surface); border: 1px solid var(--border-default);
      border-radius: 8px; padding: 18px 20px;
    }
    .card h2 { font-size: 14px; font-weight: 800; color: var(--text-primary); margin-bottom: 4px; letter-spacing: -0.01em; }
    .card h3 { font-size: 12px; font-weight: 700; color: var(--text-secondary); margin-bottom: 4px; }
    .card p { font-size: 12px; color: var(--text-muted); margin-bottom: 0; }
    .decision-copy { font-size: 13px; color: var(--text-primary); line-height: 1.6; }

    /* ── METRIC GRID ── */
    .metric-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-top: 12px; }
    .metric {
      padding: 12px 14px; border-radius: 6px;
      background: var(--bg-base); border: 1px solid var(--border-default);
    }
    .metric-label {
      display: block; font-size: 9px; font-weight: 800; letter-spacing: 0.1em;
      text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;
      font-family: ui-monospace, monospace;
    }
    .metric-value {
      display: block; font-size: 22px; font-weight: 800; line-height: 1;
      font-family: ui-monospace, monospace;
    }
    .metric-value.conf { color: var(--tactical-blue); }
    .metric-value.sev { color: var(--danger-red); }
    .metric-value.impact { color: var(--purple-intel); }
    .metric-value.urgency { color: var(--warning-amber); }
    .metric-note { display: block; font-size: 10px; color: var(--text-muted); margin-top: 4px; }

    /* ── PROMOTION CHECKS ── */
    .check-list { list-style: none; display: grid; gap: 8px; margin-top: 12px; }
    .check-list li { display: flex; align-items: flex-start; gap: 10px; }
    .check-mark {
      flex-shrink: 0; width: 18px; height: 18px; border-radius: 4px;
      display: grid; place-items: center; font-size: 10px; font-weight: 900;
      margin-top: 1px; font-family: ui-monospace, monospace;
    }
    .check-mark.pass { background: var(--success-green-dim); color: var(--success-green); border: 1px solid var(--success-green-border); }
    .check-mark.fail { background: var(--danger-red-dim); color: var(--danger-red); border: 1px solid var(--danger-red-border); }
    .check-label { font-size: 12px; font-weight: 700; color: var(--text-primary); }
    .check-detail { font-size: 11px; color: var(--text-muted); margin-top: 1px; }

    /* ── NOT-PROMOTED CANDIDATES ── */
    .not-promoted-card {
      padding: 12px 14px; border: 1px solid var(--border-default);
      border-radius: 6px; background: var(--bg-base);
    }
    .np-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px; }
    .np-id { font-family: ui-monospace, monospace; font-size: 11px; font-weight: 700; color: var(--text-secondary); }
    .np-badge {
      padding: 1px 6px; border-radius: 3px; font-size: 9px; font-weight: 800; letter-spacing: 0.06em;
      background: var(--bg-surface-elevated); color: var(--text-muted); border: 1px solid var(--border-default);
      font-family: ui-monospace, monospace; text-transform: uppercase;
    }
    .np-meta { font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-family: ui-monospace, monospace; }
    .np-checks { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 6px; }
    .check-pill {
      padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600;
      font-family: ui-monospace, monospace;
    }
    .check-pill.pass { background: var(--success-green-dim); color: var(--success-green); border: 1px solid var(--success-green-border); }
    .check-pill.fail { background: var(--danger-red-dim); color: var(--danger-red); border: 1px solid var(--danger-red-border); }
    .np-reason { font-size: 11px; color: var(--danger-red); }

    /* ── SOURCE BADGES ── */
    .source-badge {
      display: inline-block; padding: 2px 6px; border-radius: 3px;
      font-size: 9px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
      font-family: ui-monospace, monospace;
    }
    .src-siem { background: rgba(56, 189, 248, 0.12); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
    .src-endpoint { background: rgba(129, 140, 248, 0.12); color: #a5b4fc; border: 1px solid rgba(129, 140, 248, 0.3); }
    .src-network_sensor { background: rgba(20, 184, 166, 0.12); color: #2dd4bf; border: 1px solid rgba(20, 184, 166, 0.3); }
    .src-threat_intel_report { background: rgba(245, 158, 11, 0.12); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .src-opensky_airspace, .src-airspace { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.35); }
    .src-maritime_ais, .src-maritime { background: rgba(45, 212, 191, 0.15); color: #2dd4bf; border: 1px solid rgba(45, 212, 191, 0.35); }
    .src-copernicus_sentinel, .src-satellite_eo { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.35); }
    .src-nasa_firms, .src-thermal_ir { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.35); }
    .src-imd_weather, .src-weather_env { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); }
    .src-isro_bhuvan, .src-geospatial_infra { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }
    .src-emergency_usgs, .src-geophysical { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.35); }
    .src-satellite_sensor, .src-cyber_c2 { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.35); }

    /* ── TIMELINE ── */
    .timeline { position: relative; display: grid; gap: 0; margin-top: 10px; }
    .timeline-item { display: grid; grid-template-columns: 60px minmax(0, 1fr); gap: 12px; padding-bottom: 14px; position: relative; }
    .timeline-item:not(:last-child)::before {
      content: ""; position: absolute; left: 59px; top: 24px; bottom: 0; width: 1px;
      background: var(--border-subtle);
    }
    .ttime {
      color: var(--text-muted); font-family: ui-monospace, monospace;
      font-size: 10px; font-weight: 700; padding-top: 6px; text-align: right;
    }
    .evidence {
      position: relative; padding: 10px 12px;
      background: var(--bg-base); border: 1px solid var(--border-default);
      border-radius: 6px; transition: border-color 0.15s ease;
    }
    .evidence:hover { border-color: var(--border-strong); }
    .evidence::before {
      content: ""; position: absolute; top: 12px; left: -6px;
      width: 10px; height: 10px; border-radius: 50%;
      background: var(--bg-surface); border: 2px solid var(--tactical-blue);
    }
    .evidence-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; margin-bottom: 4px; }
    .evidence-title { font-size: 12px; font-weight: 700; color: var(--text-primary); }
    .technique-tag {
      font-family: ui-monospace, monospace; font-size: 10px; font-weight: 700;
      color: var(--tactical-blue); background: var(--tactical-blue-dim);
      border: 1px solid var(--tactical-blue-border); border-radius: 3px;
      display: inline-block; padding: 1px 6px;
    }
    .evidence-reason { font-size: 11px; color: var(--text-secondary); margin-top: 4px; line-height: 1.45; }

    /* ── FILTERS ── */
    .filters { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
    .filter {
      padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;
      border: 1px solid var(--border-default); background: var(--bg-base); color: var(--text-secondary);
      transition: all 0.15s ease;
    }
    .filter:hover { border-color: var(--border-strong); color: var(--text-primary); }
    .filter[aria-pressed="true"] {
      background: var(--tactical-blue-dim); border-color: var(--tactical-blue);
      color: var(--tactical-blue);
    }

    /* ── ASSETS ── */
    .asset-list { display: grid; gap: 6px; margin-top: 8px; }
    .asset-card { padding: 8px 10px; background: var(--bg-base); border: 1px solid var(--border-default); border-radius: 6px; }
    .asset-name { font-family: ui-monospace, monospace; font-size: 11px; font-weight: 700; color: var(--text-primary); }
    .asset-role { font-size: 11px; color: var(--text-secondary); margin-top: 1px; }
    .asset-crit { font-size: 10px; color: var(--text-muted); margin-top: 1px; font-family: ui-monospace, monospace; }
    .crit-bar { height: 3px; border-radius: 2px; background: var(--border-subtle); margin-top: 5px; overflow: hidden; }
    .crit-fill { height: 100%; border-radius: 2px; background: var(--warning-amber); }

    /* ── UNCERTAINTY NOTICE ── */
    .notice {
      padding: 10px 12px; border-radius: 6px;
      background: var(--bg-base); border: 1px solid var(--warning-amber-border);
      color: var(--warning-amber); font-size: 11px; margin-top: 10px; line-height: 1.45;
    }

    /* ── BRIEF ── */
    .brief-section { padding: 12px 0; border-bottom: 1px solid var(--border-subtle); }
    .brief-section:last-of-type { border-bottom: none; }
    .brief-label {
      font-size: 9px; font-weight: 800; letter-spacing: 0.1em;
      text-transform: uppercase; color: var(--tactical-blue); margin-bottom: 4px;
      font-family: ui-monospace, monospace;
    }
    .brief-text { font-size: 12px; color: var(--text-primary); line-height: 1.6; }
    .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
    .button {
      min-height: 34px; padding: 6px 14px; border-radius: 5px;
      font-size: 12px; font-weight: 600; border: 1px solid var(--tactical-blue);
      background: var(--tactical-blue); color: #000;
      transition: opacity 0.15s, transform 0.1s;
    }
    .button:hover { opacity: 0.88; transform: translateY(-1px); }
    .button.secondary {
      background: var(--bg-surface-elevated); color: var(--text-primary);
      border: 1px solid var(--border-default);
    }
    .button.secondary:hover { background: var(--bg-surface-highlight); border-color: var(--border-strong); }

    /* ── ACTION LIST (runbook) ── */
    .action-list { list-style: none; display: grid; gap: 8px; margin-top: 10px; }
    .action-item {
      padding: 10px 12px; border-radius: 6px;
      background: var(--bg-base); border: 1px solid var(--border-default);
      border-left: 3px solid var(--tactical-blue);
    }
    .action-phase {
      display: inline-block; padding: 1px 6px; border-radius: 3px;
      font-size: 9px; font-weight: 800; text-transform: uppercase;
      letter-spacing: 0.06em; margin-bottom: 4px; font-family: ui-monospace, monospace;
    }
    .phase-Containment { background: var(--danger-red-dim); color: var(--danger-red); border: 1px solid var(--danger-red-border); }
    .phase-Eradication { background: var(--warning-amber-dim); color: var(--warning-amber); border: 1px solid var(--warning-amber-border); }
    .phase-Detection { background: var(--tactical-blue-dim); color: var(--tactical-blue); border: 1px solid var(--tactical-blue-border); }
    .action-priority { display: inline-block; margin-left: 6px; font-size: 10px; font-weight: 700; color: var(--text-muted); font-family: ui-monospace, monospace; }
    .action-text { font-size: 12px; color: var(--text-primary); line-height: 1.5; }
    .action-target { font-size: 11px; color: var(--text-muted); margin-top: 3px; font-family: ui-monospace, monospace; }

    /* ── COMPARE PANEL ── */
    .compare-funnel { display: flex; align-items: center; justify-content: center; gap: 0; margin: 16px 0; }
    .funnel-box {
      text-align: center; padding: 14px 20px;
      background: var(--bg-base); border: 1px solid var(--border-default);
      border-radius: 6px; min-width: 140px;
    }
    .funnel-big { font-size: 36px; font-weight: 900; line-height: 1; display: block; font-family: ui-monospace, monospace; }
    .funnel-big.raw { color: var(--text-secondary); }
    .funnel-big.cand { color: var(--warning-amber); }
    .funnel-big.prom { color: var(--success-green); }
    .funnel-desc { font-size: 11px; color: var(--text-muted); margin-top: 6px; }
    .funnel-big-arrow { font-size: 22px; color: var(--text-faint); padding: 0 10px; }
    .compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 16px; }
    .compare-card { background: var(--bg-base); border: 1px solid var(--border-default); border-radius: 6px; padding: 14px; }
    .compare-card.bad { border-left: 3px solid var(--danger-red); }
    .compare-card.good { border-left: 3px solid var(--success-green); }
    .compare-card-title { font-size: 12px; font-weight: 800; margin-bottom: 8px; }
    .compare-card.bad .compare-card-title { color: var(--danger-red); }
    .compare-card.good .compare-card-title { color: var(--success-green); }
    .plain-list { list-style: none; display: grid; gap: 5px; }
    .plain-list li { font-size: 12px; color: var(--text-secondary); padding-left: 12px; position: relative; }
    .plain-list li::before { content: "•"; position: absolute; left: 0; color: var(--text-muted); }

    /* ── BOB PANEL ── */
    .mcp-command {
      display: flex; align-items: center; justify-content: space-between; gap: 10px;
      padding: 10px 12px; background: var(--bg-base); border: 1px solid var(--border-default);
      border-radius: 6px; transition: border-color 0.15s ease;
    }
    .mcp-command:hover { border-color: var(--border-strong); }
    .mcp-cmd-code { font-family: ui-monospace, monospace; font-size: 12px; color: var(--tactical-blue); font-weight: 700; }
    .mcp-cmd-desc { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
    .mcp-tools-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
    .tool-btn {
      padding: 6px 12px; border-radius: 4px; font-size: 11px; font-weight: 600;
      background: var(--bg-base); border: 1px solid var(--border-default); color: var(--text-secondary);
      transition: all 0.15s ease; font-family: ui-monospace, monospace;
    }
    .tool-btn:hover { border-color: var(--tactical-blue); color: var(--tactical-blue); background: var(--tactical-blue-dim); }
    .tool-output {
      min-height: 160px; max-height: 380px; overflow-y: auto;
      padding: 12px; border-radius: 6px;
      background: #05080c; border: 1px solid var(--border-default);
      color: #38bdf8; font-family: ui-monospace, monospace; font-size: 11px;
      line-height: 1.55; white-space: pre-wrap;
    }

    /* ── EMPTY / LOADING ── */
    .empty { padding: 24px; text-align: center; color: var(--text-muted); font-size: 12px; }
    .loading-pulse { animation: pulseLive 1.4s ease-in-out infinite; }

    /* ── RESPONSIVE ── */
    @media (max-width: 960px) {
      .layout { grid-template-columns: 1fr; }
      .case-rail { border-right: none; border-bottom: 1px solid var(--border-subtle); }
      .case-list { grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); display: grid; }
      .split { grid-template-columns: 1fr; }
    }
    @media (max-width: 640px) {
      .topbar { height: auto; padding: 10px 14px; flex-wrap: wrap; }
      .tabbar { padding: 0 10px; }
      .panel { padding: 14px; }
      .metric-grid { grid-template-columns: 1fr; }
      .compare-grid { grid-template-columns: 1fr; }
      .timeline-item { grid-template-columns: 1fr; gap: 4px; }
      .timeline-item::before { display: none; }
      .evidence::before { display: none; }
      .compare-funnel { flex-direction: column; gap: 6px; }
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
        <div class="brand-mark" aria-hidden="true">TF</div>
        <div>
          <div class="brand-name">
            ThreatFusion
            <span class="brand-tag">SOC / Telemetry</span>
          </div>
          <div class="brand-sub">Evidence-first deterministic intelligence &amp; telemetry workspace</div>
        </div>
      </div>
      <div class="topbar-right">
        <button id="btn-open-sim" class="topbar-btn primary" title="Simulate Multi-Source Threat Feeds">🛰️ Ingest Feeds</button>
        <button id="btn-reset-demo" class="topbar-btn" title="Reset Demo Data">↺ Reset Demo</button>
        <span class="topbar-badge" id="engine-badge"><span class="live-dot"></span> Loading…</span>
        <div class="topbar-meta">ATT&CK v19.2 · IBM Bob MCP</div>
      </div>
    </header>

    <!-- SEARCH BAR -->
    <div class="search-bar-wrap">
      <div class="search-input-wrap">
        <span class="search-icon">🔍</span>
        <input id="search-input" class="search-input" type="text" placeholder="Search indicators — IP, host, CVE, user, IOC hash, keyword… (Press Enter)" autocomplete="off">
        <div id="search-results" class="search-results"></div>
      </div>
      <button id="search-btn" class="search-btn">Search Corpus</button>
    </div>

    <div class="layout">

      <!-- SIDEBAR -->
      <aside class="case-rail" aria-label="Incident queue">
        <div class="rail-header">
          <p class="eyebrow">Triage Queue</p>
          <div class="rail-title">Active Cases</div>
          <p class="rail-copy">Promoted incident hypotheses verified across ATT&amp;CK behavior.</p>
        </div>

        <!-- Funnel numbers -->
        <div class="funnel-banner" id="funnel-banner">
          <div class="funnel-step"><div class="funnel-num raw" id="f-raw">—</div><div class="funnel-label">Raw Alerts</div></div>
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
          <strong>Deterministic Promotion Gate:</strong><br>
          Candidates must pass behavior corroboration, multi-tactic progression, confidence threshold, and source independence.
        </div>
      </aside>

      <!-- MAIN -->
      <main id="workspace">

        <!-- Case header -->
        <div class="case-header">
          <div class="case-header-left">
            <p class="eyebrow">Active Investigation</p>
            <div id="case-title" class="case-title loading-pulse">Loading…</div>
            <div id="case-summary" class="case-summary-text">Preparing evidence sequence…</div>
          </div>
          <div style="display:flex; flex-direction:column; align-items:flex-end; gap:6px;">
            <div style="display:flex; gap:8px; align-items:center;">
              <button id="btn-ask-bob-header" class="topbar-btn primary" style="background:var(--tactical-blue);color:#000;border-color:var(--tactical-blue);font-weight:700;padding:5px 12px;font-size:12px;cursor:pointer;" onclick="openBobModal(selected ? selected.id : '', 'investigate')">🤖 Ask IBM Bob</button>
              <div class="case-signal">
                <div class="case-signal-label">Assessed Priority</div>
                <div id="case-priority" class="case-signal-value">—</div>
              </div>
            </div>
            <div style="display:flex; gap:6px; align-items:center;">
              <span style="font-size:10px; color:var(--text-muted); font-weight:800; font-family:ui-monospace,monospace;">STATUS</span>
              <select id="case-status-select" class="triage-select">
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="contained">Contained</option>
                <option value="closed">Closed</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Status strip -->
        <div id="status" aria-live="polite"></div>

        <!-- Tabs -->
        <nav class="tabbar" role="tablist" aria-label="Case workspace views">
          <button class="tab" id="tab-overview"  role="tab" aria-controls="panel-overview"  aria-selected="true"  data-tab="overview">
            <span class="tab-icon">🔎</span> Case Overview
          </button>
          <button class="tab" id="tab-defence"   role="tab" aria-controls="panel-defence"   aria-selected="false" data-tab="defence">
            <span class="tab-icon">🇮🇳</span> National Defence &amp; Radar
          </button>
          <button class="tab" id="tab-evidence"  role="tab" aria-controls="panel-evidence"  aria-selected="false" data-tab="evidence">
            <span class="tab-icon">🧾</span> Evidence Sequence
          </button>
          <button class="tab" id="tab-response"  role="tab" aria-controls="panel-response"  aria-selected="false" data-tab="response">
            <span class="tab-icon">📋</span> Commander Brief (BLUF)
          </button>
          <button class="tab" id="tab-compare"   role="tab" aria-controls="panel-compare"   aria-selected="false" data-tab="compare">
            <span class="tab-icon">📊</span> Alert Reduction
          </button>
          <button class="tab" id="tab-simulator" role="tab" aria-controls="panel-simulator" aria-selected="false" data-tab="simulator">
            <span class="tab-icon">🛰️</span> Live Feeds &amp; Ingestion
          </button>
          <button class="tab" id="tab-bob"        role="tab" aria-controls="panel-bob"       aria-selected="false" data-tab="bob">
            <span class="tab-icon">🤖</span> IBM Bob MCP Bridge
          </button>
        </nav>

        <!-- ── PANEL: OVERVIEW ── -->
        <section id="panel-overview" class="panel active" role="tabpanel" aria-labelledby="tab-overview">
          <div class="split">
            <div class="stack">
              <article class="card">
                <p class="eyebrow">Executive Decision Synthesis</p>
                <h2>Operational Assessment</h2>
                <p id="decision-copy" class="decision-copy loading-pulse" style="margin-top:8px;">Loading…</p>
              </article>
              <article class="card">
                <p class="eyebrow">Attack-Flow Chronology</p>
                <h2>Observed Behavior Progression (First 5 Events)</h2>
                <p style="font-size:11px;color:var(--text-muted);margin-bottom:12px;">Correlated chain across independent sensors. See <em>Evidence Sequence</em> for complete telemetry.</p>
                <div id="overview-timeline" class="timeline"></div>
              </article>
            </div>
            <div class="stack">
              <article class="card">
                <p class="eyebrow">4D Risk Assessment</p>
                <h2>Deterministic Severity Breakdown</h2>
                <p style="font-size:11px;color:var(--text-muted);">Decoupled scoring dimensions providing explainable risk provenance.</p>
                <div id="metric-grid" class="metric-grid"></div>
              </article>
              <article class="card">
                <p class="eyebrow">Promotion Boundary</p>
                <h2>Gating Check Results</h2>
                <ul id="promotion-checks" class="check-list"></ul>
              </article>
              <article class="card">
                <p class="eyebrow">Mission Impact &amp; Detection Gaps</p>
                <h2>Affected Infrastructure &amp; Visibility Notes</h2>
                <div id="asset-context" class="asset-list"></div>
                <div id="uncertainty-context" class="notice"></div>
              </article>
              <article class="card">
                <p class="eyebrow">Analyst Triage &amp; Notes</p>
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                  <h2>Investigation Journal</h2>
                  <button id="btn-save-notes" class="btn-sm">Save Notes</button>
                </div>
                <textarea id="case-notes-input" placeholder="Record investigation findings, hypotheses, containment actions..." style="width:100%;height:68px;background:var(--bg-base);border:1px solid var(--border-default);border-radius:6px;color:var(--text-primary);padding:8px;font-size:11px;font-family:inherit;resize:vertical;"></textarea>
              </article>
            </div>
          </div>
        </section>

        <!-- ── PANEL: NATIONAL DEFENCE RADAR ── -->
        <section id="panel-defence" class="panel" role="tabpanel" aria-labelledby="tab-defence">
          <div class="split">
            <div class="stack">
              <article class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                  <div>
                    <p class="eyebrow">Multi-Domain Public Telemetry Engine</p>
                    <h2>Strategic Border &amp; Maritime Sectors (India Context)</h2>
                  </div>
                  <button id="btn-ask-bob-defence" class="topbar-btn primary" style="font-weight:700;" onclick="openBobModal(selected ? selected.id : '', 'defence')">🤖 Sector Defence Brief</button>
                </div>
                <p style="font-size:12px;color:var(--text-secondary);margin-bottom:12px;">
                  Unified multi-domain situational awareness cross-correlating civil ADS-B (OpenSky), vessel AIS (NOAA), radar &amp; optical change detection (Copernicus Sentinel-1/2), thermal hotspots (NASA FIRMS), and weather warnings (IMD).
                </p>
                <!-- Strategic Sector Cards -->
                <div id="defence-sectors-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:14px;"></div>
                
                <!-- Domain Filter Toolbar -->
                <div style="display:flex;align-items:center;justify-content:space-between;margin-top:14px;margin-bottom:8px;flex-wrap:wrap;gap:8px;">
                  <h3 style="font-size:12px;color:var(--text-primary);margin:0;">Sector Radar &amp; Telemetry Stream</h3>
                  <div id="radar-domain-filters" class="filters" style="margin:0;"></div>
                </div>

                <!-- Radar Observation Table -->
                <div style="max-height:420px;overflow-y:auto;border:1px solid var(--border-default);border-radius:6px;background:#05080c;">
                  <table style="width:100%;border-collapse:collapse;font-size:11px;font-family:ui-monospace,monospace;color:var(--text-secondary);">
                    <thead>
                      <tr style="background:var(--bg-surface-elevated);border-bottom:1px solid var(--border-default);color:var(--text-primary);text-align:left;">
                        <th style="padding:6px 10px;">Domain</th>
                        <th style="padding:6px 10px;">Entity / Call / MMSI</th>
                        <th style="padding:6px 10px;">Sector &amp; Coordinates</th>
                        <th style="padding:6px 10px;">Telemetry Metrics</th>
                        <th style="padding:6px 10px;">Observation Detail</th>
                        <th style="padding:6px 10px;text-align:right;">Action</th>
                      </tr>
                    </thead>
                    <tbody id="radar-table-body">
                      <tr><td colspan="6" style="padding:16px;text-align:center;color:var(--text-muted);">Loading radar telemetry…</td></tr>
                    </tbody>
                  </table>
                </div>
              </article>

              <!-- Multi-Domain Simulation Bar -->
              <article class="card">
                <p class="eyebrow">Public Feeds Ingestion &amp; Live Scenario Injectors</p>
                <h2>Inject Multi-Domain Defence Scenarios</h2>
                <p style="font-size:11px;color:var(--text-muted);margin-bottom:12px;">
                  Inject public multi-source telemetry to test real-time cross-domain spatial correlation without breaking cyber benchmarks:
                </p>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <button id="sim-airspace-btn" class="action-btn">✈️ Airspace Approach (OpenSky ADS-B)</button>
                  <button id="sim-maritime-btn" class="action-btn">🚢 Maritime Dark Vessel (AIS + SAR)</button>
                  <button id="sim-sentinel-btn" class="action-btn">🛰️ Ground Change (Sentinel-1 SAR)</button>
                  <button id="sim-firms-btn" class="action-btn">🔥 Thermal Hotspots (NASA FIRMS)</button>
                  <button id="sim-imd-btn" class="action-btn">🌦️ Dense Fog Cover (IMD Weather)</button>
                  <button id="sim-defence-all-btn" class="action-btn primary">🇮🇳 Full Multi-Domain Defence Fusion</button>
                </div>
              </article>
            </div>

            <div class="stack">
              <!-- Domain Stats Breakdown Card -->
              <article class="card">
                <p class="eyebrow">Cross-Domain Telemetry Distribution</p>
                <h2>Monitored Public Feeds</h2>
                <div id="domain-stats-breakdown" style="display:grid;gap:8px;margin-top:10px;"></div>
              </article>

              <!-- Indian Defence Context & Caveats -->
              <article class="card">
                <p class="eyebrow">Operational Boundary &amp; Provenance</p>
                <h2>Zero-Hallucination Public Feeds</h2>
                <ul class="plain-list" style="margin-top:8px;">
                  <li><strong>Civil Airspace (OpenSky)</strong>: Live civil flight vectors; unannounced transponder gaps flagged as telemetry blindspots.</li>
                  <li><strong>Maritime (AIS &amp; MOSDAC)</strong>: Vessel AIS positions; dark vessels cross-referenced with satellite scatterometry.</li>
                  <li><strong>Radar EO (Copernicus Sentinel-1)</strong>: C-band SAR ground coherence provides all-weather cloud-penetrating change detection.</li>
                  <li><strong>Thermal (NASA FIRMS)</strong>: 375m VIIRS active fire / heat hotspots near forward corridors.</li>
                  <li><strong>Weather (IMD AWS)</strong>: Fog/rain advisories explaining optical sensor degradation.</li>
                </ul>
                <div class="notice" style="margin-top:10px;">
                  🔒 <strong>Defensible Separation</strong>: Restricted military radar and classified feeds are not assumed. IBM Bob briefs strictly from verifiable public telemetry.
                </div>
              </article>
            </div>
          </div>
        </section>

        <!-- ── PANEL: EVIDENCE ── -->
        <section id="panel-evidence" class="panel" role="tabpanel" aria-labelledby="tab-evidence">
          <article class="card">
            <p class="eyebrow">Grounded Chronology</p>
            <h2>Full Evidence Sequence</h2>
            <p style="font-size:11px;color:var(--text-muted);margin-bottom:12px;">Every inference links to an immutable source record. Filter telemetry by sensor type:</p>
            <div id="source-filters" class="filters" aria-label="Filter by source"></div>
            <div id="full-timeline" class="timeline"></div>
          </article>
        </section>

        <!-- ── PANEL: COMMANDER BRIEF ── -->
        <section id="panel-response" class="panel" role="tabpanel" aria-labelledby="tab-response">
          <div class="split">
            <article class="card">
              <p class="eyebrow">Executive Intelligence Memo</p>
              <h2>Bottom Line Up Front (BLUF)</h2>
              <p style="font-size:11px;color:var(--text-muted);margin-bottom:12px;">Synthesized directly from deterministic engine facts for commander decision-making.</p>
              <div id="brief-content"></div>
              <div class="btn-row">
                <button id="copy-brief" class="button">📋 Copy Brief</button>
                <button id="export-brief" class="button secondary">⬇ Export Markdown</button>
              </div>
            </article>
            <article class="card">
              <p class="eyebrow">Staged Response Actions</p>
              <h2>Analyst-Gated Runbook</h2>
              <p style="font-size:11px;color:var(--text-muted);margin-bottom:0;">Containment, eradication, and detection actions requiring human confirmation.</p>
              <ol id="response-actions" class="action-list"></ol>
            </article>
          </div>
        </section>

        <!-- ── PANEL: ALERT REDUCTION ── -->
        <section id="panel-compare" class="panel" role="tabpanel" aria-labelledby="tab-compare">
          <article class="card">
            <p class="eyebrow">False-Positive Reduction Funnel</p>
            <h2>From Raw Telemetry to Defensible Incidents</h2>
            <p style="font-size:11px;color:var(--text-muted);">Real-time metrics demonstrating signal vs noise separation across multi-source feeds.</p>
            <div class="compare-funnel">
              <div class="funnel-box">
                <span class="funnel-big raw" id="c-raw">—</span>
                <div class="funnel-desc">Raw Observations<br><span style="font-size:10px;color:var(--text-muted);">4+ Source Schemas</span></div>
              </div>
              <span class="funnel-big-arrow">→</span>
              <div class="funnel-box">
                <span class="funnel-big cand" id="c-cand">—</span>
                <div class="funnel-desc">Candidate Hypotheses<br><span style="font-size:10px;color:var(--text-muted);">Entity + Time Links</span></div>
              </div>
              <span class="funnel-big-arrow">→</span>
              <div class="funnel-box">
                <span class="funnel-big prom" id="c-prom">—</span>
                <div class="funnel-desc">Promoted Incidents<br><span style="font-size:10px;color:var(--text-muted);">Gated Promotion</span></div>
              </div>
            </div>
          </article>

          <!-- NOT PROMOTED candidates -->
          <article class="card" style="margin-top:14px;">
            <p class="eyebrow">Promotion Boundary Audit</p>
            <h2>Unpromoted Candidate Hypotheses</h2>
            <p style="font-size:11px;color:var(--text-muted);margin-bottom:12px;">Candidate clusters that did not satisfy all 4 deterministic promotion checks remain auditable below:</p>
            <div id="not-promoted-list" class="stack" style="gap:8px;"></div>
          </article>

          <div class="compare-grid" style="margin-top:14px;">
            <article class="card compare-card bad">
              <div class="compare-card-title">❌ Traditional Alert Flooding (Naïve SIEM)</div>
              <ul class="plain-list">
                <li>Treats every isolated alert as an emergency ticket</li>
                <li>Fixed time windows without behavioral coherence</li>
                <li>Hides visibility gaps and contradictory evidence</li>
                <li>Floods analysts with routine administrative scripts</li>
                <li>Opaque AI scoring impossible to mathematically audit</li>
              </ul>
            </article>
            <article class="card compare-card good">
              <div class="compare-card-title">✅ ThreatFusion Engine (Deterministic Telemetry)</div>
              <ul class="plain-list">
                <li>Strict ATT&amp;CK behavior sequence verification</li>
                <li>Decoupled 4D risk scoring (Confidence vs Severity vs Impact)</li>
                <li>Explicit negative evidence &amp; visibility gap logging</li>
                <li>Ambiguous clusters safely quarantined in candidate stage</li>
                <li>100% explainable provenance ready for IBM Bob MCP</li>
              </ul>
            </article>
          </div>
        </section>

        <!-- ── PANEL: SIMULATOR & FEEDS ── -->
        <section id="panel-simulator" class="panel" role="tabpanel" aria-labelledby="tab-simulator">
          <div class="split">
            <div class="stack">
              <article class="card">
                <p class="eyebrow">Multi-Source Telemetry Feeds</p>
                <h2>Heterogeneous Ingestion (SIEM, Satellite, Cyber, CTI)</h2>
                <p style="font-size:12px;color:var(--text-secondary);margin-bottom:14px;">
                  Ingest real and synthetic telemetry streams to evaluate real-time candidate clustering, ATT&amp;CK mapping, and false-positive suppression:
                </p>
                <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
                  <button id="sim-sat-btn" class="action-btn">🛰️ SPARTA Satellite Feed (Synthetic Demo)</button>
                  <button id="sim-otrf-btn" class="action-btn">💻 OTRF Sysmon Events (Real Sample)</button>
                  <button id="sim-cicids-btn" class="action-btn">🌐 CIC-IDS2017 Flows (Real Sample)</button>
                  <button id="sim-benign-btn" class="action-btn">🛡️ Ingest Benign Routine Noise</button>
                  <button id="sim-hist-btn" class="action-btn primary">📜 Ingest Historical Archive (August 2026)</button>
                  <button id="sim-recent-btn" class="action-btn primary">⚡ Ingest Recent Threats (Sept 18-19, 2026)</button>
                  <button id="sim-all-btn" class="action-btn primary">🚀 Ingest Full Corpus (140+ Alerts)</button>
                </div>
                <div style="margin-top:10px;margin-bottom:14px;padding:12px;background:var(--bg-base);border:1px solid var(--border-default);border-radius:6px;">
                  <p class="eyebrow" style="margin-bottom:2px;">CTI Verification</p>
                  <h3 style="font-size:12px;margin-bottom:2px;color:var(--text-primary);">ThreatFox IOC &amp; CISA KEV Verification</h3>
                  <p style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">Queries curated offline CTI snapshots ensuring 100% reproducible evaluations.</p>
                  <div style="display:flex;gap:8px;">
                    <input id="cti-indicator-input" style="flex:1;background:var(--bg-surface);border:1px solid var(--border-default);border-radius:4px;color:var(--text-primary);padding:6px 10px;font-size:11px;" placeholder="e.g. 185.214.66.91 or CVE-2023-34362">
                    <button id="btn-cti-lookup" class="action-btn primary" style="font-size:11px;padding:6px 12px;">Query Snapshot</button>
                  </div>
                  <div id="cti-lookup-result" style="margin-top:8px;font-size:11px;display:none;"></div>
                </div>
                <div style="margin-top:10px;">
                  <label style="font-size:11px;font-weight:700;color:var(--text-secondary);display:block;margin-bottom:4px;font-family:ui-monospace,monospace;">Custom Alert JSON Ingestion:</label>
                  <textarea id="custom-alert-json" style="width:100%;height:90px;font-family:ui-monospace,monospace;font-size:11px;background:var(--bg-base);border:1px solid var(--border-default);border-radius:6px;color:var(--text-primary);padding:8px;" placeholder='{"source":"satellite_sensor", "host":"SAT-GROUND-01", "event_type":"downlink_anomaly", "detail":"SATCOM signal disruption and unauthorized command relay detected"}'></textarea>
                  <div style="margin-top:8px;display:flex;gap:8px;">
                    <button id="btn-ingest-custom" class="action-btn primary">Ingest Observation</button>
                    <button id="btn-recorrelate" class="action-btn">Force Re-Correlation</button>
                  </div>
                </div>
              </article>
            </div>
            <div class="stack">
              <article class="card">
                <p class="eyebrow">Operational Stream</p>
                <h2>Recent Ingested Telemetry</h2>
                <p style="font-size:11px;color:var(--text-muted);margin-bottom:10px;">Raw records stored in SQLite with full provenance tags.</p>
                <div id="sim-recent-stream" style="max-height:360px;overflow-y:auto;display:flex;flex-direction:column;gap:6px;"></div>
              </article>
            </div>
          </div>
        </section>

        <!-- ── PANEL: IBM BOB ── -->
        <section id="panel-bob" class="panel" role="tabpanel" aria-labelledby="tab-bob">
          <div class="split">
            <article class="card">
              <p class="eyebrow">Natural Language Investigation Layer</p>
              <h2>IBM Bob Grounded Commands</h2>
              <p style="font-size:12px;color:var(--text-muted);margin-bottom:14px;">IBM Bob interfaces with ThreatFusion via Model Context Protocol (MCP). It explains facts and coordinates human workflows without altering deterministic math:</p>
              <div id="bob-commands" class="stack" style="gap:6px;"></div>
            </article>
            <article class="card">
              <p class="eyebrow">MCP JSON-RPC Tool Inspector</p>
              <h2>Inspect Telemetry Tools</h2>
              <p style="font-size:11px;color:var(--text-muted);margin-bottom:12px;">Preview the exact read-only JSON data delivered to IBM Bob:</p>
              <div id="mcp-tools" class="mcp-tools-row"></div>
              <pre id="tool-output" class="tool-output">Select an MCP tool above to inspect its deterministic JSON output.</pre>
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
      threat_intel_report: 'Threat Intel',
      opensky_airspace: '✈️ OpenSky Airspace',
      airspace: '✈️ Airspace',
      maritime_ais: '🚢 NOAA Maritime AIS',
      maritime: '🚢 Maritime',
      copernicus_sentinel: '🛰️ Copernicus Sentinel',
      satellite_eo: '🛰️ Satellite EO',
      nasa_firms: '🔥 NASA FIRMS',
      thermal_ir: '🔥 Thermal IR',
      imd_weather: '🌦️ IMD Weather',
      weather_env: '🌦️ Meteorology',
      isro_bhuvan: '🇮🇳 ISRO Bhuvan',
      geospatial_infra: '🇮🇳 Critical Infra',
      emergency_usgs: '🌍 USGS / CEMS',
      geophysical: '🌍 Geophysical',
      satellite_sensor: '🛰️ SPARTA Satellite',
      cyber_c2: '💻 Cyber / Ground C2',
    };
    const SOURCE_CLASS = {
      siem: 'src-siem',
      endpoint: 'src-endpoint',
      network_sensor: 'src-network_sensor',
      threat_intel_report: 'src-threat_intel_report',
      opensky_airspace: 'src-opensky_airspace',
      airspace: 'src-opensky_airspace',
      maritime_ais: 'src-maritime_ais',
      maritime: 'src-maritime_ais',
      copernicus_sentinel: 'src-copernicus_sentinel',
      satellite_eo: 'src-copernicus_sentinel',
      nasa_firms: 'src-nasa_firms',
      thermal_ir: 'src-nasa_firms',
      imd_weather: 'src-imd_weather',
      weather_env: 'src-imd_weather',
      isro_bhuvan: 'src-isro_bhuvan',
      geospatial_infra: 'src-isro_bhuvan',
      emergency_usgs: 'src-emergency_usgs',
      geophysical: 'src-emergency_usgs',
      satellite_sensor: 'src-satellite_sensor',
      cyber_c2: 'src-satellite_sensor',
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
      el.textContent = (isError ? '⚠️ ' : '🟢 ') + msg;
      el.style.color = isError ? 'var(--danger-red)' : 'var(--success-green)';
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
        const [summaryRes, candidatesRes] = await Promise.all([
          fetch('/api/summary'),
          fetch('/api/candidates'),
        ]);
        if (!summaryRes.ok) throw new Error('Unable to load analysis');
        summary = await summaryRes.json();
        // Funnel numbers (header + compare panel)
        document.getElementById('f-raw').textContent = summary.metrics.raw_records;
        document.getElementById('f-cand').textContent = summary.metrics.candidate_clusters;
        document.getElementById('f-prom').textContent = summary.metrics.promoted_incidents;
        document.getElementById('c-raw').textContent = summary.metrics.raw_records;
        document.getElementById('c-cand').textContent = summary.metrics.candidate_clusters;
        document.getElementById('c-prom').textContent = summary.metrics.promoted_incidents;
        document.getElementById('engine-badge').innerHTML = `<span class="live-dot"></span> Engine v${summary.metadata.engine_version}`;
        if (summary.incidents.length) await loadCase(summary.incidents[0].id, false);
        else renderQueue();
        await renderDefencePanel();
        setStatus(`Engine v${summary.metadata.engine_version} · ATT&CK ${summary.metadata.attack_kb_version} · Zero hallucination telemetry`);
        // Render not-promoted candidates
        if (candidatesRes.ok) {
          const candData = await candidatesRes.json();
          renderNotPromoted(candData.candidates.filter(c => !c.promoted));
        }
      } catch (e) {
        setStatus(e.message, true);
        document.getElementById('case-title').textContent = 'Analysis unavailable';
        document.getElementById('case-title').classList.remove('loading-pulse');
      }
    }

    const CHECK_LABELS_SHORT = {
      minimum_behavior_evidence: 'Multiple ATT&CK behaviors',
      multi_tactic_progression:  'Multi-tactic progression',
      evidence_confidence:       'Evidence confidence',
      source_independence:       'Independent source support',
    };

    function renderNotPromoted(unpromoted) {
      const el = document.getElementById('not-promoted-list');
      if (!unpromoted.length) {
        el.innerHTML = '<p style="font-size:12px;color:var(--text-muted);">All candidates in this dataset passed the promotion checks.</p>';
        return;
      }
      el.innerHTML = unpromoted.map(c => {
        const checks = Object.entries(c.promotion_checks || {}).map(([k, passed]) =>
          `<span class="check-pill ${passed ? 'pass' : 'fail'}">${passed ? '✓' : '✗'} ${esc(CHECK_LABELS_SHORT[k] || k)}</span>`
        ).join('');
        const failedNames = Object.entries(c.promotion_checks || {})
          .filter(([, v]) => !v)
          .map(([k]) => CHECK_LABELS_SHORT[k] || k);
        return `<div class="not-promoted-card">
          <div class="np-header">
            <span class="np-id">${esc(c.id)}</span>
            <span class="np-badge">Candidate (Unpromoted)</span>
          </div>
          <div class="np-meta">${esc(c.record_count)} observations · ${esc(c.technique_count)} ATT&CK behaviors · ${esc(c.confidence)}% confidence · flow ${esc(c.attack_flow_score)}/100</div>
          <div class="np-checks">${checks}</div>
          ${failedNames.length ? `<div class="np-reason">Failed: ${esc(failedNames.join(', '))}. Quarantined below promotion threshold.</div>` : ''}
        </div>`;
      }).join('');
    }

    async function loadCase(id, announce = true) {
      try {
        const res = await fetch('/api/incidents/' + encodeURIComponent(id));
        if (!res.ok) throw new Error('Unable to load this case');
        selected = await res.json();
        activeSource = 'all';
        renderQueue();
        renderCase();
        if (announce) setStatus(`Active Case: ${selected.id}`);
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
        `${inc.record_ids.length} observations · ${inc.sources.length} sensor feeds · ${inc.promotable ? 'Promoted for command review' : 'Candidate state'}`;
      document.getElementById('case-priority').textContent = `${inc.priority} (${inc.priority_score}/100)`;

      const decisionEl = document.getElementById('decision-copy');
      decisionEl.textContent = brief.assessment;
      decisionEl.classList.remove('loading-pulse');

      // Metrics
      const metrics = [
        ['Evidence Confidence', `${inc.confidence}%`, 'conf', 'Mathematical support from corroborated observations.'],
        ['Threat Severity',     `${inc.severity}/100`, 'sev',  'Assessed adversary capability and tactic severity.'],
        ['Mission Impact',      `${inc.mission_impact}/100`, 'impact', 'Weighted criticality of target assets.'],
        ['Decision Urgency',    `${inc.urgency}/100`, 'urgency', 'Immediate action requirement index.'],
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

      const statusSelect = document.getElementById('case-status-select');
      if (statusSelect) statusSelect.value = inc.status || 'open';
      const notesInput = document.getElementById('case-notes-input');
      if (notesInput) notesInput.value = inc.analyst_notes || '';

      renderTimeline('overview-timeline', inc.evidence.slice(0, 5));
      renderFilters();
      renderTimeline('full-timeline', inc.evidence);
      renderBrief();
      renderBob();
      updateRecentStream();
    }

    function provenanceBadge(r) {
      const ptype = r.provenance_type || 'synthetic';
      const dname = r.dataset_name || (ptype === 'real_sample' ? 'Real Telemetry' : 'Synthetic Benchmark');
      if (ptype === 'real_sample') {
        return `<span style="background:var(--success-green-dim);color:var(--success-green);border:1px solid var(--success-green-border);font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;font-family:ui-monospace,monospace;">REAL · ${esc(dname)}</span>`;
      } else if (ptype === 'live_feed') {
        return `<span style="background:var(--tactical-blue-dim);color:var(--tactical-blue);border:1px solid var(--tactical-blue-border);font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;font-family:ui-monospace,monospace;">LIVE FEED · ${esc(dname)}</span>`;
      } else if (ptype === 'curated_snapshot') {
        return `<span style="background:var(--warning-amber-dim);color:var(--warning-amber);border:1px solid var(--warning-amber-border);font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;font-family:ui-monospace,monospace;">CTI SNAPSHOT · ${esc(dname)}</span>`;
      }
      return `<span style="background:rgba(129,140,248,0.12);color:var(--purple-intel);border:1px solid rgba(129,140,248,0.3);font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;font-family:ui-monospace,monospace;">SYNTHETIC · ${esc(dname)}</span>`;
    }

    function frameworkBadge(fw) {
      if (!fw) return '';
      const isSparta = fw.toUpperCase().includes('SPARTA');
      const color = isSparta ? 'var(--tactical-blue)' : 'var(--purple-intel)';
      const bg = isSparta ? 'var(--tactical-blue-dim)' : 'rgba(129,140,248,0.12)';
      const border = isSparta ? 'var(--tactical-blue-border)' : 'rgba(129,140,248,0.3)';
      return `<span style="background:${bg};color:${color};border:1px solid ${border};font-size:9px;font-weight:800;letter-spacing:.04em;padding:1px 5px;border-radius:3px;font-family:ui-monospace,monospace;">${esc(fw)}</span>`;
    }

    function renderTimeline(targetId, records) {
      const target = document.getElementById(targetId);
      const filtered = activeSource === 'all' ? records : records.filter(r => r.source === activeSource);
      if (!filtered.length) { target.innerHTML = '<div class="empty">No telemetry matches this source filter.</div>'; return; }
      target.innerHTML = filtered.map(r => {
        const tfHtml = r.threatfox_match
          ? `<div style="font-size:11px;color:var(--danger-red);margin-top:6px;background:var(--danger-red-dim);padding:4px 8px;border-radius:4px;border-left:2px solid var(--danger-red);">
              <strong>ThreatFox CTI Match:</strong> ${esc(r.threatfox_match.malware || 'Known Malware')} · IOC: <code>${esc(r.threatfox_match.ioc)}</code> (${esc(r.threatfox_match.confidence)}% conf)
            </div>`
          : '';
        const kevHtml = r.cisa_kev_match
          ? `<div style="font-size:11px;color:var(--warning-amber);margin-top:6px;background:var(--warning-amber-dim);padding:4px 8px;border-radius:4px;border-left:2px solid var(--warning-amber);">
              <strong>CISA KEV Exploit:</strong> ${esc(r.cisa_kev_match.cve)} — ${esc(r.cisa_kev_match.vulnerability_name)}
            </div>`
          : '';
        return `<div class="timeline-item">
          <div class="ttime">${esc(timeLabel(r.timestamp))}</div>
          <div class="evidence">
            <div class="evidence-head">
              <strong class="evidence-title">${esc(r.summary)}</strong>
              <div style="display:flex;gap:4px;align-items:center;flex-shrink:0;">
                ${sourceBadge(r.source)}
                ${provenanceBadge(r)}
              </div>
            </div>
            <div style="display:flex;gap:4px;align-items:center;margin-top:4px;flex-wrap:wrap;">
              ${r.technique ? `<span class="technique-tag">${esc(r.technique)} · ${esc(r.technique_name || '')}</span>` : ''}
              ${r.framework ? frameworkBadge(r.framework) : ''}
            </div>
            ${r.technique_reason ? `<p class="evidence-reason">↳ ${esc(r.technique_reason)}</p>` : ''}
            ${tfHtml}
            ${kevHtml}
          </div>
        </div>`;
      }).join('');
    }

    function renderFilters() {
      const sources = [...new Set(selected.evidence.map(r => r.source))];
      const filters = ['all', ...sources];
      const target = document.getElementById('source-filters');
      target.innerHTML = filters.map(s =>
        `<button class="filter" data-source="${esc(s)}" aria-pressed="${s === activeSource}">
          ${s === 'all' ? 'All Telemetry' : esc(sourceLabel(s))}
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
        ['Bottom Line', brief.bottom_line],
        ['Tactical Assessment',  brief.assessment],
        ['Attribution & Actor Context', brief.actor_assessment],
        ['Uncertainty & Visibility Gaps', brief.uncertainty],
      ];

      const blufBanner = brief.commander_briefing
        ? `<div style="background:var(--tactical-blue-dim);border:1px solid var(--tactical-blue-border);border-radius:6px;padding:12px 14px;margin-bottom:14px;">
            <div style="font-size:9px;font-weight:800;color:var(--tactical-blue);letter-spacing:.08em;margin-bottom:4px;text-transform:uppercase;font-family:ui-monospace,monospace;">Commander Decision Briefing (BLUF)</div>
            <div style="font-size:12px;color:var(--text-primary);font-weight:600;line-height:1.5;">${esc(brief.commander_briefing)}</div>
          </div>`
        : '';

      document.getElementById('brief-content').innerHTML = blufBanner + sections.map(([label, value]) =>
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
      const blufHeader = brief.commander_briefing ? `> **BLUF**: ${brief.commander_briefing}\n\n` : '';
      return `# Commander Brief — ${selected.id}\n\n${blufHeader}## Bottom line\n${brief.bottom_line}\n\n## Assessment\n${brief.assessment}\n\n## Actor context\n${brief.actor_assessment}\n\n## Uncertainty\n${brief.uncertainty}\n\n## Recommended actions\n${brief.recommended_actions.map((a, i) => `${i + 1}. ${a}`).join('\n')}`;
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
        ['/investigate', 'Retrieve the deterministic evidence chain, risk factors, gaps, and analyst next steps.'],
        ['/explain',     'Explain why the case was prioritised without altering engine scoring math.'],
        ['/bluf',        'Turn grounded case facts into a commander-ready executive summary.'],
        ['/runbook',     'Retrieve human-gated containment, eradication, and detection-engineering actions.'],
      ];
      document.getElementById('bob-commands').innerHTML = commands.map(([cmd, desc]) =>
        `<div class="mcp-command">
          <div>
            <div class="mcp-cmd-code">${esc(cmd)} ${esc(selected.id)}</div>
            <div class="mcp-cmd-desc">${esc(desc)}</div>
          </div>
          <button class="button secondary" data-copy-command="${esc(cmd)} ${esc(selected.id)}" style="padding:4px 10px;font-size:11px;">Copy</button>
        </div>`).join('');
      document.querySelectorAll('[data-copy-command]').forEach(b =>
        b.addEventListener('click', () => copyText(b.dataset.copyCommand, 'Bob command copied.')));

      const tools = [
        ['get_incident', 'Case facts'],
        ['explain_risk', 'Risk rationale'],
        ['get_detection_gaps', 'Visibility gaps'],
        ['generate_bluf', 'BLUF Memo'],
        ['get_remediation_runbook', 'Runbook'],
      ];
      document.getElementById('mcp-tools').innerHTML = tools.map(([tool, label]) =>
        `<button class="tool-btn" data-tool="${esc(tool)}">${esc(label)}</button>`).join('');
      document.querySelectorAll('[data-tool]').forEach(b =>
        b.addEventListener('click', () => runTool(b.dataset.tool)));
    }

    async function runTool(toolName) {
      const out = document.getElementById('tool-output');
      out.textContent = 'Calling MCP tool…';
      try {
        const res = await fetch(`/api/mcp-query?tool=${encodeURIComponent(toolName)}&incident_id=${encodeURIComponent(selected.id)}`);
        const data = await res.json();
        out.textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        out.textContent = 'Error: ' + e.message;
      }
    }

    async function runSearch() {
      const q = document.getElementById('search-input').value.trim();
      const resultsEl = document.getElementById('search-results');
      if (!q) { resultsEl.classList.remove('open'); return; }
      resultsEl.innerHTML = '<div style="padding:12px;text-align:center;color:var(--text-muted);">Searching indicators…</div>';
      resultsEl.classList.add('open');
      try {
        const res = await fetch(`/api/mcp-query?tool=search_indicators&query=${encodeURIComponent(q)}`);
        const data = await res.json();
        if (!data.matches || !data.matches.length) {
          resultsEl.innerHTML = `<div class="search-no-results">No matches for "${esc(q)}" across raw telemetry.</div>`;
          return;
        }
        resultsEl.innerHTML = data.matches.map(m =>
          `<div class="search-result-item" data-record-id="${esc(m.record_id)}">
            <div class="search-result-id">${esc(m.record_id)}</div>
            <div class="search-result-snippet">${esc(m.matched_snippet)}</div>
            <div class="search-result-ts">${esc(m.timestamp || '')} · ${sourceBadge(m.source || '')}</div>
          </div>`).join('') +
          (data.total_matches > data.matches.length
            ? `<div class="search-no-results">Showing ${data.matches.length} of ${data.total_matches} matches</div>`
            : '');
        resultsEl.querySelectorAll('.search-result-item').forEach(item => {
          item.addEventListener('click', () => {
            const recId = item.dataset.recordId;
            resultsEl.classList.remove('open');
            openBobModal(recId, 'investigate');
          });
        });
      } catch (e) {
        resultsEl.innerHTML = `<div class="search-no-results">Search error: ${esc(e.message)}</div>`;
      }
    }

    async function updateRecentStream() {
      const el = document.getElementById('sim-recent-stream');
      if (!el) return;
      try {
        const res = await fetch('/api/alerts?limit=6');
        if (!res.ok) return;
        const data = await res.json();
        el.innerHTML = (data.alerts || []).map(a =>
          `<div style="padding:7px 9px;background:var(--bg-base);border:1px solid var(--border-default);border-radius:4px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:2px;">
              <strong style="color:var(--tactical-blue);font-size:11px;font-family:ui-monospace,monospace;">${esc(a._id || a.id)}</strong>
              ${sourceBadge(a.source)}
            </div>
            <div style="font-size:11px;color:var(--text-primary);">${esc(a.detail || a.text || a.event_type || 'event')}</div>
            <div style="font-size:10px;color:var(--text-muted);margin-top:2px;font-family:ui-monospace,monospace;">${esc(a.timestamp)} ${a.host ? '· ' + esc(a.host) : ''}</div>
          </div>`).join('');
      } catch (e) {
        console.error(e);
      }
    }

    // Dynamic event listeners
    document.getElementById('case-status-select').addEventListener('change', async (e) => {
      if (!selected) return;
      const newStatus = e.target.value;
      try {
        const res = await fetch('/api/incidents/' + encodeURIComponent(selected.id), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });
        if (res.ok) setStatus(`Incident ${selected.id} status updated to ${newStatus}.`);
      } catch (err) {
        setStatus('Failed to update status: ' + err.message, true);
      }
    });

    document.getElementById('btn-save-notes').addEventListener('click', async () => {
      if (!selected) return;
      const notes = document.getElementById('case-notes-input').value;
      try {
        const res = await fetch('/api/incidents/' + encodeURIComponent(selected.id), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ analyst_notes: notes }),
        });
        if (res.ok) setStatus(`Analyst notes for ${selected.id} saved.`);
      } catch (err) {
        setStatus('Failed to save notes: ' + err.message, true);
      }
    });

    document.getElementById('btn-open-sim').addEventListener('click', () => switchTab('simulator'));

    document.getElementById('sim-sat-btn').addEventListener('click', async () => {
      setStatus('Simulating Satellite Telemetry Breach feed…');
      try {
        const res = await fetch('/api/simulate-feed', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: 'satellite_ground_breach' }),
        });
        const data = await res.json();
        setStatus(`Simulated satellite feed: ${data.inserted_records} records ingested. Re-correlating…`);
        await boot();
      } catch (err) {
        setStatus('Simulation failed: ' + err.message, true);
      }
    });

    document.getElementById('sim-benign-btn').addEventListener('click', async () => {
      setStatus('Ingesting Benign Routine Telemetry…');
      try {
        const res = await fetch('/api/simulate-feed', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: 'benign_admin_noise' }),
        });
        const data = await res.json();
        setStatus(`Ingested ${data.inserted_records} benign alerts. Filtered by negative evidence checks.`);
        await boot();
      } catch (err) {
        setStatus('Ingestion failed: ' + err.message, true);
      }
    });

    document.getElementById('sim-otrf-btn').addEventListener('click', async () => {
      setStatus('Ingesting real OTRF Security Datasets (Sysmon host events)…');
      try {
        const res = await fetch('/api/simulate-feed', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: 'otrf_attack_chain' }),
        });
        const data = await res.json();
        setStatus(`Ingested ${data.inserted_records} real OTRF Sysmon events with ThreatFox CTI enrichment.`);
        await boot();
      } catch (err) {
        setStatus('OTRF ingestion failed: ' + err.message, true);
      }
    });

    document.getElementById('sim-cicids-btn').addEventListener('click', async () => {
      setStatus('Ingesting real CIC-IDS2017 network flow telemetry…');
      try {
        const res = await fetch('/api/simulate-feed', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: 'cicids_network_flood' }),
        });
        const data = await res.json();
        setStatus(`Ingested ${data.inserted_records} real CIC-IDS2017 flow observations.`);
        await boot();
      } catch (err) {
        setStatus('CIC-IDS ingestion failed: ' + err.message, true);
      }
    });

    document.getElementById('sim-hist-btn').addEventListener('click', async () => {
      setStatus('Ingesting historical threat archive (August 2026 campaigns)…');
      try {
        const res = await fetch('/api/ingest/corpus', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'historical' }),
        });
        const data = await res.json();
        setStatus(`Historical archive ingested: ${data.stats.historical_ingested} records. Total alerts in DB: ${data.total_alerts}.`);
        await boot();
      } catch (err) {
        setStatus('Historical ingest error: ' + err.message, true);
      }
    });

    document.getElementById('sim-recent-btn').addEventListener('click', async () => {
      setStatus('Ingesting recent threats (September 18-19, 2026 active telemetry)…');
      try {
        const res = await fetch('/api/ingest/corpus', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'recent' }),
        });
        const data = await res.json();
        setStatus(`Recent threats ingested: ${data.stats.recent_ingested} records. Total alerts in DB: ${data.total_alerts}.`);
        await boot();
      } catch (err) {
        setStatus('Recent ingest error: ' + err.message, true);
      }
    });

    document.getElementById('sim-all-btn').addEventListener('click', async () => {
      setStatus('Ingesting full threat corpus (historical archive + recent telemetry + OTRF + CIC-IDS + SPARTA)…');
      try {
        const res = await fetch('/api/ingest/corpus', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'all' }),
        });
        const data = await res.json();
        setStatus(`Full corpus ingested: +${data.stats.total_new_ingested} records. Database now has ${data.total_alerts} observations!`);
        await boot();
      } catch (err) {
        setStatus('Full corpus ingest error: ' + err.message, true);
      }
    });

    document.getElementById('btn-cti-lookup').addEventListener('click', async () => {
      const q = document.getElementById('cti-indicator-input').value.trim();
      const resEl = document.getElementById('cti-lookup-result');
      if (!q) return;
      resEl.style.display = 'block';
      resEl.innerHTML = '<span style="color:var(--tactical-blue);">Querying CTI feeds…</span>';
      try {
        const endpoint = q.toUpperCase().startsWith('CVE-') 
          ? `/api/cisa-kev/lookup?cve=${encodeURIComponent(q)}`
          : `/api/threatfox/lookup?indicator=${encodeURIComponent(q)}`;
        const res = await fetch(endpoint);
        const data = await res.json();
        if (data.found) {
          const info = data.threat || data.vulnerability;
          resEl.innerHTML = `<div style="background:var(--bg-base);padding:8px;border-radius:4px;border-left:3px solid var(--danger-red);">
            <strong style="color:var(--danger-red);">MATCH FOUND:</strong> ${esc(q)}<br>
            <span><strong>Source:</strong> ${endpoint.includes('cisa') ? 'CISA KEV Catalog' : 'ThreatFox / abuse.ch'}</span><br>
            <span><strong>Details:</strong> ${esc(info.threat_type_desc || info.vulnerabilityName || info.shortDescription || 'Known Threat')} (${esc(info.confidence_level ? info.confidence_level + '% confidence' : 'KEV Known Exploited')})</span>
          </div>`;
        } else {
          resEl.innerHTML = `<div style="background:var(--bg-base);padding:8px;border-radius:4px;border-left:3px solid var(--success-green);">
            <strong style="color:var(--success-green);">NO MATCH:</strong> ${esc(q)} not found in local curated CTI snapshot.
          </div>`;
        }
      } catch (err) {
        resEl.innerHTML = `<span style="color:var(--danger-red);">Query failed: ${esc(err.message)}</span>`;
      }
    });

    document.getElementById('btn-ingest-custom').addEventListener('click', async () => {
      const raw = document.getElementById('custom-alert-json').value.trim();
      if (!raw) return;
      try {
        const alertObj = JSON.parse(raw);
        setStatus('Ingesting custom observation…');
        const res = await fetch('/api/alerts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(alertObj),
        });
        if (!res.ok) throw new Error('Ingestion rejected');
        setStatus('Observation successfully ingested and correlated.');
        document.getElementById('custom-alert-json').value = '';
        await boot();
      } catch (err) {
        setStatus('Custom ingest error: ' + err.message, true);
      }
    });

    document.getElementById('btn-recorrelate').addEventListener('click', async () => {
      setStatus('Executing full re-correlation over database…');
      try {
        const res = await fetch('/api/recorrelate', { method: 'POST' });
        if (res.ok) {
          setStatus('Re-correlation complete.');
          await boot();
        }
      } catch (err) {
        setStatus('Re-correlation failed: ' + err.message, true);
      }
    });

    document.getElementById('btn-reset-demo').addEventListener('click', async () => {
      if (!confirm('Reset all database tables to the default 62 demo alerts?')) return;
      setStatus('Resetting database to baseline demo state…');
      try {
        const res = await fetch('/api/reset', { method: 'POST' });
        if (res.ok) {
          setStatus('Database restored to 62 demo alerts.');
          await boot();
        }
      } catch (err) {
        setStatus('Reset failed: ' + err.message, true);
      }
    });

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

    // ── MULTI-DOMAIN DEFENCE RADAR & SIMULATION ──
    let activeRadarSector = '';
    let activeRadarDomain = '';
    let currentBobTarget = '';

    const DOMAIN_MAP = {
      all: '🌐 All Domains',
      airspace: '✈️ Airspace (OpenSky)',
      maritime: '🚢 Maritime (AIS)',
      satellite_eo: '🛰️ Satellite EO (Sentinel/ISRO)',
      thermal_ir: '🔥 Thermal (NASA FIRMS)',
      weather_env: '🌦️ Weather (IMD)',
      geospatial_infra: '🇮🇳 Strategic Infrastructure',
      cyber_c2: '💻 Cyber / Ground C2',
    };

    function renderRadarDomainFilters() {
      const el = document.getElementById('radar-domain-filters');
      if (!el) return;
      const domains = ['all', 'airspace', 'maritime', 'satellite_eo', 'thermal_ir', 'weather_env', 'geospatial_infra', 'cyber_c2'];
      el.innerHTML = domains.map(d => {
        const isSel = (d === 'all' && !activeRadarDomain) || (d === activeRadarDomain);
        return `<button class="filter" data-domain="${esc(d)}" aria-pressed="${isSel}">
          ${esc(DOMAIN_MAP[d] || d)}
        </button>`;
      }).join('');
      el.querySelectorAll('[data-domain]').forEach(b => b.addEventListener('click', () => {
        activeRadarDomain = (b.dataset.domain === 'all') ? '' : b.dataset.domain;
        renderRadarDomainFilters();
        renderDefencePanel();
      }));
    }

    async function renderDefencePanel() {
      try {
        renderRadarDomainFilters();
        const [secRes, statsRes, radarRes] = await Promise.all([
          fetch('/api/multidomain/sectors'),
          fetch('/api/multidomain/domain-stats'),
          fetch(`/api/multidomain/radar-feed${activeRadarSector ? '?sector=' + encodeURIComponent(activeRadarSector) : ''}${activeRadarDomain ? (activeRadarSector ? '&' : '?') + 'domain=' + encodeURIComponent(activeRadarDomain) : ''}`),
        ]);
        if (secRes.ok) {
          const secData = await secRes.json();
          const grid = document.getElementById('defence-sectors-grid');
          if (grid) {
            grid.innerHTML = (secData.sectors || []).map(s => {
              const isActive = s.sector_id === activeRadarSector;
              return `<div class="not-promoted-card" style="cursor:pointer;border-color:${isActive ? 'var(--tactical-blue)' : 'var(--border-default)'};background:${isActive ? 'var(--bg-surface-highlight)' : 'var(--bg-base)'};transition:all 0.15s;" onclick="toggleRadarSector('${esc(s.sector_id)}')">
                <div class="np-header">
                  <strong style="color:${isActive ? 'var(--tactical-blue)' : 'var(--text-primary)'};font-size:12px;">${esc(s.name)}</strong>
                  <span class="source-badge src-siem">${esc(s.active_observations)} Obs</span>
                </div>
                <div style="font-size:10px;color:var(--text-muted);margin:4px 0 6px;">Focus: ${esc(s.domain_focus)}</div>
                <div style="font-size:10px;color:var(--tactical-blue);font-family:ui-monospace,monospace;">Lat ${esc(s.center[0].toFixed(2))} · Lon ${esc(s.center[1].toFixed(2))}</div>
              </div>`;
            }).join('');
          }
        }

        if (statsRes.ok) {
          const statsData = await statsRes.json();
          const statsEl = document.getElementById('domain-stats-breakdown');
          if (statsEl) {
            const bd = statsData.domain_breakdown || {};
            const total = statsData.total_records || 1;
            statsEl.innerHTML = Object.entries(bd).map(([dom, count]) => {
              const pct = Math.round((count / total) * 100);
              const label = DOMAIN_MAP[dom] || dom;
              return `<div style="background:var(--bg-base);border:1px solid var(--border-default);padding:8px 10px;border-radius:5px;">
                <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                  <span style="font-size:11px;font-weight:700;color:var(--text-primary);">${esc(label)}</span>
                  <span style="font-family:ui-monospace,monospace;font-size:11px;font-weight:800;color:var(--tactical-blue);">${count} (${pct}%)</span>
                </div>
                <div style="height:4px;background:var(--border-subtle);border-radius:2px;overflow:hidden;">
                  <div style="height:100%;background:var(--tactical-blue);width:${pct}%;"></div>
                </div>
              </div>`;
            }).join('');
          }
        }

        if (radarRes.ok) {
          const radarData = await radarRes.json();
          const tbody = document.getElementById('radar-table-body');
          const items = radarData.feed || [];
          if (tbody) {
            if (!items.length) {
              tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;text-align:center;color:var(--text-muted);">No observations match the current sector or domain filter.</td></tr>';
            } else {
              tbody.innerHTML = items.slice(0, 35).map(item => {
                const metrics = [];
                if (item.altitude_ft) metrics.push(`${item.altitude_ft} ft`);
                if (item.speed_knots) metrics.push(`${item.speed_knots} kts`);
                if (item.squawk) metrics.push(`Squawk ${item.squawk}`);
                if (item.frp_mw) metrics.push(`FRP ${item.frp_mw}MW`);
                if (item.visibility_meters) metrics.push(`Vis ${item.visibility_meters}m`);
                if (item.warning_level) metrics.push(`⚠️ ${item.warning_level}`);
                
                const coords = (item.latitude && item.longitude) 
                  ? `${item.latitude.toFixed(2)}°N, ${item.longitude.toFixed(2)}°E` 
                  : 'Forward Corridor';

                return `<tr style="border-bottom:1px solid var(--border-subtle);transition:background 0.1s;">
                  <td style="padding:6px 10px;">${sourceBadge(item.domain || item.source)}</td>
                  <td style="padding:6px 10px;font-weight:700;color:var(--text-primary);">${esc(item.entity || item.host || '—')}</td>
                  <td style="padding:6px 10px;color:var(--text-secondary);">${esc(item.sector)}<br><span style="font-size:10px;color:var(--text-muted);">${esc(coords)}</span></td>
                  <td style="padding:6px 10px;color:var(--warning-amber);">${esc(metrics.join(' · ') || 'Active telemetry')}</td>
                  <td style="padding:6px 10px;max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text-secondary);" title="${esc(item.detail)}">${esc(item.detail)}</td>
                  <td style="padding:6px 10px;text-align:right;">
                    <button class="btn-sm" style="font-size:10px;padding:2px 6px;" onclick="openBobModal('${esc(item.id)}', '${esc(item.domain || 'defence')}')">🤖 Ask Bob</button>
                  </td>
                </tr>`;
              }).join('');
            }
          }
        }
      } catch (err) {
        console.error('Error rendering defence panel:', err);
      }
    }

    function toggleRadarSector(secId) {
      activeRadarSector = (activeRadarSector === secId) ? '' : secId;
      renderDefencePanel();
    }

    // Defence Simulation Injectors
    async function injectMultidomain(scenario, msg) {
      setStatus(`Injecting multi-domain defence scenario: ${msg}…`);
      try {
        const res = await fetch('/api/simulate-multidomain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario }),
        });
        if (!res.ok) throw new Error('Simulation failed');
        const data = await res.json();
        setStatus(`Injected ${msg}: ${data.total_alerts} observations in database. Re-correlating…`);
        await boot();
      } catch (err) {
        setStatus(`Simulation error: ${err.message}`, true);
      }
    }

    document.getElementById('sim-airspace-btn').addEventListener('click', () => injectMultidomain('airspace_border_incursion', 'OpenSky Airspace Corridor'));
    document.getElementById('sim-maritime-btn').addEventListener('click', () => injectMultidomain('maritime_dark_vessel_incursion', 'NOAA Maritime Dark Vessel'));
    document.getElementById('sim-sentinel-btn').addEventListener('click', () => injectMultidomain('sentinel_sar_infrastructure_change', 'Sentinel-1 SAR Change Detection'));
    document.getElementById('sim-firms-btn').addEventListener('click', () => injectMultidomain('firms_thermal_critical_infra', 'NASA FIRMS Thermal Hotspots'));
    document.getElementById('sim-imd-btn').addEventListener('click', () => injectMultidomain('imd_densefog_coordinated_approach', 'IMD Dense Fog Incursion'));
    document.getElementById('sim-defence-all-btn').addEventListener('click', () => injectMultidomain('comprehensive_defence_fusion', 'Full Multi-Domain National Defence Fusion'));

    // ── IBM BOB INTERACTIVE MODAL ──
    function renderMarkdown(md) {
      if (!md) return '';
      let text = String(md);
      // Headings
      text = text.replace(/^### (.*$)/gim, '<h3 style="font-size:13px;font-weight:800;color:var(--text-primary);margin:14px 0 4px;">$1</h3>');
      text = text.replace(/^## (.*$)/gim, '<h2 style="font-size:15px;font-weight:800;color:var(--tactical-blue);margin:18px 0 6px;border-bottom:1px solid var(--border-subtle);padding-bottom:4px;">$1</h2>');
      text = text.replace(/^# (.*$)/gim, '<h1 style="font-size:18px;font-weight:900;color:var(--text-primary);margin:0 0 10px;">$1</h1>');
      // Blockquote / BLUF
      text = text.replace(/^> (.*$)/gim, '<div style="background:var(--tactical-blue-dim);border-left:3px solid var(--tactical-blue);padding:10px 14px;border-radius:4px;margin:10px 0;font-weight:600;color:var(--text-primary);">$1</div>');
      // Bold & italic
      text = text.replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--text-primary);font-weight:700;">$1</strong>');
      text = text.replace(/\*(.*?)\*/g, '<em>$1</em>');
      // Inline code
      text = text.replace(/`(.*?)`/g, '<code style="background:var(--bg-surface-elevated);border:1px solid var(--border-default);padding:2px 5px;border-radius:3px;font-size:11px;font-family:ui-monospace,monospace;color:var(--tactical-blue);">$1</code>');
      // List items
      text = text.replace(/^\- (.*$)/gim, '<li style="margin-left:18px;margin-bottom:4px;color:var(--text-secondary);">$1</li>');
      text = text.replace(/^\d+\. (.*$)/gim, '<li style="margin-left:18px;margin-bottom:4px;color:var(--text-secondary);">$1</li>');
      // Paragraphs
      text = text.replace(/\n\n/g, '<br><br>');
      return text;
    }

    function openBobModal(targetId, defaultCmd = 'investigate') {
      currentBobTarget = targetId || (selected ? selected.id : '');
      const modal = document.getElementById('bob-modal-backdrop');
      const targetLabel = document.getElementById('bob-modal-target');
      if (targetLabel) targetLabel.textContent = currentBobTarget ? `Active Target: ${currentBobTarget}` : 'National Defence Multi-Domain Context';
      if (modal) modal.style.display = 'flex';
      askBob(defaultCmd);
    }

    function closeBobModal() {
      const modal = document.getElementById('bob-modal-backdrop');
      if (modal) modal.style.display = 'none';
    }

    async function askBob(cmd, customPrompt = '') {
      const body = document.getElementById('bob-modal-body');
      if (body) {
        body.innerHTML = '<div style="padding:30px;text-align:center;color:var(--tactical-blue);"><span class="loading-pulse">🤖 IBM Bob synthesizing deterministic MCP facts…</span></div>';
      }
      try {
        const res = await fetch('/api/bob/ask', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            incident_id: currentBobTarget,
            command: cmd,
            prompt: customPrompt || cmd,
          }),
        });
        if (!res.ok) throw new Error('Bob query failed');
        const data = await res.json();
        if (body) {
          body.innerHTML = renderMarkdown(data.response);
        }
      } catch (err) {
        if (body) {
          body.innerHTML = `<div style="color:var(--danger-red);padding:20px;"><strong>Error:</strong> ${esc(err.message)}</div>`;
        }
      }
    }

    function submitCustomBob() {
      const input = document.getElementById('bob-custom-input');
      if (!input) return;
      const val = input.value.trim();
      if (!val) return;
      askBob('custom', val);
      input.value = '';
    }

    document.getElementById('bob-custom-input').addEventListener('keydown', e => { if (e.key === 'Enter') submitCustomBob(); });

    boot();
  </script>

  <!-- ── IBM BOB INTERACTIVE BRIEFING MODAL ── -->
  <div id="bob-modal-backdrop" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.75);backdrop-filter:blur(6px);z-index:9999;align-items:center;justify-content:center;padding:20px;">
    <div style="background:var(--bg-surface-elevated);border:1px solid var(--border-strong);border-radius:8px;width:100%;max-width:880px;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 20px 50px rgba(0,0,0,0.8);animation:panelFadeIn 0.15s ease;">
      <div style="padding:14px 20px;border-bottom:1px solid var(--border-default);display:flex;justify-content:space-between;align-items:center;">
        <div style="display:flex;align-items:center;gap:10px;">
          <div style="width:26px;height:26px;border-radius:4px;background:var(--tactical-blue);color:#000;display:grid;place-items:center;font-weight:900;font-size:13px;font-family:ui-monospace,monospace;">BOB</div>
          <div>
            <h3 style="font-size:14px;font-weight:800;color:var(--text-primary);margin:0;">IBM Bob Grounded Intelligence Brief</h3>
            <span id="bob-modal-target" style="font-size:11px;color:var(--tactical-blue);font-family:ui-monospace,monospace;">Grounded MCP Telemetry</span>
          </div>
        </div>
        <button id="btn-close-bob" style="background:transparent;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;line-height:1;" onclick="closeBobModal()">✕</button>
      </div>
      <!-- Command shortcuts bar -->
      <div style="padding:8px 20px;background:var(--bg-surface);border-bottom:1px solid var(--border-subtle);display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
        <span style="font-size:10px;font-weight:800;color:var(--text-muted);text-transform:uppercase;font-family:ui-monospace,monospace;">Command:</span>
        <button class="tool-btn" onclick="askBob('defence')">🇮🇳 /defence</button>
        <button class="tool-btn" onclick="askBob('airspace')">✈️ /airspace</button>
        <button class="tool-btn" onclick="askBob('maritime')">🚢 /maritime</button>
        <button class="tool-btn" onclick="askBob('satellite')">🛰️ /satellite</button>
        <button class="tool-btn" onclick="askBob('thermal')">🔥 /thermal</button>
        <button class="tool-btn" onclick="askBob('weather')">🌦️ /weather</button>
        <button class="tool-btn" onclick="askBob('bluf')">📋 /bluf</button>
        <button class="tool-btn" onclick="askBob('investigate')">🔍 /investigate</button>
        <button class="tool-btn" onclick="askBob('runbook')">🛡️ /runbook</button>
      </div>
      <!-- Modal Content Body -->
      <div id="bob-modal-body" style="padding:20px;overflow-y:auto;flex:1;font-size:13px;line-height:1.6;color:var(--text-primary);background:var(--bg-base);">
        <div style="text-align:center;padding:30px;color:var(--text-muted);">Select a command or enter a question to generate a grounded brief.</div>
      </div>
      <!-- Custom Prompt Bar -->
      <div style="padding:12px 20px;border-top:1px solid var(--border-default);background:var(--bg-surface);display:flex;gap:8px;">
        <input id="bob-custom-input" style="flex:1;background:var(--bg-base);border:1px solid var(--border-default);border-radius:4px;color:var(--text-primary);padding:8px 12px;font-size:12px;" placeholder="Ask IBM Bob about this threat, sector, domain, or next containment step… (Press Enter)">
        <button id="btn-submit-bob" class="action-btn primary" onclick="submitCustomBob()">Ask Bob</button>
      </div>
    </div>
  </div>
</body>
</html>'''


def get_dynamic_analysis() -> dict[str, Any]:
    db_file = ROOT / "src" / "data" / "threatfusion.db"
    records = None
    assets = None
    if db_file.exists():
        try:
            records = get_all_alerts(db_file)
            assets = get_assets(db_file)
        except Exception:
            records = None
            assets = None
    analysis = analyze(ROOT, records=records, assets=assets)
    if db_file.exists():
        try:
            save_incidents(analysis["incidents"], db_file)
        except Exception:
            pass
    return analysis


def _with_presentation_fields(incident: dict) -> dict:
    """Add derived presentation and triage fields without changing engine math."""
    db_file = ROOT / "src" / "data" / "threatfusion.db"
    status = "open"
    notes = ""
    if db_file.exists():
        try:
            db_item = db_get_incident(incident["id"], db_file)
            if db_item:
                status = db_item.get("status", "open")
                notes = db_item.get("analyst_notes", "")
        except Exception:
            pass
    incident["status"] = status
    incident["analyst_notes"] = notes
    incident["bluf"] = bluf(incident)
    incident["runbook"] = remediation_runbook(incident)
    return incident


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX


@app.get("/healthz")
def healthz() -> dict:
    db_file = ROOT / "src" / "data" / "threatfusion.db"
    return {
        "status": "ok",
        "service": "threatfusion",
        "version": app.version,
        "database": "sqlite_ready" if db_file.exists() else "in_memory_only",
    }


@app.get("/api/summary")
def summary() -> dict:
    try:
        analysis = get_dynamic_analysis()
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
        "incidents": promoted,
    }


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str) -> dict:
    try:
        analysis = get_dynamic_analysis()
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}") from exc
    for candidate in promoted_incidents(analysis):
        if candidate["id"] == incident_id:
            return _with_presentation_fields(candidate)
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/candidates")
def candidates() -> dict:
    """Return all candidate hypotheses, including those that were NOT promoted."""
    try:
        analysis = get_dynamic_analysis()
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}") from exc
    promoted_ids = {inc["id"] for inc in promoted_incidents(analysis)}
    result = []
    for candidate in analysis["incidents"]:
        result.append({
            "id": candidate["id"],
            "promoted": candidate["promotable"],
            "priority": candidate.get("priority"),
            "priority_score": candidate.get("priority_score"),
            "confidence": candidate.get("confidence"),
            "record_count": len(candidate.get("record_ids", [])),
            "sources": candidate.get("sources", []),
            "technique_count": candidate.get("technique_count", 0),
            "promotion_checks": candidate.get("promotion_checks", {}),
            "attack_flow_score": round(candidate.get("attack_flow", {}).get("score", 0) * 100, 1),
        })
    return {"candidates": result, "promoted_count": len(promoted_ids), "total_candidates": len(result)}


@app.post("/api/alerts")
def create_alert(payload: dict) -> dict:
    """Dynamically ingest a single observation from SIEM, Satellite feed, Cyber sensor, or CTI."""
    try:
        inserted = insert_alert(payload)
        clear_context_cache()
        analysis = get_dynamic_analysis()
        return {
            "status": "ok",
            "alert": inserted,
            "total_alerts": len(analysis["records"]),
            "candidate_clusters": len(analysis["incidents"]),
            "promoted_incidents": len(promoted_incidents(analysis)),
        }
    except Exception as exc:
        logger.exception("Ingest alert failed")
        raise HTTPException(status_code=400, detail=f"Invalid alert payload: {exc}") from exc


@app.post("/api/alerts/bulk")
def bulk_create_alerts(payload: list[dict]) -> dict:
    """Dynamically ingest a batch of heterogeneous feed observations."""
    try:
        count = insert_alerts_bulk(payload)
        clear_context_cache()
        analysis = get_dynamic_analysis()
        return {
            "status": "ok",
            "inserted_count": count,
            "total_alerts": len(analysis["records"]),
            "promoted_incidents": len(promoted_incidents(analysis)),
        }
    except Exception as exc:
        logger.exception("Bulk ingest failed")
        raise HTTPException(status_code=400, detail=f"Bulk ingest error: {exc}") from exc


@app.get("/api/alerts")
def list_alerts(
    limit: int = 50,
    offset: int = 0,
    source: str | None = None,
    host: str | None = None,
    search: str | None = None,
) -> dict:
    """Retrieve paginated and filtered raw feed observations."""
    alerts, total = query_alerts(limit=limit, offset=offset, source=source, host=host, search=search)
    return {"alerts": alerts, "total": total, "limit": limit, "offset": offset}


@app.get("/api/assets")
def list_assets() -> dict:
    """Retrieve all registered mission-critical and corporate assets."""
    return {"assets": get_assets()}


@app.post("/api/assets")
def update_asset(payload: dict) -> dict:
    """Create or update asset criticality and mission profile in the inventory."""
    host = payload.get("host")
    if not host:
        raise HTTPException(status_code=400, detail="Missing required 'host' field")
    crit = int(payload.get("criticality", 50))
    role = payload.get("mission_role", "Standard system")
    zone = payload.get("zone", "corporate")
    res = upsert_asset(host, crit, role, zone)
    clear_context_cache()
    return {"status": "ok", "asset": res}


@app.delete("/api/assets/{host}")
def remove_asset(host: str) -> dict:
    """Remove an asset from the inventory."""
    ok = delete_asset(host)
    clear_context_cache()
    return {"status": "ok", "deleted": ok}


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, payload: dict) -> dict:
    """Update analyst triage status (open, investigating, contained, closed, false_positive) or notes."""
    status = payload.get("status")
    notes = payload.get("analyst_notes")
    res = update_incident_triage(incident_id, status=status, analyst_notes=notes)
    if not res:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "ok", "incident": res}


@app.post("/api/recorrelate")
def recorrelate() -> dict:
    """Force re-correlation of all database alerts against MITRE ATT&CK reference."""
    clear_context_cache()
    analysis = get_dynamic_analysis()
    promoted = promoted_incidents(analysis)
    return {
        "status": "ok",
        "raw_records": len(analysis["records"]),
        "candidate_clusters": len(analysis["incidents"]),
        "promoted_incidents": len(promoted),
    }


@app.post("/api/reset")
def reset_demo() -> dict:
    """Reset database back to the baseline 62 demo alerts and initial asset context."""
    reset_db(root_dir=ROOT)
    clear_context_cache()
    analysis = get_dynamic_analysis()
    promoted = promoted_incidents(analysis)
    return {
        "status": "ok",
        "message": "Database reset to baseline demo telemetry and asset definitions.",
        "raw_records": len(analysis["records"]),
        "candidate_clusters": len(analysis["incidents"]),
        "promoted_incidents": len(promoted),
    }


@app.post("/api/ingest/otrf")
def ingest_otrf(payload: dict | list[dict]) -> dict:
    """Ingest real Sysmon / Windows security events in OTRF Security Datasets format."""
    events = payload if isinstance(payload, list) else [payload]
    normalized = []
    for ev in events:
        norm = normalize_otrf(ev)
        enriched = enrich_record(norm, root=ROOT)
        normalized.append(enriched)
    count = insert_alerts_bulk(normalized)
    clear_context_cache()
    analysis = get_dynamic_analysis()
    return {
        "status": "ok",
        "format": "OTRF Security Datasets (Sysmon)",
        "inserted_count": count,
        "total_alerts": len(analysis["records"]),
        "promoted_incidents": len(promoted_incidents(analysis)),
    }


@app.post("/api/ingest/cicids")
def ingest_cicids(payload: dict | list[dict]) -> dict:
    """Ingest real network flow telemetry in CIC-IDS2017 format."""
    flows = payload if isinstance(payload, list) else [payload]
    normalized = []
    for fl in flows:
        norm = normalize_cicids(fl)
        enriched = enrich_record(norm, root=ROOT)
        normalized.append(enriched)
    count = insert_alerts_bulk(normalized)
    clear_context_cache()
    analysis = get_dynamic_analysis()
    return {
        "status": "ok",
        "format": "CIC-IDS2017 Flow Telemetry",
        "inserted_count": count,
        "total_alerts": len(analysis["records"]),
        "promoted_incidents": len(promoted_incidents(analysis)),
    }


@app.get("/api/threatfox/lookup")
def threatfox_lookup(indicator: str = Query(...)) -> dict:
    """Query local curated ThreatFox / abuse.ch CTI feed for malware IOC metadata."""
    match = lookup_threatfox(indicator, root=ROOT)
    if not match:
        return {"found": False, "indicator": indicator, "message": "No match in curated ThreatFox database"}
    return {"found": True, "indicator": indicator, "threat": match}


@app.get("/api/cisa-kev/lookup")
def cisa_kev_lookup(cve: str = Query(...)) -> dict:
    """Query CISA Known Exploited Vulnerabilities catalog."""
    match = check_cisa_kev(cve, root=ROOT)
    if not match:
        return {"found": False, "cve": cve, "message": "Not listed in CISA KEV catalog"}
    return {"found": True, "cve": cve, "vulnerability": match}


@app.post("/api/simulate-feed")
def simulate_feed(payload: dict) -> dict:
    """Simulate incoming multi-source attack feeds (Satellite sensor, cyber sensors, SIEM, OTRF, CIC-IDS)."""
    scenario = payload.get("scenario", "satellite_ground_breach")
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).isoformat()

    if scenario in ("satellite_ground_breach", "sparta_satellite_compromise"):
        sat_file = ROOT / "src" / "data" / "space" / "satellite_demo.json"
        if sat_file.exists():
            with sat_file.open(encoding="utf-8") as f:
                sim_records = [enrich_record(r, root=ROOT) for r in json.load(f)]
        else:
            sim_records = [
                {
                    "_id": f"SIM-SAT-{int(datetime.now().timestamp())}-1",
                    "timestamp": now_iso,
                    "source": "satellite_sensor",
                    "event_type": "downlink_telemetry_anomaly",
                    "host": "SATCOM-GW02",
                    "src_ip": "198.51.100.45",
                    "dst_ip": "10.40.2.1",
                    "detail": "SATCOM ground terminal downlink telemetry anomaly: unexpected telemetry relay command received.",
                },
                {
                    "_id": f"SIM-SAT-{int(datetime.now().timestamp())}-2",
                    "timestamp": now_iso,
                    "source": "network_sensor",
                    "event_type": "lateral_remote_session",
                    "protocol": "RDP",
                    "dst_port": 3389,
                    "src_host": "SATCOM-GW02",
                    "dst_host": "SAT-GROUND-01",
                    "detail": "Unauthorized lateral Remote Desktop Protocol session initiated from satellite gateway to satellite ground station.",
                },
                {
                    "_id": f"SIM-SAT-{int(datetime.now().timestamp())}-3",
                    "timestamp": now_iso,
                    "source": "endpoint",
                    "event_type": "process_injection",
                    "host": "SAT-GROUND-01",
                    "process": "powershell.exe",
                    "parent_process": "winword.exe",
                    "cmdline": "powershell.exe -enc JABzAGEAdAA9...",
                    "detail": "Encoded PowerShell execution launched by document process targeting satellite command bus.",
                },
            ]
    elif scenario == "otrf_attack_chain":
        otrf_file = ROOT / "src" / "data" / "real" / "otrf_sample.json"
        if otrf_file.exists():
            with otrf_file.open(encoding="utf-8") as f:
                sim_records = [enrich_record(normalize_otrf(ev), root=ROOT) for ev in json.load(f)]
        else:
            sim_records = []
    elif scenario == "cicids_network_flood":
        cicids_file = ROOT / "src" / "data" / "real" / "cicids_sample.json"
        if cicids_file.exists():
            with cicids_file.open(encoding="utf-8") as f:
                sim_records = [enrich_record(normalize_cicids(fl), root=ROOT) for fl in json.load(f)]
        else:
            sim_records = []
    elif scenario == "benign_admin_noise":
        sim_records = [
            {
                "_id": f"SIM-BENIGN-{int(datetime.now().timestamp())}-1",
                "timestamp": now_iso,
                "source": "endpoint",
                "event_type": "antivirus_scan_clean",
                "host": "FIN-LT22",
                "user": "corporate_user",
                "detail": "Daily scheduled antivirus scan completed with zero threats identified.",
            },
            {
                "_id": f"SIM-BENIGN-{int(datetime.now().timestamp())}-2",
                "timestamp": now_iso,
                "source": "endpoint",
                "event_type": "process_execution",
                "host": "FIN-LT22",
                "process": "powershell.exe",
                "parent_process": "explorer.exe",
                "detail": "Interactive PowerShell session launched by known admin without suspicious parameters.",
            },
        ]
    elif scenario in ("historical_threats", "historical_ghoststeal_campaign"):
        hist_file = ROOT / "src" / "data" / "historical" / "historical_threats.json"
        if hist_file.exists():
            with hist_file.open(encoding="utf-8") as f:
                sim_records = [enrich_record(r, root=ROOT) for r in json.load(f)]
        else:
            sim_records = []
    elif scenario in ("recent_threats", "recent_ransomware_predeployment"):
        rec_file = ROOT / "src" / "data" / "recent" / "recent_threats.json"
        if rec_file.exists():
            with rec_file.open(encoding="utf-8") as f:
                sim_records = [enrich_record(r, root=ROOT) for r in json.load(f)]
        else:
            sim_records = []
    elif scenario in ("all_threats", "full_threat_corpus"):
        from src.threatfusion.db import ingest_corpus_data
        stats = ingest_corpus_data(include_historical=True, include_recent=True, root_dir=ROOT)
        clear_context_cache()
        analysis = get_dynamic_analysis()
        promoted = promoted_incidents(analysis)
        return {
            "status": "ok",
            "scenario": scenario,
            "inserted_records": stats["total_new_ingested"],
            "total_alerts": len(analysis["records"]),
            "promoted_incidents": len(promoted),
            "stats": stats,
        }
    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario preset: {scenario}")

    inserted = insert_alerts_bulk(sim_records)
    clear_context_cache()
    analysis = get_dynamic_analysis()
    promoted = promoted_incidents(analysis)
    return {
        "status": "ok",
        "scenario": scenario,
        "inserted_records": inserted,
        "total_alerts": len(analysis["records"]),
        "promoted_incidents": len(promoted),
    }


@app.post("/api/ingest/corpus")
def ingest_corpus(payload: dict | None = None) -> dict:
    """Ingest historical archive and/or recent multi-source threats into SQLite database."""
    mode = (payload or {}).get("mode", "all")
    from src.threatfusion.db import ingest_corpus_data
    include_hist = mode in ("all", "historical")
    include_rec = mode in ("all", "recent")
    stats = ingest_corpus_data(
        include_historical=include_hist,
        include_recent=include_rec,
        include_otrf=True,
        include_cicids=True,
        include_sparta_satellite=True,
        include_opensky=True,
        include_maritime_ais=True,
        include_satellite_eo=True,
        include_thermal_firms=True,
        include_weather_imd=True,
        include_bhuvan_geospatial=True,
        include_emergency_usgs=True,
        root_dir=ROOT,
    )
    clear_context_cache()
    analysis = get_dynamic_analysis()
    promoted = promoted_incidents(analysis)
    return {
        "status": "ok",
        "mode": mode,
        "stats": stats,
        "total_alerts": len(analysis["records"]),
        "candidate_clusters": len(analysis["incidents"]),
        "promoted_incidents": len(promoted),
    }



@app.get("/api/evaluation")
def evaluation() -> dict:
    analysis = get_dynamic_analysis()
    return {
        "engine_version": analysis["metadata"]["engine_version"],
        "attack_kb_version": analysis["metadata"]["attack_kb_version"],
        "candidate_clusters": len(analysis["incidents"]),
        "promoted_incidents": len(promoted_incidents(analysis)),
    }


@app.get("/api/multidomain/sectors")
def get_multidomain_sectors() -> dict:
    """Return strategic Indian defence and border sectors with operational sensor metadata."""
    from src.threatfusion.spatial import STRATEGIC_SECTORS
    analysis = get_dynamic_analysis()
    records = analysis.get("records", [])

    sector_counts: dict[str, int] = {}
    for r in records:
        sec = r.get("sector") or "CENTRAL_COMMAND_CORRIDOR"
        sector_counts[sec] = sector_counts.get(sec, 0) + 1

    sectors = []
    for sec_id, info in STRATEGIC_SECTORS.items():
        sectors.append({
            "sector_id": sec_id,
            "name": info["name"],
            "strategic_importance": info["strategic_importance"],
            "domain_focus": info["domain_focus"],
            "primary_sensors": info["primary_sensors"],
            "center": info["center"],
            "bounds": info["bounds"],
            "active_observations": sector_counts.get(sec_id, 0),
        })

    return {
        "status": "ok",
        "total_sectors": len(sectors),
        "sectors": sectors,
    }


@app.get("/api/multidomain/domain-stats")
def get_multidomain_stats() -> dict:
    """Return distribution of observations across air, maritime, satellite, thermal, weather, and cyber domains."""
    analysis = get_dynamic_analysis()
    records = analysis.get("records", [])
    stats: dict[str, int] = {}
    for r in records:
        d = r.get("domain") or ("cyber_c2" if r.get("source") in ("endpoint", "network_sensor", "siem", "threat_intel_report") else r.get("source", "other"))
        stats[d] = stats.get(d, 0) + 1

    return {
        "status": "ok",
        "total_records": len(records),
        "domain_breakdown": stats,
    }


@app.get("/api/multidomain/radar-feed")
def get_radar_feed(sector: str | None = Query(None), domain: str | None = Query(None)) -> dict:
    """Return geolocated observation entities for tactical radar and sector visualization."""
    analysis = get_dynamic_analysis()
    records = analysis.get("records", [])
    feed = []
    for r in records:
        lat = r.get("latitude")
        lon = r.get("longitude")
        sec = r.get("sector") or "CENTRAL_COMMAND_CORRIDOR"
        dom = r.get("domain") or ("cyber_c2" if r.get("source") in ("endpoint", "network_sensor", "siem", "threat_intel_report") else r.get("source", "other"))

        if sector and sec != sector:
            continue
        if domain and dom != domain:
            continue

        feed.append({
            "id": str(r.get("_id") or r.get("id")),
            "timestamp": r.get("timestamp"),
            "domain": dom,
            "source": r.get("source"),
            "event_type": r.get("event_type"),
            "host": r.get("host"),
            "entity": r.get("callsign") or r.get("vessel_name") or r.get("satellite_mission") or r.get("station_name") or r.get("host"),
            "latitude": lat,
            "longitude": lon,
            "sector": sec,
            "altitude_ft": r.get("altitude_ft"),
            "speed_knots": r.get("velocity_knots") or r.get("speed_knots"),
            "heading_deg": r.get("heading_deg"),
            "squawk": r.get("squawk"),
            "frp_mw": r.get("frp_mw"),
            "visibility_meters": r.get("visibility_meters"),
            "warning_level": r.get("warning_level"),
            "provenance": r.get("dataset_name", "Public Observation Feed"),
            "detail": r.get("detail") or r.get("text") or "Telemetry observation",
        })

    return {
        "status": "ok",
        "total_items": len(feed),
        "feed": feed,
    }


@app.post("/api/simulate-multidomain")
def simulate_multidomain(payload: dict) -> dict:
    """Inject multi-domain public data scenarios (OpenSky, AIS, Sentinel SAR, NASA FIRMS, IMD Weather)."""
    scenario = payload.get("scenario", "comprehensive_defence_fusion")
    from src.threatfusion.db import ingest_corpus_data

    if scenario == "airspace_border_incursion":
        stats = ingest_corpus_data(include_historical=False, include_recent=False, include_otrf=False, include_cicids=False, include_sparta_satellite=False, include_opensky=True, include_maritime_ais=False, include_satellite_eo=False, include_thermal_firms=False, include_weather_imd=False, include_bhuvan_geospatial=True, include_emergency_usgs=False, root_dir=ROOT)
    elif scenario == "maritime_dark_vessel_incursion":
        stats = ingest_corpus_data(include_historical=False, include_recent=False, include_otrf=False, include_cicids=False, include_sparta_satellite=False, include_opensky=False, include_maritime_ais=True, include_satellite_eo=True, include_thermal_firms=False, include_weather_imd=True, include_bhuvan_geospatial=True, include_emergency_usgs=False, root_dir=ROOT)
    elif scenario == "sentinel_sar_infrastructure_change":
        stats = ingest_corpus_data(include_historical=False, include_recent=False, include_otrf=False, include_cicids=False, include_sparta_satellite=False, include_opensky=False, include_maritime_ais=False, include_satellite_eo=True, include_thermal_firms=True, include_weather_imd=True, include_bhuvan_geospatial=True, include_emergency_usgs=False, root_dir=ROOT)
    elif scenario == "firms_thermal_critical_infra":
        stats = ingest_corpus_data(include_historical=False, include_recent=False, include_otrf=False, include_cicids=False, include_sparta_satellite=False, include_opensky=False, include_maritime_ais=False, include_satellite_eo=False, include_thermal_firms=True, include_weather_imd=False, include_bhuvan_geospatial=True, include_emergency_usgs=False, root_dir=ROOT)
    elif scenario == "imd_densefog_coordinated_approach":
        stats = ingest_corpus_data(include_historical=False, include_recent=False, include_otrf=False, include_cicids=False, include_sparta_satellite=False, include_opensky=True, include_maritime_ais=False, include_satellite_eo=True, include_thermal_firms=False, include_weather_imd=True, include_bhuvan_geospatial=True, include_emergency_usgs=False, root_dir=ROOT)
    elif scenario in ("comprehensive_defence_fusion", "all_multidomain"):
        stats = ingest_corpus_data(include_historical=True, include_recent=True, include_otrf=True, include_cicids=True, include_sparta_satellite=True, include_opensky=True, include_maritime_ais=True, include_satellite_eo=True, include_thermal_firms=True, include_weather_imd=True, include_bhuvan_geospatial=True, include_emergency_usgs=True, root_dir=ROOT)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown multi-domain scenario: {scenario}")

    clear_context_cache()
    analysis = get_dynamic_analysis()
    promoted = promoted_incidents(analysis)
    return {
        "status": "ok",
        "scenario": scenario,
        "stats": stats,
        "total_alerts": len(analysis["records"]),
        "candidate_clusters": len(analysis["incidents"]),
        "promoted_incidents": len(promoted),
    }


@app.get("/api/mcp-query")
def mcp_query(tool: str = Query(...), incident_id: str | None = Query(None), query: str | None = Query(None), sector: str | None = Query(None), domain: str | None = Query(None)) -> dict:
    from src.mcp_server import tool_call

    arguments: dict[str, str] = {}
    if incident_id:
        arguments["incident_id"] = incident_id
    if query:
        arguments["query"] = query
    if sector:
        arguments["sector"] = sector
    if domain:
        arguments["domain"] = domain
    res = tool_call(tool, arguments)
    return res or {"error": f"Tool {tool} returned no output"}


@app.post("/api/bob/ask")
def ask_bob(payload: dict) -> dict:
    """Natural-language investigation and military situational briefing endpoint for IBM Bob.
    
    Accepts candidate/incident ID and command/question, evaluates deterministic facts via MCP,
    and returns a structured, factual analysis strictly grounded in ThreatFusion engine facts.
    """
    import html
    from src.mcp_server import execute_tool, load_engine_state, find_candidate

    incident_id = payload.get("incident_id") or ""
    raw_cmd = (payload.get("command") or payload.get("prompt") or "investigate").strip()
    cmd = raw_cmd.lower().lstrip("/")

    analysis, all_candidates = load_engine_state()
    target = find_candidate(incident_id, all_candidates) if incident_id else (all_candidates[0] if all_candidates else None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Candidate or incident '{incident_id}' not found")

    target_id = target["id"]
    is_promoted = bool(target.get("promotable"))
    prio = target.get("priority", "UNKNOWN")
    score = target.get("priority_score", 0)
    conf = target.get("confidence", 0)
    sev = target.get("severity", 0)
    imp = target.get("mission_impact", 0)
    urg = target.get("urgency", 0)
    checks = target.get("promotion_checks", {})
    assets = [a.get("asset") for a in target.get("assets", [])]
    techs = [f"{t.get('technique')} ({t.get('technique_name')})" for t in target.get("techniques", [])]

    # Defence / Multi-Domain Situational Briefings
    if cmd in ("defence", "military", "situational", "border", "corridor"):
        domain_summary = execute_tool("get_domain_summary", {})
        bluf_pkg = execute_tool("generate_bluf", {"incident_id": target_id})
        b = bluf_pkg.get("bluf", {})
        counts = domain_summary.get("domain_counts", {})
        response_md = f"""# 🇮🇳 IBM Bob National Defence Situational Awareness Brief — {target_id}

> **Executive Commander Assessment**: {b.get('commander_briefing') or b.get('bottom_line', 'Multi-source border and domain correlation active.')}

## 1. Multi-Domain Telemetry Summary
- **✈️ Airspace Domain (OpenSky Network)**: `{counts.get('airspace', 0)} active flight tracks & transponder checks`
- **🚢 Maritime Domain (NOAA / AIS)**: `{counts.get('maritime', 0)} monitored vessels & EEZ traffic`
- **🛰️ Satellite EO (Copernicus Sentinel-1 SAR / Sentinel-2 Optical / MOSDAC)**: `{counts.get('satellite_eo', 0)} radar & optical change scenes`
- **🔥 Thermal IR (NASA FIRMS MODIS/VIIRS)**: `{counts.get('thermal_ir', 0)} active thermal hotspots`
- **🌦️ Meteorological (IMD AWS & Radar)**: `{counts.get('weather_env', 0)} atmospheric & sea-state bulletins`
- **🇮🇳 Strategic Infrastructure (ISRO Bhuvan / OGD)**: `{counts.get('geospatial_infra', 0)} forward airfields & radar posts mapped`
- **💻 Cyber & Space (SPARTA / OTRF / CIC-IDS)**: `{counts.get('cyber_c2', 0)} C2/ground station alerts`

## 2. Strategic Risk & Mission Criticality
- **Threat Priority**: **{prio}** (`{score}/100`)
- **Evidence Confidence**: `{conf}%` · **Severity**: `{sev}/100` · **Mission Impact**: `{imp}/100` · **Urgency**: `{urg}/100`
- **Affected Strategic Assets**: {', '.join(assets) if assets else 'Border defense infrastructure'}

## 3. Grounded Correlation Rationale
{b.get('assessment')}

## 4. Uncertainty & Public-Data Sensor Limits
- {b.get('uncertainty', 'Telemetry is derived from open civil feeds (OpenSky, Copernicus, NOAA, IMD, NASA FIRMS). Authorized military radar and restricted feeds are intentionally not assumed.')}

## 5. Recommended Commander Actions
{chr(10).join([f"{i+1}. {a}" for i, a in enumerate(b.get('recommended_actions', []))])}
"""
    elif cmd in ("airspace", "opensky", "flight", "aviation"):
        response_md = f"""# ✈️ IBM Bob Airspace Domain Briefing — {target_id}

> **Sensor Provenance**: OpenSky Network Civil ADS-B & Transponder Feeds

## Observed Airspace Telemetry for {target_id}
- **Assessed Priority**: **{prio}** (`{score}/100`)
- **Evidence Confidence**: `{conf}%`
- **Associated Assets / Waypoints**: {', '.join(assets) if assets else 'Northern/Western Air Corridor'}

## Airspace Findings
- Multi-source track verification with border corridor geofencing.
- Unannounced altitude deviations or squawk anomalies (e.g. 7700 / intermittent ADS-B) are cross-correlated with weather and ground radar.
- **Rule**: Civil air-traffic data provides flight-path telemetry; absence of a transponder is flagged as a detection gap.

## Next Action
{target.get('runbook', [{}])[0].get('action', 'Verify transponder log against scheduled civil flight clearance.')}
"""
    elif cmd in ("maritime", "ais", "vessel", "navy"):
        response_md = f"""# 🚢 IBM Bob Maritime Domain & Dark Vessel Briefing — {target_id}

> **Sensor Provenance**: NOAA MarineCadastre AIS & Coastal Vessel Feeds

## Maritime Telemetry & EEZ Status for {target_id}
- **Assessed Priority**: **{prio}** (`{score}/100`)
- **Evidence Confidence**: `{conf}%`
- **Target Coastal / EEZ Corridor**: {', '.join(assets) if assets else 'Sir Creek / Andaman & Nicobar Waters'}

## Maritime Findings
- Vessel movement vectors analyzed for loitering, unusual heading changes, and AIS transponder gaps.
- Dark vessel signatures are cross-referenced with satellite microwave scatterometry (ISRO MOSDAC / Sentinel-1 SAR) to detect physical hull presence.

## Recommended Maritime Next Steps
1. Task coastal patrol craft or naval reconnaissance for visual confirmation.
2. Cross-check vessel MMSI/IMO against registered hydrographic survey manifests.
"""
    elif cmd in ("satellite", "sentinel", "sar", "optical", "isro", "mosdac"):
        response_md = f"""# 🛰️ IBM Bob Earth Observation & Satellite Briefing — {target_id}

> **Sensor Provenance**: Copernicus Sentinel-1 SAR, Sentinel-2 Optical & ISRO MOSDAC

## Earth Observation Telemetry for {target_id}
- **Sentinel-1 C-Band SAR**: Synthetic Aperture Radar provides all-weather day/night ground surface coherence analysis through cloud cover.
- **Sentinel-2 Optical**: Multispectral optical comparison identifies structural changes under clear weather windows.
- **ISRO MOSDAC**: Microwave scatterometer scans provide ocean surface roughness and wake detection.

## Grounded Assessment
{target.get('bluf', {}).get('assessment', 'Satellite change detection correlates with ground infrastructure observations.')}
"""
    elif cmd in ("thermal", "firms", "fire", "heat"):
        response_md = f"""# 🔥 IBM Bob Thermal Infrared Anomaly Briefing — {target_id}

> **Sensor Provenance**: NASA FIRMS Near-Real-Time Active Fire Telemetry (MODIS & VIIRS)

## Thermal Hotspot Analysis for {target_id}
- **Sensor Feeds**: MODIS (Terra/Aqua) and VIIRS (Suomi-NPP / NOAA-20) NRT passes.
- **Assessed FRP / Brightness**: High-temperature infrared signatures evaluated against known civilian brushfire baselines versus strategic installation coordinates.
- **Correlation**: Spatially tagged to within 5km of critical forward corridors.
"""
    elif cmd in ("weather", "imd", "fog", "cyclone"):
        response_md = f"""# 🌦️ IBM Bob Meteorological & Environmental Briefing — {target_id}

> **Sensor Provenance**: India Meteorological Department (IMD) AWS & Doppler Radar

## Operational Weather Impact for {target_id}
- **Visibility & Cloud Cover**: Evaluates optical degradation (dense fog, monsoonal cloud cover) requiring SAR radar prioritization.
- **Sea State & Coastal Bulletins**: Rough sea advisories and squall lines analyzed for tactical concealment opportunities.
"""
    elif cmd in ("investigate", "full", "case"):
        incident_pkg = execute_tool("get_incident", {"incident_id": target_id})
        risk_pkg = execute_tool("explain_risk", {"incident_id": target_id})
        gaps_pkg = execute_tool("get_detection_gaps", {"incident_id": target_id})
        bluf_pkg = execute_tool("generate_bluf", {"incident_id": target_id})
        actor_matches = target.get("actor_similarity", [])
        top_actor = actor_matches[0] if isinstance(actor_matches, list) and actor_matches else None
        actor_name = top_actor.get("group", "Unattributed Cluster") if top_actor else "Unattributed Cluster"
        actor_score = top_actor.get("similarity", 0) if top_actor else 0

        response_md = f"""# IBM Bob Investigation Report — {target_id}

> **BLUF**: {bluf_pkg.get('bluf', {}).get('commander_briefing', 'Active correlated threat requiring command review.')}

## 1. Case Status & Operational Assessment
- **Status**: `{'PROMOTED INCIDENT' if is_promoted else 'CANDIDATE HYPOTHESIS (NOT PROMOTED)'}`
- **Priority**: **{prio}** (Score: `{score}/100`)
- **Evidence Confidence**: `{conf}%` · **Severity**: `{sev}/100` · **Mission Impact**: `{imp}/100` · **Urgency**: `{urg}/100`
- **Affected Assets**: {', '.join(assets) if assets else 'Corporate workstation network'}

## 2. Observed Attack Progression & MITRE ATT&CK Mapping
{chr(10).join([f"- **`{t.get('technique')}`** ({t.get('tactic')}) — {t.get('technique_name')}" for t in target.get('techniques', [])]) if target.get('techniques') else '- No specific ATT&CK behaviors detected.'}

- **Attack-Flow Coherence**: `{round(target.get('attack_flow', {}).get('score', 0) * 100, 1)}/100`
- **Telemetry Sources**: {', '.join([s.replace('_', ' ').upper() for s in target.get('sources', [])])} ({len(target.get('record_ids', []))} raw observations)

## 3. Threat Attribution & CTI Corroboration
- **ThreatFox IOC Match**: {'✓ Verified CTI match' if target.get('has_threatfox_corroboration') else 'No known malware IOC match'}
- **CISA KEV Exploitation**: {'⚠️ Known exploited CVE confirmed' if target.get('has_cisa_kev_exploit') else 'No active KEV vulnerability match'}
- **Associated Actor Cluster**: `{actor_name}` (Similarity: `{actor_score}%`)

## 4. Detection Gaps & Visibility Notes
{chr(10).join([f"- ⚠️ **Missing {gap.get('tactic')} Telemetry**: Unobserved intermediate tactic — {gap.get('hunting_guidance')}" for gap in gaps_pkg.get('telemetry_gaps', [])[:2]]) if gaps_pkg.get('telemetry_gaps') else '- No major visibility blindspots identified.'}

## 5. Recommended Next Actions
{chr(10).join([f"{i+1}. **[{step.get('phase')}]** {step.get('action')} (Target: `{step.get('target')}`)" for i, step in enumerate(target.get('runbook', [])[:3])])}
"""
    elif cmd in ("explain", "risk"):
        risk_pkg = execute_tool("explain_risk", {"incident_id": target_id})
        rf = risk_pkg.get("risk_factors", {})
        response_md = f"""# IBM Bob Risk Assessment & Prioritization Rationale — {target_id}

> **Executive Synthesis**: This case is assessed at **{prio}** priority with **{conf}%** evidence confidence and **{imp}/100** mission impact.

## 4D Risk Factor Breakdown
1. **Evidence Confidence ({conf}%)**: {rf.get('confidence_explanation', 'High corroboration across independent sensors.')}
2. **Threat Severity ({sev}/100)**: Harm potential assessed from observed techniques ({', '.join(techs[:2])}).
3. **Mission Impact ({imp}/100)**: Criticality of affected assets ({', '.join(assets) if assets else 'standard endpoints'}).
4. **Decision Urgency ({urg}/100)**: Immediate analyst attention is recommended based on killchain progress.

## Promotion Gate Decision
- **Promotion Status**: `{'PROMOTED INCIDENT (Passed 4/4 Checks)' if is_promoted else 'QUARANTINED AS CANDIDATE (Failed Checks)'}`
- **Gate Audit**:
{chr(10).join([f"  - {'✓' if passed else '✗'} **{k.replace('_', ' ').title()}**: {'Satisfied' if passed else 'Failed gate threshold'}" for k, passed in checks.items()])}
"""
    elif cmd in ("bluf", "brief"):
        bluf_pkg = execute_tool("generate_bluf", {"incident_id": target_id})
        b = bluf_pkg.get("bluf", {})
        response_md = f"""# Commander Decision Briefing (BLUF) — {target_id}

> **BOTTOM LINE UP FRONT**: {b.get('commander_briefing') or b.get('bottom_line')}

## Operational Assessment
{b.get('assessment')}

## Adversary Attribution & TTPs
{b.get('actor_assessment')}

## Uncertainty & Visibility Limits
{b.get('uncertainty')}

## Recommended Commander Actions
{chr(10).join([f"{i+1}. {a}" for i, a in enumerate(b.get('recommended_actions', []))])}
"""
    elif cmd in ("runbook", "containment", "response"):
        runbook_pkg = execute_tool("get_remediation_runbook", {"incident_id": target_id})
        steps = runbook_pkg.get("remediation_steps", [])
        response_md = f"""# Human-Gated Containment & Remediation Runbook — {target_id}

> **Policy Notice**: ThreatFusion provides analyst-gated recommendations. All containment actions require explicit human confirmation.

## Staged Action Checklist
{chr(10).join([f"### Step {i+1}: [{s.get('phase')}] {s.get('action')}\n- **Target**: `{s.get('target')}`\n- **Rationale**: {s.get('rationale')}\n- **Verification**: {s.get('verification')}" for i, s in enumerate(steps)])}
"""
    elif cmd in ("gaps", "detection", "hunting"):
        gaps_pkg = execute_tool("get_detection_gaps", {"incident_id": target_id})
        gaps = gaps_pkg.get("telemetry_gaps", [])
        response_md = f"""# Detection Blindspots & Threat Hunting Guidance — {target_id}

> **Principle**: An unobserved killchain tactic indicates potential telemetry gaps rather than proof of attacker absence.

## Identified Visibility Blindspots
{chr(10).join([f"- **{g.get('tactic').title()} Blindspot**: {g.get('explanation')}\n  - *Hunting Query Guidance*: `{g.get('hunting_guidance')}`" for g in gaps]) if gaps else '- No significant detection blindspots detected in this evidence chain.'}
"""
    else:
        response_md = f"""# IBM Bob Response — {target_id}

Regarding your inquiry: *"**{html.escape(raw_cmd)}**"*

## Grounded Analysis for {target_id}
- **Assessed Priority**: **{prio}** (`{score}/100`)
- **Evidence Confidence**: `{conf}%` across {len(target.get('record_ids', []))} independent observations.
- **Affected Assets**: {', '.join(assets) if assets else 'Corporate workstations'} (Mission Criticality: `{imp}/100`)
- **Observed Behavior**: {', '.join(techs) if techs else 'No explicit techniques.'}

## Key Finding
{target.get('bluf', {}).get('assessment', 'Case telemetry indicates structured activity requiring human triage.')}

## Recommended Next Step
{target.get('runbook', [{}])[0].get('action', 'Inspect full evidence timeline in the workspace.')}
"""

    return {
        "status": "ok",
        "incident_id": target_id,
        "command": cmd,
        "response": response_md,
        "tools_used": ["get_incident", "explain_risk", "generate_bluf", "get_domain_summary"],
    }
