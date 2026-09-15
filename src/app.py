"""ThreatFusion analyst workspace and read-only API.

The UI deliberately presents a case review workflow instead of an alert-counting
dashboard: understand the case, inspect evidence, decide on next actions, and
hand the grounded facts to IBM Bob when narrative assistance is useful.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from src.threatfusion.engine import ENGINE_VERSION, analyze, bluf, promoted_incidents, remediation_runbook

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="ThreatFusion - Analyst Workspace", version=ENGINE_VERSION)

INDEX = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#1c3129">
  <title>ThreatFusion - Analyst Workspace</title>
  <style>
    :root { --canvas:#f5f1e8; --paper:#fffdf8; --ink:#17251e; --muted:#617068; --faint:#8b978f; --line:#d5dcd4; --soft:#e8eee7; --moss:#1f624d; --moss-dark:#174837; --moss-pale:#dcece3; --amber:#9b6614; --amber-pale:#f6e7c7; --rose:#963e36; --rose-pale:#f5dfdc; --navy:#1c3129; --navy-soft:#2d4940; --shadow:0 14px 34px rgba(23,37,30,.08); }
    * { box-sizing:border-box; }
    html { scroll-behavior:smooth; }
    body { margin:0; background:var(--canvas); color:var(--ink); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; font-size:15px; line-height:1.5; }
    button,input { font:inherit; }
    button { cursor:pointer; }
    button:focus-visible,a:focus-visible { outline:3px solid #136b98; outline-offset:3px; }
    .skip-link { position:fixed; left:16px; top:-80px; z-index:100; padding:10px 14px; border-radius:8px; background:var(--paper); color:var(--ink); }
    .skip-link:focus { top:16px; }
    .shell { min-height:100vh; }
    .topbar { min-height:72px; padding:14px clamp(20px,4vw,64px); display:flex; align-items:center; justify-content:space-between; gap:18px; background:var(--navy); color:#f7f6f1; border-bottom:1px solid rgba(255,255,255,.12); }
    .brand { display:flex; align-items:center; gap:13px; }
    .brand-mark { width:38px; height:38px; display:grid; place-items:center; border-radius:10px; color:var(--navy); background:#dfeee6; font-family:Georgia,serif; font-size:22px; font-weight:700; }
    .brand-name { font-size:20px; font-weight:750; letter-spacing:-.02em; }
    .brand-subtitle { color:#b9c9c0; font-size:12px; }
    .topbar-meta { color:#c8d6cf; font-size:12px; text-align:right; }
    .topbar-meta strong { color:#f6e0aa; font-weight:700; }
    .layout { display:grid; grid-template-columns:minmax(240px,300px) minmax(0,1fr); max-width:1600px; margin:0 auto; min-height:calc(100vh - 72px); }
    .case-rail { padding:30px 20px; border-right:1px solid var(--line); }
    .eyebrow { margin:0 0 8px; color:var(--moss); font-size:11px; font-weight:800; letter-spacing:.1em; text-transform:uppercase; }
    h1,h2,h3,p { margin-top:0; }
    .rail-title { font-family:Georgia,"Times New Roman",serif; font-size:26px; line-height:1.1; margin-bottom:10px; }
    .rail-copy { color:var(--muted); font-size:13px; margin-bottom:22px; }
    .case-list { display:grid; gap:10px; }
    .case-item { width:100%; min-height:104px; padding:15px; text-align:left; border:1px solid var(--line); border-radius:12px; color:var(--ink); background:transparent; transition:.16s ease; }
    .case-item:hover { background:var(--paper); border-color:#a9bbb0; }
    .case-item[aria-current="true"] { background:var(--paper); border-color:var(--moss); box-shadow:0 7px 18px rgba(31,98,77,.12); }
    .case-row { display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .case-id { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; font-weight:700; }
    .priority { display:inline-flex; align-items:center; justify-content:center; min-width:34px; min-height:24px; padding:2px 7px; border-radius:999px; font-size:11px; font-weight:800; }
    .priority.p1 { color:#7a251e; background:var(--rose-pale); }
    .priority.p2 { color:#704700; background:var(--amber-pale); }
    .case-desc { display:block; margin-top:9px; color:var(--muted); font-size:12px; }
    .case-foot { display:flex; gap:10px; margin-top:8px; color:var(--faint); font-size:11px; }
    .rail-note { margin-top:24px; padding-top:19px; border-top:1px solid var(--line); color:var(--muted); font-size:12px; }
    .rail-note strong { color:var(--ink); }
    main { min-width:0; padding:clamp(22px,4vw,54px); }
    .case-header { display:flex; align-items:flex-start; justify-content:space-between; gap:22px; padding-bottom:24px; border-bottom:1px solid var(--line); }
    .case-title { font-family:Georgia,"Times New Roman",serif; font-size:clamp(30px,4vw,48px); letter-spacing:-.035em; line-height:1.02; margin-bottom:9px; }
    .case-summary { max-width:720px; color:var(--muted); font-size:16px; }
    .case-signal { min-width:168px; padding:14px 16px; border-radius:12px; background:var(--moss-pale); color:var(--moss-dark); }
    .case-signal span { display:block; font-size:11px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; }
    .case-signal strong { display:block; margin-top:3px; font-size:18px; }
    .tabbar { display:flex; gap:4px; overflow-x:auto; padding:17px 0; border-bottom:1px solid var(--line); }
    .tab { min-height:44px; padding:9px 13px; border:0; border-radius:8px; background:transparent; color:var(--muted); white-space:nowrap; font-size:13px; font-weight:700; }
    .tab:hover { background:var(--soft); color:var(--ink); }
    .tab[aria-selected="true"] { background:var(--navy); color:#fffdf8; }
    .panel { display:none; padding-top:26px; }
    .panel.active { display:block; }
    .split { display:grid; grid-template-columns:minmax(0,1.35fr) minmax(300px,.85fr); gap:22px; }
    .stack { display:grid; gap:22px; }
    .card { padding:23px; border:1px solid var(--line); border-radius:14px; background:var(--paper); box-shadow:var(--shadow); }
    .card h2 { font-family:Georgia,"Times New Roman",serif; font-size:25px; letter-spacing:-.02em; margin-bottom:7px; }
    .card h3 { font-size:14px; margin-bottom:7px; }
    .muted { color:var(--muted); }
    .decision-card { border-left:5px solid var(--moss); }
    .decision-copy { font-size:18px; line-height:1.55; }
    .metric-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
    .metric { padding:14px; background:#f7f8f4; border:1px solid #e1e6df; border-radius:10px; }
    .metric-label { display:block; color:var(--muted); font-size:11px; font-weight:800; letter-spacing:.06em; text-transform:uppercase; }
    .metric-value { display:block; margin-top:5px; font-family:Georgia,serif; font-size:29px; line-height:1; }
    .metric-note { display:block; margin-top:6px; color:var(--faint); font-size:11px; }
    .check-list,.action-list,.plain-list { margin:0; padding:0; list-style:none; }
    .check-list { display:grid; gap:10px; }
    .check-list li { display:flex; align-items:flex-start; gap:10px; color:var(--ink); }
    .check-mark { flex:0 0 20px; height:20px; display:grid; place-items:center; margin-top:1px; border-radius:50%; background:var(--moss-pale); color:var(--moss-dark); font-weight:900; font-size:12px; }
    .check-mark.fail { background:var(--rose-pale); color:var(--rose); }
    .check-detail { color:var(--muted); font-size:13px; }
    .timeline { position:relative; display:grid; gap:0; }
    .timeline-item { position:relative; display:grid; grid-template-columns:78px minmax(0,1fr); gap:16px; padding:0 0 20px; }
    .timeline-item::before { content:""; position:absolute; top:22px; bottom:-1px; left:79px; width:1px; background:var(--line); }
    .timeline-item:last-child::before { display:none; }
    .time { color:var(--moss); font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; font-weight:700; padding-top:3px; }
    .evidence { position:relative; min-width:0; padding:12px 14px; border:1px solid var(--line); border-radius:10px; background:#fbfcf9; }
    .evidence::before { content:""; position:absolute; top:17px; left:-7px; width:12px; height:12px; border:3px solid var(--moss); border-radius:50%; background:var(--canvas); }
    .evidence-head { display:flex; align-items:flex-start; justify-content:space-between; gap:10px; }
    .evidence-title { font-weight:750; }
    .source { color:var(--muted); font-size:11px; text-transform:capitalize; }
    .technique { margin-top:6px; color:var(--moss-dark); font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; }
    .evidence-reason { margin:5px 0 0; color:var(--muted); font-size:12px; }
    .filters { display:flex; flex-wrap:wrap; gap:7px; margin:0 0 17px; }
    .filter { min-height:36px; padding:6px 10px; border:1px solid var(--line); border-radius:999px; color:var(--muted); background:var(--paper); font-size:12px; font-weight:700; }
    .filter[aria-pressed="true"] { background:var(--moss); border-color:var(--moss); color:white; }
    .brief-section { padding:16px 0; border-bottom:1px solid var(--line); }
    .brief-section:last-of-type { border-bottom:0; }
    .brief-label { margin-bottom:4px; color:var(--moss); font-size:11px; font-weight:800; letter-spacing:.09em; text-transform:uppercase; }
    .action-list { display:grid; gap:11px; }
    .action-item { padding:13px; border-left:3px solid var(--amber); background:#fbf7ef; }
    .action-item strong { display:block; font-size:13px; }
    .action-item span { display:block; margin-top:3px; color:var(--muted); font-size:12px; }
    .btn-row { display:flex; flex-wrap:wrap; gap:9px; margin-top:18px; }
    .button { min-height:44px; padding:10px 14px; border:1px solid var(--navy); border-radius:8px; color:white; background:var(--navy); font-size:13px; font-weight:750; }
    .button:hover { background:var(--navy-soft); }
    .button.secondary { color:var(--navy); background:transparent; }
    .button.secondary:hover { background:var(--soft); }
    .compare { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-top:18px; }
    .compare-step { min-height:156px; padding:17px; border:1px solid var(--line); border-radius:10px; background:#f9faf7; }
    .compare-number { display:block; margin-bottom:9px; color:var(--moss); font-family:Georgia,serif; font-size:42px; line-height:.9; }
    .compare-step strong { display:block; margin-bottom:5px; }
    .compare-step p { margin:0; color:var(--muted); font-size:12px; }
    .mcp-command { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:13px; border:1px solid var(--line); border-radius:9px; background:#f7f8f4; }
    .mcp-command code { overflow-wrap:anywhere; color:var(--moss-dark); font-size:13px; }
    .tool-output { min-height:150px; max-height:410px; overflow:auto; margin-top:16px; padding:14px; border-radius:10px; background:#17251e; color:#e4f0e8; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; line-height:1.55; white-space:pre-wrap; }
    .notice { padding:14px; border-radius:10px; background:var(--amber-pale); color:#6f490e; font-size:13px; }
    .status { min-height:20px; margin:16px 0 0; color:var(--moss-dark); font-size:13px; }
    .empty { padding:28px; color:var(--muted); text-align:center; }
    @media (max-width:980px) { .layout { grid-template-columns:1fr; } .case-rail { border-right:0; border-bottom:1px solid var(--line); } .case-list { grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); } .rail-note { display:none; } .split { grid-template-columns:1fr; } }
    @media (max-width:620px) { .topbar { align-items:flex-start; flex-direction:column; } .topbar-meta { text-align:left; } main { padding:24px 16px 42px; } .case-rail { padding:24px 16px; } .case-header { flex-direction:column; } .case-signal { width:100%; } .metric-grid,.compare { grid-template-columns:1fr; } .timeline-item { grid-template-columns:1fr; gap:6px; } .timeline-item::before { left:5px; top:26px; } .evidence { margin-left:16px; } .time { padding-left:22px; } }
  </style>
</head>
<body>
  <a class="skip-link" href="#workspace">Skip to investigation workspace</a>
  <div class="shell">
    <header class="topbar"><div class="brand"><div class="brand-mark" aria-hidden="true">T</div><div><div class="brand-name">ThreatFusion</div><div class="brand-subtitle">Evidence-first investigation workspace</div></div></div><div class="topbar-meta"><strong>Synthetic case study</strong><br>Grounded analysis · local IBM Bob MCP</div></header>
    <div class="layout">
      <aside class="case-rail" aria-label="Incident queue"><p class="eyebrow">Investigation queue</p><h1 class="rail-title">Cases that earned review</h1><p class="rail-copy">Candidates stay out of this list until available evidence meets the promotion boundary.</p><div id="case-list" class="case-list" aria-live="polite"><div class="empty">Loading cases…</div></div><div class="rail-note"><strong>What this workspace does:</strong><br>It distinguishes facts, confidence, uncertainty, and actions. It does not claim production accuracy or actor attribution.</div></aside>
      <main id="workspace">
        <div class="case-header"><div><p class="eyebrow">Active investigation</p><h1 id="case-title" class="case-title">Loading the case…</h1><p id="case-summary" class="case-summary">Preparing the evidence narrative.</p></div><div class="case-signal"><span>Current priority</span><strong id="case-priority">—</strong></div></div>
        <nav class="tabbar" role="tablist" aria-label="Case workspace views"><button class="tab" id="tab-overview" role="tab" aria-controls="panel-overview" aria-selected="true" data-tab="overview">Case overview</button><button class="tab" id="tab-evidence" role="tab" aria-controls="panel-evidence" aria-selected="false" data-tab="evidence">Evidence sequence</button><button class="tab" id="tab-response" role="tab" aria-controls="panel-response" aria-selected="false" data-tab="response">Commander brief</button><button class="tab" id="tab-compare" role="tab" aria-controls="panel-compare" aria-selected="false" data-tab="compare">Why this case</button><button class="tab" id="tab-bob" role="tab" aria-controls="panel-bob" aria-selected="false" data-tab="bob">IBM Bob handoff</button></nav>
        <div id="status" class="status" aria-live="polite"></div>
        <section id="panel-overview" class="panel active" role="tabpanel" aria-labelledby="tab-overview"><div class="split"><div class="stack"><article class="card decision-card"><p class="eyebrow">Decision in plain language</p><h2>Why this needs attention</h2><p id="decision-copy" class="decision-copy">Loading…</p></article><article class="card"><p class="eyebrow">Evidence path</p><h2>What happened</h2><p class="muted">A time-ordered chain across independent sources. Select the evidence-sequence view for full provenance.</p><div id="overview-timeline" class="timeline"></div></article></div><div class="stack"><article class="card"><p class="eyebrow">Risk dimensions</p><h2>Four separate questions</h2><div id="metric-grid" class="metric-grid"></div></article><article class="card"><p class="eyebrow">Promotion boundary</p><h2>Why this became a case</h2><ul id="promotion-checks" class="check-list"></ul></article><article class="card"><p class="eyebrow">Assets and uncertainty</p><h2>Context to preserve</h2><div id="asset-context" class="muted"></div><div id="uncertainty-context" class="notice" style="margin-top:16px;"></div></article></div></div></section>
        <section id="panel-evidence" class="panel" role="tabpanel" aria-labelledby="tab-evidence"><article class="card"><p class="eyebrow">Grounded chronology</p><h2>Evidence sequence</h2><p class="muted">Every inference points back to a source record. Filter the timeline without changing the underlying case.</p><div id="source-filters" class="filters" aria-label="Filter evidence by source"></div><div id="full-timeline" class="timeline"></div></article></section>
        <section id="panel-response" class="panel" role="tabpanel" aria-labelledby="tab-response"><div class="split"><article class="card"><p class="eyebrow">Commander brief</p><h2>Bottom line up front</h2><div id="brief-content"></div><div class="btn-row"><button id="copy-brief" class="button">Copy brief</button><button id="export-brief" class="button secondary">Export Markdown</button></div></article><article class="card"><p class="eyebrow">Recommended response</p><h2>Actions, not automation</h2><p class="muted">The prototype recommends analyst-reviewed response steps. It never contains systems autonomously.</p><ol id="response-actions" class="action-list"></ol></article></div></section>
        <section id="panel-compare" class="panel" role="tabpanel" aria-labelledby="tab-compare"><article class="card"><p class="eyebrow">Method check</p><h2>From alerts to a defensible case</h2><p class="muted">The bundled benchmark is a reproducible synthetic demonstration, not a generalized effectiveness claim.</p><div class="compare"><div class="compare-step"><span class="compare-number">37</span><strong>Raw observations</strong><p>Four source schemas arrive with different context and reliability.</p></div><div class="compare-step"><span class="compare-number">2</span><strong>Candidate hypotheses</strong><p>Weighted entity and time links create possibilities, not incidents.</p></div><div class="compare-step"><span class="compare-number">1</span><strong>Promoted case</strong><p>Behavior, corroboration, confidence, and independence must agree.</p></div></div></article><div class="split" style="margin-top:22px;"><article class="card"><p class="eyebrow">Naive approach</p><h2>What it gets wrong</h2><ul class="plain-list"><li>• Treats shared entities as proof.</li><li>• Uses fixed time windows alone.</li><li>• Hides contradictory or missing evidence.</li><li>• Can promote routine activity.</li></ul></article><article class="card"><p class="eyebrow">ThreatFusion boundary</p><h2>What changes</h2><ul class="plain-list"><li>• Checks observable ATT&amp;CK behavior.</li><li>• Scores confidence separately from impact.</li><li>• Keeps telemetry gaps explicit.</li><li>• Holds ambiguous clusters below promotion.</li></ul></article></div></section>
        <section id="panel-bob" class="panel" role="tabpanel" aria-labelledby="tab-bob"><div class="split"><article class="card"><p class="eyebrow">Grounded handoff</p><h2>Ask IBM Bob with the case in view</h2><p class="muted">Bob retrieves evidence from the local, read-only MCP server. It explains the deterministic result; it does not manufacture a score or attribution.</p><div id="bob-commands" class="stack"></div></article><article class="card"><p class="eyebrow">Tool preview</p><h2>Inspect the same facts</h2><p class="muted">This preview calls the same implementation exposed over MCP, so the dashboard and Bob remain consistent.</p><div id="mcp-tools" class="btn-row"></div><pre id="tool-output" class="tool-output">Choose a tool to inspect its grounded output.</pre></article></div></section>
      </main>
    </div>
  </div>
  <script>
    let summary = null;
    let selected = null;
    let activeSource = 'all';
    const SOURCE_LABELS = {siem:'SIEM',endpoint:'Endpoint',network_sensor:'Network sensor',threat_intel_report:'Threat intelligence'};
    const CHECK_LABELS = {
      minimum_behavior_evidence:['Multiple behavior observations','At least two ATT&CK-backed behavior observations were found.'],
      multi_tactic_progression:['Coherent tactic progression','The case crosses multiple tactics with sufficient attack-flow coherence.'],
      evidence_confidence:['Sufficient evidence confidence','Evidence quality and corroboration cleared the promotion threshold.'],
      source_independence:['Independent source support','The story is supported across sufficiently independent telemetry sources.']
    };
    function esc(value) { return String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character])); }
    function sourceLabel(source) { return SOURCE_LABELS[source] || source.replaceAll('_',' '); }
    function timeLabel(timestamp) { return timestamp ? timestamp.slice(11,16) + ' UTC' : 'Unknown time'; }
    function setStatus(message,isError=false) { const el=document.getElementById('status'); el.textContent=message; el.style.color=isError?'var(--rose)':'var(--moss-dark)'; }
    function switchTab(next) { document.querySelectorAll('[role="tab"]').forEach(button => button.setAttribute('aria-selected',String(button.dataset.tab===next))); document.querySelectorAll('[role="tabpanel"]').forEach(panel => panel.classList.toggle('active',panel.id==='panel-'+next)); }
    function renderQueue() {
      const list=document.getElementById('case-list');
      if (!summary.incidents.length) { list.innerHTML='<div class="empty">No cases currently meet the promotion boundary.</div>'; return; }
      list.innerHTML=summary.incidents.map(incident => `<button class="case-item" data-case-id="${esc(incident.id)}" aria-current="${incident.id===selected?.id?'true':'false'}"><span class="case-row"><span class="case-id">${esc(incident.id)}</span><span class="priority ${incident.priority.toLowerCase()}">${esc(incident.priority)}</span></span><span class="case-desc">${esc(incident.techniques.map(item=>item.technique_name).filter((item,index,values)=>values.indexOf(item)===index).slice(0,2).join(' · '))}</span><span class="case-foot"><span>${esc(incident.confidence)}% confidence</span><span>${esc(incident.mission_impact)}/100 impact</span></span></button>`).join('');
      list.querySelectorAll('[data-case-id]').forEach(button => button.addEventListener('click',()=>loadCase(button.dataset.caseId)));
    }
    async function boot() {
      try { const response=await fetch('/api/summary'); if(!response.ok) throw new Error('Unable to load the analysis'); summary=await response.json(); if(summary.incidents.length) await loadCase(summary.incidents[0].id,false); else renderQueue(); setStatus(`Engine ${summary.metadata.engine_version} · ATT&CK ${summary.metadata.attack_kb_version} · ground truth excluded from runtime`); }
      catch(error) { setStatus(error.message,true); document.getElementById('case-title').textContent='Analysis unavailable'; }
    }
    async function loadCase(id,announce=true) { try { const response=await fetch('/api/incidents/'+encodeURIComponent(id)); if(!response.ok) throw new Error('Unable to load this case'); selected=await response.json(); activeSource='all'; renderQueue(); renderCase(); if(announce) setStatus(`Loaded case ${selected.id}.`); } catch(error) { setStatus(error.message,true); } }
    function renderCase() {
      const inc=selected, brief=inc.bluf;
      document.getElementById('case-title').textContent=inc.id;
      document.getElementById('case-summary').textContent=`${inc.record_ids.length} observations across ${inc.sources.length} source types. The case is ${inc.promotable?'ready for analyst review':'still a hypothesis'}.`;
      document.getElementById('case-priority').textContent=`${inc.priority} · score ${inc.priority_score}/100`;
      document.getElementById('decision-copy').textContent=brief.assessment;
      const metrics=[['Evidence confidence',`${inc.confidence}%`,'How well available evidence supports this story.'],['Threat severity',`${inc.severity}/100`,'Potential harm represented by observed behavior.'],['Mission impact',`${inc.mission_impact}/100`,'Criticality of affected assets and mission role.'],['Urgency',`${inc.urgency}/100`,'How quickly this needs a human decision.']];
      document.getElementById('metric-grid').innerHTML=metrics.map(([label,value,note])=>`<div class="metric"><span class="metric-label">${esc(label)}</span><strong class="metric-value">${esc(value)}</strong><span class="metric-note">${esc(note)}</span></div>`).join('');
      document.getElementById('promotion-checks').innerHTML=Object.entries(inc.promotion_checks||{}).map(([key,passed])=>{const [label,detail]=CHECK_LABELS[key]||[key.replaceAll('_',' '),'Promotion check']; return `<li><span class="check-mark ${passed?'':'fail'}">${passed?'✓':'×'}</span><span><strong>${esc(label)}</strong><br><span class="check-detail">${esc(detail)}</span></span></li>`;}).join('');
      const assets=[...new Map((inc.assets||[]).map(asset=>[asset.asset,asset])).values()];
      document.getElementById('asset-context').innerHTML=assets.length?assets.map(asset=>`<p><strong>${esc(asset.asset)}</strong> · ${esc(asset.mission_role)}<br><span class="muted">Criticality ${esc(asset.criticality)}/100 · ${esc(asset.zone)}</span></p>`).join(''):'<p>No registered asset context was available.</p>';
      document.getElementById('uncertainty-context').textContent=brief.uncertainty;
      renderTimeline('overview-timeline',inc.evidence.slice(0,5)); renderFilters(); renderTimeline('full-timeline',inc.evidence); renderBrief(); renderBob();
    }
    function renderTimeline(targetId,records) {
      const target=document.getElementById(targetId), filtered=activeSource==='all'?records:records.filter(record=>record.source===activeSource);
      target.innerHTML=filtered.length?filtered.map(record=>`<div class="timeline-item"><div class="time">${esc(timeLabel(record.timestamp))}</div><div class="evidence"><div class="evidence-head"><strong class="evidence-title">${esc(record.summary)}</strong><span class="source">${esc(sourceLabel(record.source))}</span></div>${record.technique?`<div class="technique">${esc(record.technique)} · ${esc(record.technique_name||'')}</div>`:''}${record.technique_reason?`<p class="evidence-reason">Why it matters: ${esc(record.technique_reason)}</p>`:''}</div></div>`).join(''):'<div class="empty">No evidence from this source appears in the selected case.</div>';
    }
    function renderFilters() { const sourceSet=[...new Set(selected.evidence.map(record=>record.source))], filters=['all',...sourceSet], target=document.getElementById('source-filters'); target.innerHTML=filters.map(source=>`<button class="filter" data-source="${esc(source)}" aria-pressed="${source===activeSource}">${source==='all'?'All evidence':esc(sourceLabel(source))}</button>`).join(''); target.querySelectorAll('[data-source]').forEach(button=>button.addEventListener('click',()=>{activeSource=button.dataset.source;renderFilters();renderTimeline('full-timeline',selected.evidence);})); }
    function renderBrief() { const brief=selected.bluf, sections=[['Bottom line',brief.bottom_line],['Assessment',brief.assessment],['Actor context',brief.actor_assessment],['Uncertainty and visibility gaps',brief.uncertainty]]; document.getElementById('brief-content').innerHTML=sections.map(([label,value])=>`<section class="brief-section"><div class="brief-label">${esc(label)}</div><div>${esc(value)}</div></section>`).join(''); document.getElementById('response-actions').innerHTML=(selected.runbook||[]).map(step=>`<li class="action-item"><strong>${esc(step.phase)} · ${esc(step.priority)}</strong><span>${esc(step.action)}</span><span>Target: ${esc(step.target)}</span></li>`).join(''); }
    function briefText() { const brief=selected.bluf; return `# Commander Brief — ${selected.id}\n\n## Bottom line\n${brief.bottom_line}\n\n## Assessment\n${brief.assessment}\n\n## Actor context\n${brief.actor_assessment}\n\n## Uncertainty\n${brief.uncertainty}\n\n## Recommended actions\n${brief.recommended_actions.map((action,index)=>`${index+1}. ${action}`).join('\n')}`; }
    async function copyText(text,success) { try { await navigator.clipboard.writeText(text); setStatus(success); } catch { setStatus('Clipboard access was unavailable. Select and copy the text manually.',true); } }
    function exportBrief() { const blob=new Blob([briefText()],{type:'text/markdown'}), url=URL.createObjectURL(blob), anchor=document.createElement('a'); anchor.href=url; anchor.download=`${selected.id}_commander_brief.md`; anchor.click(); URL.revokeObjectURL(url); setStatus('Commander brief exported.'); }
    function renderBob() {
      const commands=[['/investigate','Retrieve the evidence chain, risk factors, gaps, and analyst next steps.'],['/explain','Explain why the case was prioritised without changing the deterministic score.'],['/bluf','Turn grounded case facts into a commander-ready summary.'],['/runbook','Retrieve staged containment, eradication, and detection-engineering actions.']];
      document.getElementById('bob-commands').innerHTML=commands.map(([command,detail])=>`<div class="mcp-command"><div><code>${esc(command)} ${esc(selected.id)}</code><div class="muted" style="font-size:12px;margin-top:4px;">${esc(detail)}</div></div><button class="button secondary" data-copy-command="${esc(command)} ${esc(selected.id)}">Copy</button></div>`).join('');
      document.querySelectorAll('[data-copy-command]').forEach(button=>button.addEventListener('click',()=>copyText(button.dataset.copyCommand,'Bob command copied.')));
      const tools=[['get_incident','Case facts'],['explain_risk','Risk rationale'],['get_detection_gaps','Visibility gaps'],['generate_bluf','Brief'],['get_remediation_runbook','Runbook']];
      document.getElementById('mcp-tools').innerHTML=tools.map(([tool,label])=>`<button class="button secondary" data-tool="${esc(tool)}">${esc(label)}</button>`).join(''); document.querySelectorAll('[data-tool]').forEach(button=>button.addEventListener('click',()=>runTool(button.dataset.tool)));
    }
    async function runTool(tool) { const output=document.getElementById('tool-output'); output.textContent=`Retrieving ${tool}…`; try { const parameters=new URLSearchParams({tool,incident_id:selected.id}), response=await fetch('/api/mcp-query?'+parameters.toString()), payload=await response.json(); output.textContent=JSON.stringify(payload,null,2); } catch(error) { output.textContent=`Unable to retrieve tool output: ${error.message}`; } }
    document.querySelectorAll('[role="tab"]').forEach(button=>button.addEventListener('click',()=>switchTab(button.dataset.tab)));
    document.getElementById('copy-brief').addEventListener('click',()=>copyText(briefText(),'Commander brief copied.'));
    document.getElementById('export-brief').addEventListener('click',exportBrief);
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
    analysis = analyze(ROOT)
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
    analysis = analyze(ROOT)
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
