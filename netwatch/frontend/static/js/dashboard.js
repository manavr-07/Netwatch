/**
 * dashboard.js — NetWatch frontend logic
 *
 * Three novel features reflected in the UI:
 *  1. Temporal Baseline Segmentation — segment badge in header + column in feed
 *  2. Incident Correlation          — live incident panel above the feed
 *  3. Counterfactual Explanations   — shown in detail panel per anomaly
 */

/* ================================================================ */
/* State                                                             */
/* ================================================================ */
const state = {
  anomalies:       [],
  incidents:       {},    // incident_id -> incident dict
  maxFeedRows:     100,
  severityFilter:  '',
  trendChart:      null,
  pieChart:        null,
  lastSeenTs:      null,
  sseSource:       null,
  sseIncidentSource: null,
  sseReconnectTimer: null,
  isReconnecting:  false,
};

/* ================================================================ */
/* Utility                                                           */
/* ================================================================ */
const $ = id => document.getElementById(id);

function fmtTime(ts) {
  return new Date(ts * 1000).toTimeString().slice(0, 8);
}

function fmtProto(p) {
  return p === 6 ? 'TCP' : p === 17 ? 'UDP' : `IP/${p}`;
}

function fmtDuration(s) {
  if (s < 60)   return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.round(s/60)}m`;
  return `${(s/3600).toFixed(1)}h`;
}

function scoreBarColor(score) {
  if (score >= 0.8)  return '#c0392b';
  if (score >= 0.65) return '#d97706';
  if (score >= 0.5)  return '#b59a0e';
  return '#16a34a';
}

function sevBorderColor(sev) {
  const m = { CRITICAL:'#c0392b', HIGH:'#d97706', MEDIUM:'#b59a0e', LOW:'#16a34a' };
  return m[sev] || '#4b5563';
}

/* ================================================================ */
/* Charts                                                            */
/* ================================================================ */
function initCharts() {
  Chart.defaults.color       = '#6b7a8d';
  Chart.defaults.borderColor = '#232b35';
  Chart.defaults.font.family = "'DM Mono', monospace";
  Chart.defaults.font.size   = 11;

  const trendCtx = $('trend-chart').getContext('2d');
  state.trendChart = new Chart(trendCtx, {
    type: 'line',
    data: { labels: [], datasets: [{
      label: 'Anomalies', data: [],
      borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.06)',
      borderWidth: 1.5, pointRadius: 2, pointBackgroundColor: '#3b82f6',
      fill: true, tension: 0.3,
    }]},
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 300 },
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor:'#13171c', borderColor:'#232b35', borderWidth:1,
          callbacks: { label: ctx => ` ${ctx.parsed.y} anomalies` } }
      },
      scales: {
        x: { grid:{color:'#1a2030'}, ticks:{maxTicksLimit:8,maxRotation:0} },
        y: { grid:{color:'#1a2030'}, beginAtZero:true, ticks:{stepSize:1} }
      }
    }
  });

  const pieCtx = $('severity-chart').getContext('2d');
  state.pieChart = new Chart(pieCtx, {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{
        data: [0,0,0,0],
        backgroundColor: ['#3d1212','#3d2208','#3d3308','#0a2a16'],
        borderColor:     ['#c0392b','#d97706','#b59a0e','#16a34a'],
        borderWidth: 1.5, hoverOffset: 4,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '72%',
      animation: { duration: 400 },
      plugins: {
        legend: { position:'bottom', labels:{padding:12,boxWidth:10,usePointStyle:true} },
        tooltip: { backgroundColor:'#13171c', borderColor:'#232b35', borderWidth:1 }
      }
    }
  });
}

/* ================================================================ */
/* Status polling                                                     */
/* ================================================================ */
async function pollStatus() {
  try {
    const res  = await fetch('/api/stats');
    const json = await res.json();
    if (json.status !== 'ok') return;
    const d = json.data;

    $('stat-flows').textContent     = (d.total_flows     ?? 0).toLocaleString();
    $('stat-anomalies').textContent = (d.total_anomalies ?? 0).toLocaleString();
    $('stat-incidents').textContent = (d.active_incidents ?? 0).toLocaleString();
    $('stat-rate').textContent      = d.total_flows > 0
      ? ((d.total_anomalies / d.total_flows) * 100).toFixed(2) + '%' : '—';

    // Segment badge — Novel Feature 1
    if (d.current_segment) {
      $('segment-badge').textContent = d.current_segment;
    }

    // Baseline quality badge
    if (d.baseline_quality) {
      const q = d.baseline_quality;
      const qBadge = $('quality-badge');
      if (qBadge) {
        qBadge.textContent = `Baseline: ${q.quality} (${q.regime})`;
        qBadge.title = q.description || '';
        qBadge.className = 'quality-badge quality-' + q.quality;
      }
    }

    const wrap = $('warmup-wrap');
    if (d.trained) {
      if (!state.isReconnecting) {
        $('status-dot').className    = 'status-dot live';
        $('status-text').textContent = 'Live';
      }
      wrap.style.display = 'none';
    } else {
      if (!state.isReconnecting) {
        $('status-dot').className    = 'status-dot warmup';
        $('status-text').textContent = 'Warm-up';
      }
      wrap.style.display = 'flex';
      const pct = d.warmup_total > 0
        ? Math.round((d.warmup_progress / d.warmup_total) * 100) : 0;
      $('warmup-bar').style.width  = pct + '%';
      $('warmup-pct').textContent  = pct + '%';
    }
  } catch (e) {
    if (!state.isReconnecting) {
      $('status-dot').className    = 'status-dot error';
      $('status-text').textContent = 'Disconnected';
    }
  }
}

/* ================================================================ */
/* Charts update                                                      */
/* ================================================================ */
async function updateCharts() {
  try {
    const tRes  = await fetch('/api/anomalies/trend?hours=1');
    const tJson = await tRes.json();
    if (tJson.status === 'ok' && tJson.data.length > 0) {
      state.trendChart.data.labels             = tJson.data.map(d => `T-${d.minute_bucket}m`);
      state.trendChart.data.datasets[0].data   = tJson.data.map(d => d.count);
      state.trendChart.update('none');
    }
    const sRes  = await fetch('/api/severity');
    const sJson = await sRes.json();
    if (sJson.status === 'ok') {
      const dist = sJson.data;
      state.pieChart.data.datasets[0].data = [
        dist['CRITICAL']||0, dist['HIGH']||0, dist['MEDIUM']||0, dist['LOW']||0
      ];
      state.pieChart.update('none');
    }
  } catch (e) { /* silent */ }
}

/* ================================================================ */
/* Novel Feature 2: Incident panel                                   */
/* ================================================================ */
function renderIncident(incident) {
  state.incidents[incident.incident_id] = incident;

  const section = $('incidents-section');
  section.style.display = 'block';
  $('incident-count').textContent = Object.keys(state.incidents).length;
  $('stat-incidents').textContent = Object.keys(state.incidents).length;

  const list = $('incident-list');
  const existing = document.querySelector(`[data-incident="${incident.incident_id}"]`);
  if (existing) existing.remove();

  const card = document.createElement('div');
  card.className = `incident-card ${incident.composite_severity}`;
  card.dataset.incident = incident.incident_id;
  card.style.borderLeftColor = sevBorderColor(incident.composite_severity);

  // Build destination summary
  const dstSummary = (incident.dst_summary || []).slice(0, 3)
    .map(d => `<span class="incident-dst-tag">${d.dst_ip}${d.ports.length ? ':' + d.ports[0] : ''} <span class="incident-dst-count">×${d.count}</span></span>`)
    .join('');

  // Build flow breakdown rows
  const flowRows = (incident.flow_breakdown || []).slice(0, 3)
    .map(f => `
      <div class="incident-flow-row">
        <span class="incident-flow-num">#${f.index}</span>
        <span class="incident-flow-dst">${f.dst_ip || '—'}:${f.dst_port || '?'}</span>
        <span class="incident-flow-score">${(f.score||0).toFixed(2)}</span>
        <span class="sev-badge ${f.severity}" style="font-size:0.6rem;padding:1px 5px">${f.severity}</span>
        <span class="incident-flow-feat">${f.top_feature ? f.top_feature + ' (' + (f.top_z > 0 ? '+' : '') + f.top_z + 'σ)' : ''}</span>
      </div>`).join('');

  card.innerHTML = `
    <div class="incident-top">
      <div class="incident-meta">
        <div class="incident-id">${incident.incident_id.slice(0, 18)}</div>
        <div class="incident-count">${incident.anomaly_count}</div>
        <div class="incident-count-label">flows</div>
      </div>
      <div class="incident-main">
        <div class="incident-src-row">
          <span class="incident-src">${incident.src_ip}</span>
          <span class="incident-arrow">→</span>
          <span class="incident-dsts">${dstSummary || '—'}</span>
        </div>
        <div class="incident-summary">${incident.pattern_summary}</div>
        ${incident.correlation_reason ? `<div class="incident-correlation-reason">${incident.correlation_reason}</div>` : ''}
      </div>
      <div class="incident-right">
        <span class="sev-badge ${incident.composite_severity}">${incident.composite_severity}</span>
        <span class="incident-duration">${fmtDuration(incident.duration_seconds)}</span>
        <span class="incident-scores">avg ${(incident.avg_score||0).toFixed(2)} / top ${(incident.top_score||0).toFixed(2)}</span>
      </div>
    </div>
    ${flowRows ? `<div class="incident-flows-breakdown">${flowRows}</div>` : ''}
  `;

  list.insertBefore(card, list.firstChild);
  // Keep max 5 visible
  while (list.children.length > 5) list.removeChild(list.lastChild);
}

async function loadInitialIncidents() {
  try {
    const res  = await fetch('/api/incidents?limit=10');
    const json = await res.json();
    if (json.status === 'ok' && json.data.length > 0) {
      json.data.slice(0, 5).reverse().forEach(renderIncident);
    }
  } catch (e) { /* silent */ }
}

/* ================================================================ */
/* Feed table                                                         */
/* ================================================================ */
function prependAnomalyRow(anomaly, isNew = true) {
  if (state.severityFilter && anomaly.severity !== state.severityFilter) return;

  const emptyRow = $('empty-row');
  if (emptyRow) emptyRow.remove();

  const tbody  = $('feed-body');
  const tr     = document.createElement('tr');
  if (isNew) tr.classList.add('new-row');
  tr.dataset.id = anomaly.id;

  const pct    = Math.round(anomaly.anomaly_score * 100);
  const bColor = scoreBarColor(anomaly.anomaly_score);
  const seg    = anomaly.temporal_segment || '—';
  const safeExpl = (anomaly.explanation || '').replace(/"/g, '&quot;');

  // Build IP cells with loading shimmer — async enrichment happens after insert
  const srcCellHTML = buildIPCellHTML(anomaly.src_ip, ipCache[anomaly.src_ip] || null);
  const dstCellHTML = buildIPCellHTML(anomaly.dst_ip, ipCache[anomaly.dst_ip] || null);

  tr.innerHTML = `
    <td class="ip-addr">${fmtTime(anomaly.ts)}</td>
    <td>${srcCellHTML}</td>
    <td>
      <div class="ip-cell">
        <div class="ip-addr-main">${anomaly.dst_ip || '—'}:${anomaly.dst_port || '?'}&nbsp;<span style="color:var(--text-tertiary)">${fmtProto(anomaly.protocol)}</span></div>
        <div class="ip-intel-loading" id="dst-intel-${anomaly.id}"></div>
      </div>
    </td>
    <td>
      <div class="score-bar-wrap">
        <span class="score-val">${anomaly.anomaly_score.toFixed(2)}</span>
        <div class="score-bar"><div class="score-fill" style="width:${pct}%;background:${bColor}"></div></div>
      </div>
    </td>
    <td><span class="sev-badge ${anomaly.severity}">${anomaly.severity}</span></td>
    <td><span class="segment-pill">${seg}</span></td>
    <td><div class="expl-text" title="${safeExpl}">${anomaly.explanation || '—'}</div></td>
    <td><span class="action-text">View detail</span></td>
  `;

  tr.addEventListener('click', () => openDetail(anomaly));
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > state.maxFeedRows) tbody.removeChild(tbody.lastChild);

  // Async: enrich IP cells after row is in DOM
  if (isNew) {
    enrichRowIPs(tr, anomaly.src_ip, anomaly.dst_ip);
  }
}

/* ================================================================ */
/* Initial feed load                                                  */
/* ================================================================ */
async function loadInitialFeed() {
  try {
    const res  = await fetch('/api/anomalies?limit=50');
    const json = await res.json();
    if (json.status !== 'ok') return;
    const records = json.data.reverse();
    records.forEach(a => { state.anomalies.unshift(a); prependAnomalyRow(a, false); });
    if (records.length > 0) {
      state.lastSeenTs           = records[records.length - 1].ts;
      $('stat-last') && ($('stat-last').textContent = fmtTime(state.lastSeenTs));
    }
  } catch (e) { console.warn('Feed load failed:', e); }
}

/* ================================================================ */
/* SSE streams                                                        */
/* ================================================================ */
function connectStream() {
  if (state.sseSource) { state.sseSource.close(); state.sseSource = null; }

  const es = new EventSource('/api/stream');
  state.sseSource      = es;
  state.isReconnecting = false;

  es.onopen = () => {
    state.isReconnecting = false;
    clearTimeout(state.sseReconnectTimer);
  };

  es.onmessage = event => {
    try {
      const anomaly = JSON.parse(event.data);
      state.anomalies.unshift(anomaly);
      if (state.anomalies.length > 500) state.anomalies.pop();
      prependAnomalyRow(anomaly, true);
      state.lastSeenTs = anomaly.ts;

      const cur = parseInt($('stat-anomalies').textContent.replace(/,/g,'')) || 0;
      $('stat-anomalies').textContent = (cur + 1).toLocaleString();

      scheduleChartUpdate();
    } catch (e) { console.warn('SSE parse error:', e); }
  };

  es.onerror = () => {
    state.isReconnecting         = true;
    $('status-dot').className    = 'status-dot error';
    $('status-text').textContent = 'Reconnecting...';
    es.close();
    state.sseSource = null;
    clearTimeout(state.sseReconnectTimer);
    state.sseReconnectTimer = setTimeout(connectStream, 3000);
  };
}

function connectIncidentStream() {
  if (state.sseIncidentSource) { state.sseIncidentSource.close(); }

  const es = new EventSource('/api/stream/incidents');
  state.sseIncidentSource = es;

  es.onmessage = event => {
    try {
      const incident = JSON.parse(event.data);
      renderIncident(incident);
    } catch (e) { /* silent */ }
  };

  es.onerror = () => {
    es.close();
    setTimeout(connectIncidentStream, 5000);
  };
}

let chartUpdateTimer = null;
function scheduleChartUpdate() {
  clearTimeout(chartUpdateTimer);
  chartUpdateTimer = setTimeout(updateCharts, 2000);
}

/* ================================================================ */
/* Novel Feature 3: Detail panel with counterfactuals               */
/* ================================================================ */
async function openDetail(anomaly) {
  const panel   = $('detail-panel');
  const overlay = $('detail-overlay');
  const body    = $('detail-body');

  // Fetch counterfactuals from API
  let cfHtml = '<div style="color:var(--text-tertiary);font-size:0.8rem">Computing...</div>';
  body.innerHTML = buildDetailHTML(anomaly, [], []);
  panel.classList.add('open');
  overlay.classList.add('open');

  try {
    const res  = await fetch(`/api/anomalies/${anomaly.id}/counterfactuals`);
    const json = await res.json();
    const cfs  = json.status === 'ok' ? json.data : (anomaly.counterfactuals || []);
    body.innerHTML = buildDetailHTML(anomaly, anomaly.deviating_features || [], cfs);
  } catch (e) {
    body.innerHTML = buildDetailHTML(anomaly, anomaly.deviating_features || [], anomaly.counterfactuals || []);
  }
}

function buildDetailHTML(anomaly, deviating, counterfactuals) {
  // Deviating features
  let featHtml = '';
  if (!deviating || deviating.length === 0) {
    featHtml = '<div style="color:var(--text-tertiary);font-size:0.8rem">No individual features stand out; composite deviation flagged.</div>';
  } else {
    featHtml = '<div class="feat-list">' + deviating.map(f => {
      const z = f.z_score;
      const dir = z > 0 ? 'pos' : 'neg';
      return `<div class="feat-item">
        <span class="feat-name">${f.label}</span>
        <span class="feat-val">${f.value}</span>
        <span class="feat-z ${dir}">${z > 0 ? '+' : ''}${z.toFixed(1)}&sigma;</span>
      </div>`;
    }).join('') + '</div>';
  }

  // Counterfactuals — Novel Feature 3
  let cfHtml = '';
  if (!counterfactuals || counterfactuals.length === 0) {
    cfHtml = '<div style="color:var(--text-tertiary);font-size:0.8rem">No counterfactuals available — anomaly may be driven by composite deviation.</div>';
  } else {
    cfHtml = '<div class="counterfactual-list">' +
      counterfactuals.map(cf => `
        <div class="cf-item">
          <strong>${cf.direction === 'decrease' ? 'Decrease' : 'Increase'} ${cf.label}</strong>
          to <strong>${cf.threshold}</strong> (currently ${cf.observed}).<br>
          ${cf.statement}
        </div>`).join('') + '</div>';
  }

  const seg = anomaly.temporal_segment || '—';

  return `
    <div class="detail-section">
      <div class="detail-section-title">Flow Identity</div>
      <div class="detail-grid">
        <div class="detail-field"><span class="field-label">Source IP</span>${buildIPDetailBlock(anomaly.src_ip, ipCache[anomaly.src_ip])}</div>
        <div class="detail-field"><span class="field-label">Destination</span>${buildIPDetailBlock(anomaly.dst_ip, ipCache[anomaly.dst_ip])}</div>
        <div class="detail-field"><span class="field-label">Protocol</span><span class="field-value">${fmtProto(anomaly.protocol)}</span></div>
        <div class="detail-field"><span class="field-label">Time</span><span class="field-value">${fmtTime(anomaly.ts)}</span></div>
        <div class="detail-field"><span class="field-label">Time Segment</span><span class="field-value"><span class="segment-pill">${seg}</span></span></div>
        ${anomaly.incident_id ? `<div class="detail-field"><span class="field-label">Incident</span><span class="field-value"><span class="incident-link">${anomaly.incident_id.slice(0,20)}</span></span></div>` : ''}
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Detection Result</div>
      <div class="detail-grid">
        <div class="detail-field"><span class="field-label">Anomaly Score</span><span class="field-value">${anomaly.anomaly_score.toFixed(4)}</span></div>
        <div class="detail-field"><span class="field-label">Severity</span><span class="field-value"><span class="sev-badge ${anomaly.severity}">${anomaly.severity}</span></span></div>
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Behavioral Explanation</div>
      <div class="detail-explanation">${anomaly.explanation||'—'}</div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Counterfactual Analysis</div>
      <div style="font-size:0.75rem;color:var(--text-tertiary);margin-bottom:8px">What would need to change for this flow to not be flagged?</div>
      ${cfHtml}
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Deviating Features</div>
      ${featHtml}
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Recommended Action</div>
      <div class="detail-mitigation">${anomaly.mitigation||'—'}</div>
    </div>
  `;
}

function closeDetail() {
  $('detail-panel').classList.remove('open');
  $('detail-overlay').classList.remove('open');
}

/* ================================================================ */
/* Filter                                                             */
/* ================================================================ */
function applyFilter() {
  const tbody = $('feed-body');
  tbody.innerHTML = '';
  const filtered = state.severityFilter
    ? state.anomalies.filter(a => a.severity === state.severityFilter)
    : state.anomalies;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr class="feed-empty-row" id="empty-row"><td colspan="8">No anomalies match the current filter.</td></tr>`;
    return;
  }
  filtered.forEach(a => prependAnomalyRow(a, false));
}

/* ================================================================ */
/* Boot                                                               */
/* ================================================================ */
document.addEventListener('DOMContentLoaded', () => {
  initCharts();

  $('severity-filter').addEventListener('change', e => {
    state.severityFilter = e.target.value;
    applyFilter();
  });

  $('clear-btn').addEventListener('click', () => {
    state.anomalies = [];
    $('feed-body').innerHTML = `<tr class="feed-empty-row" id="empty-row"><td colspan="8">Feed cleared.</td></tr>`;
  });

  $('detail-close').addEventListener('click', closeDetail);
  $('detail-overlay').addEventListener('click', closeDetail);

  // Fetch this machine's IPs first so we can label them
  fetchLocalIPs().then(() => {
    loadInitialFeed().then(() => {
      // Batch-enrich all initially loaded IPs
      enrichAllVisibleIPs();
    });
  });

  loadInitialIncidents();
  pollStatus();
  updateCharts();

  connectStream();
  connectIncidentStream();

  setInterval(pollStatus, 5000);
  setInterval(updateCharts, 30000);
});

/* ================================================================ */
/* IP INTELLIGENCE — Lookup + Cache + Render                        */
/* ================================================================ */

// Client-side IP intel cache: ip -> intel dict
const ipCache = {};
// Set of this machine's own IPs (fetched once on boot)
const localIPs = new Set();

async function fetchLocalIPs() {
  try {
    const res  = await fetch('/api/ip/local');
    const json = await res.json();
    if (json.status === 'ok') {
      json.data.forEach(ip => localIPs.add(ip));
    }
  } catch (e) { /* silent */ }
}

async function getIPIntel(ip) {
  if (!ip || ip === '—') return null;
  if (ipCache[ip]) return ipCache[ip];
  try {
    const res  = await fetch(`/api/ip/${ip}`);
    const json = await res.json();
    if (json.status === 'ok') {
      ipCache[ip] = json.data;
      return json.data;
    }
  } catch (e) { /* silent */ }
  return null;
}

async function batchFetchIPs(ips) {
  // Filter out already cached
  const needed = [...new Set(ips)].filter(ip => ip && ip !== '—' && !ipCache[ip]);
  if (needed.length === 0) return;
  try {
    const res  = await fetch('/api/ip/batch', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({ips: needed.slice(0, 20)})
    });
    const json = await res.json();
    if (json.status === 'ok') {
      Object.assign(ipCache, json.data);
    }
  } catch (e) { /* silent */ }
}

function buildIPCellHTML(ip, intel) {
  if (!intel) {
    // Show IP with loading shimmer for intel
    const isLocal = localIPs.has(ip);
    return `
      <div class="ip-cell">
        <div class="ip-addr-main ${isLocal ? 'is-local' : ''}">
          ${ip || '—'}
          ${isLocal ? '<span class="ip-local-badge">You</span>' : ''}
        </div>
        <div class="ip-intel-loading"></div>
      </div>`;
  }

  const isLocal   = intel.is_local || localIPs.has(ip);
  const isPrivate = intel.is_private;
  const flag      = intel.flag || '';
  const label     = intel.label || intel.org || '';

  let labelHtml = '';
  if (isLocal) {
    labelHtml = `<span class="ip-service-tag">This Device</span>`;
  } else if (isPrivate) {
    labelHtml = `<span class="ip-intel-label private">Private Network</span>`;
  } else if (intel.type === 'KNOWN_SERVICE') {
    labelHtml = `<span class="ip-intel-label"><span class="flag">${flag}</span>${intel.org} <span class="ip-service-tag">${intel.service}</span></span>`;
  } else if (label) {
    labelHtml = `<span class="ip-intel-label"><span class="flag">${flag}</span>${label}</span>`;
  }

  return `
    <div class="ip-cell">
      <div class="ip-addr-main ${isLocal ? 'is-local' : ''}">
        ${ip || '—'}
        ${isLocal ? '<span class="ip-local-badge">You</span>' : ''}
      </div>
      ${labelHtml}
    </div>`;
}

function buildIPDetailBlock(ip, intel) {
  if (!intel) return `<div class="field-value" style="font-family:var(--font-mono)">${ip}</div>`;

  const isLocal = intel.is_local || localIPs.has(ip);
  const rows = [
    ['IP',          ip],
    ['Type',        intel.type],
    ['Organization',intel.org || '—'],
    ['ISP',         intel.isp || '—'],
    ['Location',    [intel.city, intel.country].filter(Boolean).join(', ') || '—'],
    ['Service',     intel.service || '—'],
  ].filter(([_, v]) => v && v !== '—');

  return `
    <div class="ip-detail-block">
      ${isLocal ? `<div style="color:var(--accent);font-size:0.78rem;font-weight:600;margin-bottom:4px">This Device</div>` : ''}
      ${rows.map(([k, v]) => `
        <div class="ip-detail-row">
          <span class="ip-detail-key">${k}</span>
          <span class="ip-detail-val">${intel.flag ? intel.flag + ' ' : ''}${v}</span>
        </div>`).join('')}
    </div>`;
}

// Enrich IP cells in the feed table after rows are inserted
async function enrichRowIPs(tr, srcIP, dstIP) {
  const srcIntel = await getIPIntel(srcIP);
  const dstIntel = await getIPIntel(dstIP);

  const cells = tr.querySelectorAll('td');
  if (cells[1]) cells[1].innerHTML = buildIPCellHTML(srcIP, srcIntel);
  if (cells[2]) {
    // Destination cell has port/proto after the IP — rebuild it
    const anomalyId = tr.dataset.id;
    const proto = cells[2].textContent.includes('TCP') ? 6 : 17;
    const port  = cells[2].textContent.match(/:(\d+)/)?.[1] || '?';
    cells[2].innerHTML = `
      <div class="ip-cell">
        <div class="ip-addr-main">
          ${dstIP || '—'}:${port}&nbsp;<span style="color:var(--text-tertiary)">${fmtProto(proto)}</span>
        </div>
        ${dstIntel ? `<span class="ip-intel-label"><span class="flag">${dstIntel.flag||''}</span>${dstIntel.label||''}</span>` : ''}
      </div>`;
  }
}

// Called after initial feed load to batch-enrich all visible IPs
async function enrichAllVisibleIPs() {
  const rows = document.querySelectorAll('#feed-body tr[data-id]');
  const ips  = [];
  rows.forEach(tr => {
    const cells = tr.querySelectorAll('td');
    if (cells[1]) ips.push(cells[1].textContent.trim().split('\n')[0].trim());
    if (cells[2]) {
      const m = cells[2].textContent.match(/^[\d.]+/);
      if (m) ips.push(m[0]);
    }
  });
  await batchFetchIPs(ips);
  // Now re-render each row's IP cells
  rows.forEach(tr => {
    const cells  = tr.querySelectorAll('td');
    const srcIP  = cells[1]?.textContent.trim().split('\n')[0].trim();
    const dstRaw = cells[2]?.textContent.trim();
    const dstIP  = dstRaw?.match(/^([\d.]+)/)?.[1];
    if (srcIP && dstIP) enrichRowIPs(tr, srcIP, dstIP);
  });
}

/* ================================================================ */
/* DETECTION PAUSE / RESUME                                          */
/* ================================================================ */

let _detectionPaused = false;

async function toggleDetection() {
  const btn      = document.getElementById('detection-btn');
  const icon     = document.getElementById('detection-btn-icon');
  const label    = document.getElementById('detection-btn-label');

  const endpoint = _detectionPaused ? '/api/detection/resume' : '/api/detection/pause';

  try {
    const res  = await fetch(`${window.location.origin}${endpoint}`, { method: 'POST' });
    const json = await res.json();
    if (json.status !== 'ok') return;

    _detectionPaused = json.data.paused;
    _updateDetectionUI();

  } catch (e) {
    console.warn('Detection toggle failed:', e);
  }
}

function _updateDetectionUI() {
  const btn   = document.getElementById('detection-btn');
  const icon  = document.getElementById('detection-btn-icon');
  const label = document.getElementById('detection-btn-label');

  // Create banner if it doesn't exist
  let banner = document.getElementById('paused-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id        = 'paused-banner';
    banner.className = 'paused-banner';
    banner.textContent = '⏸  Detection is paused — no flows are being analysed. Click Resume to restart.';
    // Insert before feed section
    const feedSection = document.querySelector('.feed-section');
    if (feedSection) feedSection.parentNode.insertBefore(banner, feedSection);
  }

  if (_detectionPaused) {
    btn.classList.add('paused');
    icon.textContent  = '▶';
    label.textContent = 'Resume';
    banner.classList.add('visible');
    // Update status dot
    document.getElementById('status-dot').className    = 'status-dot error';
    document.getElementById('status-text').textContent = 'Paused';
  } else {
    btn.classList.remove('paused');
    icon.textContent  = '⏸';
    label.textContent = 'Pause';
    banner.classList.remove('visible');
  }
}

// Sync pause state on load and during status polls
async function syncDetectionState() {
  try {
    const res  = await fetch(`${window.location.origin}/api/detection/status`);
    const json = await res.json();
    if (json.status === 'ok') {
      _detectionPaused = json.data.paused;
      _updateDetectionUI();
    }
  } catch (e) { /* silent */ }
}

// Hook into existing pollStatus to also sync detection state
const _origPollStatus = pollStatus;
pollStatus = async function() {
  await _origPollStatus();
  await syncDetectionState();
};
