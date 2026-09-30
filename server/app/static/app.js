'use strict';

// All data shown here (host names, process names, command lines...) comes
// from monitored machines and is untrusted: it only ever reaches the DOM via
// textContent / text nodes, never innerHTML.

const SVGNS = 'http://www.w3.org/2000/svg';
const $ = (sel, root = document) => root.querySelector(sel);

const state = {
  meta: null,
  hosts: [],
  skew: 0,                       // server clock minus browser clock, seconds
  timers: [],
  ticks: [],
  range: loadPref('range', 1),   // history hours
  hostFilter: '',
  proc: { sortKey: 'cpu', sortDir: -1, filter: '', limit: 50, paused: false },
};

// -- small helpers -------------------------------------------------------

function loadPref(key, fallback) {
  try {
    const v = localStorage.getItem('serverstats.' + key);
    return v == null ? fallback : JSON.parse(v);
  } catch { return fallback; }
}
function savePref(key, value) {
  try { localStorage.setItem('serverstats.' + key, JSON.stringify(value)); } catch { /* ignore */ }
}

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid != null && kid !== false) e.append(kid instanceof Node ? kid : String(kid));
  }
  return e;
}

function svg(tag, attrs) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  return e;
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
function fmtBytes(n) {
  if (n == null || !isFinite(n)) return '—';
  let i = 0;
  while (Math.abs(n) >= 1024 && i < UNITS.length - 1) { n /= 1024; i++; }
  return (i === 0 || n >= 100 ? Math.round(n) : n.toFixed(1)) + ' ' + UNITS[i];
}
const fmtRate = (n) => (n == null || !isFinite(n) ? '—' : fmtBytes(n) + '/s');
function fmtPct(n) {
  if (n == null || !isFinite(n)) return '—';
  return (n < 10 ? n.toFixed(1) : Math.round(n)) + '%';
}
function fmtNum(n) { return n == null ? '—' : Number(n).toLocaleString(); }
function fmtDuration(sec) {
  if (sec == null || !isFinite(sec)) return '—';
  const d = Math.floor(sec / 86400), hr = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${hr}h`;
  if (hr) return `${hr}h ${m}m`;
  return `${m}m`;
}
function fmtAgo(sec) {
  if (sec == null || !isFinite(sec)) return 'never';
  if (sec < 5) return 'just now';
  if (sec < 60) return `${Math.round(sec)}s ago`;
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
}
function fmtClock(ts, withDate) {
  const d = new Date(ts * 1000);
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return withDate ? d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + time : time;
}
function fmtStarted(ts) {
  if (!ts) return '—';
  const age = serverNow() - ts;
  if (age < 86400) return fmtClock(ts, false);
  return new Date(ts * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
}
const serverNow = () => Date.now() / 1000 + state.skew;
const level = (pct) => (pct >= 90 ? 'critical' : pct >= 75 ? 'warning' : 'normal');

function fullestDisk(host) {
  return (host.disks || []).reduce((a, d) => (!a || d.percent > a.percent ? d : a), null);
}

// -- data fetching ---------------------------------------------------------

async function api(path) {
  let res;
  try {
    res = await fetch(path, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
  } catch (e) {
    connectionLost(true);
    throw e;
  }
  const json = (res.headers.get('content-type') || '').includes('application/json');
  // An expired SSO session typically shows up as a redirect to the login page.
  if (res.status === 401 || res.redirected || (res.ok && !json)) {
    connectionLost(true);
    throw new Error('not authenticated');
  }
  connectionLost(false);
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// State-changing requests carry this header; the server refuses them without
// it, which stops other sites from triggering them via a signed-in browser.
async function apiPost(path, body) {
  const headers = { Accept: 'application/json', 'X-ServerStats-Action': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const reply = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(reply.detail || `HTTP ${res.status}`);
  return reply;
}

function connectionLost(lost) {
  $('#conn-banner').hidden = !lost;
}

function every(ms, fn) {
  const tick = async () => {
    if (document.hidden) return;
    try { await fn(); } catch (e) { console.warn(e); }
  };
  tick();
  state.ticks.push(tick);
  state.timers.push(setInterval(tick, ms));
}
function clearTimers() {
  state.timers.forEach(clearInterval);
  state.timers = [];
  state.ticks = [];
}

async function refreshHosts() {
  const before = Date.now() / 1000;
  state.hosts = await api('/api/hosts');
  if (state.hosts.length) state.skew = state.hosts[0].server_time - before;
  const online = state.hosts.filter((x) => x.status === 'online').length;
  $('#fleet-summary').textContent = state.hosts.length ? `${online} of ${state.hosts.length} hosts online` : '';
}

// -- shared widgets ----------------------------------------------------------

const STATUS_LABEL = { online: 'Online', offline: 'Offline', error: 'Error', pending: 'Waiting for data' };
function setStatus(elm, status) {
  elm.dataset.status = status;
  $('.status-label', elm).textContent = STATUS_LABEL[status] || status;
}

// `trend` (optional): [{t, v}] percentages to draw as a sparkline above the bar.
// `valueText` (optional): replaces the percentage shown next to the bar.
function meter(label, pct, title, trend, valueText) {
  const fill = h('div', { class: 'meter-fill', 'data-level': level(pct || 0) });
  fill.style.width = Math.max(0, Math.min(100, pct || 0)) + '%';
  const track = h('div', {
    class: 'meter-track', role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100,
    'aria-valuenow': pct == null ? 0 : pct, 'aria-label': label || title,
  }, fill);
  let middle = track;
  if (trend) {
    const vals = trend.map((p) => p.v);
    if (vals.length) title += ` · last hour ${fmtPct(Math.min(...vals))}–${fmtPct(Math.max(...vals))}`;
    middle = h('div', { class: 'meter-viz' }, sparkline(trend), track);
  }
  return h('div', { class: 'meter', title },
    label != null && h('span', { class: 'meter-label', text: label }),
    middle,
    h('span', { class: 'meter-value', text: valueText || fmtPct(pct) }));
}

// Overall load (see load_of on the server): Sandpiper's volume as a
// percentage, 100 * (1 - (1-cpu)(1-mem)(1-disk)), so it's 100% when
// something is maxed out. Drawn as one bar split into a colored segment per
// resource, so it's clear what drives it.
const LOAD_PARTS = [
  ['cpu', 'CPU', 'CPU'], ['mem', 'Memory', 'memory'], ['disk_util', 'Disk I/O', 'disk I/O'],
];
// Load levels: 90% and up is a warning, 100% (something maxed out) is full.
const loadLevel = (load) => (load == null ? null : load >= 99.5 ? 'full' : load >= 89.5 ? 'warning' : null);
const LEVEL_LABEL = { full: '⚠ Full', warning: '⚠ Warning' };
const levelClass = (load) => (loadLevel(load) ? ` is-${loadLevel(load)}` : '');
const levelBadge = (load) => (loadLevel(load) ? h('span', { class: `level-badge${levelClass(load)}`, text: LEVEL_LABEL[loadLevel(load)] }) : null);
const LOAD_EXPLAINED = "Load combines CPU, memory and disk I/O the way Sandpiper's \"volume\" does: "
  + '100% × (1 − (1−CPU)(1−memory)(1−disk)). The busier any of them, the higher it goes, faster when several are busy, '
  + "and it's 100% (full) when one is maxed out. 90% and up is a warning. Storage isn't counted.";
// Each resource's share of the load, as a percentage of it.
const shareOf = (part, load) => (load > 0 ? (100 * (part || 0)) / load : 0);
const topPart = (parts) => LOAD_PARTS.filter(([k]) => parts[k] > 0).sort((a, b) => parts[b[0]] - parts[a[0]])[0];

function loadTrack(parts, label, load) {
  const lvl = loadLevel(load);
  const track = h('div', {
    class: 'meter-track load-track' + levelClass(load), role: 'meter', 'aria-valuemin': 0,
    'aria-valuemax': 100, 'aria-valuenow': load == null ? 0 : load,
    'aria-label': lvl ? `${label}, ${lvl}` : label,
  });
  for (const [k] of LOAD_PARTS) {
    if (!(parts && parts[k] > 0)) continue;
    const seg = h('div', { class: 'load-seg', 'data-part': k });
    seg.style.width = Math.min(100, parts[k]) + '%';
    track.append(seg);
  }
  return track;
}

function fmtSpan(hours) {
  if (hours >= 24) return `${Math.floor(hours / 24)}d` + (Math.round(hours % 24) ? ` ${Math.round(hours % 24)}h` : '');
  return hours >= 1 ? `${Math.round(hours)}h` : `${Math.max(1, Math.round(hours * 60))} min`;
}

// `kind`: 'avg' (3-day average) or 'high' (the busiest 1% of the past week).
function loadMeter(score, kind) {
  const high = kind === 'high';
  const full = high ? 167.5 : 71.5; // hours in the window, give or take a slot
  const [label, sub] = high ? ['1% high', 'past 7 days'] : ['Load', '3-day avg'];
  let caption = 'Not enough data yet';
  let title = high ? 'Peak load: not enough history yet.' : 'Overall load: not enough history yet.';
  if (score) {
    const top = topPart(score.parts);
    caption = top && score.load >= 1 ? `Mostly ${top[2]}` : 'Idle';
    if (loadLevel(score.load)) caption = `${LEVEL_LABEL[loadLevel(score.load)]} · ${top[2]}`;
    if (score.hours < full) caption += ` · ${fmtSpan(score.hours)}`; // newer hosts: say how much data this is
    const span = score.hours < full ? fmtSpan(score.hours) : high ? '7 days' : '3 days';
    title = (high
      ? `Peak load: the busiest 1% of the past ${span} (the top ${score.slots} five-minute stretches, `
        + `${fmtSpan(score.slots / 12)} in all), averaged. Open the host to see what caused it.\n`
      : `Overall load, averaged over the past ${span}. `) + LOAD_EXPLAINED + '\n'
      + ({ full: 'Full: something is maxed out.\n', warning: 'Warning: 90% or more.\n' }[loadLevel(score.load)] || '')
      + LOAD_PARTS.map(([k, name]) => `${name}: ${fmtPct(shareOf(score.parts[k], score.load))} of it`
        + (score.avg ? ` (average ${fmtPct(score.avg[k])} used)` : '')).join('\n');
  }
  return h('div', { class: 'meter meter-load', title },
    h('span', { class: 'meter-label' }, label, h('small', { text: sub })),
    h('div', { class: 'meter-viz' }, h('span', { class: 'load-caption', text: caption }),
      loadTrack(score && score.parts, high ? 'Peak load, past week' : 'Overall load', score && score.load)),
    h('span', { class: 'meter-value' + (score ? levelClass(score.load) : ''), text: score ? fmtPct(score.load) : '—' }));
}

// Last-hour trend on a fixed 0-100% scale, so hosts compare honestly.
function sparkline(points) {
  const W = 120, H = 22;
  const x1 = serverNow(), x0 = x1 - 3600;
  const X = (t) => ((t - x0) / (x1 - x0)) * W;
  const Y = (v) => H - 1 - (Math.max(0, Math.min(100, v)) / 100) * (H - 2);
  const root = svg('svg', { class: 'spark', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  const pts = points.filter((p) => p.t >= x0);
  if (!pts.length) return root;
  const gap = Math.max(180, 3 * cadence(pts.map((p) => p.t)));
  let line = '', area = '', seg = [];
  const flush = () => {
    if (!seg.length) return;
    const xs = seg.map((p) => X(p.t).toFixed(1));
    const ys = seg.map((p) => Y(p.v).toFixed(1));
    line += 'M' + xs.map((x, i) => `${x},${ys[i]}`).join('L') + (seg.length === 1 ? 'h1' : '');
    area += `M${xs[0]},${H}L` + xs.map((x, i) => `${x},${ys[i]}`).join('L') + `L${xs[xs.length - 1]},${H}Z`;
    seg = [];
  };
  pts.forEach((p, i) => {
    if (i && p.t - pts[i - 1].t > gap) flush();
    seg.push(p);
  });
  flush();
  root.append(svg('path', { class: 'spark-area', d: area }), svg('path', { class: 'spark-line', d: line, 'vector-effect': 'non-scaling-stroke' }));
  return root;
}

function tile(label, value, sub) {
  return h('div', { class: 'tile' },
    h('div', { class: 'tile-label', text: label }),
    h('div', { class: 'tile-value', text: value }),
    sub && h('div', { class: 'tile-sub', text: sub }));
}

function subline(host) {
  const parts = [
    host.description,
    host.os,
    host.cpu && `${host.cpu.count} cores`,
    host.memory && `${fmtBytes(host.memory.total)} RAM`,
  ].filter(Boolean);
  if (parts.length) return parts.join(' · ');
  return host.mode === 'ssh' ? `SSH ${host.target}` : 'Agent · waiting for first report';
}

// -- overview ----------------------------------------------------------------

function renderOverview() {
  document.title = 'ServerStats';
  const app = $('#app');
  app.replaceChildren($('#tpl-overview').content.cloneNode(true));
  const grid = $('#host-grid');
  const cards = new Map();

  const filter = $('#host-filter');
  filter.value = state.hostFilter;
  filter.addEventListener('input', () => { state.hostFilter = filter.value; draw(); });

  const updateBtn = $('#update-all');
  const updateNote = $('#update-all-note');
  const updatable = () => state.hosts.filter((x) => x.mode === 'agent' && x.update_available && x.updates && !x.update_pending
    && !(state.meta && x.update_failed === state.meta.agent_version));
  updateBtn.addEventListener('click', async () => {
    const list = updatable();
    const version = state.meta ? state.meta.agent_version : 'the latest version';
    if (!list.length || !confirm(`Update ${list.length} agent${list.length > 1 ? 's' : ''} to ${version}?\n\n`
      + `${list.map((x) => x.name).join(', ')}\n\nThey will download and run the agent code this server provides.`)) return;
    updateBtn.disabled = true;
    try {
      const r = await apiPost('/api/update-agents');
      const skipped = Object.keys(r.skipped || {});
      updateNote.textContent = `Update requested for ${r.queued.length}` + (skipped.length ? `; skipped ${skipped.join(', ')}` : '');
      await refreshHosts();
      draw();
    } catch (e) {
      updateNote.textContent = `Update failed: ${e.message}`;
    } finally {
      updateBtn.disabled = false;
    }
  });

  function draw() {
    // A refresh that finishes after navigating away has nothing to draw into.
    if (!document.body.contains(grid)) return;
    const q = state.hostFilter.trim().toLowerCase();
    $('#empty').hidden = state.hosts.length > 0;
    const n = updatable().length;
    updateBtn.hidden = n === 0;
    updateBtn.textContent = `Update agents (${n})`;
    const seen = new Set();
    state.hosts.forEach((host, i) => {
      let card = cards.get(host.name);
      if (!card) {
        card = $('#tpl-card').content.firstElementChild.cloneNode(true);
        cards.set(host.name, card);
      }
      updateCard(card, host, trendFor(host.name));
      card.hidden = !!q && ![host.name, host.hostname, host.os, host.description, host.target]
        .some((x) => x && x.toLowerCase().includes(q));
      if (grid.children[i] !== card) grid.insertBefore(card, grid.children[i] || null);
      seen.add(host.name);
    });
    for (const [name, card] of cards) {
      if (!seen.has(name)) { card.remove(); cards.delete(name); }
    }
  }

  let trends = null;
  function trendFor(name) {
    const tr = trends && trends.hosts[name];
    if (!tr) return { load: trends && trends.load && trends.load.hosts[name] };
    const series = (key) => tr.t.map((t, i) => ({ t, v: tr[key][i] })).filter((p) => p.v != null);
    return {
      cpu: series('cpu'), mem: series('mem'), disk: series('disk_util'), storage: series('storage'),
      load: trends.load && trends.load.hosts[name],
    };
  }

  every(5000, async () => { await refreshHosts(); draw(); });
  every(30000, async () => { trends = await api('/api/trends'); draw(); });
}

function updateCard(card, host, trend = {}) {
  card.href = '#/host/' + encodeURIComponent(host.name);
  card.classList.toggle('is-offline', host.status !== 'online');
  $('.host-name', card).textContent = host.name;
  setStatus($('.status', card), host.status);
  $('.host-sub', card).textContent = subline(host);

  const meters = [];
  if (host.cpu) {
    const disk = fullestDisk(host);
    const mem = host.memory || {};
    const keyed = (part, m) => { m.dataset.part = part; return m; };
    meters.push(
      h('div', { class: 'load-block' },
        loadMeter(trend.load && trend.load.load != null ? trend.load : null, 'avg'),
        loadMeter(trend.load && trend.load.high1, 'high')),
      keyed('cpu', meter('CPU', host.cpu.percent, `${host.cpu.count} cores`, trend.cpu || [])),
      keyed('mem', meter('Memory', mem.percent, `${fmtBytes(mem.used)} of ${fmtBytes(mem.total)} used`, trend.mem || [])),
      keyed('disk_util', meter('Disk I/O', host.disk_io ? host.disk_io.util : null,
        host.disk_io ? `Busiest disk. Read ${fmtRate(host.disk_io.read_rate)}, write ${fmtRate(host.disk_io.write_rate)}` : 'Not reported',
        trend.disk || [])),
      keyed('storage', meter('Storage', disk ? disk.percent : null,
        disk ? `Fullest filesystem: ${disk.mount} (${fmtBytes(disk.used)} of ${fmtBytes(disk.total)})` : 'No filesystems',
        trend.storage || [])),
    );
  }
  $('.meters', card).replaceChildren(...meters);

  const foot = $('.card-foot', card);
  const age = host.last_seen ? host.server_time - host.last_seen : null;
  const item = (label, value) => h('span', null, label + ' ', h('b', { text: value }));
  foot.replaceChildren(...[
    host.uptime != null && item('Up', fmtDuration(host.uptime)),
    item(host.status === 'online' ? 'Updated' : 'Last seen', fmtAgo(age)),
  ].filter(Boolean));

  const err = $('.card-error', card);
  err.hidden = !host.error;
  err.textContent = host.error || '';
}

// -- host detail -------------------------------------------------------------

function renderDetail(name) {
  document.title = `${name} · ServerStats`;
  const app = $('#app');
  app.replaceChildren($('#tpl-detail').content.cloneNode(true));
  $('#d-name').textContent = name;
  const enc = encodeURIComponent(name);
  const proc = state.proc;
  proc.limit = 50;
  let host = null;
  let procData = [];
  let history = null;

  // range selector
  const rangeBtns = [...document.querySelectorAll('#range button')];
  const markRange = () => rangeBtns.forEach((b) => {
    b.setAttribute('aria-checked', String(Number(b.dataset.hours) === state.range));
  });
  markRange();
  rangeBtns.forEach((b) => b.addEventListener('click', () => {
    state.range = Number(b.dataset.hours);
    savePref('range', state.range);
    markRange();
    loadHistory(true);
  }));

  // process table controls
  const filter = $('#proc-filter');
  filter.value = proc.filter;
  filter.addEventListener('input', () => { proc.filter = filter.value; proc.limit = 50; drawProcs(); });
  const pause = $('#proc-pause');
  pause.checked = proc.paused;
  pause.addEventListener('change', () => { proc.paused = pause.checked; if (!proc.paused && host) { procData = host.processes; drawProcs(); } });
  document.querySelectorAll('#proc-table th[data-sort]').forEach((th) => {
    th.tabIndex = 0;
    const sort = () => {
      const key = th.dataset.sort;
      if (proc.sortKey === key) proc.sortDir *= -1;
      else { proc.sortKey = key; proc.sortDir = ['user', 'name', 'state'].includes(key) ? 1 : -1; }
      drawProcs();
    };
    th.addEventListener('click', sort);
    th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sort(); } });
  });
  $('#proc-more').addEventListener('click', () => { proc.limit = Infinity; drawProcs(); });

  async function loadHost() {
    const before = Date.now() / 1000;
    try {
      host = await api(`/api/hosts/${enc}`);
    } catch (e) {
      if (e.status === 404) {
        clearTimers();
        app.replaceChildren(h('div', { class: 'empty' },
          h('h2', { text: 'Unknown host' }),
          h('p', null, h('a', { href: '#/' , text: 'Back to all hosts' }))));
      }
      throw e;
    }
    state.skew = host.server_time - before;
    if (!proc.paused) procData = host.processes || [];
    drawHost();
    drawDocker();
    drawProcs();
  }

  let historySeq = 0;
  let historyAt = 0;
  async function loadHistory(force) {
    // Long ranges are hourly averages; refetching them every 30s buys nothing.
    if (!force && state.range > 24 && Date.now() - historyAt < 300000) return;
    const seq = ++historySeq;
    const charts = document.querySelectorAll('.chart');
    charts.forEach((c) => c.classList.add('loading'));
    try {
      const data = await api(`/api/hosts/${enc}/history?hours=${state.range}`);
      if (seq !== historySeq) return; // a newer range was picked meanwhile
      history = data;
      historyAt = Date.now();
      drawCharts();
    } finally {
      if (seq === historySeq) charts.forEach((c) => c.classList.remove('loading'));
    }
  }

  const updateBtn = $('#d-update-btn');
  updateBtn.addEventListener('click', async () => {
    const version = state.meta ? state.meta.agent_version : 'the latest version';
    if (!confirm(`Update ${name}'s agent to ${version}? It will download and run the agent code this server provides.`)) return;
    updateBtn.disabled = true;
    try {
      await apiPost(`/api/hosts/${enc}/update`);
      await loadHost();
    } catch (e) {
      $('#d-update-text').textContent = `Couldn't request the update: ${e.message}`;
    } finally {
      updateBtn.disabled = false;
    }
  });

  function drawUpdate() {
    const row = $('#d-update');
    const latest = state.meta && state.meta.agent_version;
    let text = '', button = '';
    if (host.mode === 'agent' && host.agent_version) {
      if (host.update_failed && host.update_failed === latest) text = `The update to ${latest} failed to start on this host, so it's running ${host.agent_version}. Check its log, then rerun the installer to retry.`;
      else if (host.update_pending) text = `Update to ${latest} requested; the agent picks it up on its next report.`;
      else if (host.update_failed) text = `The update to ${host.update_failed} failed to start on this host, so it's running ${host.agent_version}. Check its log.`;
      else if (host.update_available && host.updates) { text = `Agent ${host.agent_version} · ${latest} is available.`; button = `Update agent to ${latest}`; }
      else if (host.update_available) text = `Agent ${host.agent_version} · ${latest} is available. This agent doesn't accept remote updates; rerun the installer on the host.`;
    }
    row.hidden = !text;
    $('#d-update-text').textContent = text;
    updateBtn.hidden = !button;
    updateBtn.textContent = button;
  }

  const removeBtn = $('#d-remove');
  removeBtn.addEventListener('click', async () => {
    if (!confirm(`Remove ${name} and all of its history? If its agent is still running it can't report any more; `
      + 'uninstall it on the host (install.sh --uninstall) or join again.')) return;
    try {
      await apiPost(`/api/hosts/${enc}/remove`);
      location.hash = '#/';
    } catch (e) {
      alert(`Couldn't remove ${name}: ${e.message}`);
    }
  });

  function drawHost() {
    markRange();
    drawUpdate();
    removeBtn.hidden = !host.enrolled;
    setStatus($('#d-status'), host.status);
    const sub = [
      host.description,
      host.os,
      host.kernel && `kernel ${host.kernel}`,
      host.arch,
      host.hostname && host.hostname !== host.name && `hostname ${host.hostname}`,
      host.mode === 'ssh' ? `SSH ${host.target}` : `agent ${host.agent_version || ''}`.trim(),
      host.host_key,
    ].filter(Boolean);
    $('#d-sub').textContent = sub.join(' · ');

    const banner = $('#d-error');
    const age = host.last_seen ? host.server_time - host.last_seen : null;
    let msg = host.error || '';
    if (!msg && host.status === 'offline') msg = `No report for ${fmtAgo(age).replace(' ago', '')}. Showing the last data received.`;
    if (!msg && host.status === 'pending') msg = host.mode === 'agent'
      ? 'Waiting for the agent to send its first report.'
      : 'Connecting over SSH…';
    banner.hidden = !msg;
    banner.textContent = msg;

    const tiles = $('#d-tiles');
    if (!host.cpu) { tiles.replaceChildren(); return; }
    const mem = host.memory || {};
    const dio = host.disk_io || {};
    const disk = fullestDisk(host);
    const net = host.net || {};
    const tasks = host.tasks || {};
    tiles.replaceChildren(
      tile('CPU', fmtPct(host.cpu.percent), `${host.cpu.count} cores · load ${(host.load || []).map((l) => l.toFixed(2)).join(' ')}`),
      tile('Memory', fmtPct(mem.percent),
        `${fmtBytes(mem.used)} of ${fmtBytes(mem.total)}` + (mem.swap_total ? ` · swap ${fmtBytes(mem.swap_used)}` : '')),
      tile('Disk I/O busy', fmtPct(dio.util), `read ${fmtRate(dio.read_rate)} · write ${fmtRate(dio.write_rate)}`),
      tile('Storage (fullest)', disk ? fmtPct(disk.percent) : '—',
        disk ? `${disk.mount} · ${fmtBytes(disk.free ?? disk.total - disk.used)} free` : 'no filesystems'),
      tile('Network in', fmtRate(net.rx_rate), `out ${fmtRate(net.tx_rate)}`),
      tile('Tasks', fmtNum(tasks.total),
        `${fmtNum(tasks.running)} running · ${fmtNum(tasks.threads)} threads` + (tasks.zombie ? ` · ${tasks.zombie} zombie` : '')),
      tile('Uptime', fmtDuration(host.uptime), `updated ${fmtAgo(age)}`),
    );

    // storage table
    const disks = (host.disks || []).slice().sort((a, b) => a.mount.localeCompare(b.mount));
    $('#storage-table tbody').replaceChildren(...(disks.length ? disks.map((d) => h('tr', null,
      h('td', { text: d.mount }),
      h('td', { class: 'muted', text: d.device }),
      h('td', { class: 'muted', text: d.fs }),
      h('td', { class: 'num', text: fmtBytes(d.used) }),
      h('td', { class: 'num', text: fmtBytes(d.free ?? d.total - d.used) }),
      h('td', { class: 'num', text: fmtBytes(d.total) }),
      h('td', null, meter(null, d.percent, `${d.mount}: ${fmtPct(d.percent)} used`)),
    )) : [h('tr', null, h('td', { colspan: 7, class: 'muted', text: 'No local filesystems reported' }))]));

    // disk activity table
    const devs = dio.devices || [];
    $('#diskio-table tbody').replaceChildren(...(devs.length ? devs.map((d) => h('tr', null,
      h('td', null, d.label, d.label !== d.name ? h('span', { class: 'muted', text: ` (${d.name})` }) : null),
      h('td', { class: 'num', text: fmtRate(d.read_rate) }),
      h('td', { class: 'num', text: fmtRate(d.write_rate) }),
      h('td', null, meter(null, d.util, `${d.label}: ${fmtPct(d.util)} busy`)),
    )) : [h('tr', null, h('td', { colspan: 4, class: 'muted', text: 'No disk activity reported' }))]));
  }

  // Stacks the user has expanded to show their containers.
  const expanded = new Set();

  function drawDocker() {
    const dk = host.docker;
    const ctl = host.docker_ctl; // null for SSH hosts and agents older than 1.4.0
    $('#docker-card').hidden = !dk && !(ctl && ctl.present);
    if ($('#docker-card').hidden) return;

    // On/off from the dashboard (agent hosts whose agent can read Docker).
    const on = ctl ? ctl.enabled : !!dk;
    const want = host.docker_pref != null ? host.docker_pref : on;
    const toggle = $('#docker-toggle');
    toggle.hidden = !(host.mode === 'agent' && ctl && ctl.available);
    toggle.textContent = want ? 'Turn off Docker stats' : 'Turn on Docker stats';
    toggle.dataset.want = String(!want);
    let stateText = '';
    if (host.mode === 'agent' && ctl && !ctl.available) {
      stateText = "Docker is running on this host, but the agent can't read it yet. Rerun the installer on this host once "
        + '(it sets up read-only access to Docker), then turn Docker stats on here.';
    } else if (want !== on) {
      stateText = want ? 'Turning Docker stats on; the agent picks this up on its next report.'
        : 'Turning Docker stats off; the agent picks this up on its next report.';
    } else if (!on) {
      stateText = "Docker stats are off for this host. Turn them on to see each compose stack's share of CPU, memory, "
        + 'disk and network. The agent reads Docker through a read-only helper; it never gets Docker access itself.';
    }
    $('#docker-state').hidden = !stateText;
    $('#docker-state').textContent = stateText;

    const err = $('#docker-error');
    err.hidden = !(dk && dk.error);
    err.textContent = (dk && dk.error) || '';
    const showData = !!(dk && !dk.error);
    $('#docker-body').hidden = !showData;
    if (!showData) {
      $('#docker-count').textContent = '';
      $('#docker-summary').textContent = '';
      $('#docker-note').textContent = '';
      return;
    }
    const containers = dk.containers || [];
    const ncpu = (host.cpu && host.cpu.count) || 1;

    // Group containers by compose project; standalone containers stand alone.
    const groups = new Map();
    const group = (key, name, kind) => {
      if (!groups.has(key)) groups.set(key, { key, name, kind, containers: [], volumeBytes: 0, volumes: 0 });
      return groups.get(key);
    };
    for (const c of containers) {
      if (c.project) group('p:' + c.project, c.project, 'stack').containers.push(c);
      else group('c:' + c.name, c.name, 'container').containers.push(c);
    }
    const diskKnown = Array.isArray(dk.volumes);
    for (const v of dk.volumes || []) {
      const g = v.project ? group('p:' + v.project, v.project, 'stack')
        : v.container ? group('c:' + v.container, v.container, 'container')
          : group('unused', 'Unused volumes', 'volumes');
      g.volumeBytes += v.size || 0;
      g.volumes += 1;
    }

    const total = (list, key) => {
      const vals = list.map((c) => c[key]).filter((v) => v != null);
      return vals.length ? vals.reduce((a, b) => a + b, 0) : null;
    };
    const pair = (a, b, fmt) => (a == null && b == null ? '—' : `${fmt(a)} / ${fmt(b)}`);
    const cells = (list, extraDisk) => {
      const cpu = total(list, 'cpu'), mem = total(list, 'mem'), memPct = total(list, 'mem_percent');
      const rw = total(list, 'disk');
      const disk = diskKnown ? (rw || 0) + extraDisk : null;
      return [
        h('td', null, meter(null, cpu == null ? null : cpu / ncpu,
          cpu == null ? 'Not measured' : `${fmtPct(cpu)} of one core (${ncpu} cores)`)),
        h('td', { class: 'mem-cell' }, meter(null, memPct, mem == null ? 'Not measured' : `${fmtBytes(mem)} of ${fmtBytes(host.memory.total)}`,
          null, mem == null ? '—' : `${fmtBytes(mem)} · ${fmtPct(memPct)}`)),
        h('td', { class: 'num', text: pair(total(list, 'read_rate'), total(list, 'write_rate'), fmtRate) }),
        h('td', { class: 'num', text: pair(total(list, 'rx_rate'), total(list, 'tx_rate'), fmtRate) }),
        h('td', { class: 'num', text: disk == null ? '—' : fmtBytes(disk) }),
      ];
    };

    const order = { stack: 0, container: 1, volumes: 2 };
    const rows = [];
    for (const g of [...groups.values()].sort((a, b) => order[a.kind] - order[b.kind] || a.name.localeCompare(b.name))) {
      const open = expanded.has(g.key);
      const canExpand = g.kind === 'stack' && g.containers.length > 0;
      const nameCell = h('td', { class: 'stack-name' },
        canExpand ? h('button', {
          class: 'expander', type: 'button', 'aria-expanded': String(open),
          'aria-label': `${open ? 'Hide' : 'Show'} containers in ${g.name}`,
          onclick: () => { if (open) expanded.delete(g.key); else expanded.add(g.key); drawDocker(); },
        }, open ? '▾' : '▸') : h('span', { class: 'expander-spacer' }),
        h('b', { text: g.name }),
        g.kind === 'container' && h('span', { class: 'muted', text: ' standalone' }),
        g.volumes ? h('span', { class: 'muted', text: ` · ${g.volumes} volume${g.volumes > 1 ? 's' : ''}` }) : null);
      if (g.kind === 'volumes') {
        rows.push(h('tr', { class: 'stack-row' }, nameCell, h('td', { class: 'num', text: '—' }),
          h('td'), h('td'), h('td'), h('td'), h('td', { class: 'num', text: fmtBytes(g.volumeBytes) })));
        continue;
      }
      rows.push(h('tr', { class: 'stack-row' }, nameCell,
        h('td', { class: 'num', text: g.containers.length }), ...cells(g.containers, g.volumeBytes)));
      if (open) {
        for (const c of g.containers) {
          rows.push(h('tr', { class: 'container-row' },
            h('td', { class: 'stack-name', title: `${c.image} · ${c.status}` },
              h('span', { class: 'expander-spacer' }), c.service || c.name,
              h('span', { class: 'muted', text: ` ${c.image}` })),
            h('td', { class: 'num muted', text: c.status.split(' ')[0] }),
            ...cells([c], 0)));
        }
      }
    }
    $('#docker-table tbody').replaceChildren(...(rows.length ? rows
      : [h('tr', null, h('td', { colspan: 7, class: 'muted', text: 'No running containers' }))]));

    const stacks = [...groups.values()].filter((g) => g.kind === 'stack').length;
    $('#docker-count').textContent = containers.length
      ? `${containers.length} running container${containers.length > 1 ? 's' : ''} · ${stacks} stack${stacks === 1 ? '' : 's'}` : '';
    const cpu = total(containers, 'cpu'), memPct = total(containers, 'mem_percent');
    $('#docker-summary').textContent = containers.length && cpu != null
      ? `Containers are using ${fmtPct(cpu / ncpu)} of this host's CPU and ${fmtPct(memPct)} of its memory.` : '';
    $('#docker-note').textContent = dk.error ? '' : diskKnown
      ? `Disk space is container writable layers plus their volumes (bind mounts not included), measured ${fmtAgo(serverNow() - dk.disk_at)}. CPU share is of all ${ncpu} cores.`
      : 'Disk space per stack is measured by the push agent every 15 minutes; it isn\'t available over SSH.';
  }

  $('#docker-toggle').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      await apiPost(`/api/hosts/${enc}/docker`, { enabled: btn.dataset.want === 'true' });
      await loadHost();
    } catch (err) {
      $('#docker-state').hidden = false;
      $('#docker-state').textContent = `Couldn't change the Docker setting: ${err.message}`;
    } finally {
      btn.disabled = false;
    }
  });

  function drawProcs() {
    const q = proc.filter.trim().toLowerCase();
    let rows = procData;
    if (q) {
      rows = rows.filter((p) => String(p.pid) === q
        || (p.name || '').toLowerCase().includes(q)
        || (p.cmd || '').toLowerCase().includes(q)
        || (p.user || '').toLowerCase().includes(q));
    }
    const { sortKey: key, sortDir: dir } = proc;
    rows = rows.slice().sort((a, b) => {
      const x = a[key], y = b[key];
      if (typeof x === 'number' && typeof y === 'number') return (x - y) * dir || a.pid - b.pid;
      return String(x ?? '').localeCompare(String(y ?? '')) * dir || a.pid - b.pid;
    });
    const shown = rows.slice(0, proc.limit);

    document.querySelectorAll('#proc-table th[data-sort]').forEach((th) => {
      if (th.dataset.sort === key) th.setAttribute('aria-sort', dir > 0 ? 'ascending' : 'descending');
      else th.removeAttribute('aria-sort');
    });
    $('#proc-count').textContent = host && host.tasks
      ? `${fmtNum(rows.length)} shown of ${fmtNum(host.tasks.total)}`
      : '';

    $('#proc-table tbody').replaceChildren(...shown.map((p) => {
      const cmd = p.cmd || p.name || '';
      const kernel = cmd.startsWith('[');
      return h('tr', null,
        h('td', { class: 'num', text: p.pid }),
        h('td', { text: p.user }),
        h('td', { class: 'num' + (p.cpu >= 50 ? ' hot' : ''), text: p.cpu.toFixed(1) }),
        h('td', { class: 'num' + (p.mem >= 20 ? ' hot' : ''), text: p.mem.toFixed(1) }),
        h('td', { class: 'num', text: fmtBytes(p.rss) }),
        h('td', { class: 'num', text: p.threads }),
        h('td', { text: p.state }),
        h('td', { class: 'num', text: fmtStarted(p.started) }),
        h('td', { class: 'cmd', title: cmd },
          kernel ? h('span', { class: 'pargs', text: cmd })
            : [h('span', { class: 'pname', text: p.name }), ' ', h('span', { class: 'pargs', text: cmd })]),
      );
    }));

    const more = $('#proc-more');
    more.hidden = rows.length <= shown.length;
    more.textContent = `Show all ${fmtNum(rows.length)} processes`;
  }

  function drawCharts() {
    if (!history) return;
    const x1 = serverNow();
    const x0 = x1 - state.range * 3600;
    const m = history.metrics || [];
    // Never break lines for gaps shorter than a host needs to be marked offline.
    const minGap = Math.max(history.bucket * 3, (state.meta ? state.meta.stale_after : 60) * 1.5);
    const pick = (key) => m.filter((r) => r[key] != null).map((r) => ({ t: r.t, v: r[key] }));
    // Tooltip time: long ranges are averaged per hour or more, so a date
    // (plus the year for 6 months and up) is what the reader needs.
    const tipTime = (t) => {
      const d = new Date(t * 1000);
      if (history.bucket >= 86400) {
        return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: state.range >= 4380 ? 'numeric' : undefined });
      }
      return fmtClock(t, state.range > 24);
    };
    const pickAt = (span) => (t) => openMoment(t, span);
    const common = { x0, x1, minGap, tipTime, pick: chartPick && chartPick.t, onPick: pickAt(history.bucket) };
    const fmtCount = (v) => (v == null ? '—' : (+v.toFixed(v < 10 ? 2 : 0)).toLocaleString());

    const usage = [
      { label: 'CPU', slot: 1, points: pick('cpu') },
      { label: 'Memory', slot: 2, points: pick('mem') },
      { label: 'Disk busy', slot: 3, points: pick('disk_util') },
    ];
    // Hosts without swap get no swap line rather than a flat 0%.
    const swap = pick('swap');
    if (swap.length) usage.push({ label: 'Swap', slot: 4, points: swap });
    lineChart($('#chart-usage'), { ...common, title: 'Utilization', yMax: 100, fmt: fmtPct, series: usage });

    const storage = history.storage || {};
    const mounts = Object.keys(storage).sort().slice(0, 8);
    lineChart($('#chart-storage'), {
      ...common, title: 'Storage used', yMax: 100, fmt: fmtPct,
      minGap: Math.max(history.bucket, 300) * 3,
      onPick: pickAt(Math.max(history.bucket, 300)), // storage is sampled every 5 minutes
      series: mounts.map((mount, i) => ({
        label: mount, slot: i + 1,
        points: storage[mount].map((r) => ({ t: r.t, v: r.total ? (100 * r.used) / r.total : 0, extra: `${fmtBytes(r.used)} of ${fmtBytes(r.total)}` })),
      })),
      empty: 'Storage is sampled every 5 minutes',
    });

    lineChart($('#chart-diskio'), {
      ...common, title: 'Disk I/O', bytes: true, fmt: fmtRate,
      series: [
        { label: 'Read', slot: 1, points: pick('disk_read') },
        { label: 'Write', slot: 2, points: pick('disk_write') },
      ],
    });

    lineChart($('#chart-net'), {
      ...common, title: 'Network', bytes: true, fmt: fmtRate,
      series: [
        { label: 'Received', slot: 1, points: pick('rx') },
        { label: 'Sent', slot: 2, points: pick('tx') },
      ],
    });

    lineChart($('#chart-load'), {
      ...common, title: 'Load average', count: true, fmt: fmtCount,
      series: [
        { label: '1 min', slot: 1, points: pick('load1') },
        { label: '5 min', slot: 2, points: pick('load5') },
        { label: '15 min', slot: 3, points: pick('load15') },
      ],
    });

    lineChart($('#chart-tasks'), {
      ...common, title: 'Tasks', count: true, fmt: fmtCount,
      series: [
        { label: 'Processes', slot: 1, points: pick('procs') },
        { label: 'Threads', slot: 2, points: pick('threads') },
      ],
    });
  }

  // -- load peaks: the past week's load, and what was running at its busiest --

  let week = null;
  let pick = null;       // start of the selected 5-minute slot
  let pickUser = false;  // chosen by the user, so refreshes keep it
  let momentSeq = 0;

  async function loadPeaks() {
    const data = await api(`/api/hosts/${enc}/load`);
    week = data;
    const keep = pickUser && pick != null && week.t.includes(pick);
    const before = pick;
    if (!keep) pick = week.peaks.length ? week.peaks[0].t : null;
    drawPeaks();
    if (pick != null && (pick !== before || !$('#peak-moment').childElementCount)) loadMoment(pick);
    if (pick == null) $('#peak-moment').replaceChildren();
  }

  function selectMoment(t) {
    pick = t;
    pickUser = true;
    // Redrawing replaces the chart; keep keyboard focus on it.
    const refocus = $('#chart-peaks').contains(document.activeElement);
    drawPeaks();
    if (refocus) $('#chart-peaks svg').focus();
    loadMoment(t);
  }

  function drawPeaks() {
    if (!week) return;
    const n = week.t.length;
    const now = serverNow();
    const stats = $('#peak-stats');
    const chips = $('#peak-chips');
    if (!n) {
      stats.replaceChildren();
      chips.replaceChildren();
      $('#chart-peaks').replaceChildren(h('p', { class: 'muted', text: 'No load history yet. It fills in as the host reports.' }));
      return;
    }
    const recent = week.t.map((t, i) => [t, i]).filter(([t]) => t >= now - 72 * 3600).map(([, i]) => i);
    const avg3 = recent.length ? recent.reduce((a, i) => a + week.load[i], 0) / recent.length : null;
    const avgParts = {};
    for (const [k] of LOAD_PARTS) avgParts[k] = recent.reduce((a, i) => a + (week.parts[k][i] || 0), 0) / (recent.length || 1);
    const mostly = (parts) => { const top = topPart(parts); return top ? `mostly ${top[2]}` : 'idle'; };
    const loadTile = (label, load, sub) => {
      const lvl = loadLevel(load);
      const t = tile(label, fmtPct(load), lvl ? `${LEVEL_LABEL[lvl]} · ${sub}` : sub);
      if (lvl) t.classList.add(`is-${lvl}`);
      return t;
    };
    const hi = week.high1;
    const peak = week.peaks[0];
    stats.replaceChildren(
      loadTile('Load · 3-day average', avg3, avg3 == null ? 'no data in the past 3 days' : mostly(avgParts)),
      loadTile('1% high · 7 days', hi.load, `${mostly(hi.parts)} · busiest ${fmtSpan(hi.slots / 12)} averaged`),
      loadTile('Busiest 5 minutes', peak ? peak.load : null, peak ? fmtWhen(peak.t) : ''),
    );

    loadChart($('#chart-peaks'), { week, x0: now - week.days * 86400, x1: now, pick, onPick: selectMoment });

    chips.replaceChildren(
      h('span', { class: 'muted', text: 'Busiest times:' }),
      ...week.peaks.map((p) => h('button', {
        class: 'chip' + levelClass(p.load), type: 'button', 'aria-pressed': String(p.t === pick),
        onclick: () => selectMoment(p.t),
      }, fmtWhen(p.t), ' ', h('b', { text: (loadLevel(p.load) ? '⚠ ' : '') + fmtPct(p.load) }))));
  }

  async function loadMoment(t) {
    const seq = ++momentSeq;
    const panel = $('#peak-moment');
    panel.classList.add('loading');
    let m;
    try {
      m = await api(`/api/hosts/${enc}/moment?t=${t}&span=${week.slot}`);
    } finally {
      if (seq === momentSeq) panel.classList.remove('loading');
    }
    if (seq !== momentSeq) return;
    panel.replaceChildren(...momentView(m, host));
  }

  // -- click any point on the history charts: what was happening then --

  let chartPick = null; // {t, span}
  let chartPickSeq = 0;
  async function openMoment(t, span) {
    chartPick = { t, span };
    const card = $('#moment-card');
    const body = $('#moment-body');
    // Redrawing replaces the charts; keep keyboard focus where it was.
    const focused = document.activeElement && document.activeElement.closest && document.activeElement.closest('.chart');
    drawCharts();
    if (focused && focused.id) $(`#${focused.id} svg`)?.focus();
    card.hidden = false;
    body.classList.add('loading');
    const seq = ++chartPickSeq;
    try {
      const m = await api(`/api/hosts/${enc}/moment?t=${t}&span=${span}`);
      if (seq !== chartPickSeq) return;
      body.replaceChildren(...momentView(m, host));
    } catch (e) {
      if (seq === chartPickSeq) body.replaceChildren(h('p', { class: 'muted', text: `Couldn't load that time: ${e.message}` }));
    } finally {
      if (seq === chartPickSeq) body.classList.remove('loading');
    }
    if (!focused) card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  $('#moment-close').addEventListener('click', () => {
    chartPick = null;
    ++chartPickSeq;
    $('#moment-card').hidden = true;
    drawCharts();
  });

  state.redraw = () => { drawCharts(); drawPeaks(); };
  every(5000, loadHost);
  every(30000, loadHistory);
  every(300000, loadPeaks);
}

// "5-minute", "42-minute", "3-hour"... for "N average".
function fmtSpanWord(secs) {
  if (secs < 60) return `${Math.round(secs)}-second`;
  if (secs < 3600) return `${Math.round(secs / 60)}-minute`;
  if (secs < 86400) return `${+(secs / 3600).toFixed(1)}-hour`;
  return `${+(secs / 86400).toFixed(1)}-day`;
}

// Everything about one stretch of time (from /api/hosts/{name}/moment):
// average stats, the load they add up to, and what was running at the
// busiest recorded moment in it.
function momentView(m, host) {
  const when = m.span >= 86400 ? `${fmtWhen(m.t)} – ${fmtWhen(m.t + m.span)}`
    : m.span >= 60 ? `${fmtWhen(m.t)}–${fmtClock(m.t + m.span, false)}`
      : new Date(m.t * 1000).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const st = m.stats;
  if (!st) {
    return [h('div', { class: 'moment-head' }, h('h3', { text: when })),
      h('p', { class: 'muted moment-note', text: 'No data was recorded for this time.' })];
  }
  const L = m.load;
  const kids = [
    h('div', { class: 'moment-head' },
      h('h3', { text: when }),
      h('span', { class: 'muted', text: 'load ' }), h('b', { text: fmtPct(L.load) }),
      h('span', { class: 'muted', text: ` (${fmtSpanWord(m.span)} average)` }), levelBadge(L.load)),
    loadTrack(L.parts, 'Load at this time', L.load),
    h('div', { class: 'moment-parts' },
      ...LOAD_PARTS.map(([k, name]) => h('div', { class: 'moment-part', 'data-part': k },
        h('span', { class: 'swatch' }),
        h('span', { text: name }),
        h('b', { text: L.values[k] == null ? '—' : `${fmtPct(L.values[k])} used` }),
        h('span', { class: 'muted', text: `${fmtPct(shareOf(L.parts[k], L.load))} of the load` })))),
  ];

  const n2 = (v) => (v == null ? '—' : (+v.toFixed(2)).toLocaleString());
  const mounts = (m.storage || []).filter((d) => d.total);
  const fullest = mounts.reduce((a, d) => (!a || d.used / d.total > a.used / a.total ? d : a), null);
  kids.push(h('div', { class: 'tiles moment-stats' },
    tile('CPU', fmtPct(st.cpu), `load ${n2(st.load1)} ${n2(st.load5)} ${n2(st.load15)}`),
    tile('Memory', fmtPct(st.mem), st.swap == null ? 'no swap' : `swap ${fmtPct(st.swap)}`),
    tile('Disk I/O busy', fmtPct(st.disk_util), `read ${fmtRate(st.disk_read)} · write ${fmtRate(st.disk_write)}`),
    tile('Network in', fmtRate(st.rx), `out ${fmtRate(st.tx)}`),
    tile('Storage (fullest)', fullest ? fmtPct((100 * fullest.used) / fullest.total) : fmtPct(st.storage),
      fullest ? `${fullest.mount} · ${fmtBytes(fullest.total - fullest.used)} free` : ''),
    tile('Tasks', st.procs == null ? '—' : fmtNum(Math.round(st.procs)), st.threads == null ? '' : `${fmtNum(Math.round(st.threads))} threads`)));

  const snap = m.snapshot;
  if (!snap) {
    kids.push(h('p', { class: 'muted moment-note', text: "What was running isn't recorded for this time. ServerStats "
      + 'keeps the busiest moment of every 5 minutes for 30 days, then of every hour, starting from when the server was updated to record it.' }));
    return kids;
  }
  const ncpu = snap.ncpu || (host && host.cpu && host.cpu.count) || 1;
  const procs = snap.processes || [];
  const byCpu = procs.slice().sort((a, b) => b.cpu - a.cpu).slice(0, 6).filter((p) => p.cpu > 0);
  const byMem = procs.slice().sort((a, b) => b.mem - a.mem).slice(0, 6).filter((p) => p.mem > 0);
  const procRow = (p, pct, value, part, title) => rankRow(part, p.name || String(p.pid), p.user, `${p.cmd || p.name} (PID ${p.pid})\n${title}`, pct, value);
  const lists = [
    rankList('Processes by CPU', 'Share of all cores', byCpu.map((p) => procRow(p, p.cpu / ncpu, fmtPct(p.cpu / ncpu), 'cpu',
      `${p.cpu.toFixed(0)}% of one core`))),
    rankList('Processes by memory', 'Share of RAM', byMem.map((p) => procRow(p, p.mem, fmtPct(p.mem), 'mem',
      `${fmtBytes(p.rss)} resident`))),
  ];
  if (snap.stacks && snap.stacks.length) {
    lists.push(
      rankList('Docker by CPU', 'Share of all cores', snap.stacks.slice().sort((a, b) => b.cpu - a.cpu).filter((x) => x.cpu > 0).map((x) =>
        rankRow('cpu', x.name, x.stack ? `${x.containers} container${x.containers > 1 ? 's' : ''}` : 'container',
          `${x.cpu.toFixed(0)}% of one core`, x.cpu / ncpu, fmtPct(x.cpu / ncpu)))),
      rankList('Docker by memory', 'Share of RAM', snap.stacks.slice().sort((a, b) => b.mem_percent - a.mem_percent).filter((x) => x.mem_percent > 0).map((x) =>
        rankRow('mem', x.name, fmtBytes(x.mem), `${fmtBytes(x.mem)} used`, x.mem_percent, fmtPct(x.mem_percent)))));
  }
  if ((snap.disks || []).length) {
    lists.push(rankList('Busiest disks', 'Time busy', snap.disks.map((d) => rankRow('disk_util', d.label, `${fmtRate(d.read_rate)} read · ${fmtRate(d.write_rate)} write`,
      `${d.label}: read ${fmtRate(d.read_rate)}, write ${fmtRate(d.write_rate)}`, d.util, fmtPct(d.util)))));
  }
  const within = m.span < 300 ? 'in the 5 minutes around this' : m.span <= 300 ? 'in these 5 minutes' : 'recorded in this span';
  kids.push(
    h('p', { class: 'moment-note' }, h('span', { class: 'muted', text: `What was running at the busiest moment ${within}, ` }),
      h('b', { text: m.span >= 86400 ? fmtWhen(snap.ts) : fmtClock(snap.ts, false) }),
      h('span', { class: 'muted', text: `, when load was ${fmtPct(snap.load)}:` })),
    h('div', { class: 'rank-grid' }, ...lists));
  return kids;
}

function fmtWhen(t) {
  return new Date(t * 1000).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// A short ranked list ("what was using the most X"), each row with a bar in
// its resource's color.
function rankList(title, unit, rows) {
  return h('div', { class: 'rank-list' },
    h('div', { class: 'rank-title' }, h('b', { text: title }), h('span', { class: 'muted', text: unit })),
    rows.length ? rows : h('p', { class: 'muted', text: 'Nothing notable' }));
}
function rankRow(part, name, sub, title, pct, value) {
  const m = meter(null, pct, title, null, value);
  m.dataset.part = part;
  return h('div', { class: 'rank-row', title },
    h('div', { class: 'rank-name' }, h('span', { class: 'pname', text: name }), sub ? h('span', { class: 'muted', text: ' ' + sub }) : null),
    m);
}

// -- load peaks chart: stacked areas per resource, 5-minute steps ------------

function loadChart(container, opts) {
  const { week, x0, x1, onPick } = opts;
  container.replaceChildren();
  const W = Math.max(container.clientWidth, 280);
  const H = 210;
  const M = { l: 44, r: 12, t: 12, b: 24 };
  const iw = W - M.l - M.r;
  const ih = H - M.t - M.b;
  const X = (t) => M.l + ((Math.min(Math.max(t, x0), x1) - x0) / (x1 - x0)) * iw;
  const Y = (v) => M.t + ih - (Math.min(Math.max(v, 0), 100) / 100) * ih;
  const slot = week.slot;
  const n = week.t.length;
  const hi = week.high1;

  const legend = h('div', { class: 'legend' },
    ...LOAD_PARTS.map(([k, name]) => h('span', { class: 'legend-item', 'data-part': k }, h('span', { class: 'swatch' }), name)),
    hi && h('span', { class: 'legend-item' }, h('span', { class: 'key key-dashed' }), '1% high ', h('b', { text: fmtPct(hi.load) })));
  container.append(legend);

  const root = svg('svg', {
    viewBox: `0 0 ${W} ${H}`, width: W, height: H, tabindex: 0, role: 'img',
    'aria-label': `Load over the past ${week.days} days, by resource. 1% high ${fmtPct(hi && hi.load)}. `
      + 'Use the arrow keys to move and Enter to see what was running.',
  });
  container.append(root);

  // 90-100%: the warning band
  root.append(svg('rect', { class: 'warn-zone', x: M.l, y: Y(100), width: iw, height: Y(90) - Y(100) }));
  for (const v of [0, 25, 50, 75, 100]) {
    root.append(svg('line', { class: v === 0 ? 'baseline' : 'grid', x1: M.l, x2: W - M.r, y1: Y(v), y2: Y(v) }));
    const label = svg('text', { class: 'tick', x: M.l - 8, y: Y(v) + 4, 'text-anchor': 'end' });
    label.textContent = `${v}%`;
    root.append(label);
  }
  timeAxis(root, { x0, x1, X, iw, W, M, H });

  // Contiguous runs of slots; a gap (host offline) breaks the areas.
  const runs = [];
  for (let i = 0; i < n; i++) {
    if (i && week.t[i] - week.t[i - 1] <= 3 * slot) runs[runs.length - 1].push(i);
    else runs.push([i]);
  }
  for (const run of runs) {
    const lower = run.map(() => 0);
    for (const [k] of LOAD_PARTS) {
      const upper = run.map((i, j) => lower[j] + (week.parts[k][i] || 0));
      let top = '', bottom = '';
      run.forEach((i, j) => {
        const xa = X(week.t[i]).toFixed(1), xb = X(week.t[i] + slot).toFixed(1);
        top += `${j ? 'L' : 'M'}${xa},${Y(upper[j]).toFixed(1)}L${xb},${Y(upper[j]).toFixed(1)}`;
        bottom = `L${xb},${Y(lower[j]).toFixed(1)}L${xa},${Y(lower[j]).toFixed(1)}` + bottom;
      });
      root.append(svg('path', { class: 'area', 'data-part': k, d: top + bottom + 'Z' }));
      upper.forEach((v, j) => { lower[j] = v; });
    }
  }

  if (hi) {
    const y = Y(hi.load);
    root.append(svg('line', { class: 'high-line', x1: M.l, x2: W - M.r, y1: y, y2: y }));
    const label = svg('text', { class: 'high-label', x: W - M.r - 4, y: y - 5, 'text-anchor': 'end' });
    label.textContent = `1% high ${fmtPct(hi.load)}`;
    root.append(label);
  }

  // Selected time
  if (opts.pick != null) {
    const x = X(opts.pick + slot / 2);
    const i = week.t.indexOf(opts.pick);
    root.append(svg('line', { class: 'pick-line', x1: x, x2: x, y1: M.t, y2: M.t + ih }));
    if (i >= 0) root.append(svg('circle', { class: 'pick-dot', cx: x, cy: Y(week.load[i]), r: 4.5 }));
  }

  // hover: crosshair + breakdown; click or Enter picks that time
  const cross = svg('line', { class: 'crosshair', y1: M.t, y2: M.t + ih, visibility: 'hidden' });
  const hit = svg('rect', { x: M.l, y: M.t, width: iw, height: ih, fill: 'transparent', class: 'hit' });
  root.append(cross, hit);
  const tip = $('#tooltip');
  let idx = -1;

  function show(i, clientX, clientY) {
    if (!n) return;
    idx = Math.max(0, Math.min(n - 1, i));
    const t = week.t[idx];
    const x = X(t + slot / 2);
    cross.setAttribute('x1', x);
    cross.setAttribute('x2', x);
    cross.setAttribute('visibility', 'visible');
    tip.replaceChildren(
      h('div', { class: 'tt-time', text: `${fmtWhen(t)}–${fmtClock(t + slot, false)}` }),
      h('div', { class: 'tt-row' }, h('span', { class: 'key key-blank' }), h('b', { text: fmtPct(week.load[idx]) }),
        h('span', { text: loadLevel(week.load[idx]) ? `Load · ${LEVEL_LABEL[loadLevel(week.load[idx])]}` : 'Load' })),
      ...LOAD_PARTS.map(([k, name]) => h('div', { class: 'tt-row', 'data-part': k },
        h('span', { class: 'swatch' }), h('b', { text: fmtPct(shareOf(week.parts[k][idx], week.load[idx])) }),
        h('span', { text: `${name}'s share · ${fmtPct(week.values[k][idx])} used` }))),
      h('div', { class: 'tt-hint', text: 'Click to see what was running' }));
    tip.hidden = false;
    const rect = root.getBoundingClientRect();
    if (clientX == null) {
      clientX = rect.left + (x / W) * rect.width;
      clientY = rect.top + M.t;
    }
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = clientX + 14;
    if (left + tw > window.innerWidth - 8) left = clientX - tw - 14;
    tip.style.left = Math.max(8, left) + 'px';
    tip.style.top = Math.max(8, Math.min(clientY - th / 2, window.innerHeight - th - 8)) + 'px';
  }
  function hide() {
    idx = -1;
    tip.hidden = true;
    cross.setAttribute('visibility', 'hidden');
  }
  function nearest(clientX) {
    const rect = root.getBoundingClientRect();
    const t = x0 + ((((clientX - rect.left) / rect.width) * W - M.l) / iw) * (x1 - x0) - slot / 2;
    let best = 0;
    for (let i = 1; i < n; i++) if (Math.abs(week.t[i] - t) < Math.abs(week.t[best] - t)) best = i;
    return best;
  }

  hit.addEventListener('pointermove', (e) => show(nearest(e.clientX), e.clientX, e.clientY));
  hit.addEventListener('pointerleave', hide);
  hit.addEventListener('click', (e) => { const i = nearest(e.clientX); hide(); onPick(week.t[i]); });
  root.addEventListener('focus', () => show(opts.pick != null ? week.t.indexOf(opts.pick) : n - 1));
  root.addEventListener('blur', hide);
  root.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault();
      show((idx < 0 ? n - 1 : idx) + (e.key === 'ArrowLeft' ? -1 : 1));
    } else if (e.key === 'Enter' && idx >= 0) {
      e.preventDefault();
      onPick(week.t[idx]);
    } else if (e.key === 'Escape') {
      hide();
    }
  });
}

// -- line chart --------------------------------------------------------------

function niceStep(raw) {
  const mag = 10 ** Math.floor(Math.log10(raw));
  const n = raw / mag;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * mag;
}

function yScale(max, opts) {
  if (opts.yMax) {
    const step = opts.yMax / 4;
    return { top: opts.yMax, ticks: [0, 1, 2, 3, 4].map((i) => i * step), label: (v) => `${+v.toFixed(1)}%` };
  }
  if (opts.count) {
    max = Math.max(max, 1);
    const step = niceStep(max / 4);
    const top = Math.ceil(max / step) * step;
    const ticks = [];
    for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v);
    return { top, ticks, label: (v) => (+v.toFixed(2)).toLocaleString() };
  }
  // Byte rates: pick a binary unit first so ticks land on round numbers of it.
  max = Math.max(max, 1024);
  const k = Math.min(Math.floor(Math.log(max) / Math.log(1024)), UNITS.length - 1);
  const unit = 1024 ** k;
  const step = niceStep(max / unit / 4);
  const top = Math.ceil(max / unit / step) * step;
  const ticks = [];
  for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v * unit);
  return { top: top * unit, ticks, label: (v) => `${+(v / unit).toFixed(2)} ${UNITS[k]}/s` };
}

// Typical spacing between samples. Lines only break for gaps well beyond it,
// so a host polled every few minutes still draws as a line while a real
// outage shows up as a gap.
function cadence(times) {
  const steps = [];
  for (let i = 1; i < times.length; i++) steps.push(times[i] - times[i - 1]);
  if (!steps.length) return 0;
  steps.sort((a, b) => a - b);
  return steps[(steps.length - 1) >> 1]; // lower median: few samples shouldn't bridge a real gap
}

const TIME_STEPS = [300, 600, 900, 1800, 3600, 7200, 10800, 14400, 21600, 43200, 86400, 172800, 259200, 604800, 1209600];
const MIN_TICK_GAP = 76; // px between x-axis labels

// x axis: steps aligned to local time (months for long ranges)
function timeAxis(root, { x0, x1, X, iw, W, M, H }) {
  const span = x1 - x0;
  const maxTicks = Math.max(2, Math.floor(iw / MIN_TICK_GAP));
  const xTicks = [];
  if (span > 90 * 86400) {
    // Months, starting at the first 1st-of-the-month in range.
    const d = new Date(x0 * 1000);
    d.setDate(1);
    d.setHours(0, 0, 0, 0);
    d.setMonth(d.getMonth() + 1);
    const months = [];
    while (d.getTime() / 1000 <= x1) {
      months.push(d.getTime() / 1000);
      d.setMonth(d.getMonth() + 1);
    }
    const every = Math.ceil(months.length / maxTicks);
    months.filter((_, i) => i % every === 0).forEach((t) => xTicks.push([t,
      new Date(t * 1000).toLocaleDateString([], { month: 'short', year: '2-digit' })]));
  } else {
    const step = TIME_STEPS.find((s) => span / s <= maxTicks) || TIME_STEPS[TIME_STEPS.length - 1];
    const off = -new Date().getTimezoneOffset() * 60;
    for (let t = Math.ceil((x0 + off) / step) * step - off; t <= x1; t += step) {
      xTicks.push([t, step >= 86400
        ? new Date(t * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' })
        : fmtClock(t, false)]);
    }
  }
  for (const [t, text] of xTicks) {
    const x = X(t);
    if (x < M.l + 16 || x > W - M.r - 16) continue;
    const label = svg('text', { class: 'tick', x, y: H - 6, 'text-anchor': 'middle' });
    label.textContent = text;
    root.append(label);
  }
}

function lineChart(container, opts) {
  const { series, x0, x1, fmt } = opts;
  container.replaceChildren();

  const W = Math.max(container.clientWidth, 280);
  const H = 190;
  const M = { l: 64, r: 12, t: 10, b: 24 };
  const iw = W - M.l - M.r;
  const ih = H - M.t - M.b;
  const X = (t) => M.l + ((t - x0) / (x1 - x0)) * iw;

  const visible = series.map((s) => ({ ...s, points: s.points.filter((p) => p.t >= x0 - 3600) }));
  const allTimes = [...new Set(visible.flatMap((s) => s.points.map((p) => p.t)))].sort((a, b) => a - b);
  const gap = Math.max(opts.minGap || 0, 3 * cadence(allTimes));
  const hasData = visible.some((s) => s.points.some((p) => p.t >= x0));
  const maxV = Math.max(0, ...visible.flatMap((s) => s.points.map((p) => p.v)));
  const ys = yScale(maxV, opts);
  const Y = (v) => M.t + ih - (Math.min(v, ys.top) / ys.top) * ih;

  // Legend doubles as the latest-value readout.
  const legend = h('div', { class: 'legend' });
  for (const s of visible) {
    const last = s.points.length ? s.points[s.points.length - 1].v : null;
    legend.append(h('span', { class: `legend-item c${s.slot}` },
      h('span', { class: 'key' }), s.label, ' ', h('b', { text: fmt(last) })));
  }
  container.append(legend);

  const root = svg('svg', {
    viewBox: `0 0 ${W} ${H}`, width: W, height: H, tabindex: 0, role: 'img',
    'aria-label': `${opts.title}. Latest: ` + visible.map((s) => `${s.label} ${fmt(s.points.length ? s.points[s.points.length - 1].v : null)}`).join(', '),
  });
  container.append(root);

  // grid + y axis
  for (const t of ys.ticks) {
    root.append(svg('line', { class: t === 0 ? 'baseline' : 'grid', x1: M.l, x2: W - M.r, y1: Y(t), y2: Y(t) }));
    const label = svg('text', { class: 'tick', x: M.l - 8, y: Y(t) + 4, 'text-anchor': 'end' });
    label.textContent = ys.label(t);
    root.append(label);
  }

  timeAxis(root, { x0, x1, X, iw, W, M, H });

  if (!hasData) {
    const msg = svg('text', { class: 'empty-msg', x: M.l + iw / 2, y: M.t + ih / 2, 'text-anchor': 'middle' });
    msg.textContent = opts.empty && visible.length === 0 ? opts.empty : 'No data for this range yet';
    root.append(msg);
    return;
  }

  // clip so lines that start before x0 don't bleed over the axis
  const clipId = 'clip-' + Math.random().toString(36).slice(2);
  const clip = svg('clipPath', { id: clipId });
  clip.append(svg('rect', { x: M.l, y: 0, width: iw, height: H }));
  root.append(clip);

  for (const s of visible) {
    let d = '';
    const lone = [];
    s.points.forEach((p, i) => {
      const pt = X(p.t).toFixed(1) + ',' + Y(p.v).toFixed(1);
      const prev = s.points[i - 1], next = s.points[i + 1];
      if (prev && p.t - prev.t <= gap) d += 'L' + pt;
      else {
        d += 'M' + pt;
        // A sample with no neighbours has no line to sit on; mark it instead.
        // (The newest sample already gets the end dot.)
        if (next && next.t - p.t > gap && p.t >= x0) lone.push(p);
      }
    });
    root.append(svg('path', { class: `line c${s.slot}`, d, 'clip-path': `url(#${clipId})` }));
    for (const p of lone) root.append(svg('circle', { class: `dot c${s.slot}`, cx: X(p.t), cy: Y(p.v), r: 3 }));
    const last = s.points[s.points.length - 1];
    if (last && last.t >= x0) root.append(svg('circle', { class: `dot c${s.slot}`, cx: X(last.t), cy: Y(last.v), r: 4 }));
  }

  // the picked time (see openMoment)
  if (opts.pick != null && opts.pick >= x0 && opts.pick <= x1) {
    root.append(svg('line', { class: 'pick-line', x1: X(opts.pick), x2: X(opts.pick), y1: M.t, y2: M.t + ih }));
  }

  // hover layer: crosshair snaps to the nearest sample time
  const times = allTimes.filter((t) => t >= x0);
  const lookup = visible.map((s) => new Map(s.points.map((p) => [p.t, p])));
  const cross = svg('line', { class: 'crosshair', y1: M.t, y2: M.t + ih, visibility: 'hidden' });
  const dots = visible.map((s) => svg('circle', { class: `dot c${s.slot}`, r: 4, visibility: 'hidden' }));
  const hit = svg('rect', { x: M.l, y: M.t, width: iw, height: ih, fill: 'transparent', class: opts.onPick ? 'hit' : null });
  root.append(cross, ...dots, hit);

  const tip = $('#tooltip');
  let idx = -1;

  function show(i, clientX, clientY) {
    idx = Math.max(0, Math.min(times.length - 1, i));
    const t = times[idx];
    const x = X(t);
    cross.setAttribute('x1', x);
    cross.setAttribute('x2', x);
    cross.setAttribute('visibility', 'visible');
    const rows = [];
    visible.forEach((s, si) => {
      const p = lookup[si].get(t);
      if (p) {
        dots[si].setAttribute('cx', x);
        dots[si].setAttribute('cy', Y(p.v));
        dots[si].setAttribute('visibility', 'visible');
      } else {
        dots[si].setAttribute('visibility', 'hidden');
      }
      rows.push(h('div', { class: `tt-row c${s.slot}` },
        h('span', { class: 'key' }),
        h('b', { text: p ? fmt(p.v) : '—' }),
        h('span', { text: p && p.extra ? `${s.label} · ${p.extra}` : s.label })));
    });
    tip.replaceChildren(h('div', { class: 'tt-time', text: opts.tipTime ? opts.tipTime(t) : fmtClock(t, false) }), ...rows,
      opts.onPick ? h('div', { class: 'tt-hint', text: 'Click to see what was running' }) : null);
    tip.hidden = false;
    const rect = root.getBoundingClientRect();
    if (clientX == null) {
      clientX = rect.left + (x / W) * rect.width;
      clientY = rect.top + M.t;
    }
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = clientX + 14;
    if (left + tw > window.innerWidth - 8) left = clientX - tw - 14;
    tip.style.left = Math.max(8, left) + 'px';
    tip.style.top = Math.max(8, Math.min(clientY - th / 2, window.innerHeight - th - 8)) + 'px';
  }
  function hide() {
    idx = -1;
    tip.hidden = true;
    cross.setAttribute('visibility', 'hidden');
    dots.forEach((d) => d.setAttribute('visibility', 'hidden'));
  }
  function nearest(t) {
    let lo = 0, hi = times.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (times[mid] < t) lo = mid + 1; else hi = mid;
    }
    return lo > 0 && t - times[lo - 1] < times[lo] - t ? lo - 1 : lo;
  }

  hit.addEventListener('pointermove', (e) => {
    const rect = root.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * W;
    show(nearest(x0 + ((x - M.l) / iw) * (x1 - x0)), e.clientX, e.clientY);
  });
  hit.addEventListener('pointerleave', hide);
  if (opts.onPick) {
    hit.addEventListener('click', (e) => {
      const rect = root.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * W;
      const i = nearest(x0 + ((x - M.l) / iw) * (x1 - x0));
      hide();
      if (times.length) opts.onPick(times[i]);
    });
  }
  root.addEventListener('focus', () => show(times.length - 1));
  root.addEventListener('blur', hide);
  root.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault();
      show((idx < 0 ? times.length - 1 : idx) + (e.key === 'ArrowLeft' ? -1 : 1));
    } else if (e.key === 'Enter' && idx >= 0 && opts.onPick) {
      e.preventDefault();
      opts.onPick(times[idx]);
    } else if (e.key === 'Escape') {
      hide();
    }
  });
}

// -- prune dialog ------------------------------------------------------------

function setupPrune() {
  const dialog = $('#prune-dialog');
  const ages = $('#prune-ages');
  const hostSel = $('#prune-host');
  const preview = $('#prune-preview');
  const go = $('#prune-go');
  let days = null;
  let seq = 0;
  let busy = false;
  const label = () => (state.meta.prune_options.find((o) => o.days === days) || {}).label;
  const fmtDate = (t) => new Date(t * 1000).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });

  async function refresh() {
    const n = ++seq;
    const host = hostSel.value;
    ages.querySelectorAll('button').forEach((b) => b.setAttribute('aria-checked', String(Number(b.dataset.days) === days)));
    go.disabled = true;
    go.textContent = `Delete history older than ${label()}`;
    preview.textContent = 'Checking…';
    try {
      const p = await api(`/api/prune?days=${days}` + (host ? `&host=${encodeURIComponent(host)}` : ''));
      if (n !== seq) return;
      if (!p.rows) {
        preview.textContent = `Nothing ${host ? `for ${host} ` : ''}is older than ${label()} (before ${fmtDate(p.cutoff)}).`;
        return;
      }
      const who = host || (p.hosts.length === 1 ? p.hosts[0] : `${p.hosts.length} hosts`);
      preview.replaceChildren('This permanently deletes ', h('strong', { text: `${fmtNum(p.rows)} data points` }),
        ` for ${who}, from ${fmtDate(p.oldest)} up to ${fmtDate(p.cutoff)}. It can't be undone.`);
      go.disabled = busy;
    } catch (e) {
      if (n === seq) preview.textContent = `Couldn't check: ${e.message}`;
    }
  }

  async function open() {
    if (!state.meta) state.meta = await api('/api/meta');
    if (!ages.childElementCount) {
      ages.replaceChildren(...state.meta.prune_options.map((o) => h('button', {
        type: 'button', role: 'radio', 'data-days': o.days, text: o.label,
        onclick: () => { days = o.days; refresh(); },
      })));
    }
    const current = hostSel.value;
    const names = (state.hosts || []).map((x) => x.name).sort((a, b) => a.localeCompare(b));
    hostSel.replaceChildren(h('option', { value: '', text: 'All hosts' }), ...names.map((n) => h('option', { value: n, text: n })));
    hostSel.value = names.includes(current) ? current : '';
    if (days == null) days = 365;
    dialog.showModal();
    refresh();
  }

  hostSel.addEventListener('change', refresh);
  go.addEventListener('click', async () => {
    const host = hostSel.value;
    if (!confirm(`Delete all history older than ${label()} for ${host || 'all hosts'}? This can't be undone.`)) return;
    busy = true;
    go.disabled = true;
    preview.textContent = 'Deleting…';
    try {
      const r = await apiPost('/api/prune', { days, host: host || null });
      preview.textContent = r.rows
        ? `Deleted ${fmtNum(r.rows)} data points` + (r.freed ? ` and freed ${fmtBytes(r.freed)}.` : '.')
        : 'Nothing to delete.';
      route(); // re-fetch whatever page is open behind the dialog
    } catch (e) {
      preview.textContent = `Couldn't prune: ${e.message}`;
    } finally {
      busy = false;
    }
  });
  $('#prune-btn').addEventListener('click', open);
  dialog.querySelectorAll('[data-action="close"]').forEach((b) => b.addEventListener('click', () => dialog.close()));
  dialog.addEventListener('click', (e) => { if (e.target === dialog) dialog.close(); });
}

// -- add host dialog ---------------------------------------------------------

function setupDialog() {
  const dialog = $('#add-dialog');
  const origin = location.origin;
  let token = '';

  const quote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
  const yamlName = (s) => (/^[A-Za-z0-9._-]+$/.test(s) ? s : JSON.stringify(s));

  function update() {
    const docker = $('#add-docker').checked ? ' --docker' : '';
    $('#docker-warning').hidden = !docker;
    const joinKey = state.meta && state.meta.join_key;
    $('#join-flow').hidden = !joinKey;
    $('#token-flow').hidden = !!joinKey;
    const installer = `curl -fsSL ${origin}/api/agent/install.sh | sudo sh -s -- --url ${quote(origin)}`;
    if (joinKey) {
      const name = $('#agent-name').value.trim();
      $('#agent-install').textContent =
        `${installer} --join ${quote(joinKey)}${name ? ' --name ' + quote(name) : ''}${docker}`;
    }
    const aName = $('#agent-name-cfg').value.trim() || 'my-server';
    $('#agent-config').textContent =
      `hosts:\n  - name: ${yamlName(aName)}\n    mode: agent\n    token: ${token}`;
    $('#agent-install-token').textContent = `${installer} --token ${token}${docker}`;

    const sName = $('#ssh-name').value.trim() || 'my-server';
    const addr = $('#ssh-address').value.trim() || '192.168.1.10';
    const key = state.meta ? state.meta.ssh_public_key : '<loading…>';
    $('#ssh-setup').textContent =
      `curl -fsSL ${origin}/api/agent/install.sh | sudo sh -s -- --url ${quote(origin)} --ssh-key ${quote(key)}${docker}`;
    $('#ssh-config').textContent =
      `hosts:\n  - name: ${yamlName(sName)}\n    mode: ssh\n    address: ${yamlName(addr)}\n    user: serverstats`;
  }

  function open() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    token = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
    update();
    dialog.showModal();
  }

  $('#add-host-btn').addEventListener('click', open);
  document.addEventListener('click', (e) => {
    if (e.target.closest('[data-action="add-host"]')) open();
    if (e.target.closest('[data-action="reload"]')) location.reload();
  });
  dialog.querySelector('[data-action="close"]').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', (e) => { if (e.target === dialog) dialog.close(); });
  ['#agent-name', '#agent-name-cfg', '#ssh-name', '#ssh-address', '#add-docker'].forEach((id) => $(id).addEventListener('input', update));
  $('#rotate-join').addEventListener('click', async () => {
    if (!confirm('Make a new join key? The current one stops working for new hosts; hosts that already joined are unaffected.')) return;
    try {
      const r = await apiPost('/api/join-key/rotate');
      state.meta.join_key = r.join_key;
      update();
    } catch (e) {
      alert(`Couldn't make a new join key: ${e.message}`);
    }
  });

  dialog.querySelectorAll('[role="tab"]').forEach((tab) => tab.addEventListener('click', () => {
    dialog.querySelectorAll('[role="tab"]').forEach((t) => t.setAttribute('aria-selected', String(t === tab)));
    dialog.querySelectorAll('[data-panel]').forEach((p) => { p.hidden = p.dataset.panel !== tab.dataset.tab; });
  }));

  dialog.querySelectorAll('pre.code').forEach((pre) => pre.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pre.textContent);
      pre.classList.add('copied');
      setTimeout(() => pre.classList.remove('copied'), 1200);
    } catch {
      getSelection().selectAllChildren(pre);
    }
  }));
}

// -- boot --------------------------------------------------------------------

function route() {
  clearTimers();
  state.redraw = null;
  $('#tooltip').hidden = true;
  const m = location.hash.match(/^#\/host\/(.+)$/);
  if (m) renderDetail(decodeURIComponent(m[1]));
  else renderOverview();
  window.scrollTo(0, 0);
}

async function boot() {
  setupDialog();
  setupPrune();
  window.addEventListener('hashchange', route);
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => state.redraw && state.redraw(), 150);
  });
  // Polling pauses while the tab is hidden; catch up as soon as it's visible.
  document.addEventListener('visibilitychange', () => { if (!document.hidden) state.ticks.forEach((t) => t()); });
  route();
  try {
    state.meta = await api('/api/meta');
    if (state.meta.user) {
      const user = $('#user');
      user.textContent = state.meta.user;
      user.hidden = false;
    }
  } catch (e) { console.warn(e); }
}

boot();
