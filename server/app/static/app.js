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
async function apiPost(path) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { Accept: 'application/json', 'X-ServerStats-Action': '1' },
    credentials: 'same-origin',
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
  return body;
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
  drawUpdateAll();
}

// -- update all agents (top bar) -----------------------------------------------

// Agents the server can update right now.
function updatableAgents() {
  return state.hosts.filter((x) => x.mode === 'agent' && x.update_available && x.updates && !x.update_pending
    && !(state.meta && x.update_failed === state.meta.agent_version));
}

function drawUpdateAll() {
  const btn = $('#update-all');
  const agents = state.hosts.filter((x) => x.mode === 'agent');
  const latest = state.meta ? state.meta.agent_version : 'the latest version';
  const ready = updatableAgents();
  const updating = agents.filter((x) => x.update_pending);
  // Outdated, but not updatable from here (remote updates off, or the update failed there).
  const manual = agents.filter((x) => x.update_available && !x.update_pending && !ready.includes(x));
  const names = (list) => list.map((x) => x.name).join(', ');
  btn.hidden = agents.length === 0;
  btn.disabled = ready.length === 0 || btn.dataset.busy === '1';
  if (ready.length) {
    btn.textContent = `Update agents (${ready.length})`;
    btn.title = `Update ${names(ready)} to agent ${latest}`;
  } else if (updating.length) {
    btn.textContent = `Updating ${updating.length} agent${updating.length > 1 ? 's' : ''}…`;
    btn.title = names(updating);
  } else if (manual.length) {
    btn.textContent = `${manual.length} agent${manual.length > 1 ? 's' : ''} need a manual update`;
    btn.title = `Rerun the installer on ${names(manual)} to update ${manual.length > 1 ? 'them' : 'it'}; `
      + 'the host page says why.';
  } else {
    btn.textContent = 'All agents up to date';
    btn.title = `Every agent runs ${latest}`;
  }
}

function setupUpdateAll() {
  const btn = $('#update-all');
  const note = $('#update-all-note');
  let hideNote;
  const say = (text) => {
    note.textContent = text;
    note.hidden = false;
    clearTimeout(hideNote);
    hideNote = setTimeout(() => { note.hidden = true; }, 15000);
  };
  btn.addEventListener('click', async () => {
    const list = updatableAgents();
    const version = state.meta ? state.meta.agent_version : 'the latest version';
    if (!list.length || !confirm(`Update ${list.length} agent${list.length > 1 ? 's' : ''} to ${version}?\n\n`
      + `${list.map((x) => x.name).join(', ')}\n\nThey will download and run the agent code this server provides.`)) return;
    btn.dataset.busy = '1';
    btn.disabled = true;
    try {
      const r = await apiPost('/api/update-agents');
      const skipped = Object.keys(r.skipped || {});
      say(`Update requested for ${r.queued.length}` + (skipped.length ? `; skipped ${skipped.join(', ')}` : ''));
      await refreshHosts();
    } catch (e) {
      say(`Update failed: ${e.message}`);
    } finally {
      delete btn.dataset.busy;
      drawUpdateAll();
    }
  });
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

function cores(n) {
  return `${n} core${n === 1 ? '' : 's'}`;
}

function subline(host) {
  const parts = [
    host.description,
    host.os,
    host.cpu && cores(host.cpu.count),
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

  function draw() {
    const q = state.hostFilter.trim().toLowerCase();
    $('#empty').hidden = state.hosts.length > 0;
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
    if (!tr) return {};
    const series = (key) => tr.t.map((t, i) => ({ t, v: tr[key][i] })).filter((p) => p.v != null);
    return {
      cpu: series('cpu'), mem: series('mem'), swap: series('swap'), disk: series('disk_util'), storage: series('storage'),
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
    meters.push(
      meter('CPU', host.cpu.percent, cores(host.cpu.count), trend.cpu || []),
      meter('Memory', mem.percent, `${fmtBytes(mem.used)} of ${fmtBytes(mem.total)} used`, trend.mem || []),
      mem.swap_total
        ? meter('Swap', 100 * (mem.swap_used || 0) / mem.swap_total,
          `${fmtBytes(mem.swap_used || 0)} of ${fmtBytes(mem.swap_total)} swap used`, trend.swap || [])
        : meter('Swap', null, 'No swap configured on this host', [], 'None'),
      meter('Disk I/O', host.disk_io ? host.disk_io.util : null,
        host.disk_io ? `Busiest disk. Read ${fmtRate(host.disk_io.read_rate)}, write ${fmtRate(host.disk_io.write_rate)}` : 'Not reported',
        trend.disk || []),
      meter('Storage', disk ? disk.percent : null,
        disk ? `Fullest filesystem: ${disk.mount} (${fmtBytes(disk.used)} of ${fmtBytes(disk.total)})` : 'No filesystems',
        trend.storage || []),
    );
  }
  $('.meters', card).replaceChildren(...meters);

  const foot = $('.card-foot', card);
  const age = host.last_seen ? host.server_time - host.last_seen : null;
  const item = (label, value) => h('span', null, label + ' ', h('b', { text: value }));
  foot.replaceChildren(...[
    host.load && item('Load', host.load[0].toFixed(2)),
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
    const hours = Number(b.dataset.hours);
    b.setAttribute('aria-checked', String(hours === state.range));
    // Ranges longer than the configured retention would only ever be partly filled.
    const kept = state.meta ? state.meta.retention_days * 24 : Infinity;
    b.disabled = hours > kept + 24;
    b.title = b.disabled ? `History is kept for ${state.meta.retention_days} days (settings.retention_days)` : '';
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
      tile('CPU', fmtPct(host.cpu.percent), `${cores(host.cpu.count)} · load ${(host.load || []).map((l) => l.toFixed(2)).join(' ')}`),
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
    $('#docker-card').hidden = !dk;
    if (!dk) return;
    const err = $('#docker-error');
    err.hidden = !dk.error;
    err.textContent = dk.error || '';
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
    const common = { x0, x1, minGap, tipTime };
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

  state.redraw = drawCharts;
  every(5000, loadHost);
  every(30000, loadHistory);
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

const TIME_STEPS = [300, 600, 900, 1800, 3600, 7200, 10800, 14400, 21600, 43200, 86400, 172800, 604800, 1209600];
const MIN_TICK_GAP = 76; // px between x-axis labels

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

  // x axis: steps aligned to local time
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

  // hover layer: crosshair snaps to the nearest sample time
  const times = allTimes.filter((t) => t >= x0);
  const lookup = visible.map((s) => new Map(s.points.map((p) => [p.t, p])));
  const cross = svg('line', { class: 'crosshair', y1: M.t, y2: M.t + ih, visibility: 'hidden' });
  const dots = visible.map((s) => svg('circle', { class: `dot c${s.slot}`, r: 4, visibility: 'hidden' }));
  const hit = svg('rect', { x: M.l, y: M.t, width: iw, height: ih, fill: 'transparent' });
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
    tip.replaceChildren(h('div', { class: 'tt-time', text: opts.tipTime ? opts.tipTime(t) : fmtClock(t, false) }), ...rows);
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
  root.addEventListener('focus', () => show(times.length - 1));
  root.addEventListener('blur', hide);
  root.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault();
      show((idx < 0 ? times.length - 1 : idx) + (e.key === 'ArrowLeft' ? -1 : 1));
    } else if (e.key === 'Escape') {
      hide();
    }
  });
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
  setupUpdateAll();
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
    drawUpdateAll(); // now with the latest agent version
    if (state.meta.user) {
      const user = $('#user');
      user.textContent = state.meta.user;
      user.hidden = false;
    }
  } catch (e) { console.warn(e); }
}

boot();
