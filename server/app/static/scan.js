'use strict';

// Disk usage on a host's page: ask the host's agent to scan a folder (only when
// you click Scan), then browse any saved run as a WizTree-style folder tree,
// treemap, list of the largest files and file types.
//
// Loaded before app.js; everything it needs from app.js (h, $, api, fmtBytes...)
// is looked up when a host page opens. Names, paths and sizes come from the
// monitored machine and are untrusted: they only ever reach the DOM through
// textContent / text nodes, never innerHTML.

const SCAN_STATUS = { pending: 'Waiting for the agent', running: 'Scanning', done: 'Done', failed: 'Failed', cancelled: 'Cancelled' };
const scanActive = (r) => r.status === 'pending' || r.status === 'running';
const TREEMAP_HEIGHT = 380;
const TREE_ROW_LIMIT = 1500;
const FILE_ROW_STEP = 200;

let scanRedraw = null; // redraws the open treemap when the window is resized
window.addEventListener('resize', () => { if (scanRedraw) scanRedraw(); });

function scanSep(result) { return result.windows ? '\\' : '/'; }

function scanExt(name) {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i).toLowerCase().slice(0, 24) : '(none)';
}

function scanClip(s, max) { return s.length > max ? s.slice(0, Math.max(1, max - 1)) + '…' : s; }

// A small color chip. The page's CSP forbids style attributes, so it's set through the DOM.
function swatch(color) {
  const s = h('span', { class: 'swatch' });
  s.style.background = color;
  return s;
}

function scanTook(sec) {
  if (sec < 1) return 'under a second';
  sec = Math.round(sec);
  return sec < 60 ? `${sec} s` : sec < 3600 ? `${Math.floor(sec / 60)} min ${sec % 60} s` : `${Math.floor(sec / 3600)} h ${Math.floor((sec % 3600) / 60)} min`;
}

function scanSigned(n) { return (n > 0 ? '+' : n < 0 ? '−' : '') + fmtBytes(Math.abs(n)); }

// Squarified treemap: lays `nodes` (sorted by size, largest first) out inside a box.
function scanLayout(nodes, x, y, w, h) {
  const total = nodes.reduce((a, n) => a + n.s, 0);
  if (!(total > 0) || w <= 0 || h <= 0) return [];
  const scale = (w * h) / total;
  const items = nodes.filter((n) => n.s > 0).map((n) => ({ n, a: n.s * scale }));
  const out = [];
  let row = [];
  const worst = (r, side) => {
    const s = r.reduce((a, i) => a + i.a, 0);
    const max = r[0].a;
    const min = r[r.length - 1].a;
    return Math.max((side * side * max) / (s * s), (s * s) / (side * side * min));
  };
  const flush = () => {
    if (!row.length) return;
    const s = row.reduce((a, i) => a + i.a, 0);
    if (w >= h) {                      // a column down the left edge
      const cw = s / h;
      let cy = y;
      for (const i of row) { const ch = i.a / cw; out.push({ n: i.n, x, y: cy, w: cw, h: ch }); cy += ch; }
      x += cw; w -= cw;
    } else {                           // a row along the top edge
      const rh = s / w;
      let cx = x;
      for (const i of row) { const cw = i.a / rh; out.push({ n: i.n, x: cx, y, w: cw, h: rh }); cx += cw; }
      y += rh; h -= rh;
    }
    row = [];
  };
  for (const item of items) {
    const side = Math.min(w, h);
    if (!row.length || worst(row.concat(item), side) <= worst(row, side)) row.push(item);
    else { flush(); row.push(item); }
  }
  flush();
  return out;
}

function setupScanCard(name, getHost) {
  const card = $('#scan-card');
  if (!card) return;
  const enc = encodeURIComponent(name);
  const tip = $('#tooltip');
  const pathInput = $('#scan-path');
  const crossBox = $('#scan-cross');
  const goBtn = $('#scan-go');
  const errBox = $('#scan-error');
  const activeBox = $('#scan-active');
  const view = $('#scan-view');
  const runsBody = $('#scan-runs tbody');

  let runs = [];
  let unavailable = null;
  let lastLoad = 0;
  let wasActive = false;
  let openId = loadPref('scan.open.' + name, null);
  let opened = null;      // {meta, result, parents, colors, focus, selected, expanded}
  let tab = 'tree';
  let openSeq = 0;

  pathInput.value = loadPref('scan.path.' + name, '') || '';
  crossBox.checked = !!loadPref('scan.cross.' + name, false);

  // -- starting and stopping --------------------------------------------------------

  function mounts() {
    const host = getHost();
    return host && host.disks ? host.disks.map((d) => d.mount).filter(Boolean) : [];
  }

  function fillMounts() {
    const list = $('#scan-mounts');
    const found = mounts();
    list.replaceChildren(...found.map((m) => h('option', { value: m })));
    if (!pathInput.value && found.length) {
      const host = getHost();
      pathInput.value = host && host.platform === 'windows' ? found[0] : (found.includes('/') ? '/' : found[0]);
    }
  }

  function showError(msg) {
    errBox.hidden = !msg;
    errBox.textContent = msg || '';
  }

  goBtn.addEventListener('click', async () => {
    const path = pathInput.value.trim();
    if (!path) { showError('Enter the folder to scan.'); return; }
    showError('');
    goBtn.disabled = true;
    savePref('scan.path.' + name, path);
    savePref('scan.cross.' + name, crossBox.checked);
    try {
      await apiPost(`/api/hosts/${enc}/scans`, { path, cross_fs: crossBox.checked });
    } catch (e) {
      showError(e.message);
    }
    await loadRuns();
  });
  pathInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') goBtn.click(); });

  $('#scan-cancel').addEventListener('click', async () => {
    const run = runs.find(scanActive);
    if (!run) return;
    try { await apiPost(`/api/hosts/${enc}/scans/${run.id}/cancel`); } catch (e) { showError(e.message); }
    await loadRuns();
  });

  // -- the list of runs -------------------------------------------------------------

  async function loadRuns() {
    const reply = await api(`/api/hosts/${enc}/scans`);
    lastLoad = Date.now();
    runs = reply.scans;
    unavailable = reply.unavailable;
    fillMounts();
    const active = runs.find(scanActive);
    // A scan that just finished opens by itself.
    if (wasActive && !active && runs[0] && runs[0].status === 'done') openRun(runs[0].id);
    wasActive = !!active;
    drawRuns(active);
    if (openId == null) {
      const latest = runs.find((r) => r.status === 'done');
      if (latest) openRun(latest.id);
    }
  }

  function drawRuns(active) {
    const note = $('#scan-unavailable');
    note.hidden = !unavailable;
    note.textContent = unavailable || '';
    $('#scan-controls').hidden = !!unavailable;
    goBtn.disabled = !!active || !!unavailable;
    pathInput.disabled = crossBox.disabled = !!active || !!unavailable;

    activeBox.hidden = !active;
    if (active) {
      const p = active.progress;
      $('#scan-active-text').textContent = active.status === 'pending' || !p
        ? `Waiting for ${name}'s agent to pick up the request. Agents check in every few seconds.`
        : `Scanning ${active.path}: ${fmtNum(p.files)} files in ${fmtNum(p.dirs)} folders so far, ${fmtBytes(p.bytes)}`
          + (p.unreadable ? `, ${fmtNum(p.unreadable)} folders couldn't be opened` : '')
          + (p.current ? `. Now in ${scanClip(p.current, 90)}` : '');
    }

    $('#scan-runs').hidden = !runs.length;
    $('#scan-empty').hidden = !!runs.length || !!unavailable;
    const done = runs.filter((r) => r.status === 'done');
    runsBody.replaceChildren(...runs.map((r) => {
      // Change since the run before it on the same folder: the quick way to see what grew.
      const before = done.find((o) => o.id < r.id && o.path === r.path && o.cross_fs === r.cross_fs);
      const delta = r.status === 'done' && before ? r.alloc - before.alloc : null;
      const open = r.status === 'done';
      const status = h('span', { class: `scan-status is-${r.status}`, text: SCAN_STATUS[r.status] || r.status });
      const tr = h('tr', { class: open ? 'is-clickable' : '', 'aria-selected': String(r.id === openId) },
        h('td', { text: fmtWhen(r.finished || r.requested) }),
        h('td', { class: 'scan-path', text: r.path + (r.cross_fs ? ' (all filesystems)' : ''), title: r.path }),
        h('td', { class: 'num', text: r.alloc != null ? fmtBytes(r.alloc) : '—' }),
        h('td', { class: 'num', title: 'Compared with the previous scan of this folder', text: delta == null ? '' : scanSigned(delta) }),
        h('td', { class: 'num', text: r.files != null ? fmtNum(r.files) : '—' }),
        h('td', null, status, r.error ? h('span', { class: 'muted', text: ` ${r.error}` }) : null),
        h('td', { class: 'num' },
          open ? h('button', { class: 'btn btn-quiet', type: 'button', text: 'Open', onclick: (e) => { e.stopPropagation(); openRun(r.id); } }) : null,
          !scanActive(r) ? h('button', { class: 'btn btn-quiet', type: 'button', text: 'Delete', onclick: (e) => { e.stopPropagation(); removeRun(r); } }) : null));
      if (open) tr.addEventListener('click', () => openRun(r.id));
      return tr;
    }));
  }

  async function removeRun(r) {
    if (!window.confirm(`Delete the scan of ${r.path} from ${fmtWhen(r.finished || r.requested)}? This can't be undone.`)) return;
    try {
      await apiPost(`/api/hosts/${enc}/scans/${r.id}/delete`);
    } catch (e) { showError(e.message); }
    if (openId === r.id) { openId = null; opened = null; view.replaceChildren(); savePref('scan.open.' + name, null); }
    await loadRuns();
  }

  // -- opening one run ---------------------------------------------------------------

  async function openRun(id) {
    const seq = ++openSeq;
    openId = id;
    savePref('scan.open.' + name, id);
    drawRuns(runs.find(scanActive));
    view.classList.add('loading');
    let meta;
    try {
      meta = await api(`/api/hosts/${enc}/scans/${id}`);
    } catch (e) {
      if (seq === openSeq) {
        view.classList.remove('loading');
        view.replaceChildren(h('p', { class: 'muted', text: e.status === 404 ? 'That scan was deleted.' : `Couldn't load that scan: ${e.message}` }));
        if (e.status === 404) { openId = null; savePref('scan.open.' + name, null); }
      }
      return;
    }
    if (seq !== openSeq) return;
    view.classList.remove('loading');
    if (!meta.result) { view.replaceChildren(h('p', { class: 'muted', text: meta.error || 'This scan has no result.' })); return; }
    const result = meta.result;
    const parents = new Map();
    const todo = [result.tree];
    while (todo.length) {
      const n = todo.pop();
      for (const c of n.c || []) { parents.set(c, n); todo.push(c); }
    }
    // The biggest file types get well-separated colors; the long tail falls back to a hash.
    const colors = new Map();
    result.exts.filter((e) => e[0] !== '(other)').slice(0, 40).forEach((e, i) => colors.set(e[0], `hsl(${(i * 137.5) % 360} 58% 60%)`));
    opened = { meta, result, parents, colors, focus: result.tree, selected: result.tree, expanded: new Set([result.tree]) };
    drawView();
  }

  function nodePath(node) {
    const { result, parents } = opened;
    const parts = [];
    for (let n = node; n && n !== result.tree; n = parents.get(n)) parts.push(n.n || '');
    parts.reverse();
    const sep = scanSep(result);
    const root = result.tree.n;
    return parts.reduce((acc, p) => (acc.endsWith(sep) ? acc : acc + sep) + p, root);
  }

  function nodeColor(node) {
    if (node.t === 'o') return 'hsl(0 0% 72%)';
    if (node.t === 'd') return 'hsl(214 14% 62%)';
    const ext = scanExt(node.n);
    if (opened.colors.has(ext)) return opened.colors.get(ext);
    let x = 0;
    for (let i = 0; i < ext.length; i++) x = (x * 31 + ext.charCodeAt(i)) >>> 0;
    return `hsl(${x % 360} 40% 66%)`;
  }

  function nodeLabel(node) {
    return node.t === 'o' ? `${fmtNum(node.k)} smaller item${node.k === 1 ? '' : 's'}` : node.n;
  }

  function focusOn(node) {
    opened.focus = node;
    opened.selected = node;
    drawMap();
    drawCrumbs();
    drawTab();
  }

  // -- the whole view ----------------------------------------------------------------

  function drawView() {
    const { meta, result } = opened;
    const tiles = h('div', { class: 'tiles scan-tiles' },
      tile('Scanned', fmtBytes(result.alloc), result.path + (result.cross_fs ? ' and other filesystems' : '')),
      result.fs ? tile('Filesystem', `${fmtBytes(result.fs.used)} used`, `of ${fmtBytes(result.fs.total)} · ${fmtBytes(result.fs.free)} free`) : null,
      tile('Files', fmtNum(result.files), result.links ? `${fmtNum(result.links)} links not followed` : ''),
      tile('Folders', fmtNum(result.dirs), `took ${scanTook((result.finished || 0) - (result.started || 0))}`));

    view.replaceChildren(
      h('div', { class: 'scan-when muted', text: `Scan from ${fmtWhen(meta.finished || meta.requested)}${meta.requested_by ? ` · started by ${meta.requested_by}` : ''}` }),
      tiles,
      scanNotes(result),
      h('div', { id: 'scan-crumbs', class: 'scan-crumbs' }),
      h('div', { id: 'scan-treemap', class: 'treemap' }),
      h('div', { class: 'seg scan-tabs', role: 'tablist' },
        ...[['tree', 'Folders'], ['files', 'Largest files'], ['types', 'File types']].map(([id, label]) => h('button', {
          type: 'button', role: 'tab', 'data-tab': id, 'aria-selected': String(id === tab), text: label,
          onclick: () => { tab = id; view.querySelectorAll('.scan-tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === tab))); drawTab(); },
        }))),
      h('div', { id: 'scan-tab' }));
    drawMap();
    drawCrumbs();
    drawTab();
    scanRedraw = () => { if (opened && $('#scan-treemap')) drawMap(); };
  }

  function scanNotes(result) {
    const items = [];
    if (result.unreadable) {
      items.push(h('li', null,
        `${fmtNum(result.unreadable)} folder${result.unreadable === 1 ? '' : 's'} couldn't be opened by the agent's user, so what's inside isn't counted. `,
        result.unreadable_paths.length ? h('details', null, h('summary', { text: 'Which ones' }),
          h('ul', { class: 'scan-paths' }, ...result.unreadable_paths.map((p) => h('li', { text: p })),
            result.unreadable > result.unreadable_paths.length ? h('li', { class: 'muted', text: `…and ${fmtNum(result.unreadable - result.unreadable_paths.length)} more` }) : null)) : null));
    }
    if (result.skipped_mounts.length) {
      items.push(h('li', null, 'Other filesystems were not scanned: ',
        h('span', { class: 'scan-mono', text: result.skipped_mounts.slice(0, 8).join(', ') + (result.skipped_mounts.length > 8 ? ', …' : '') }),
        '. Tick “Include other filesystems” to scan them too.'));
    }
    const root = /^(\/|[A-Za-z]:[\\/]?)$/.test(result.path);
    if (result.fs && root && !result.cross_fs && result.fs.used > result.alloc * 1.05 + (1 << 28)) {
      items.push(h('li', { text: `The filesystem reports ${fmtBytes(result.fs.used)} used but ${fmtBytes(result.alloc)} was found in files. The difference is usually folders the agent can't open, filesystem metadata and journals, or deleted files that are still held open.` }));
    }
    if (result.keep_min > 0) {
      items.push(h('li', { text: `Folders and files under ${fmtBytes(result.keep_min)} are grouped as “smaller items”. Totals include them.` }));
    }
    if (result.truncated) items.push(h('li', { class: 'is-warn', text: result.truncated }));
    for (const n of result.notes) items.push(h('li', { text: n.charAt(0).toUpperCase() + n.slice(1) + (/[.!?]$/.test(n) ? '' : '.') }));
    return h('ul', { class: 'scan-notes' }, ...items);
  }

  function drawCrumbs() {
    const box = $('#scan-crumbs');
    if (!box) return;
    const { result, parents, focus } = opened;
    const chain = [];
    for (let n = focus; n; n = parents.get(n)) chain.unshift(n);
    box.replaceChildren(...chain.flatMap((n, i) => [
      i ? h('span', { class: 'muted', text: ' › ' }) : null,
      i === chain.length - 1
        ? h('b', { text: n.n })
        : h('button', { class: 'link', type: 'button', text: n.n, onclick: () => focusOn(n) }),
    ]).filter(Boolean), h('span', { class: 'muted', text: `  ${fmtBytes(focus.s)}` }));
  }

  // -- treemap -----------------------------------------------------------------------

  function showTip(e, node) {
    const { result, parents } = opened;
    const parent = parents.get(node);
    const rows = [
      h('div', { class: 'tt-time', text: node.t === 'o' ? nodeLabel(node) : nodePath(node) }),
      h('div', { class: 'tt-row' }, h('b', { text: fmtBytes(node.s) }), h('span', { text: 'on disk' })),
    ];
    if (node.a !== node.s) rows.push(h('div', { class: 'tt-row' }, h('b', { text: fmtBytes(node.a) }), h('span', { text: 'file size' })));
    if (node.t !== 'f') rows.push(h('div', { class: 'tt-row' }, h('b', { text: fmtNum(node.f) }), h('span', { text: node.f === 1 ? 'file' : 'files' })));
    rows.push(h('div', { class: 'tt-row' }, h('b', { text: fmtPct(result.alloc ? (100 * node.s) / result.alloc : 0) }), h('span', { text: 'of the scan' })));
    if (parent) rows.push(h('div', { class: 'tt-row' }, h('b', { text: fmtPct(parent.s ? (100 * node.s) / parent.s : 0) }), h('span', { text: 'of its folder' })));
    if (node.t === 'f' && node.m) rows.push(h('div', { class: 'tt-row' }, h('b', { text: new Date(node.m * 1000).toLocaleDateString() }), h('span', { text: 'modified' })));
    if (node.t === 'd') rows.push(h('div', { class: 'tt-hint', text: 'Click to zoom in' }));
    tip.replaceChildren(...rows);
    tip.hidden = false;
    const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
    const y = Math.min(e.clientY + 14, window.innerHeight - tip.offsetHeight - 8);
    tip.style.left = Math.max(4, x) + 'px';
    tip.style.top = Math.max(4, y) + 'px';
  }

  function drawMap() {
    const box = $('#scan-treemap');
    if (!box) return;
    const { focus } = opened;
    const W = Math.max(320, box.clientWidth || 800);
    const H = TREEMAP_HEIGHT;
    const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img', 'aria-label': `Treemap of ${nodeLabel(focus)}, ${fmtBytes(focus.s)}` });
    let count = 0;

    const rect = (node, x, y, w, h2, fill, cls) => {
      const r = svg('rect', { x: x.toFixed(1), y: y.toFixed(1), width: Math.max(0, w).toFixed(1), height: Math.max(0, h2).toFixed(1), class: cls });
      if (fill) r.setAttribute('fill', fill);
      r.node = node;
      root.append(r);
      return r;
    };
    const label = (text, x, y, cls) => {
      const t = svg('text', { x: (x + 4).toFixed(1), y: (y + 11).toFixed(1), class: cls });
      t.textContent = text;
      root.append(t);
    };

    const paint = (node, x, y, w, h2, depth) => {
      if (w < 3 || h2 < 3 || count > 4000) return;
      count++;
      const kids = node.c && node.c.length ? node.c : null;
      if (kids && node.t === 'd' && w >= 36 && h2 >= 28 && depth < 7) {
        rect(node, x, y, w, h2, null, 'tm-dir');
        const header = w >= 60 && h2 >= 44 ? 14 : 0;
        if (header) label(scanClip(node.n, Math.floor((w - 8) / 6.4)), x, y, 'tm-dirlabel');
        for (const r of scanLayout(kids, x + 2, y + 2 + header, w - 4, h2 - 4 - header)) paint(r.n, r.x, r.y, r.w, r.h, depth + 1);
        return;
      }
      rect(node, x, y, w, h2, nodeColor(node), 'tm-leaf');
      if (w >= 64 && h2 >= 18) label(scanClip(nodeLabel(node), Math.floor((w - 8) / 6.4)), x, y, 'tm-label');
    };

    if (focus.c && focus.c.length) {
      for (const r of scanLayout(focus.c, 0, 0, W, H)) paint(r.n, r.x, r.y, r.w, r.h, 0);
    } else {
      rect(focus, 0, 0, W, H, nodeColor(focus), 'tm-leaf');
      label(focus.t === 'd' ? 'Nothing here is big enough to show on its own' : nodePath(focus), 0, 0, 'tm-label');
    }
    root.addEventListener('mousemove', (e) => { if (e.target.node) showTip(e, e.target.node); else tip.hidden = true; });
    root.addEventListener('mouseleave', () => { tip.hidden = true; });
    root.addEventListener('click', (e) => {
      const n = e.target.node;
      if (n && n.t === 'd' && n !== opened.focus) { tip.hidden = true; focusOn(n); }
    });
    box.replaceChildren(root);
  }

  // -- tabs below the map ------------------------------------------------------------

  function drawTab() {
    const box = $('#scan-tab');
    if (!box) return;
    if (tab === 'tree') box.replaceChildren(treeTable());
    else if (tab === 'files') box.replaceChildren(...filesTable().filter(Boolean));
    else box.replaceChildren(typesTable());
  }

  function treeTable() {
    const { focus, expanded } = opened;
    const rows = [];
    const add = (node, depth) => {
      for (const c of node.c || []) {
        rows.push({ c, depth, parent: node });
        if (expanded.has(c)) add(c, depth + 1);
      }
    };
    rows.push({ c: focus, depth: 0, parent: null });
    expanded.add(focus);
    add(focus, 1);
    const shown = rows.slice(0, TREE_ROW_LIMIT);
    const tbody = h('tbody', null, ...shown.map(({ c, depth, parent }) => {
      const dir = c.t === 'd' && c.c && c.c.length;
      const pct = parent && parent.s ? (100 * c.s) / parent.s : 100;
      const name = h('td', { class: 'tree-name' },
        dir ? h('button', {
          class: 'expander', type: 'button', 'aria-expanded': String(expanded.has(c)), 'aria-label': `${expanded.has(c) ? 'Collapse' : 'Expand'} ${nodeLabel(c)}`,
          text: expanded.has(c) ? '▾' : '▸',
          onclick: (e) => { e.stopPropagation(); if (expanded.has(c)) expanded.delete(c); else expanded.add(c); drawTab(); },
        }) : h('span', { class: 'expander-gap' }),
        swatch(nodeColor(c)),
        h('span', { class: c.t === 'o' ? 'muted' : '', text: c === focus ? nodePath(c) : nodeLabel(c), title: c.t === 'o' ? '' : nodePath(c) }));
      name.style.paddingLeft = (10 + depth * 18) + 'px';
      const bar = h('span', { class: 'pct-fill' });
      bar.style.width = Math.max(0, Math.min(100, pct)).toFixed(1) + '%';
      const tr = h('tr', { class: 'is-clickable', 'aria-selected': String(c === opened.selected) },
        name,
        h('td', { class: 'pct-cell' }, h('span', { class: 'pct-bar' }, bar), h('span', { class: 'pct-text', text: fmtPct(pct) })),
        h('td', { class: 'num', text: fmtBytes(c.s) }),
        h('td', { class: 'num', text: fmtBytes(c.a) }),
        h('td', { class: 'num', text: c.t === 'f' ? '' : fmtNum(c.f) }));
      tr.addEventListener('click', () => {
        opened.selected = c;
        if (c.t === 'd' && c !== opened.focus) focusOn(c);
        else drawTab();
      });
      return tr;
    }));
    const table = h('table', { class: 'table tree-table' },
      h('thead', null, h('tr', null, h('th', { text: 'Folder' }), h('th', { text: '% of parent' }),
        h('th', { class: 'num', text: 'Size on disk' }), h('th', { class: 'num', text: 'File size' }), h('th', { class: 'num', text: 'Files' }))),
      tbody);
    return h('div', { class: 'table-wrap' }, table,
      rows.length > shown.length ? h('p', { class: 'muted', text: `Showing the first ${fmtNum(shown.length)} rows; collapse some folders to see the rest.` }) : null);
  }

  let fileFilter = '';
  let fileLimit = FILE_ROW_STEP;
  function filesTable() {
    const { result } = opened;
    const q = fileFilter.toLowerCase();
    const matches = q ? result.top.filter((f) => f[0].toLowerCase().includes(q)) : result.top;
    const shown = matches.slice(0, fileLimit);
    const input = h('input', { class: 'input', type: 'search', placeholder: 'Filter by path', 'aria-label': 'Filter largest files', value: fileFilter });
    input.addEventListener('input', () => { fileFilter = input.value; fileLimit = FILE_ROW_STEP; drawTab(); const i = $('#scan-tab input'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } });
    return [
      h('div', { class: 'toolbar' }, input, h('span', { class: 'muted', text: `${fmtNum(matches.length)} of the ${fmtNum(result.top.length)} largest files` })),
      h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
        h('thead', null, h('tr', null, h('th', { class: 'num', text: 'Size on disk' }), h('th', { class: 'num', text: 'File size' }),
          h('th', { class: 'num', text: '% of scan' }), h('th', { text: 'Modified' }), h('th', { text: 'Path' }))),
        h('tbody', null, ...shown.map((f) => h('tr', null,
          h('td', { class: 'num', text: fmtBytes(f[1]) }),
          h('td', { class: 'num', text: fmtBytes(f[2]) }),
          h('td', { class: 'num', text: fmtPct(result.alloc ? (100 * f[1]) / result.alloc : 0) }),
          h('td', { text: f[3] ? new Date(f[3] * 1000).toLocaleDateString() : '—' }),
          h('td', { class: 'scan-mono scan-file', text: f[0], title: f[0] })))))),
      matches.length > shown.length ? h('button', { class: 'btn btn-quiet', type: 'button', text: `Show ${Math.min(FILE_ROW_STEP, matches.length - shown.length)} more`, onclick: () => { fileLimit += FILE_ROW_STEP; drawTab(); } }) : null,
    ];
  }

  function typesTable() {
    const { result } = opened;
    const top = result.exts[0] ? result.exts[0][1] || 1 : 1;
    return h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
      h('thead', null, h('tr', null, h('th', { text: 'Type' }), h('th', { text: 'Share of the scan' }),
        h('th', { class: 'num', text: 'Size on disk' }), h('th', { class: 'num', text: 'Files' }))),
      h('tbody', null, ...result.exts.map((e) => {
        const fill = h('span', { class: 'pct-fill' });
        fill.style.width = Math.min(100, (100 * e[1]) / top).toFixed(1) + '%';
        fill.style.background = opened.colors.get(e[0]) || 'var(--muted)';
        return h('tr', null,
          h('td', null, swatch(opened.colors.get(e[0]) || 'var(--muted)'), h('span', { class: 'scan-mono', text: e[0] })),
          h('td', { class: 'pct-cell' }, h('span', { class: 'pct-bar' }, fill), h('span', { class: 'pct-text', text: fmtPct(result.alloc ? (100 * e[1]) / result.alloc : 0) })),
          h('td', { class: 'num', text: fmtBytes(e[1]) }),
          h('td', { class: 'num', text: fmtNum(e[3]) }));
      }))));
  }

  // -- polling: every few seconds while a scan runs, now and then otherwise ------------

  every(3000, async () => {
    if (!pathInput.value) fillMounts(); // the host's disk list may arrive after the first load
    if (runs.some(scanActive) || Date.now() - lastLoad > 20000) await loadRuns();
  });
  if (openId != null) openRun(openId);
}
