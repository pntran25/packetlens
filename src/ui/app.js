// PacketLens main-thread controller.
import { fmtBytes, fmtTime } from '../core/bytes.js';
import { renderSecurity, renderConversations, renderCredentials, renderFiles, renderDns, renderHierarchy } from './views.js';
import { openFollow, initFollow } from './follow.js';

const $ = (s, r = document) => r.querySelector(s);
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };

const state = {
  worker: null, reqId: 0, pending: new Map(),
  rows: [], filtered: null, meta: null, analysis: null,
  selected: null, detailCache: new Map(),
  filterMatched: null,
  view: 'packets',
  hexRanges: null,
};

// ---- worker plumbing --------------------------------------------------------
function initWorker() {
  state.worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  state.worker.onmessage = (e) => {
    const m = e.data;
    if (m.type === 'progress') { onProgress(m); return; }
    const p = state.pending.get(m.id);
    if (m.type === 'loaded' || m.type === 'error') hideProgress();
    if (p) { state.pending.delete(m.id); p(m); }
  };
}
function call(msg, transfer) {
  const id = ++state.reqId;
  return new Promise((res) => { state.pending.set(id, res); state.worker.postMessage({ ...msg, id }, transfer || []); });
}

// ---- loading ----------------------------------------------------------------
async function loadBuffer(buf, name) {
  showProgress('Reading…');
  state.detailCache.clear();
  const res = await call({ type: 'load', buffer: buf }, [buf]);
  if (res.type === 'error') { toast('Failed: ' + res.message.split('\n')[0]); return; }
  state.rows = res.rows; state.meta = res.meta; state.analysis = res.analysis; state.filtered = null; state.filterMatched = null;
  state.meta.name = name || 'capture';
  $('#welcome').style.display = 'none';
  $('#pkt-table').hidden = false;
  $('#btn-export').disabled = false;
  updateCapStat();
  updateBadges();
  buildList();
  renderActiveView();
  if (res.meta.warnings?.length) toast(res.meta.warnings[0]);
}

async function openFile(file) {
  const buf = await file.arrayBuffer();
  await loadBuffer(buf, file.name);
}

function updateCapStat() {
  const m = state.meta;
  const dur = (m.lastTs - m.firstTs);
  $('#capstat').innerHTML = `<b>${m.name}</b> · ${m.format.toUpperCase()} · <b>${m.packetCount.toLocaleString()}</b> pkts · ${fmtBytes(m.bytes)} · ${dur > 0 ? dur.toFixed(2) + 's' : ''} · parsed in ${m.parseMs}ms`;
}
function updateBadges() {
  const a = state.analysis;
  const alerts = a?.iocs?.alerts || [];
  const highMed = alerts.filter(x => x.severity === 'high' || x.severity === 'medium').length;
  setBadge('#badge-sec', alerts.length, highMed > 0);
  setBadge('#badge-cred', a?.iocs?.credentials?.length || 0, (a?.iocs?.credentials?.length || 0) > 0);
  setBadge('#badge-files', a?.extraction?.files?.length || 0, false);
}
function setBadge(sel, n, alarm) {
  const b = $(sel); b.textContent = n; b.classList.toggle('zero', n === 0);
  if (alarm && n > 0) b.style.background = 'var(--red)'; else b.style.removeProperty('background');
}

// ---- packet list (virtualized) ---------------------------------------------
const ROW_H = 22;
let listState = { top: 0, height: 0 };
function activeRows() { return state.filtered || state.rows; }

function buildList() {
  const pane = $('#pane-packets');
  pane.onscroll = () => renderWindow();
  renderWindow();
}
function renderWindow() {
  const rows = activeRows();
  const tbody = $('#pkt-body');
  const pane = $('#pane-packets');
  const total = rows.length;
  const viewH = pane.clientHeight;
  const scroll = pane.scrollTop;
  const start = Math.max(0, Math.floor(scroll / ROW_H) - 8);
  const count = Math.ceil(viewH / ROW_H) + 16;
  const end = Math.min(total, start + count);
  // Spacer rows via padding on tbody using two filler rows.
  tbody.style.setProperty('--pad-top', (start * ROW_H) + 'px');
  const frag = document.createDocumentFragment();
  const padTop = el('tr'); padTop.style.height = (start * ROW_H) + 'px'; frag.appendChild(padTop);
  for (let i = start; i < end; i++) frag.appendChild(rowEl(rows[i]));
  const padBot = el('tr'); padBot.style.height = ((total - end) * ROW_H) + 'px'; frag.appendChild(padBot);
  tbody.replaceChildren(frag);
}
function rowEl(r) {
  const tr = el('tr');
  tr.dataset.n = r.n;
  if (r.err) tr.classList.add('err');
  if (r.tags.includes('credential')) tr.classList.add('tag-credential');
  if (state.selected === r.n) tr.classList.add('sel');
  const info = el('td', 'col-info');
  info.textContent = r.info || '';
  for (const t of r.tags) if (t !== 'credential') { const c = el('span', 'chip ' + t, t); info.appendChild(c); }
  tr.append(
    tdc('col-n', r.n), tdc('col-time', r.rel.toFixed(6)),
    tdc('col-src', r.src), tdc('col-dst', r.dst),
    protoTd(r.proto), tdc('col-len', r.len), info,
  );
  tr.onclick = () => selectPacket(r.n, tr);
  return tr;
}
function tdc(cls, txt) { const t = el('td', cls); t.textContent = txt == null ? '' : txt; return t; }
function protoTd(p) { const t = el('td', 'col-proto'); const s = el('span', 'proto-tag p-' + p, p); t.appendChild(s); return t; }

async function selectPacket(n, tr) {
  state.selected = n;
  for (const e of $('#pkt-body').querySelectorAll('tr.sel')) e.classList.remove('sel');
  if (tr) tr.classList.add('sel');
  let detail = state.detailCache.get(n);
  if (!detail) { detail = await call({ type: 'detail', n }); state.detailCache.set(n, detail); }
  renderDetail(detail);
}

// ---- detail tree + hex ------------------------------------------------------
function renderDetail(d) {
  const tree = $('#detail-tree');
  tree.replaceChildren();
  for (const layer of d.layers) tree.appendChild(layerNode(layer));
  state.curHex = d.hex;
  renderHex(d.hex, null);
}
function layerNode(layer) {
  const node = el('div', 'tnode layer' + (layer.errors?.length ? ' err' : ''));
  const row = el('div', 'row');
  const tw = el('span', 'tw', '▾');
  row.appendChild(tw);
  const nm = el('span', 'fname', layer.name);
  row.appendChild(nm);
  if (layer.summary) { const s = el('span', 'fval', '  ·  ' + layer.summary); s.style.color = 'var(--fg-dim)'; s.style.fontWeight = '400'; row.appendChild(s); }
  node.appendChild(row);
  const kids = el('div', 'tchildren');
  for (const f of layer.fields) kids.appendChild(fieldNode(f, layer));
  node.appendChild(kids);
  row.onclick = () => { kids.classList.toggle('collapsed'); tw.textContent = kids.classList.contains('collapsed') ? '▸' : '▾'; };
  row.onmouseenter = () => highlightHex(layer.offset, layer.length);
  return node;
}
function fieldNode(f, layer) {
  const node = el('div', 'tnode');
  const row = el('div', 'row');
  const hasKids = f.children && f.children.length;
  const tw = el('span', 'tw', hasKids ? '▾' : '');
  row.appendChild(tw);
  row.appendChild(el('span', 'fname', f.name));
  if (f.value !== '') { const v = el('span', 'fval', ': ' + f.value); row.appendChild(v); }
  node.appendChild(row);
  if (hasKids) {
    const kids = el('div', 'tchildren');
    for (const c of f.children) kids.appendChild(fieldNode(c, layer));
    node.appendChild(kids);
    row.onclick = (e) => { e.stopPropagation(); kids.classList.toggle('collapsed'); tw.textContent = kids.classList.contains('collapsed') ? '▸' : '▾'; };
  }
  row.onmouseenter = () => { if (f.offset >= 0) highlightHex(f.offset, f.length || 1); };
  return node;
}

function renderHex(bytes, hl) {
  const box = $('#detail-hex');
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    let off = i.toString(16).padStart(4, '0');
    let hexPart = '', ascii = '';
    for (let j = 0; j < 16; j++) {
      const idx = i + j;
      if (idx < bytes.length) {
        const b = bytes[idx];
        const on = hl && idx >= hl[0] && idx < hl[1];
        hexPart += `<span class="hex-b${on ? ' hl' : ''}">${b.toString(16).padStart(2, '0')}</span>` + (j === 7 ? '  ' : ' ');
        const ch = (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
        ascii += on ? `<span class="hl">${escapeHtml(ch)}</span>` : escapeHtml(ch);
      } else { hexPart += '   '; }
    }
    lines.push(`<span class="hex-off">${off}</span>  ${hexPart} <span class="hex-asc">${ascii}</span>`);
  }
  box.innerHTML = lines.join('\n');
}
function highlightHex(off, len) {
  if (!state.curHex || off < 0) return;
  renderHex(state.curHex, [off, off + len]);
}
function escapeHtml(s) { return s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }

// ---- filter -----------------------------------------------------------------
let filterFields = null;
let suggestIdx = -1;
async function ensureFields() {
  if (filterFields) return filterFields;
  try { const F = await import('../analysis/filter.js'); filterFields = F.FIELDS || []; } catch { filterFields = []; }
  return filterFields;
}

async function applyFilter() {
  const expr = $('#filter').value.trim();
  if (!expr) { clearFilter(); return; }
  const res = await call({ type: 'filter', expr });
  if (!res.ok) { $('#filter').className = 'bad'; $('#filter-err').textContent = res.error?.message || 'invalid filter'; return; }
  $('#filter').className = 'ok'; $('#filter-err').textContent = '';
  const set = new Set(res.matched);
  state.filterMatched = set;
  state.filtered = state.rows.filter(r => set.has(r.n));
  $('#pane-packets').scrollTop = 0;
  renderWindow();
  updateCapStat2(res.matched.length);
}
function updateCapStat2(n) {
  const m = state.meta;
  $('#capstat').innerHTML = `<b>${m.name}</b> · showing <b>${n.toLocaleString()}</b> of ${m.packetCount.toLocaleString()} pkts`;
}
function clearFilter() {
  $('#filter').value = ''; $('#filter').className = ''; $('#filter-err').textContent = '';
  state.filtered = null; state.filterMatched = null;
  renderWindow(); updateCapStat();
  hideSuggest();
}

async function onFilterInput() {
  const inp = $('#filter');
  const expr = inp.value.trim();
  if (!expr) { inp.className = ''; $('#filter-err').textContent = ''; hideSuggest(); return; }
  const res = await call({ type: 'validateFilter', expr });
  const ok = res.result?.ok;
  inp.className = ok ? 'ok' : 'bad';
  $('#filter-err').textContent = ok ? '' : (res.result?.error?.message || '');
  showSuggest(inp.value);
}
async function showSuggest(val) {
  const fields = await ensureFields();
  const m = val.match(/([a-zA-Z0-9_.]+)$/);
  const word = m ? m[1] : '';
  if (!word || word.length < 1) { hideSuggest(); return; }
  const matches = fields.filter(f => f.name.startsWith(word)).slice(0, 12);
  const box = $('#suggest');
  if (!matches.length) { hideSuggest(); return; }
  box.replaceChildren();
  matches.forEach((f, i) => {
    const d = el('div'); d.innerHTML = `<span>${f.name}</span><span class="desc">${f.desc || f.type || ''}</span>`;
    d.onmousedown = (e) => { e.preventDefault(); pickSuggest(f.name, word); };
    box.appendChild(d);
  });
  suggestIdx = -1; box.hidden = false;
}
function pickSuggest(name, word) {
  const inp = $('#filter');
  inp.value = inp.value.slice(0, inp.value.length - word.length) + name + ' ';
  inp.focus(); hideSuggest(); onFilterInput();
}
function hideSuggest() { $('#suggest').hidden = true; suggestIdx = -1; }

// ---- tab views --------------------------------------------------------------
function switchView(v) {
  state.view = v;
  for (const t of $('#tabs').children) t.classList.toggle('active', t.dataset.view === v);
  for (const view of $('#main').children) view.classList.toggle('active', view.dataset.view === v);
  renderActiveView();
}
function renderActiveView() {
  if (!state.analysis) return;
  const ctx = { analysis: state.analysis, meta: state.meta, goToPacket, followStream, downloadFile, applyFilterExpr };
  if (state.view === 'security') renderSecurity($('#panel-security'), ctx);
  else if (state.view === 'conversations') renderConversations($('#panel-conversations'), ctx);
  else if (state.view === 'credentials') renderCredentials($('#panel-credentials'), ctx);
  else if (state.view === 'files') renderFiles($('#panel-files'), ctx);
  else if (state.view === 'dns') renderDns($('#panel-dns'), ctx);
  else if (state.view === 'hierarchy') renderHierarchy($('#panel-hierarchy'), ctx);
}

function goToPacket(n) {
  switchView('packets');
  if (state.filtered && !state.filterMatched?.has(n)) clearFilter();
  const rows = activeRows();
  const idx = rows.findIndex(r => r.n === n);
  if (idx < 0) return;
  $('#pane-packets').scrollTop = Math.max(0, idx * ROW_H - 120);
  renderWindow();
  setTimeout(() => { const tr = $('#pkt-body').querySelector(`tr[data-n="${n}"]`); selectPacket(n, tr); }, 30);
}
function applyFilterExpr(expr) { $('#filter').value = expr; applyFilter(); }

async function followStream(kind, sid, title) {
  const res = await call({ type: 'stream', kind, sid });
  if (res.error) { toast(res.error); return; }
  openFollow(res, title, downloadBytes);
}
async function downloadFile(idx) {
  const res = await call({ type: 'artifact', idx });
  if (res.error) { toast('File data unavailable'); return; }
  downloadBytes(new Uint8Array(res.buffer), res.name || 'file.bin', res.mime);
}

// ---- export -----------------------------------------------------------------
async function doExport() {
  const expr = state.filtered ? $('#filter').value.trim() : '';
  const res = await call({ type: 'exportFilter', expr });
  downloadBytes(new Uint8Array(res.buffer), (state.meta.name.replace(/\.[^.]+$/, '') || 'export') + (expr ? '-filtered' : '') + '.pcap', 'application/vnd.tcpdump.pcap');
  toast(`Exported ${res.count} packets`);
}
function downloadBytes(bytes, name, mime) {
  const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = el('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

// ---- progress + toast -------------------------------------------------------
function showProgress() { $('#progress').hidden = false; $('#progress-bar').style.width = '5%'; }
function onProgress(m) {
  if (m.total) { const pct = m.phase === 'analyze' ? 92 : Math.round((m.done / m.total) * 88); $('#progress-bar').style.width = pct + '%'; }
}
function hideProgress() { $('#progress-bar').style.width = '100%'; setTimeout(() => { $('#progress').hidden = true; $('#progress-bar').style.width = '0'; }, 250); }
let toastT;
function toast(msg) { let t = $('#toast'); if (!t) { t = el('div', 'toast'); t.id = 'toast'; document.body.appendChild(t); } t.textContent = msg; t.style.display = 'block'; clearTimeout(toastT); toastT = setTimeout(() => t.style.display = 'none', 4000); }

// ---- events -----------------------------------------------------------------
function wire() {
  $('#btn-open').onclick = $('#wl-open').onclick = () => $('#file').click();
  $('#file').onchange = (e) => { if (e.target.files[0]) openFile(e.target.files[0]); };
  $('#btn-sample').onclick = $('#wl-sample').onclick = loadSample;
  $('#btn-apply').onclick = applyFilter;
  $('#btn-clear').onclick = clearFilter;
  $('#btn-export').onclick = doExport;
  $('#filter').addEventListener('input', onFilterInput);
  $('#filter').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { applyFilter(); hideSuggest(); }
    else if (e.key === 'Escape') hideSuggest();
  });
  for (const t of $('#tabs').children) t.onclick = () => switchView(t.dataset.view);
  // drag & drop
  const wl = $('#welcome'), dz = $('#dropzone');
  window.addEventListener('dragover', (e) => { e.preventDefault(); wl.classList.add('drag'); dz.classList.add('drag'); });
  window.addEventListener('dragleave', (e) => { if (e.relatedTarget === null) { wl.classList.remove('drag'); dz.classList.remove('drag'); } });
  window.addEventListener('drop', (e) => { e.preventDefault(); wl.classList.remove('drag'); dz.classList.remove('drag'); if (e.dataTransfer.files[0]) openFile(e.dataTransfer.files[0]); });
  window.addEventListener('resize', () => { if (state.rows.length) renderWindow(); });
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT') return;
    if (!activeRows().length) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const rows = activeRows();
      let idx = rows.findIndex(r => r.n === state.selected);
      idx = e.key === 'ArrowDown' ? Math.min(rows.length - 1, idx + 1) : Math.max(0, idx - 1);
      const n = rows[idx].n;
      $('#pane-packets').scrollTop = Math.max(0, idx * ROW_H - 120); renderWindow();
      setTimeout(() => selectPacket(n, $('#pkt-body').querySelector(`tr[data-n="${n}"]`)), 10);
    } else if (e.key === '/') { e.preventDefault(); $('#filter').focus(); }
  });
  initFollow();
}

async function loadSample() {
  showProgress();
  try {
    const mod = await import('../../fixtures/sample.js');
    const buf = mod.buildSample();
    await loadBuffer(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength), 'sample.pcap');
  } catch (err) { hideProgress(); toast('Sample unavailable: ' + String(err).split('\n')[0]); }
}

initWorker();
wire();
window.PL = { goToPacket, state };
