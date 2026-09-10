// Follow-stream overlay: renders reassembled stream chunks in ASCII / hex / raw.
let current = null; // { chunks:[{dir,bytes:number[]}], meta }
let saveFn = null;

const $ = (s) => document.querySelector(s);

export function initFollow() {
  $('#follow-close').onclick = close;
  $('#follow').addEventListener('click', (e) => { if (e.target.id === 'follow') close(); });
  $('#follow-dir').onchange = render;
  $('#follow-mode').onchange = render;
  $('#follow-save').onclick = save;
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('#follow').classList.contains('open')) close(); });
}

export function openFollow(res, title, download) {
  current = res; saveFn = download;
  $('#follow-title').textContent = title || `Stream ${res.sid}`;
  $('#follow').classList.add('open');
  $('#follow-dir').value = 'both'; $('#follow-mode').value = 'ascii';
  render();
}
function close() { $('#follow').classList.remove('open'); current = null; }

function bytesOf(dirFilter) {
  const out = [];
  for (const c of current.chunks) {
    if (dirFilter === 'c' && c.dir !== 0) continue;
    if (dirFilter === 's' && c.dir !== 1) continue;
    out.push(c);
  }
  return out;
}

function render() {
  if (!current) return;
  const dir = $('#follow-dir').value;
  const mode = $('#follow-mode').value;
  const chunks = bytesOf(dir);
  const body = $('#follow-body');
  if (mode === 'hex') { body.innerHTML = chunks.map(c => `<div class="${c.dir === 0 ? 'c2s' : 's2c'}">${hexDump(c.bytes)}</div>`).join(''); return; }
  const parts = [];
  for (const c of chunks) {
    const cls = c.dir === 0 ? 'c2s' : 's2c';
    const text = mode === 'raw' ? rawText(c.bytes) : asciiText(c.bytes);
    parts.push(`<span class="${cls}">${escapeHtml(text)}</span>`);
  }
  body.innerHTML = parts.join('');
}

function asciiText(bytes) {
  let s = '';
  for (const b of bytes) s += (b === 10 || b === 13 || b === 9 || (b >= 32 && b < 127)) ? String.fromCharCode(b) : '.';
  return s;
}
function rawText(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return s; }
function hexDump(bytes) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    let hex = '', asc = '';
    for (let j = 0; j < 16; j++) {
      if (i + j < bytes.length) { const b = bytes[i + j]; hex += b.toString(16).padStart(2, '0') + ' '; asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.'; }
      else hex += '   ';
    }
    lines.push(i.toString(16).padStart(4, '0') + '  ' + hex + ' ' + escapeHtml(asc));
  }
  return lines.join('\n');
}
function save() {
  if (!current || !saveFn) return;
  const dir = $('#follow-dir').value;
  const chunks = bytesOf(dir);
  let total = 0; for (const c of chunks) total += c.bytes.length;
  const out = new Uint8Array(total); let o = 0;
  for (const c of chunks) { out.set(c.bytes, o); o += c.bytes.length; }
  saveFn(out, `stream-${current.sid || 0}.bin`, 'application/octet-stream');
}
function escapeHtml(s) { return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }
