// Tab panel renderers. Each takes (containerEl, ctx) where ctx = { analysis, meta,
// goToPacket, followStream, downloadFile, applyFilterExpr }.
import { fmtBytes } from '../core/bytes.js';

const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
function clear(n) { n.replaceChildren(); }
function pktLinks(nums, ctx, max = 12) {
  const span = el('span');
  const list = (nums || []).slice(0, max);
  list.forEach((n, i) => { const a = el('a', 'linklike', '#' + n); a.onclick = () => ctx.goToPacket(n); span.appendChild(a); span.appendChild(document.createTextNode(' ')); });
  if ((nums || []).length > max) span.appendChild(el('span', 'faint', `+${nums.length - max} more`));
  return span;
}
function card(k, v, small) { const c = el('div', 'card'); c.appendChild(el('div', 'k', k)); const vv = el('div', 'v' + (small ? ' small' : ''), v); c.appendChild(vv); return c; }
function grid(headers) {
  const table = el('table', 'grid');
  const thead = el('thead'); const tr = el('tr');
  headers.forEach(h => tr.appendChild(el('th', null, typeof h === 'string' ? h : h.label)));
  thead.appendChild(tr); table.appendChild(thead);
  const tbody = el('tbody'); table.appendChild(tbody);
  return { table, tbody };
}

// ---- Security ---------------------------------------------------------------
export function renderSecurity(root, ctx) {
  clear(root);
  const iocs = ctx.analysis.iocs || {};
  const alerts = iocs.alerts || [];
  root.appendChild(el('h2', null, 'Security overview'));
  root.appendChild(el('p', 'dim', 'Automated findings from passive analysis. Investigate before acting; heuristics can produce false positives.'));

  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const a of alerts) counts[a.severity] = (counts[a.severity] || 0) + 1;
  const cards = el('div', 'cards');
  cards.appendChild(card('High', counts.high || 0));
  cards.appendChild(card('Medium', counts.medium || 0));
  cards.appendChild(card('Low / Info', (counts.low || 0) + (counts.info || 0)));
  cards.appendChild(card('Credentials', (iocs.credentials || []).length));
  cards.appendChild(card('Suspicious domains', (iocs.domains || []).filter(d => d.suspicious).length));
  root.appendChild(cards);

  if (!alerts.length) { root.appendChild(el('div', 'empty', 'No findings. That does not mean the traffic is clean — just that no heuristic fired.')); }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  for (const a of [...alerts].sort((x, y) => order[x.severity] - order[y.severity])) {
    const box = el('div', 'alert ' + a.severity);
    const title = el('div', 'title');
    title.appendChild(el('span', 'pill ' + a.severity, a.severity.toUpperCase()));
    title.appendChild(el('span', null, a.title));
    if (a.category) title.appendChild(el('span', 'faint', '· ' + a.category));
    box.appendChild(title);
    if (a.detail) box.appendChild(el('div', 'detail', a.detail));
    if (a.hosts && a.hosts.length) { const h = el('div', 'detail'); h.innerHTML = 'Hosts: <span class="mono">' + a.hosts.slice(0, 8).map(escapeHtml).join(', ') + '</span>'; box.appendChild(h); }
    if (a.packets && a.packets.length) { const p = el('div', 'pkts'); p.appendChild(el('span', 'faint', 'Packets: ')); p.appendChild(pktLinks(a.packets, ctx)); box.appendChild(p); }
    root.appendChild(box);
  }

  // TLS findings
  const tls = iocs.tlsFindings;
  if (tls && (tls.ja3?.length || tls.selfSigned?.length || tls.expired?.length)) {
    root.appendChild(el('h3', null, 'TLS fingerprints (JA3)'));
    const g = grid(['JA3 hash', 'SNI', 'Count', 'Destinations']);
    for (const j of (tls.ja3 || []).slice(0, 40)) {
      const tr = el('tr');
      tr.append(td(j.hash, 'mono'), td(j.sni || '—'), td(String(j.count || 1), 'num'), td((j.destinations || []).slice(0, 4).join(', ')));
      g.tbody.appendChild(tr);
    }
    root.appendChild(g.table);
  }
}

// ---- Conversations ----------------------------------------------------------
export function renderConversations(root, ctx) {
  clear(root);
  const c = ctx.analysis.conversations || {};
  root.appendChild(el('h2', null, 'Conversations & endpoints'));
  const cards = el('div', 'cards');
  cards.appendChild(card('Hosts', (c.hosts || []).length));
  cards.appendChild(card('IP conversations', (c.ipConvs || []).length));
  cards.appendChild(card('TCP streams', (c.tcpConvs || []).length));
  cards.appendChild(card('UDP flows', (c.udpConvs || []).length));
  root.appendChild(cards);

  root.appendChild(el('h3', null, 'Top hosts'));
  const gh = grid(['Address', 'Hostnames', 'Pkts', 'Bytes', 'Protocols']);
  for (const h of (c.hosts || []).slice(0, 60)) {
    const tr = el('tr');
    const addr = td(h.ip, 'mono linklike'); addr.firstChild && (addr.onclick = () => ctx.applyFilterExpr(`ip.addr == ${h.ip}`));
    addr.onclick = () => ctx.applyFilterExpr(`ip.addr == ${h.ip}`);
    tr.append(addr, td((h.hostnames || []).slice(0, 3).join(', ') || (h.isPrivate ? '(private)' : '')), td(String((h.packetsIn || 0) + (h.packetsOut || 0)), 'num'), td(fmtBytes((h.bytesIn || 0) + (h.bytesOut || 0)), 'num'), td((h.protocols || []).join(' ')));
    gh.tbody.appendChild(tr);
  }
  root.appendChild(gh.table);

  root.appendChild(el('h3', null, 'TCP streams'));
  const gt = grid(['Stream', 'Client', 'Server', 'Proto', 'Bytes', 'Health', '']);
  for (const t of (c.tcpConvs || []).slice(0, 200)) {
    const tr = el('tr');
    const health = [];
    if (t.retrans) health.push(`${t.retrans} retrans`);
    if (t.resets) health.push('RST');
    if (!t.complete) health.push('incomplete');
    const follow = el('a', 'linklike', 'follow');
    follow.onclick = () => ctx.followStream('tcp', t.id, `TCP stream ${t.id}  ${t.a?.ip}:${t.a?.port} ↔ ${t.b?.ip}:${t.b?.port}`);
    tr.append(td('#' + t.id, 'num'), td(`${t.a?.ip}:${t.a?.port}`, 'mono'), td(`${t.b?.ip}:${t.b?.port}`, 'mono'),
      td((t.proto || '').toUpperCase()), td(fmtBytes(t.bytes || 0), 'num'), td(health.join(', ') || 'ok', health.length ? '' : 'dim'), tdNode(follow));
    gt.tbody.appendChild(tr);
  }
  root.appendChild(gt.table);
}

// ---- Credentials ------------------------------------------------------------
export function renderCredentials(root, ctx) {
  clear(root);
  const creds = ctx.analysis.iocs?.credentials || [];
  root.appendChild(el('h2', null, 'Captured credentials'));
  root.appendChild(el('p', 'dim', 'Secrets observed in cleartext or weakly protected protocols. Presence here means the credential was exposed on the wire.'));
  if (!creds.length) { root.appendChild(el('div', 'empty', 'No credentials recovered from this capture.')); return; }
  const g = grid(['Protocol', 'Type', 'Username', 'Secret', 'Server', 'Packet']);
  for (const c of creds) {
    const tr = el('tr');
    const link = el('a', 'linklike', '#' + c.packet); link.onclick = () => ctx.goToPacket(c.packet);
    tr.append(td((c.proto || '').toUpperCase()), td(c.kind || ''), td(c.user || '—'), td(truncate(c.secret, 60), 'mono'), td(c.dst || c.note || ''), tdNode(link));
    g.tbody.appendChild(tr);
  }
  root.appendChild(g.table);
}

// ---- Files ------------------------------------------------------------------
export function renderFiles(root, ctx) {
  clear(root);
  const ex = ctx.analysis.extraction || {};
  const files = ex.files || [];
  root.appendChild(el('h2', null, 'Extracted files & artifacts'));
  root.appendChild(el('p', 'dim', `Objects carved from reassembled streams. ${files.length} file(s), ${fmtBytes(ex.totalBytes || 0)} total. Downloaded files are reconstructed from packet data — treat unknown executables as hostile.`));
  if (!files.length) { root.appendChild(el('div', 'empty', 'No transferable files found (HTTP bodies, SMB reads, email attachments).')); }
  else {
    const g = grid(['Name', 'Type', 'Size', 'SHA-256', 'Host', 'Src', '']);
    files.forEach(f => {
      const tr = el('tr');
      if (f.executable) tr.style.background = '#2a1010';
      const dl = el('a', 'linklike', 'download'); dl.onclick = () => ctx.downloadFile(f.idx);
      const nameCell = td(truncate(f.filename, 40)); if (f.executable) nameCell.appendChild(el('span', 'chip arp-conflict', 'exe'));
      tr.append(tdNode(nameCell), td(f.fileType || f.contentType || '?'), td(fmtBytes(f.size || 0), 'num'), td(truncate(f.sha256, 20), 'mono'), td(f.host || ''), td('#' + (f.packet || '?'), 'mono'), tdNode(dl));
      g.tbody.appendChild(tr);
    });
    root.appendChild(g.table);
  }
  if (ex.emails && ex.emails.length) {
    root.appendChild(el('h3', null, 'Email messages'));
    const g = grid(['From', 'To', 'Subject', 'Packet']);
    ex.emails.forEach(m => { const tr = el('tr'); const l = el('a', 'linklike', '#' + (m.packet || '?')); l.onclick = () => ctx.goToPacket(m.packet); tr.append(td(m.from || ''), td((m.to || []).join(', ')), td(m.subject || ''), tdNode(l)); g.tbody.appendChild(tr); });
    root.appendChild(g.table);
  }
}

// ---- DNS --------------------------------------------------------------------
export function renderDns(root, ctx) {
  clear(root);
  const iocs = ctx.analysis.iocs || {};
  const domains = iocs.domains || [];
  root.appendChild(el('h2', null, 'DNS activity'));
  const cards = el('div', 'cards');
  cards.appendChild(card('Unique domains', domains.length));
  cards.appendChild(card('Suspicious', domains.filter(d => d.suspicious).length));
  root.appendChild(cards);
  root.appendChild(el('h3', null, 'Queried domains'));
  const g = grid(['Domain', 'Type', 'Resolved to', 'Count', 'Flags']);
  for (const d of domains.slice(0, 400)) {
    const tr = el('tr');
    if (d.suspicious) tr.style.background = '#241010';
    const name = td(truncate(d.name, 50), 'mono linklike'); name.onclick = () => ctx.applyFilterExpr(`dns.qry.name contains "${d.name.slice(0, 40)}"`);
    tr.append(tdNode(name), td((d.types || []).join(',') || ''), td((d.addresses || []).slice(0, 3).join(', ') || ''), td(String(d.count || 1), 'num'), td(d.suspicious ? (d.reason || 'suspicious') : '', d.suspicious ? '' : 'dim'));
    g.tbody.appendChild(tr);
  }
  root.appendChild(g.table);
}

// ---- Protocol hierarchy -----------------------------------------------------
export function renderHierarchy(root, ctx) {
  clear(root);
  const h = ctx.analysis.summary?.protocolHierarchy;
  root.appendChild(el('h2', null, 'Protocol hierarchy'));
  const s = ctx.analysis.summary || {};
  const cards = el('div', 'cards');
  cards.appendChild(card('Packets', (s.packetCount || 0).toLocaleString()));
  cards.appendChild(card('Bytes', fmtBytes(s.bytes || 0)));
  cards.appendChild(card('Duration', (s.duration || 0).toFixed(2) + 's', true));
  root.appendChild(cards);
  const wrap = el('div', 'hierarchy');
  const head = el('div', 'hrow head'); head.append(el('div', null, 'Protocol'), el('div', 'num', 'Packets'), el('div', 'num', 'Bytes'), el('div', 'num', '%'));
  wrap.appendChild(head);
  const total = s.packetCount || 1;
  const walk = (node, depth) => {
    if (!node) return;
    for (const [name, v] of Object.entries(node)) {
      const row = el('div', 'hrow');
      const label = el('div', null, '  '.repeat(depth) + name);
      label.classList.add('linklike'); label.onclick = () => ctx.applyFilterExpr(name);
      row.append(label, el('div', 'num', (v.packets || 0).toLocaleString()), el('div', 'num', fmtBytes(v.bytes || 0)), el('div', 'num', ((v.packets / total) * 100).toFixed(1) + '%'));
      wrap.appendChild(row);
      if (v.children) walk(v.children, depth + 1);
    }
  };
  // Root may be a single node { packets, bytes, children } or a map of proto->node.
  const rootChildren = h && h.children && typeof h.children === 'object' && !('packets' in h.children) ? h.children : (h && ('packets' in h) ? h.children : h);
  walk(rootChildren || {}, 0);
  root.appendChild(wrap);
}

// helpers
function td(txt, cls) { const t = el('td', cls); t.textContent = txt == null ? '' : txt; return t; }
function tdNode(node) { const t = el('td'); t.appendChild(node); return t; }
function truncate(s, n) { s = s == null ? '' : String(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
function escapeHtml(s) { return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }
