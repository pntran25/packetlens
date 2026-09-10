// DNS (RFC 1035) dissector, also used for mDNS (5353) and LLMNR (5355).
// Exports name/RR helpers reused by nbns.js and dhcp.js.
import { Layer } from '../../core/packet.js';
import { u16be, u32be, ipv4, ipv6, hex, toHex, entropy } from '../../core/bytes.js';

export const OPCODES = { 0: 'Standard query', 1: 'Inverse query', 2: 'Server status request', 4: 'Notify', 5: 'Dynamic update', 6: 'DNS Stateful Operations' };
export const RCODES = {
  0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name', 4: 'Not implemented', 5: 'Refused',
  6: 'Name exists', 7: 'RRset exists', 8: 'RRset does not exist', 9: 'Not authoritative', 10: 'Name not in zone', 11: 'DSO type not implemented',
  16: 'Bad OPT version', 17: 'Key not recognized', 18: 'Signature out of time window', 19: 'Bad TKEY mode', 20: 'Duplicate key name', 21: 'Algorithm not supported', 22: 'Bad truncation', 23: 'Bad/missing server cookie',
};
export const RR_TYPES = {
  1: 'A', 2: 'NS', 3: 'MD', 4: 'MF', 5: 'CNAME', 6: 'SOA', 7: 'MB', 8: 'MG', 9: 'MR', 10: 'NULL', 11: 'WKS', 12: 'PTR', 13: 'HINFO', 14: 'MINFO', 15: 'MX', 16: 'TXT',
  17: 'RP', 18: 'AFSDB', 19: 'X25', 20: 'ISDN', 21: 'RT', 24: 'SIG', 25: 'KEY', 28: 'AAAA', 29: 'LOC', 33: 'SRV', 35: 'NAPTR', 36: 'KX', 37: 'CERT', 39: 'DNAME',
  41: 'OPT', 42: 'APL', 43: 'DS', 44: 'SSHFP', 45: 'IPSECKEY', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 49: 'DHCID', 50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA', 53: 'SMIMEA',
  55: 'HIP', 59: 'CDS', 60: 'CDNSKEY', 61: 'OPENPGPKEY', 62: 'CSYNC', 63: 'ZONEMD', 64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 108: 'EUI48', 109: 'EUI64',
  249: 'TKEY', 250: 'TSIG', 251: 'IXFR', 252: 'AXFR', 253: 'MAILB', 254: 'MAILA', 255: 'ANY', 256: 'URI', 257: 'CAA', 32768: 'TA', 32769: 'DLV',
};
const CLASSES = { 1: 'IN', 2: 'CS', 3: 'CH', 4: 'HS', 254: 'NONE', 255: 'ANY' };
const EDNS_OPTIONS = { 1: 'LLQ', 2: 'UL', 3: 'NSID', 5: 'DAU', 6: 'DHU', 7: 'N3U', 8: 'Client Subnet', 9: 'EXPIRE', 10: 'COOKIE', 11: 'TCP Keepalive', 12: 'Padding', 13: 'CHAIN', 14: 'Key Tag', 15: 'Extended DNS Error', 65001: 'Device ID' };
const SVC_PARAMS = { 0: 'mandatory', 1: 'alpn', 2: 'no-default-alpn', 3: 'port', 4: 'ipv4hint', 5: 'ech', 6: 'ipv6hint', 7: 'dohpath' };

export function typeName(t) { return RR_TYPES[t] || `TYPE${t}`; }
export function className(c) { return CLASSES[c] || `Class ${c}`; }

function escapeLabel(d, s, e) {
  let out = '';
  for (let i = s; i < e; i++) {
    const c = d[i];
    if (c === 0x2e || c === 0x5c) out += '\\' + String.fromCharCode(c);
    else if (c >= 0x20 && c < 0x7f) out += String.fromCharCode(c);
    else out += '\\' + c.toString().padStart(3, '0');
  }
  return out;
}

/**
 * Read a (possibly compressed) domain name.
 * @returns {{ name: string, labels: string[], raw: Uint8Array[], next: number, err: string|null }}
 *   next = offset just past the name in the *original* byte stream (after the first pointer, if any).
 */
export function readName(data, o, base, end) {
  const labels = [], raw = [];
  let p = o, next = -1, err = null, jumps = 0;
  const visited = new Set();
  for (;;) {
    if (p >= end) { err = 'Name truncated'; break; }
    const len = data[p];
    if (len === 0) { p++; break; }
    if ((len & 0xc0) === 0xc0) {
      if (p + 1 >= end) { err = 'Name pointer truncated'; break; }
      const ptr = base + (((len & 0x3f) << 8) | data[p + 1]);
      if (next < 0) next = p + 2;
      if (ptr >= end || visited.has(ptr) || ++jumps > 32) { err = 'Name pointer loop'; break; }
      visited.add(ptr);
      p = ptr;
      continue;
    }
    if (len & 0xc0) { err = `Unsupported label type 0x${hex(len & 0xc0)}`; break; }
    if (p + 1 + len > end) { err = 'Label truncated'; break; }
    labels.push(escapeLabel(data, p + 1, p + 1 + len));
    raw.push(data.subarray(p + 1, p + 1 + len));
    p += 1 + len;
    if (labels.length > 127) { err = 'Too many labels'; break; }
  }
  if (next < 0) next = p;
  return { name: labels.length ? labels.join('.') : '<Root>', labels, raw, next, err };
}

/** Heuristic anomaly reasons for a name (DNS tunnelling / DGA hints). */
export function nameAnomalies(nm, qtype) {
  const out = [];
  if (nm.name.length > 100) out.push(`name length ${nm.name.length} > 100`);
  const longLabel = nm.raw.find(r => r.length > 40);
  if (longLabel) out.push(`label length ${longLabel.length} > 40`);
  for (const r of nm.raw) {
    if (r.length >= 20) {
      const h = entropy(r);
      if (h > 3.8) { out.push(`high-entropy label (${h.toFixed(2)} bits/byte)`); break; }
    }
  }
  if ((qtype === 10 || qtype === 16) && nm.labels.length >= 4) out.push(`${typeName(qtype)} query for ${nm.labels.length}-label name`);
  return out;
}

function charStrings(data, o, end) {
  const out = [];
  while (o < end) {
    const n = data[o];
    const e = Math.min(end, o + 1 + n);
    out.push(escapeLabel(data, o + 1, e).replace(/\\\./g, '.'));
    o = e;
  }
  return out;
}

function typeBitmap(data, o, end) {
  const types = [];
  while (o + 2 <= end) {
    const win = data[o], len = data[o + 1];
    const e = Math.min(end, o + 2 + len);
    for (let i = o + 2; i < e; i++) {
      for (let b = 0; b < 8; b++) if (data[i] & (0x80 >> b)) types.push(typeName(win * 256 + (i - o - 2) * 8 + b));
    }
    o = e;
    if (!len) break;
  }
  return types;
}

function fmtEpoch(s) {
  try { return new Date(s * 1000).toISOString().slice(0, 19).replace('T', ' '); } catch { return String(s); }
}

/** Render RDATA as a display string. Returns { text, ...extras }. */
export function renderRdata(data, ro, rlen, base, end, type) {
  const re = Math.min(ro + rlen, end);
  const r = { text: '' };
  const hexTail = (o, n = 32) => toHex(data, o, Math.min(re, o + n)) + (re - o > n ? '…' : '');
  try {
    switch (type) {
      case 1: if (rlen === 4 && ro + 4 <= end) { r.text = ipv4(data, ro); r.addr = r.text; } else r.text = `${rlen} bytes`; break;
      case 28: if (rlen === 16 && ro + 16 <= end) { r.text = ipv6(data, ro); r.addr = r.text; } else r.text = `${rlen} bytes`; break;
      case 2: case 5: case 12: case 39: case 7: case 8: case 9: {
        const n = readName(data, ro, base, re); r.text = n.name; r.target = n.name; if (n.err) r.err = n.err; break;
      }
      case 15: case 36: case 21: case 18: {
        if (ro + 2 > re) { r.text = 'truncated'; r.err = 'MX truncated'; break; }
        const n = readName(data, ro + 2, base, re); r.text = `${u16be(data, ro)} ${n.name}`; r.pref = u16be(data, ro); r.target = n.name; if (n.err) r.err = n.err; break;
      }
      case 16: case 99: {
        const strs = charStrings(data, ro, re); r.strings = strs; r.text = strs.map(s => `"${s}"`).join(' '); break;
      }
      case 6: {
        const m = readName(data, ro, base, re); const rn = readName(data, m.next, base, re);
        if (rn.next + 20 <= re) {
          const serial = u32be(data, rn.next), refresh = u32be(data, rn.next + 4), retry = u32be(data, rn.next + 8), expire = u32be(data, rn.next + 12), min = u32be(data, rn.next + 16);
          r.text = `${m.name} ${rn.name} ${serial} ${refresh} ${retry} ${expire} ${min}`;
          r.mname = m.name; r.rname = rn.name; r.serial = serial;
        } else { r.text = `${m.name} ${rn.name} (truncated)`; r.err = 'SOA truncated'; }
        break;
      }
      case 33: {
        if (ro + 6 > re) { r.text = 'truncated'; r.err = 'SRV truncated'; break; }
        const n = readName(data, ro + 6, base, re);
        r.priority = u16be(data, ro); r.weight = u16be(data, ro + 2); r.port = u16be(data, ro + 4); r.target = n.name;
        r.text = `${r.priority} ${r.weight} ${r.port} ${n.name}`; if (n.err) r.err = n.err; break;
      }
      case 35: {
        if (ro + 4 > re) { r.text = 'truncated'; r.err = 'NAPTR truncated'; break; }
        let p = ro + 4; const parts = [];
        for (let i = 0; i < 3 && p < re; i++) { const n = data[p]; parts.push(escapeLabel(data, p + 1, Math.min(re, p + 1 + n))); p = Math.min(re, p + 1 + n); }
        const rep = readName(data, p, base, re);
        r.text = `${u16be(data, ro)} ${u16be(data, ro + 2)} ${parts.map(s => `"${s}"`).join(' ')} ${rep.name}`; break;
      }
      case 13: { const s = charStrings(data, ro, re); r.text = s.map(x => `"${x}"`).join(' '); break; }
      case 257: {
        if (ro + 2 > re) { r.text = 'truncated'; break; }
        const tl = data[ro + 1]; const tagEnd = Math.min(re, ro + 2 + tl);
        r.text = `${data[ro]} ${escapeLabel(data, ro + 2, tagEnd)} "${escapeLabel(data, tagEnd, re)}"`; break;
      }
      case 41: r.text = `${rlen} bytes of options`; break; // handled in parseRR (needs class/ttl)
      case 48: case 60: case 25: {
        if (ro + 4 > re) { r.text = 'truncated'; break; }
        const flags = u16be(data, ro);
        r.text = `flags ${flags}${flags & 1 ? (flags & 0x100 ? ' (KSK/SEP)' : ' (ZSK)') : ''} proto ${data[ro + 2]} alg ${data[ro + 3]} key ${rlen - 4} bytes`; break;
      }
      case 46: case 24: {
        if (ro + 18 > re) { r.text = 'truncated'; break; }
        const signer = readName(data, ro + 18, base, re);
        r.text = `${typeName(u16be(data, ro))} alg ${data[ro + 2]} labels ${data[ro + 3]} ttl ${u32be(data, ro + 4)} exp ${fmtEpoch(u32be(data, ro + 8))} inc ${fmtEpoch(u32be(data, ro + 12))} keytag ${u16be(data, ro + 16)} signer ${signer.name} sig ${Math.max(0, re - signer.next)} bytes`;
        break;
      }
      case 43: case 59: case 32769: {
        if (ro + 4 > re) { r.text = 'truncated'; break; }
        r.text = `keytag ${u16be(data, ro)} alg ${data[ro + 2]} digest type ${data[ro + 3]} ${toHex(data, ro + 4, re)}`; break;
      }
      case 47: { const n = readName(data, ro, base, re); r.text = `${n.name} [${typeBitmap(data, n.next, re).join(' ')}]`; break; }
      case 50: {
        if (ro + 5 > re) { r.text = 'truncated'; break; }
        const sl = data[ro + 4]; let p = ro + 5; const salt = toHex(data, p, Math.min(re, p + sl)); p = Math.min(re, p + sl);
        const hl = p < re ? data[p] : 0; const nh = toHex(data, p + 1, Math.min(re, p + 1 + hl)); p = Math.min(re, p + 1 + hl);
        r.text = `alg ${data[ro]} flags ${data[ro + 1]} iter ${u16be(data, ro + 2)} salt ${salt || '-'} next ${nh} [${typeBitmap(data, p, re).join(' ')}]`; break;
      }
      case 51: { if (ro + 5 > re) { r.text = 'truncated'; break; } r.text = `alg ${data[ro]} flags ${data[ro + 1]} iter ${u16be(data, ro + 2)} salt ${toHex(data, ro + 5, Math.min(re, ro + 5 + data[ro + 4])) || '-'}`; break; }
      case 52: case 53: { if (ro + 3 > re) { r.text = 'truncated'; break; } r.text = `${data[ro]} ${data[ro + 1]} ${data[ro + 2]} ${toHex(data, ro + 3, re)}`; break; }
      case 44: { if (ro + 2 > re) { r.text = 'truncated'; break; } r.text = `alg ${data[ro]} type ${data[ro + 1]} ${toHex(data, ro + 2, re)}`; break; }
      case 64: case 65: {
        if (ro + 2 > re) { r.text = 'truncated'; break; }
        const prio = u16be(data, ro); const t = readName(data, ro + 2, base, re);
        r.priority = prio; r.target = t.name === '<Root>' ? '.' : t.name;
        const params = [];
        let p = t.next;
        while (p + 4 <= re) {
          const k = u16be(data, p), kl = u16be(data, p + 2); const ke = Math.min(re, p + 4 + kl);
          const kn = SVC_PARAMS[k] || `key${k}`;
          let v = toHex(data, p + 4, ke);
          if (k === 1) { const a = charStrings(data, p + 4, ke); r.alpn = a; v = a.join(','); }
          else if (k === 3 && kl === 2) v = String(u16be(data, p + 4));
          else if (k === 4) { const a = []; for (let q = p + 4; q + 4 <= ke; q += 4) a.push(ipv4(data, q)); v = a.join(','); }
          else if (k === 6) { const a = []; for (let q = p + 4; q + 16 <= ke; q += 16) a.push(ipv6(data, q)); v = a.join(','); }
          else if (k === 7) v = escapeLabel(data, p + 4, ke);
          params.push(k === 2 ? kn : `${kn}=${v}`);
          p = ke;
        }
        r.text = `${prio} ${r.target}${params.length ? ' ' + params.join(' ') : ''}`; break;
      }
      case 256: { if (ro + 4 > re) { r.text = 'truncated'; break; } r.text = `${u16be(data, ro)} ${u16be(data, ro + 2)} "${escapeLabel(data, ro + 4, re)}"`; break; }
      case 250: case 249: {
        const alg = readName(data, ro, base, re); r.text = `${alg.name} ${Math.max(0, re - alg.next)} bytes`; break;
      }
      default: r.text = rlen ? `${rlen} bytes: ${hexTail(ro)}` : '(empty)';
    }
  } catch (e) {
    r.text = `${rlen} bytes (undecodable)`; r.err = 'RDATA decode error';
  }
  return r;
}

function parseQuestion(data, o, base, end, mdns) {
  const n = readName(data, o, base, end);
  if (n.err) return { err: n.err, next: n.next };
  if (n.next + 4 > end) return { err: 'Question truncated', next: end };
  const type = u16be(data, n.next); let cls = u16be(data, n.next + 2);
  const q = { name: n.name, type, typeName: typeName(type), cls, clsName: '' };
  if (mdns && (cls & 0x8000)) { q.unicast = true; cls &= 0x7fff; q.cls = cls; }
  q.clsName = className(cls);
  const field = { name: `${n.name}: type ${q.typeName}, class ${q.clsName}`, value: '', offset: o, length: n.next + 4 - o, children: [
    { name: 'Name', value: n.name, offset: o, length: n.next - o },
    { name: 'Type', value: `${q.typeName} (${type})`, offset: n.next, length: 2 },
    { name: 'Class', value: `${q.clsName} (0x${hex(cls, 4)})${q.unicast ? ', "QU" question' : ''}`, offset: n.next + 2, length: 2 },
  ] };
  return { rr: q, nm: n, field, next: n.next + 4 };
}

function parseRR(data, o, base, end, mdns) {
  const n = readName(data, o, base, end);
  if (n.err) return { err: n.err, next: n.next };
  const h = n.next;
  if (h + 10 > end) return { err: 'Resource record truncated', next: end };
  const type = u16be(data, h); let cls = u16be(data, h + 2); const ttl = u32be(data, h + 4); const rlen = u16be(data, h + 8);
  const ro = h + 10;
  const rr = { name: n.name, type, typeName: typeName(type), cls, clsName: '', ttl, data: '', rdOffset: ro, rdLen: rlen };
  let err = null;
  if (ro + rlen > end) err = 'RDATA truncated';
  const re = Math.min(ro + rlen, end);
  const children = [{ name: 'Name', value: n.name, offset: o, length: h - o }, { name: 'Type', value: `${rr.typeName} (${type})`, offset: h, length: 2 }];
  if (type === 41) {
    // EDNS0 pseudo-RR: class = UDP payload size, ttl = ext rcode / version / flags.
    rr.udpSize = cls; rr.extRcode = ttl >>> 24; rr.ednsVersion = (ttl >>> 16) & 0xff; rr.do = !!(ttl & 0x8000);
    rr.clsName = `UDP payload size ${cls}`;
    children.push({ name: 'UDP payload size', value: cls, offset: h + 2, length: 2 });
    children.push({ name: 'Higher bits in extended RCODE', value: rr.extRcode, offset: h + 4, length: 1 });
    children.push({ name: 'EDNS0 version', value: rr.ednsVersion, offset: h + 5, length: 1 });
    children.push({ name: 'Z', value: `0x${hex(ttl & 0xffff, 4)}${rr.do ? ' (DO: DNSSEC OK)' : ''}`, offset: h + 6, length: 2 });
    children.push({ name: 'Data length', value: rlen, offset: h + 8, length: 2 });
    const opts = [];
    let p = ro;
    while (p + 4 <= re) {
      const code = u16be(data, p), ol = u16be(data, p + 2); const oe = Math.min(re, p + 4 + ol);
      const on = EDNS_OPTIONS[code] || `Option ${code}`;
      let v = toHex(data, p + 4, oe);
      if (code === 8 && p + 8 <= oe) {
        const fam = u16be(data, p + 4), src = data[p + 6], scope = data[p + 7];
        const ab = new Uint8Array(fam === 2 ? 16 : 4); ab.set(data.subarray(p + 8, Math.min(oe, p + 8 + ab.length)));
        v = `${fam === 2 ? ipv6(ab, 0) : ipv4(ab, 0)}/${src} (scope ${scope})`;
        rr.clientSubnet = v;
      } else if (code === 15 && p + 6 <= oe) v = `code ${u16be(data, p + 4)} ${escapeLabel(data, p + 6, oe)}`;
      else if (code === 3) v = escapeLabel(data, p + 4, oe) || '(empty)';
      opts.push({ code, name: on, value: v });
      children.push({ name: on, value: v, offset: p, length: oe - p });
      p = oe;
    }
    rr.options = opts;
    rr.data = `UDP size ${cls}, version ${rr.ednsVersion}${rr.do ? ', DO' : ''}${opts.length ? ', ' + opts.map(x => `${x.name}=${x.value}`).join(' ') : ''}`;
  } else {
    if (mdns && (cls & 0x8000)) { rr.cacheFlush = true; cls &= 0x7fff; rr.cls = cls; }
    rr.clsName = className(cls);
    const rd = renderRdata(data, ro, rlen, base, end, type);
    rr.data = rd.text;
    for (const k of ['addr', 'target', 'pref', 'priority', 'weight', 'port', 'strings', 'alpn', 'mname', 'rname', 'serial']) if (rd[k] !== undefined) rr[k] = rd[k];
    if (rd.err && !err) err = rd.err;
    children.push({ name: 'Class', value: `${rr.clsName} (0x${hex(cls, 4)})${rr.cacheFlush ? ', cache flush' : ''}`, offset: h + 2, length: 2 });
    children.push({ name: 'Time to live', value: `${ttl} (${fmtTtl(ttl)})`, offset: h + 4, length: 4 });
    children.push({ name: 'Data length', value: rlen, offset: h + 8, length: 2 });
    children.push({ name: rdataFieldName(type), value: rr.data, offset: ro, length: re - ro });
  }
  const field = { name: `${n.name}: type ${rr.typeName}, class ${rr.clsName}${type === 41 ? '' : ', ' + rr.data}`, value: '', offset: o, length: re - o, children };
  return { rr, nm: n, field, next: re, err };
}

function rdataFieldName(type) {
  switch (type) {
    case 1: case 28: return 'Address';
    case 5: return 'CNAME'; case 2: return 'Name server'; case 12: return 'Domain name';
    case 15: return 'Mail exchange'; case 16: return 'TXT'; case 6: return 'SOA';
    case 33: return 'Service'; default: return 'RDATA';
  }
}

function fmtTtl(t) {
  if (t < 60) return `${t} second${t === 1 ? '' : 's'}`;
  if (t < 3600) return `${Math.floor(t / 60)} minute${t < 120 ? '' : 's'}${t % 60 ? `, ${t % 60} seconds` : ''}`;
  if (t < 86400) return `${Math.floor(t / 3600)} hour${t < 7200 ? '' : 's'}${t % 3600 ? `, ${Math.floor((t % 3600) / 60)} minutes` : ''}`;
  return `${Math.floor(t / 86400)} day${t < 172800 ? '' : 's'}${t % 86400 ? `, ${Math.floor((t % 86400) / 3600)} hours` : ''}`;
}

/**
 * Parse one DNS message at data[base, end) into layer `l`.
 * Returns the parsed message (also mirrored as layer properties) plus `errs`.
 */
export function parseDnsMessage(l, data, base, end, opts = {}) {
  const errs = [];
  const msg = { queries: [], answers: [], authorities: [], additionals: [], names: [], errs };
  if (end - base < 12) { errs.push('DNS header truncated'); return msg; }
  const id = u16be(data, base), flags = u16be(data, base + 2);
  const counts = [u16be(data, base + 4), u16be(data, base + 6), u16be(data, base + 8), u16be(data, base + 10)];
  const isResponse = !!(flags & 0x8000);
  const opcode = (flags >> 11) & 0xf;
  let rcode = flags & 0xf;
  const fl = { qr: isResponse, aa: !!(flags & 0x0400), tc: !!(flags & 0x0200), rd: !!(flags & 0x0100), ra: !!(flags & 0x0080), z: !!(flags & 0x0040), ad: !!(flags & 0x0020), cd: !!(flags & 0x0010) };
  const opcodeName = OPCODES[opcode] || `Opcode ${opcode}`;
  Object.assign(msg, { id, flagsRaw: flags, isResponse, opcode, opcodeName, rcode, flags: fl });

  l.add('Transaction ID', `0x${hex(id, 4)}`, base, 2);
  const fg = l.addGroup('Flags', `0x${hex(flags, 4)} ${opcodeName}${isResponse ? ' response' : ''}`, base + 2, 2, []);
  const bit = (name, v, desc) => fg.children.push({ name, value: `${v ? 1 : 0} (${desc})`, offset: base + 2, length: 2 });
  bit('Response', isResponse, isResponse ? 'Message is a response' : 'Message is a query');
  fg.children.push({ name: 'Opcode', value: `${opcodeName} (${opcode})`, offset: base + 2, length: 2 });
  if (isResponse) bit('Authoritative', fl.aa, fl.aa ? 'Server is an authority for domain' : 'Server is not an authority for domain');
  bit('Truncated', fl.tc, fl.tc ? 'Message is truncated' : 'Message is not truncated');
  bit('Recursion desired', fl.rd, fl.rd ? 'Do query recursively' : "Don't do query recursively");
  if (isResponse) bit('Recursion available', fl.ra, fl.ra ? 'Server can do recursive queries' : "Server can't do recursive queries");
  bit('Z', fl.z, 'reserved');
  if (isResponse) bit('Answer authenticated', fl.ad, fl.ad ? 'Answer/authority portion was authenticated by the server' : 'Answer/authority portion was not authenticated by the server');
  bit('Non-authenticated data', fl.cd, fl.cd ? 'Acceptable' : 'Unacceptable');
  const rcField = fg.children.push({ name: 'Reply code', value: '', offset: base + 2, length: 2 }) - 1;
  l.add('Questions', counts[0], base + 4, 2);
  l.add('Answer RRs', counts[1], base + 6, 2);
  l.add('Authority RRs', counts[2], base + 8, 2);
  l.add('Additional RRs', counts[3], base + 10, 2);

  let o = base + 12;
  const sections = [['Queries', 'queries', true], ['Answers', 'answers', false], ['Authoritative nameservers', 'authorities', false], ['Additional records', 'additionals', false]];
  let stop = false;
  for (let s = 0; s < 4 && !stop; s++) {
    const [title, prop, isQ] = sections[s];
    const count = counts[s];
    if (!count) continue;
    const g = l.addGroup(title, String(count), o, 0, []);
    for (let i = 0; i < count; i++) {
      if (o >= end) { errs.push(`${title} section truncated (${i} of ${count} records present)`); stop = true; break; }
      const r = isQ ? parseQuestion(data, o, base, end, opts.mdns) : parseRR(data, o, base, end, opts.mdns);
      if (r.rr) {
        msg[prop].push(r.rr);
        g.children.push(r.field);
        msg.names.push({ nm: r.nm, qtype: isQ ? r.rr.type : r.rr.type, rr: r.rr, section: prop });
        if (r.rr.type === 41 && !isQ) { msg.opt = r.rr; if (r.rr.extRcode) rcode |= r.rr.extRcode << 4; }
      }
      if (r.err) { errs.push(r.err); stop = true; break; }
      if (r.next <= o) { stop = true; break; }
      o = r.next;
    }
    g.length = Math.max(0, o - g.offset);
  }
  msg.rcode = rcode;
  msg.rcodeName = RCODES[rcode] || `Rcode ${rcode}`;
  fg.children[rcField].value = `${msg.rcodeName} (${rcode})`;
  msg.end = o;
  return msg;
}

/** Build the Info-column summary in Wireshark style. */
export function dnsSummary(msg, label = '') {
  if (!msg.opcodeName) return `${label ? label + ' ' : ''}[Malformed]`;
  let s = `${msg.opcodeName}${msg.isResponse ? ' response' : ''} 0x${hex(msg.id, 4)}`;
  if (msg.isResponse && msg.rcode !== 0) s += ` ${msg.rcodeName}`;
  for (const q of msg.queries) s += ` ${q.typeName} ${q.name}${q.unicast ? ' "QU" question' : ''}`;
  if (msg.isResponse) for (const a of msg.answers) s += ` ${a.typeName} ${a.type === 41 ? '' : a.data}`.replace(/\s+$/, '');
  if (msg.flags?.tc) s += ' [Truncated]';
  return s;
}

/** Update state.dns.names / answers / transactions and the per-capture suspicious list. */
function updateState(l, msg, ctx) {
  const { state, packet, parent } = ctx;
  const ip = packet.ip;
  const src = ip?.src ?? '', dst = ip?.dst ?? '';
  const dnsSt = state.dns;
  const ext = state.ext.dns ||= { suspicious: [] };

  // Hostname map from A/AAAA (+ CNAME chain aliases).
  const alias = new Map(); // target -> alias (CNAME rr.name)
  const all = [...msg.answers, ...msg.authorities, ...msg.additionals];
  for (const rr of all) if (rr.type === 5 && rr.target) alias.set(rr.target.toLowerCase(), rr.name);
  for (const rr of all) {
    if ((rr.type === 1 || rr.type === 28) && rr.addr) {
      let set = dnsSt.names.get(rr.addr);
      if (!set) dnsSt.names.set(rr.addr, set = new Set());
      set.add(rr.name);
      let cur = rr.name.toLowerCase(), hops = 0;
      while (alias.has(cur) && hops++ < 16) { const a = alias.get(cur); set.add(a); cur = a.toLowerCase(); }
      let aset = dnsSt.answers.get(rr.name);
      if (!aset) dnsSt.answers.set(rr.name, aset = new Set());
      aset.add(rr.addr);
    }
  }

  // Transactions.
  const q = msg.queries[0];
  const client = msg.isResponse ? dst : src, server = msg.isResponse ? src : dst;
  const key = `${msg.id}|${(q?.name || '').toLowerCase()}|${q?.type ?? ''}|${client}|${server}`;
  const txns = dnsSt.transactions ||= [];
  if (!msg.isResponse) {
    const t = { id: msg.id, name: q?.name ?? '', type: q?.type ?? 0, typeName: q?.typeName ?? '', query: packet.index, response: null, ts: packet.ts, src: client, server, answers: [] };
    dnsSt.pending.set(key, t);
    txns.push(t);
    l.transaction = t;
  } else {
    const answers = msg.answers.filter(a => a.type !== 41).map(a => `${a.typeName} ${a.data}`);
    let t = dnsSt.pending.get(key);
    if (t) {
      dnsSt.pending.delete(key);
      t.response = packet.index; t.rtt = packet.ts - t.ts;
    } else {
      t = { id: msg.id, name: q?.name ?? msg.answers[0]?.name ?? '', type: q?.type ?? msg.answers[0]?.type ?? 0, typeName: q?.typeName ?? msg.answers[0]?.typeName ?? '', query: null, response: packet.index, ts: packet.ts, src: client, server, answers: [] };
      txns.push(t);
    }
    t.rcode = msg.rcode; t.rcodeName = msg.rcodeName; t.answers = answers;
    l.transaction = t;
    if (t.rtt !== undefined) l.add('[Time]', `${t.rtt.toFixed(6)} seconds`, -1, 0);
    if (t.query) l.add('[Request In]', t.query, -1, 0);
  }

  // Anomaly hints.
  const reasons = [];
  const seen = new Set();
  for (const { nm, qtype, rr, section } of msg.names) {
    for (const r of nameAnomalies(nm, section === 'queries' ? qtype : 0)) reasons.push([r, nm.name]);
    if (rr.type === 16 && rr.rdLen > 200) reasons.push([`TXT rdata ${rr.rdLen} bytes > 200`, nm.name]);
  }
  if (reasons.length) {
    packet.tags.add('dns-suspicious');
    l.notes ||= [];
    const g = l.addGroup('[Anomalies]', `${reasons.length}`, -1, 0, []);
    for (const [reason, name] of reasons) {
      const k = `${reason}|${name}`;
      if (seen.has(k)) continue;
      seen.add(k);
      l.notes.push(`${reason}: ${name}`);
      g.children.push({ name: reason, value: name, offset: -1, length: 0 });
      ext.suspicious.push({ packet: packet.index, reason, name });
    }
  }
  void parent;
}

function applyMsg(l, msg) {
  l.id = msg.id; l.isResponse = !!msg.isResponse; l.opcode = msg.opcode ?? 0; l.opcodeName = msg.opcodeName ?? '';
  l.rcode = msg.rcode ?? 0; l.rcodeName = msg.rcodeName ?? ''; l.flags = msg.flags ?? {};
  l.queries = msg.queries; l.answers = msg.answers; l.authorities = msg.authorities; l.additionals = msg.additionals;
  if (msg.opt) l.edns = { udpSize: msg.opt.udpSize, version: msg.opt.ednsVersion, do: msg.opt.do, options: msg.opt.options, clientSubnet: msg.opt.clientSubnet };
  // Filter-friendly aliases.
  l.qryName = msg.queries[0]?.name ?? ''; l.qryType = msg.queries[0]?.type ?? 0;
  l.respAddr = msg.answers.filter(a => a.addr).map(a => a.addr);
}

function labelFor(key, isTcp) {
  const [sp, dp] = key;
  if (!isTcp && (sp === 5353 || dp === 5353)) return ['MDNS', 'Multicast Domain Name System'];
  if (!isTcp && (sp === 5355 || dp === 5355)) return ['LLMNR', 'Link-local Multicast Name Resolution'];
  return ['DNS', 'Domain Name System'];
}

function markStream(ctx) {
  const st = ctx.packet.stream;
  if (!st) return;
  const rec = ctx.state[st.kind]?.list[st.id];
  if (rec && !rec.proto) rec.proto = 'dns';
}

const dns = {
  id: 'dns',
  name: 'Domain Name System',
  udpPorts: [53, 5353, 5355],
  tcpPorts: [53],
  dissect(ctx) {
    const { data, offset, end, parent, packet } = ctx;
    // parent is the tcp layer for the first message, or a previous dns layer when chained.
    const isTcp = parent?.proto === 'tcp' || packet.stream?.kind === 'tcp' || !!packet.layer('tcp');
    const [label, name] = labelFor(ctx.key || [0, 0], isTcp);
    if (isTcp) {
      if (end - offset < 2) return null;
      const mlen = u16be(data, offset);
      if (mlen < 12) return null; // not a DNS message start (continuation of a previous segment?)
      const base = offset + 2;
      const mend = Math.min(base + mlen, end);
      const l = new Layer('dns', name, offset, mend - offset);
      l.label = label;
      l.add('Length', mlen, offset, 2);
      const msg = parseDnsMessage(l, data, base, mend, {});
      applyMsg(l, msg);
      const partial = base + mlen > end;
      if (partial) {
        l.notes = [`Message continues in next segment (${mlen} bytes declared, ${end - base} present)`];
        l.add('[Continuation]', l.notes[0], -1, 0);
      } else for (const e of msg.errs) l.error(e);
      l.summary = dnsSummary(msg) + (partial ? ' [TCP segment of a reassembled PDU]' : '');
      if (msg.opcodeName) updateState(l, msg, ctx);
      markStream(ctx);
      if (!partial && mend + 2 <= end) l.next = { table: 'tcpPort', key: ctx.key, offset: mend, end };
      return l;
    }
    if (end - offset < 12) return null;
    const l = new Layer('dns', name, offset, end - offset);
    l.label = label;
    const msg = parseDnsMessage(l, data, offset, end, { mdns: label !== 'DNS' });
    applyMsg(l, msg);
    for (const e of msg.errs) l.error(e);
    l.summary = dnsSummary(msg);
    if (msg.opcodeName) updateState(l, msg, ctx);
    markStream(ctx);
    void packet;
    return l;
  },
};

export default [dns];
