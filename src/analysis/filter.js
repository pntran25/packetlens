// Wireshark-like display filter: tokenizer + recursive-descent parser + evaluator.
//
// Public API:
//   compileFilter(expr) -> { ok:true, predicate:(packet)=>boolean, fields:string[] }
//                        | { ok:false, error:{ message, position } }
//   filterPackets(packets, expr) -> Packet[]  (or the { ok:false, error } object)
//   validateFilter(expr) -> { ok:true } | { ok:false, error:{ message, position } }
//   FIELDS -> [{ name, proto, type, desc }]  catalog for autocomplete
//
// Grammar (precedence low->high): or -> and -> not -> comparison/primary.
//   expr    := orExpr
//   orExpr  := andExpr (('||'|'or') andExpr)*
//   andExpr := notExpr (('&&'|'and') notExpr)*
//   notExpr := ('!'|'not') notExpr | cmpExpr
//   cmpExpr := '(' orExpr ')' | field (OP value | 'in' '{' value* '}')?
// A bare protocol name or field is an existence test. Comparisons are type-aware.
// Never throws on bad input — compile errors are returned as { ok:false, error }.

import { byId } from '../core/registry.js';

// ---------------------------------------------------------------------------
// Error type carrying a character position for live UI feedback.
class FilterError extends Error {
  constructor(message, position) { super(message); this.name = 'FilterError'; this.position = position | 0; }
}

// ---------------------------------------------------------------------------
// Tokenizer.
// Word tokens greedily capture identifiers AND bare values (ips, macs, numbers,
// hostnames, cidr). Context (field vs value) is resolved by the parser.
const WORD_RE = /[A-Za-z0-9_.:%/\-]/;

function tokenize(src) {
  const toks = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v') { i++; continue; }
    const start = i;
    if (c === '(') { toks.push({ type: '(', pos: i }); i++; continue; }
    if (c === ')') { toks.push({ type: ')', pos: i }); i++; continue; }
    if (c === '{') { toks.push({ type: '{', pos: i }); i++; continue; }
    if (c === '}') { toks.push({ type: '}', pos: i }); i++; continue; }
    if (c === '"' || c === "'") {
      const q = c; i++; let buf = '';
      while (i < n && src[i] !== q) {
        if (src[i] === '\\' && i + 1 < n) { buf += src[i + 1]; i += 2; }
        else { buf += src[i]; i++; }
      }
      if (i >= n) throw new FilterError('Unterminated string literal', start);
      i++; toks.push({ type: 'string', value: buf, pos: start }); continue;
    }
    if (c === '&') { if (src[i + 1] === '&') { toks.push({ type: 'and', pos: i }); i += 2; continue; } throw new FilterError("Expected '&&'", i); }
    if (c === '|') { if (src[i + 1] === '|') { toks.push({ type: 'or', pos: i }); i += 2; continue; } throw new FilterError("Expected '||'", i); }
    if (c === '=') { if (src[i + 1] === '=') i++; toks.push({ type: 'op', value: '==', pos: start }); i++; continue; }
    if (c === '!') { if (src[i + 1] === '=') { toks.push({ type: 'op', value: '!=', pos: i }); i += 2; continue; } toks.push({ type: 'not', pos: i }); i++; continue; }
    if (c === '<') { if (src[i + 1] === '=') { toks.push({ type: 'op', value: '<=', pos: i }); i += 2; continue; } toks.push({ type: 'op', value: '<', pos: i }); i++; continue; }
    if (c === '>') { if (src[i + 1] === '=') { toks.push({ type: 'op', value: '>=', pos: i }); i += 2; continue; } toks.push({ type: 'op', value: '>', pos: i }); i++; continue; }
    if (WORD_RE.test(c)) {
      let j = i; while (j < n && WORD_RE.test(src[j])) j++;
      toks.push({ type: 'word', value: src.slice(i, j), pos: i }); i = j; continue;
    }
    throw new FilterError(`Unexpected character '${c}'`, i);
  }
  toks.push({ type: 'eof', pos: n });
  return toks;
}

// Keyword maps for word tokens acting as operators/logic.
const CMP_WORDS = { eq: '==', ne: '!=', gt: '>', ge: '>=', lt: '<', le: '<=', contains: 'contains', matches: 'matches' };

// ---------------------------------------------------------------------------
// Literal classification and typed comparison helpers.

function ip4int(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let v = 0;
  for (let k = 1; k <= 4; k++) { const o = +m[k]; if (o > 255) return null; v = (v * 256) + o; }
  return v >>> 0;
}

function ip6Groups(s) {
  if (!/^[0-9a-fA-F:]+$/.test(s)) return null;
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':').filter(x => x !== '') : [];
  let groups;
  if (dbl.length === 1) { groups = head; if (groups.length !== 8) return null; }
  else {
    const tail = dbl[1] ? dbl[1].split(':').filter(x => x !== '') : [];
    const mid = 8 - head.length - tail.length;
    if (mid < 0) return null;
    groups = [...head, ...new Array(mid).fill('0'), ...tail];
  }
  const out = [];
  for (const g of groups) { if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null; out.push(parseInt(g, 16)); }
  return out.length === 8 ? out : null;
}

const isMacStr = (x) => /^([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}$/.test(x);
const normMac = (x) => x.split(':').map(h => h.padStart(2, '0').toLowerCase()).join(':');

function addrEq(a, b) {
  a = String(a); b = String(b);
  const ai = ip4int(a), bi = ip4int(b);
  if (ai != null && bi != null) return ai === bi;
  if (isMacStr(a) && isMacStr(b)) return normMac(a) === normMac(b);
  if (a.includes(':') && b.includes(':')) {
    const ga = ip6Groups(a), gb = ip6Groups(b);
    if (ga && gb) return ga.every((x, k) => x === gb[k]);
  }
  return a.toLowerCase() === b.toLowerCase();
}

function cidrMatch(str, lit) {
  if (lit.family === 'v4') {
    const ip = ip4int(str);
    if (ip == null) return false;
    return ((ip & lit.mask) >>> 0) === ((lit.base & lit.mask) >>> 0);
  }
  const g = ip6Groups(str);
  if (!g) return false;
  let ip = 0n; for (const x of g) ip = (ip << 16n) | BigInt(x);
  return (ip & lit.mask) === (lit.base & lit.mask);
}

function toNum(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'string') {
    if (v === '') return NaN;
    if (/^0x[0-9a-fA-F]+$/.test(v)) return parseInt(v, 16);
    return Number(v);
  }
  return NaN;
}
const litNum = (lit) => (lit.num !== undefined ? lit.num : toNum(lit.value));

function toBool(x) {
  if (typeof x === 'boolean') return x;
  if (typeof x === 'number') return x !== 0;
  if (typeof x === 'string') {
    const s = x.toLowerCase();
    if (s === 'true' || s === '1' || s === 'yes') return true;
    if (s === 'false' || s === '0' || s === 'no' || s === '') return false;
    return true;
  }
  return !!x;
}

// Build a typed literal from a value token; validates ip/cidr, throws on bad ones.
function makeLiteral(tok) {
  if (tok.type === 'string') return { type: 'str', value: tok.value };
  if (tok.type !== 'word') throw new FilterError('Expected a value', tok.pos);
  const s = tok.value;
  if (/^(true|false)$/i.test(s)) return { type: 'bool', value: /^true$/i.test(s) };
  if (/^0x[0-9a-fA-F]+$/.test(s)) return { type: 'number', value: s, num: parseInt(s, 16) };
  let m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(s);
  if (m) {
    const base = ip4int(m[1]); const bits = +m[2];
    if (base == null || bits > 32) throw new FilterError(`Invalid IPv4 CIDR '${s}'`, tok.pos);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return { type: 'cidr', family: 'v4', base, mask };
  }
  m = /^([0-9a-fA-F:]+)\/(\d{1,3})$/.exec(s);
  if (m && s.includes(':')) {
    const g = ip6Groups(m[1]); const bits = +m[2];
    if (!g || bits > 128) throw new FilterError(`Invalid IPv6 CIDR '${s}'`, tok.pos);
    let base = 0n; for (const x of g) base = (base << 16n) | BigInt(x);
    const mask = bits === 0 ? 0n : (((1n << BigInt(bits)) - 1n) << BigInt(128 - bits));
    return { type: 'cidr', family: 'v6', base: base & mask, mask };
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    if (ip4int(s) == null) throw new FilterError(`Invalid IPv4 address '${s}'`, tok.pos);
    return { type: 'ip', value: s };
  }
  if (/^-?\d+$/.test(s)) return { type: 'number', value: s, num: parseInt(s, 10) };
  if (/^-?\d+\.\d+$/.test(s)) return { type: 'number', value: s, num: parseFloat(s) };
  if (isMacStr(s)) return { type: 'mac', value: s };
  if (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s)) {
    if (!ip6Groups(s)) throw new FilterError(`Invalid IPv6 address '${s}'`, tok.pos);
    return { type: 'ipv6', value: s };
  }
  return { type: 'str', value: s };
}

function eqOne(v, lit, entry) {
  if (lit.type === 'cidr') return entry.type === 'addr' ? cidrMatch(String(v), lit) : false;
  if (entry.type === 'bool' || lit.type === 'bool') return toBool(v) === toBool(lit.value);
  if (entry.type === 'addr') return addrEq(v, lit.value);
  if (entry.type === 'num' || lit.type === 'number') {
    const a = toNum(v), b = litNum(lit);
    if (Number.isFinite(a) && Number.isFinite(b)) return a === b;
    return String(v) === String(lit.value);
  }
  return String(v) === String(lit.value);
}

function relOne(op, v, lit) {
  const a = toNum(v), b = litNum(lit);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
  switch (op) { case '<': return a < b; case '<=': return a <= b; case '>': return a > b; case '>=': return a >= b; }
  return false;
}

function compareOne(op, v, lit, entry) {
  switch (op) {
    case 'contains': return String(v).toLowerCase().includes(String(lit.value).toLowerCase());
    case 'matches': return lit.re ? lit.re.test(String(v)) : false;
    case 'in': return lit.items.some(it => eqOne(v, it, entry));
    case '==': return eqOne(v, lit, entry);
    case '!=': return !eqOne(v, lit, entry);
    default: return relOne(op, v, lit);
  }
}

// ---------------------------------------------------------------------------
// Field resolver catalog. Each entry: { name, protocol, kind, type, get }.
//   kind: 'single' | 'multi'      cardinality (multi => any-match semantics)
//   type: 'num' | 'str' | 'addr' | 'bool'
// Protocol entries carry isProto:true and present:(packet)=>boolean.

const R = new Map();
export const FIELDS = [];
const TYPE_LABEL = { num: 'number', str: 'string', addr: 'address', bool: 'boolean' };

function field(name, protocol, kind, type, get, desc) {
  R.set(name, { name, protocol, kind, type, get });
  FIELDS.push({ name, proto: protocol, type: TYPE_LABEL[type] || type, desc: desc || '' });
}
function protoEntry(id, present, desc) {
  R.set(id, { name: id, protocol: id, isProto: true, present });
  FIELDS.push({ name: id, proto: id, type: 'protocol', desc: desc || '' });
}

const ipL = (p) => p.layer('ipv4') || p.layer('ipv6');
const tcpFlag = (bit) => (p) => { const t = p.tcp; return t ? !!(t.flags & bit) : false; };
const tag = (name) => (p) => p.tags.has(name);

// --- protocols (existence) ---
protoEntry('ip', (p) => !!(p.layer('ipv4') || p.layer('ipv6')), 'IPv4 or IPv6 present');
protoEntry('ipv4', (p) => p.has('ipv4'), 'IPv4 present');
protoEntry('ipv6', (p) => p.has('ipv6'), 'IPv6 present');
protoEntry('eth', (p) => p.has('eth'), 'Ethernet present');
protoEntry('vlan', (p) => p.has('vlan'), '802.1Q VLAN present');
protoEntry('arp', (p) => p.has('arp'), 'ARP present');
protoEntry('tcp', (p) => p.has('tcp'), 'TCP present');
protoEntry('udp', (p) => p.has('udp'), 'UDP present');
protoEntry('icmp', (p) => p.has('icmp'), 'ICMP present');
protoEntry('icmpv6', (p) => p.has('icmpv6'), 'ICMPv6 present');
protoEntry('igmp', (p) => p.has('igmp'), 'IGMP present');
protoEntry('gre', (p) => p.has('gre'), 'GRE present');
protoEntry('dns', (p) => p.has('dns'), 'DNS present');
protoEntry('nbns', (p) => p.has('nbns'), 'NetBIOS-NS present');
protoEntry('http', (p) => p.has('http'), 'HTTP present');
protoEntry('tls', (p) => p.has('tls'), 'TLS present');
protoEntry('ssl', (p) => p.has('tls'), 'TLS/SSL present');
protoEntry('dhcp', (p) => p.has('dhcp'), 'DHCP present');
protoEntry('bootp', (p) => p.has('dhcp'), 'BOOTP/DHCP present');
protoEntry('ntp', (p) => p.has('ntp'), 'NTP present');
protoEntry('ssh', (p) => p.has('ssh'), 'SSH present');
protoEntry('ftp', (p) => p.has('ftp'), 'FTP present');
protoEntry('smtp', (p) => p.has('smtp'), 'SMTP present');
protoEntry('pop', (p) => p.has('pop'), 'POP present');
protoEntry('imap', (p) => p.has('imap'), 'IMAP present');
protoEntry('telnet', (p) => p.has('telnet'), 'Telnet present');
protoEntry('smb', (p) => p.has('smb'), 'SMB present');
protoEntry('smb2', (p) => p.has('smb2'), 'SMB2 present');

// --- frame ---
field('frame.number', 'frame', 'single', 'num', (p) => p.index, 'Packet number');
field('frame.len', 'frame', 'single', 'num', (p) => p.origLen, 'Frame length on the wire');
field('frame.cap_len', 'frame', 'single', 'num', (p) => p.capLen, 'Captured frame length');
field('frame.time_relative', 'frame', 'single', 'num', (p) => p.rel, 'Seconds since first packet');
field('frame.time_delta', 'frame', 'single', 'num', (p) => p.delta, 'Seconds since previous packet');
field('frame.protocols', 'frame', 'multi', 'str', (p) => p.layers.map(l => l.proto), 'Protocol id list');
field('frame.comment', 'frame', 'single', 'str', (p) => p.comment || undefined, 'Packet comment');

// --- eth ---
field('eth.addr', 'eth', 'multi', 'addr', (p) => { const e = p.layer('eth'); return e ? [e.src, e.dst] : []; }, 'Ethernet source or destination');
field('eth.src', 'eth', 'single', 'addr', (p) => p.layer('eth')?.src, 'Ethernet source MAC');
field('eth.dst', 'eth', 'single', 'addr', (p) => p.layer('eth')?.dst, 'Ethernet destination MAC');
field('eth.type', 'eth', 'single', 'num', (p) => p.layer('eth')?.type, 'EtherType');

// --- ip (ipv4 or ipv6) ---
field('ip.addr', 'ip', 'multi', 'addr', (p) => { const l = ipL(p); return l ? [l.src, l.dst] : []; }, 'IP source or destination (v4/v6, CIDR ok)');
field('ip.src', 'ip', 'single', 'addr', (p) => ipL(p)?.src, 'IP source');
field('ip.dst', 'ip', 'single', 'addr', (p) => ipL(p)?.dst, 'IP destination');
field('ip.ttl', 'ip', 'single', 'num', (p) => ipL(p)?.ttl, 'Time to live / hop limit');
field('ip.proto', 'ip', 'single', 'num', (p) => ipL(p)?.proto_, 'IP protocol / next header number');
field('ip.version', 'ip', 'single', 'num', (p) => ipL(p)?.version, 'IP version');
field('ip.len', 'ip', 'single', 'num', (p) => { const l = ipL(p); if (!l) return undefined; return l.totalLen !== undefined ? l.totalLen : (l.payloadLen !== undefined ? l.payloadLen + 40 : undefined); }, 'Total length');
field('ip.id', 'ip', 'single', 'num', (p) => p.layer('ipv4')?.id, 'IPv4 identification');
field('ip.flags.df', 'ip', 'single', 'bool', (p) => { const l = p.layer('ipv4'); return l ? !!l.df : false; }, "Don't fragment");
field('ip.flags.mf', 'ip', 'single', 'bool', (p) => { const l = p.layer('ipv4'); return l ? !!l.mf : false; }, 'More fragments');
field('ip.checksum.status', 'ip', 'single', 'str', (p) => { const l = p.layer('ipv4'); if (!l || l.checksumOk === undefined) return undefined; return l.checksumOk ? 'good' : 'bad'; }, 'Header checksum good/bad');

// --- ipv4 / ipv6 specific ---
field('ipv4.addr', 'ipv4', 'multi', 'addr', (p) => { const l = p.layer('ipv4'); return l ? [l.src, l.dst] : []; }, 'IPv4 source or destination');
field('ipv4.src', 'ipv4', 'single', 'addr', (p) => p.layer('ipv4')?.src, 'IPv4 source');
field('ipv4.dst', 'ipv4', 'single', 'addr', (p) => p.layer('ipv4')?.dst, 'IPv4 destination');
field('ipv6.addr', 'ipv6', 'multi', 'addr', (p) => { const l = p.layer('ipv6'); return l ? [l.src, l.dst] : []; }, 'IPv6 source or destination');
field('ipv6.src', 'ipv6', 'single', 'addr', (p) => p.layer('ipv6')?.src, 'IPv6 source');
field('ipv6.dst', 'ipv6', 'single', 'addr', (p) => p.layer('ipv6')?.dst, 'IPv6 destination');
field('ipv6.hlim', 'ipv6', 'single', 'num', (p) => p.layer('ipv6')?.ttl, 'IPv6 hop limit');

// --- tcp ---
field('tcp.port', 'tcp', 'multi', 'num', (p) => { const t = p.tcp; return t ? [t.srcPort, t.dstPort] : []; }, 'TCP source or destination port');
field('tcp.srcport', 'tcp', 'single', 'num', (p) => p.tcp?.srcPort, 'TCP source port');
field('tcp.dstport', 'tcp', 'single', 'num', (p) => p.tcp?.dstPort, 'TCP destination port');
field('tcp.seq', 'tcp', 'single', 'num', (p) => p.tcp?.relSeq, 'TCP sequence (relative)');
field('tcp.ack', 'tcp', 'single', 'num', (p) => p.tcp?.relAck, 'TCP ack (relative)');
field('tcp.len', 'tcp', 'single', 'num', (p) => p.tcp?.payloadLen, 'TCP payload length');
field('tcp.window_size', 'tcp', 'single', 'num', (p) => p.tcp?.window, 'TCP window size');
field('tcp.stream', 'tcp', 'single', 'num', (p) => p.tcp?.stream, 'TCP stream index');
field('tcp.flags', 'tcp', 'single', 'num', (p) => p.tcp?.flags, 'TCP flags (numeric)');
field('tcp.flags.fin', 'tcp', 'single', 'bool', tcpFlag(0x01), 'FIN flag');
field('tcp.flags.syn', 'tcp', 'single', 'bool', tcpFlag(0x02), 'SYN flag');
field('tcp.flags.reset', 'tcp', 'single', 'bool', tcpFlag(0x04), 'RST flag');
field('tcp.flags.rst', 'tcp', 'single', 'bool', tcpFlag(0x04), 'RST flag');
field('tcp.flags.push', 'tcp', 'single', 'bool', tcpFlag(0x08), 'PSH flag');
field('tcp.flags.psh', 'tcp', 'single', 'bool', tcpFlag(0x08), 'PSH flag');
field('tcp.flags.ack', 'tcp', 'single', 'bool', tcpFlag(0x10), 'ACK flag');
field('tcp.flags.urg', 'tcp', 'single', 'bool', tcpFlag(0x20), 'URG flag');
field('tcp.analysis.retransmission', 'tcp', 'single', 'bool', tag('retransmission'), 'Retransmission');
field('tcp.analysis.zero_window', 'tcp', 'single', 'bool', tag('zero-window'), 'Zero window');
field('tcp.analysis.out_of_order', 'tcp', 'single', 'bool', tag('out-of-order'), 'Out of order');

// --- udp ---
field('udp.port', 'udp', 'multi', 'num', (p) => { const u = p.udp; return u ? [u.srcPort, u.dstPort] : []; }, 'UDP source or destination port');
field('udp.srcport', 'udp', 'single', 'num', (p) => p.udp?.srcPort, 'UDP source port');
field('udp.dstport', 'udp', 'single', 'num', (p) => p.udp?.dstPort, 'UDP destination port');
field('udp.length', 'udp', 'single', 'num', (p) => { const u = p.udp; return u ? 8 + (u.payloadLen || 0) : undefined; }, 'UDP datagram length');

// --- arp ---
field('arp.opcode', 'arp', 'single', 'num', (p) => p.layer('arp')?.opcode, 'ARP opcode');
field('arp.src.proto_ipv4', 'arp', 'single', 'addr', (p) => p.layer('arp')?.senderIp, 'ARP sender IPv4');
field('arp.dst.proto_ipv4', 'arp', 'single', 'addr', (p) => p.layer('arp')?.targetIp, 'ARP target IPv4');
field('arp.isgratuitous', 'arp', 'single', 'bool', (p) => { const a = p.layer('arp'); return a ? (a.senderIp === a.targetIp && (a.opcode === 1 || a.opcode === 2)) : false; }, 'Gratuitous ARP');

// --- icmp / icmpv6 ---
field('icmp.type', 'icmp', 'single', 'num', (p) => p.layer('icmp')?.type, 'ICMP type');
field('icmp.code', 'icmp', 'single', 'num', (p) => p.layer('icmp')?.code, 'ICMP code');
field('icmpv6.type', 'icmpv6', 'single', 'num', (p) => p.layer('icmpv6')?.type, 'ICMPv6 type');
field('icmpv6.code', 'icmpv6', 'single', 'num', (p) => p.layer('icmpv6')?.code, 'ICMPv6 code');

// --- dns ---
const dnsL = (p) => p.layer('dns');
field('dns.id', 'dns', 'single', 'num', (p) => dnsL(p)?.id, 'DNS transaction id');
field('dns.flags.response', 'dns', 'single', 'bool', (p) => { const d = dnsL(p); return d ? !!d.isResponse : false; }, 'Response flag');
field('dns.qry.name', 'dns', 'multi', 'str', (p) => { const d = dnsL(p); return d?.queries ? d.queries.map(q => q.name) : []; }, 'Query name(s)');
field('dns.qry.type', 'dns', 'multi', 'num', (p) => { const d = dnsL(p); return d?.queries ? d.queries.map(q => q.type) : []; }, 'Query type(s)');
field('dns.resp.name', 'dns', 'multi', 'str', (p) => { const d = dnsL(p); return d?.answers ? d.answers.map(a => a.name) : []; }, 'Answer name(s)');
field('dns.resp.addr', 'dns', 'multi', 'addr', (p) => { const d = dnsL(p); return d?.answers ? d.answers.filter(a => a.type === 1 || a.type === 28).map(a => a.data) : []; }, 'Answer address(es)');
field('dns.a', 'dns', 'multi', 'addr', (p) => { const d = dnsL(p); return d?.answers ? d.answers.filter(a => a.type === 1).map(a => a.data) : []; }, 'A record address(es)');
field('dns.count.answers', 'dns', 'single', 'num', (p) => { const d = dnsL(p); return d?.answers ? d.answers.length : undefined; }, 'Answer count');

// --- http ---
const httpL = (p) => p.layer('http');
field('http.request', 'http', 'single', 'bool', (p) => { const h = httpL(p); return h ? !!h.isRequest : false; }, 'Is an HTTP request');
field('http.response', 'http', 'single', 'bool', (p) => { const h = httpL(p); return h ? h.isRequest === false : false; }, 'Is an HTTP response');
field('http.request.method', 'http', 'single', 'str', (p) => httpL(p)?.method, 'Request method');
field('http.request.uri', 'http', 'single', 'str', (p) => httpL(p)?.uri, 'Request URI');
field('http.request.full_uri', 'http', 'single', 'str', (p) => httpL(p)?.url, 'Full request URL');
field('http.host', 'http', 'single', 'str', (p) => httpL(p)?.host, 'Host header');
field('http.user_agent', 'http', 'single', 'str', (p) => httpL(p)?.userAgent, 'User-Agent header');
field('http.response.code', 'http', 'single', 'num', (p) => httpL(p)?.status, 'Response status code');
field('http.authorization', 'http', 'single', 'str', (p) => httpL(p)?.authorization, 'Authorization header');

// --- tls ---
const tlsL = (p) => p.layer('tls');
field('tls.handshake.type', 'tls', 'multi', 'num', (p) => { const t = tlsL(p); return t?.records ? t.records.map(r => r.handshakeType).filter(x => x != null) : []; }, 'Handshake type(s)');
field('tls.handshake.extensions_server_name', 'tls', 'single', 'str', (p) => tlsL(p)?.sni, 'SNI server name');
field('tls.handshake.ja3', 'tls', 'single', 'str', (p) => { const t = tlsL(p); return t ? (t.ja3Hash || t.ja3) : undefined; }, 'JA3 fingerprint');
field('tls.handshake.ja3s', 'tls', 'single', 'str', (p) => { const t = tlsL(p); return t ? (t.ja3sHash || t.ja3s) : undefined; }, 'JA3S fingerprint');
field('tls.version', 'tls', 'single', 'str', (p) => { const v = tlsL(p)?.version; return v == null ? undefined : String(v); }, 'Negotiated TLS version');
field('tls.record.content_type', 'tls', 'multi', 'num', (p) => { const t = tlsL(p); return t?.records ? t.records.map(r => r.type).filter(x => x != null) : []; }, 'Record content type(s)');

// --- ssh ---
field('ssh.protocol', 'ssh', 'single', 'str', (p) => p.layer('ssh')?.banner, 'SSH identification banner');
field('ssh.hassh', 'ssh', 'single', 'str', (p) => p.layer('ssh')?.hassh, 'HASSH fingerprint');

// --- dhcp ---
field('dhcp.option.dhcp', 'dhcp', 'single', 'num', (p) => p.layer('dhcp')?.msgType, 'DHCP message type');

FIELDS.sort((a, b) => a.name.localeCompare(b.name));

function isKnownProto(name) {
  const e = R.get(name);
  if (e && e.isProto) return true;
  return byId ? byId.has(name) : false;
}

// ---------------------------------------------------------------------------
// Parser: builds predicate closures directly and records used field names.

class Parser {
  constructor(toks) { this.toks = toks; this.i = 0; this.fields = new Set(); }
  peek() { return this.toks[this.i]; }
  next() { return this.toks[this.i++]; }

  parse() {
    if (this.peek().type === 'eof') return () => true;
    const fn = this.parseOr();
    const t = this.peek();
    if (t.type !== 'eof') throw new FilterError(`Unexpected ${this.describe(t)}`, t.pos);
    return fn;
  }

  describe(t) {
    if (t.type === 'word') return `token '${t.value}'`;
    if (t.type === 'op') return `operator '${t.value}'`;
    if (t.type === 'string') return 'string';
    if (t.type === 'eof') return 'end of input';
    return `'${t.type}'`;
  }

  isWord(t, w) { return t.type === 'word' && t.value.toLowerCase() === w; }
  isOrTok(t) { return t.type === 'or' || this.isWord(t, 'or'); }
  isAndTok(t) { return t.type === 'and' || this.isWord(t, 'and'); }
  isNotTok(t) { return t.type === 'not' || this.isWord(t, 'not'); }

  parseOr() {
    let left = this.parseAnd();
    while (this.isOrTok(this.peek())) { this.next(); const right = this.parseAnd(); const a = left, b = right; left = (p) => a(p) || b(p); }
    return left;
  }
  parseAnd() {
    let left = this.parseNot();
    while (this.isAndTok(this.peek())) { this.next(); const right = this.parseNot(); const a = left, b = right; left = (p) => a(p) && b(p); }
    return left;
  }
  parseNot() {
    if (this.isNotTok(this.peek())) { this.next(); const inner = this.parseNot(); return (p) => !inner(p); }
    return this.parseCmp();
  }

  // Returns {opStr} if the next token is a comparison operator, else null.
  peekOp() {
    const t = this.peek();
    if (t.type === 'op') return t.value;
    if (t.type === 'word') {
      const w = t.value.toLowerCase();
      if (w === 'in') return 'in';
      if (CMP_WORDS[w]) return CMP_WORDS[w];
    }
    return null;
  }

  parseCmp() {
    const t = this.peek();
    if (t.type === '(') {
      this.next();
      const inner = this.parseOr();
      const c = this.peek();
      if (c.type !== ')') throw new FilterError("Expected ')'", c.pos);
      this.next();
      return inner;
    }
    if (t.type === ')') throw new FilterError("Unbalanced ')'", t.pos);
    if (t.type !== 'word') throw new FilterError(`Expected a field or protocol but found ${this.describe(t)}`, t.pos);

    const nameTok = this.next();
    const name = nameTok.value;
    // A reserved logic/operator word cannot start a primary.
    const lower = name.toLowerCase();
    if (lower === 'and' || lower === 'or') throw new FilterError(`Unexpected '${name}'`, nameTok.pos);

    const op = this.peekOp();
    const entry = R.get(name);

    if (op) {
      this.next(); // consume operator token
      if (!entry) throw new FilterError(`Unknown field '${name}'`, nameTok.pos);
      if (entry.isProto) throw new FilterError(`'${name}' is a protocol, not a comparable field`, nameTok.pos);
      this.fields.add(name);
      const lit = this.parseValue(op);
      return (p) => this.evalCmp(entry, op, lit, p);
    }

    // Existence test.
    if (entry) {
      this.fields.add(name);
      if (entry.isProto) { const present = entry.present; return (p) => present(p); }
      return this.existFn(entry);
    }
    if (isKnownProto(name)) { this.fields.add(name); return (p) => p.has(name); }
    throw new FilterError(`Unknown field or protocol '${name}'`, nameTok.pos);
  }

  parseValue(op) {
    if (op === 'in') {
      const brace = this.peek();
      if (brace.type !== '{') throw new FilterError("Expected '{' after 'in'", brace.pos);
      this.next();
      const items = [];
      while (this.peek().type !== '}') {
        const vt = this.peek();
        if (vt.type === 'eof') throw new FilterError("Unterminated set: expected '}'", vt.pos);
        if (vt.type !== 'word' && vt.type !== 'string') throw new FilterError(`Unexpected ${this.describe(vt)} in set`, vt.pos);
        this.next();
        items.push(makeLiteral(vt));
      }
      this.next(); // consume '}'
      return { type: 'set', items };
    }
    const vt = this.peek();
    if (vt.type !== 'word' && vt.type !== 'string') throw new FilterError(`Expected a value after operator but found ${this.describe(vt)}`, vt.pos);
    this.next();
    if (op === 'matches') {
      try { return { type: 'regex', re: new RegExp(vt.value) }; }
      catch (e) { throw new FilterError(`Invalid regular expression: ${e.message}`, vt.pos); }
    }
    return makeLiteral(vt);
  }

  existFn(entry) {
    if (entry.type === 'bool') { const g = entry.get; return (p) => toBool(g(p)); }
    if (entry.kind === 'multi') { const g = entry.get; return (p) => { const a = g(p); return Array.isArray(a) && a.length > 0; }; }
    const g = entry.get;
    return (p) => { const v = g(p); return v !== undefined && v !== null && v !== ''; };
  }

  evalCmp(entry, op, lit, p) {
    let raw = entry.get(p);
    let arr;
    if (entry.kind === 'multi') arr = Array.isArray(raw) ? raw : (raw == null ? [] : [raw]);
    else arr = (raw === undefined || raw === null) ? [] : [raw];
    for (const v of arr) { if (v === undefined || v === null) continue; if (compareOne(op, v, lit, entry)) return true; }
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public API.

export function compileFilter(expr) {
  try {
    const src = expr == null ? '' : String(expr);
    const toks = tokenize(src);
    const parser = new Parser(toks);
    const predicate = parser.parse();
    return { ok: true, predicate, fields: [...parser.fields] };
  } catch (e) {
    if (e instanceof FilterError) return { ok: false, error: { message: e.message, position: e.position } };
    return { ok: false, error: { message: e && e.message ? e.message : 'Invalid filter', position: 0 } };
  }
}

export function validateFilter(expr) {
  const r = compileFilter(expr);
  return r.ok ? { ok: true } : { ok: false, error: r.error };
}

export function filterPackets(packets, expr) {
  const r = compileFilter(expr);
  if (!r.ok) return r;
  const pred = r.predicate;
  const out = [];
  for (const p of packets) { try { if (pred(p)) out.push(p); } catch { /* defensive: skip on evaluator error */ } }
  return out;
}

export default { compileFilter, validateFilter, filterPackets, FIELDS };
