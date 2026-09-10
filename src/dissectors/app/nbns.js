// NetBIOS Name Service (UDP 137) and NetBIOS Datagram Service (UDP 138, incl. SMB MailSlot browser announcements).
import { Layer } from '../../core/packet.js';
import { u16be, u32be, u16le, u32le, ipv4, mac, hex, toHex, printable } from '../../core/bytes.js';
import { readName } from './dns.js';

export const NB_SUFFIXES = {
  0x00: 'Workstation/Redirector', 0x01: 'Messenger', 0x03: 'Messenger', 0x06: 'RAS Server', 0x1b: 'Domain Master Browser', 0x1c: 'Domain Controllers', 0x1d: 'Master Browser', 0x1e: 'Browser Service Elections',
  0x1f: 'NetDDE', 0x20: 'File Server', 0x21: 'RAS Client', 0x22: 'Exchange Interchange', 0x23: 'Exchange Store', 0x24: 'Exchange Directory', 0x2b: 'Lotus Notes Server', 0x30: 'Modem Sharing Server', 0x31: 'Modem Sharing Client',
  0x43: 'SMS Client Remote Control', 0x44: 'SMS Admin Remote Control Tool', 0x45: 'SMS Client Remote Chat', 0x46: 'SMS Client Remote Transfer', 0x87: 'Exchange MTA', 0x6a: 'Exchange IMC', 0xbe: 'Network Monitor Agent', 0xbf: 'Network Monitor Application',
};
const OPCODES = { 0: 'Name query', 5: 'Registration', 6: 'Release', 7: 'WACK', 8: 'Refresh', 9: 'Refresh', 15: 'Multi-homed registration' };
const RCODES = { 0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'Requested name does not exist', 4: 'Unsupported request', 5: 'Refused', 6: 'Active error (name owned by another node)', 7: 'Name in conflict' };
const RR_TYPES = { 1: 'A', 2: 'NS', 10: 'NULL', 32: 'NB', 33: 'NBSTAT' };
const NODE_TYPES = ['B-node', 'P-node', 'M-node', 'H-node'];

/** Decode a first-level-encoded NetBIOS label ("EHEPFCEJ...") into { name, suffix, suffixName, display, scope }. */
export function decodeNbName(label, scopeLabels = []) {
  if (label.length !== 32 || !/^[A-P]{32}$/.test(label)) return { name: label, suffix: null, suffixName: '', display: label, scope: scopeLabels.join('.') };
  const bytes = [];
  for (let i = 0; i < 32; i += 2) bytes.push(((label.charCodeAt(i) - 65) << 4) | (label.charCodeAt(i + 1) - 65));
  const suffix = bytes[15];
  let name = '';
  for (let i = 0; i < 15; i++) {
    const c = bytes[i];
    name += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : `\\x${hex(c)}`;
  }
  name = name.replace(/( |\\x00)+$/, '');
  return { name, suffix, suffixName: NB_SUFFIXES[suffix] || '', display: `${name}<${hex(suffix)}>`, scope: scopeLabels.join('.') };
}

/** Read an encoded NetBIOS name at o. Returns { name, suffix, suffixName, display, scope, next, err }. */
export function readNbName(data, o, base, end) {
  const n = readName(data, o, base, end);
  if (n.err) return { ...n, display: n.name, suffix: null, suffixName: '' };
  const raw = n.raw[0];
  const label = raw ? printable(raw, 0, raw.length) : '';
  const d = decodeNbName(label, n.labels.slice(1));
  return { ...d, next: n.next, err: null };
}

function nbFlags(f) {
  const group = !!(f & 0x8000), ont = (f >> 13) & 3;
  return { group, nodeType: NODE_TYPES[ont], text: `${group ? 'Group' : 'Unique'}, ${NODE_TYPES[ont]}` };
}

function parseRR(l, data, o, base, end, isQ) {
  const n = readNbName(data, o, base, end);
  if (n.err) return { err: n.err, next: n.next };
  const h = n.next;
  if (h + 4 > end) return { err: 'Record truncated', next: end };
  const type = u16be(data, h), cls = u16be(data, h + 2);
  const rr = { name: n.name, suffix: n.suffix, suffixName: n.suffixName, display: n.display, scope: n.scope, type, typeName: RR_TYPES[type] || `TYPE${type}`, cls };
  const children = [
    { name: 'Name', value: `${n.display}${n.suffixName ? ` (${n.suffixName})` : ''}`, offset: o, length: h - o },
    { name: 'Type', value: `${rr.typeName} (${type})`, offset: h, length: 2 },
    { name: 'Class', value: `${cls === 1 ? 'IN' : cls} (${cls})`, offset: h + 2, length: 2 },
  ];
  if (isQ) return { rr, field: { name: `${n.display}: type ${rr.typeName}, class IN`, value: '', offset: o, length: h + 4 - o, children }, next: h + 4 };
  if (h + 10 > end) return { rr, err: 'Resource record truncated', next: end };
  const ttl = u32be(data, h + 4), rlen = u16be(data, h + 8), ro = h + 10;
  rr.ttl = ttl; rr.rdLen = rlen;
  let err = null;
  if (ro + rlen > end) err = 'RDATA truncated';
  const re = Math.min(ro + rlen, end);
  children.push({ name: 'Time to live', value: `${ttl} seconds`, offset: h + 4, length: 4 });
  children.push({ name: 'Data length', value: rlen, offset: h + 8, length: 2 });
  rr.addrs = [];
  if (type === 32) {
    const parts = [];
    for (let p = ro; p + 6 <= re; p += 6) {
      const f = nbFlags(u16be(data, p)); const ip = ipv4(data, p + 2);
      rr.addrs.push(ip); rr.flags = f;
      parts.push(ip);
      children.push({ name: 'Flags', value: `0x${hex(u16be(data, p), 4)} (${f.text})`, offset: p, length: 2 });
      children.push({ name: 'Addr', value: ip, offset: p + 2, length: 4 });
    }
    rr.data = parts.join(', ');
  } else if (type === 33) {
    const num = ro < re ? data[ro] : 0;
    rr.nodeNames = [];
    let p = ro + 1;
    children.push({ name: 'Number of names', value: num, offset: ro, length: 1 });
    for (let i = 0; i < num && p + 18 <= re; i++, p += 18) {
      let nm = printable(data, p, p + 15).replace(/ +$/, '');
      const sfx = data[p + 15];
      if (data[p] === 1 && data[p + 1] === 2) nm = '\\x01\\x02' + printable(data, p + 2, p + 14).replace(/\.+$/, '') + '\\x02';
      const f = u16be(data, p + 16);
      const entry = { name: nm, suffix: sfx, suffixName: NB_SUFFIXES[sfx] || '', display: `${nm}<${hex(sfx)}>`, group: !!(f & 0x8000), active: !!(f & 0x0400) };
      rr.nodeNames.push(entry);
      children.push({ name: 'Name', value: `${entry.display}${entry.suffixName ? ` (${entry.suffixName})` : ''}${entry.group ? ' <GROUP>' : ''}`, offset: p, length: 18 });
    }
    if (p + 6 <= re) { rr.mac = mac(data, p); children.push({ name: 'Unit ID', value: rr.mac, offset: p, length: 6 }); }
    rr.data = rr.nodeNames.map(x => x.display).join(', ');
  } else if (type === 1 && rlen === 4) { rr.data = ipv4(data, ro); rr.addrs.push(rr.data); }
  else rr.data = rlen ? `${rlen} bytes: ${toHex(data, ro, Math.min(re, ro + 24))}` : '';
  if (type !== 32 && type !== 33) children.push({ name: 'Data', value: rr.data, offset: ro, length: re - ro });
  return { rr, field: { name: `${n.display}: type ${rr.typeName}, class IN${rr.data ? ', ' + rr.data : ''}`, value: '', offset: o, length: re - o, children }, next: re, err };
}

const nbns = {
  id: 'nbns',
  name: 'NetBIOS Name Service',
  udpPorts: [137],
  dissect(ctx) {
    const { data, offset, end, packet, state } = ctx;
    if (end - offset < 12) return null;
    const l = new Layer('nbns', 'NetBIOS Name Service', offset, end - offset);
    l.label = 'NBNS';
    const id = u16be(data, offset), flags = u16be(data, offset + 2);
    const counts = [u16be(data, offset + 4), u16be(data, offset + 6), u16be(data, offset + 8), u16be(data, offset + 10)];
    const isResponse = !!(flags & 0x8000), opcode = (flags >> 11) & 0xf, rcode = flags & 0xf;
    l.id = id; l.isResponse = isResponse; l.opcode = opcode; l.opcodeName = OPCODES[opcode] || `Opcode ${opcode}`;
    l.rcode = rcode; l.rcodeName = RCODES[rcode] || `Rcode ${rcode}`;
    l.flags = { aa: !!(flags & 0x0400), tc: !!(flags & 0x0200), rd: !!(flags & 0x0100), ra: !!(flags & 0x0080), b: !!(flags & 0x0010) };
    l.add('Transaction ID', `0x${hex(id, 4)}`, offset, 2);
    const fg = l.addGroup('Flags', `0x${hex(flags, 4)} (${l.opcodeName}${isResponse ? ' response' : ''})`, offset + 2, 2, []);
    fg.children.push({ name: 'Response', value: isResponse ? '1 (Message is a response)' : '0 (Message is a query)', offset: offset + 2, length: 2 });
    fg.children.push({ name: 'Opcode', value: `${l.opcodeName} (${opcode})`, offset: offset + 2, length: 2 });
    if (isResponse) fg.children.push({ name: 'Authoritative', value: l.flags.aa ? 1 : 0, offset: offset + 2, length: 2 });
    fg.children.push({ name: 'Truncated', value: l.flags.tc ? 1 : 0, offset: offset + 2, length: 2 });
    fg.children.push({ name: 'Recursion desired', value: l.flags.rd ? 1 : 0, offset: offset + 2, length: 2 });
    if (isResponse) fg.children.push({ name: 'Recursion available', value: l.flags.ra ? 1 : 0, offset: offset + 2, length: 2 });
    fg.children.push({ name: 'Broadcast', value: l.flags.b ? '1 (Broadcast packet)' : '0 (Not a broadcast packet)', offset: offset + 2, length: 2 });
    if (isResponse) fg.children.push({ name: 'Reply code', value: `${l.rcodeName} (${rcode})`, offset: offset + 2, length: 2 });
    l.add('Questions', counts[0], offset + 4, 2);
    l.add('Answer RRs', counts[1], offset + 6, 2);
    l.add('Authority RRs', counts[2], offset + 8, 2);
    l.add('Additional RRs', counts[3], offset + 10, 2);
    l.queries = []; l.answers = []; l.authorities = []; l.additionals = [];
    const sections = [['Queries', 'queries', true], ['Answers', 'answers', false], ['Authoritative nameservers', 'authorities', false], ['Additional records', 'additionals', false]];
    let o = offset + 12, stop = false;
    for (let s = 0; s < 4 && !stop; s++) {
      const [title, prop, isQ] = sections[s];
      if (!counts[s]) continue;
      const g = l.addGroup(title, String(counts[s]), o, 0, []);
      for (let i = 0; i < counts[s]; i++) {
        if (o >= end) { l.error(`${title} section truncated`); stop = true; break; }
        const r = parseRR(l, data, o, offset, end, isQ);
        if (r.rr) { l[prop].push(r.rr); if (r.field) g.children.push(r.field); }
        if (r.err) { l.error(r.err); stop = true; break; }
        if (r.next <= o) { stop = true; break; }
        o = r.next;
      }
      g.length = Math.max(0, o - g.offset);
    }
    // Convenience properties.
    const first = l.queries[0] || l.answers[0] || l.additionals[0];
    l.name = first?.name ?? ''; l.suffix = first?.suffix ?? null; l.suffixName = first?.suffixName ?? '';
    l.addrs = [];
    for (const rr of [...l.answers, ...l.additionals]) if (rr.addrs) l.addrs.push(...rr.addrs);
    l.addr = l.addrs[0];

    let summary = `${l.opcodeName}${isResponse ? ' response' : ''}`;
    if (isResponse && rcode !== 0) summary += `, ${l.rcodeName}`;
    else if (isResponse) {
      for (const a of l.answers) summary += ` ${a.typeName}${a.type === 33 ? '' : a.data ? ' ' + a.data : ' ' + a.display}`;
      if (!l.answers.length) for (const q of l.queries) summary += ` ${q.typeName} ${q.display}`;
    } else {
      for (const q of l.queries) summary += ` ${q.typeName} ${q.display}`;
      // Registration / release carry the address in the additional section.
      if (opcode !== 0) for (const a of l.additionals) if (a.addrs?.length) summary += ` ${a.addrs.join(', ')}`;
    }
    if (l.flags.tc) summary += ' [Truncated]';
    l.summary = summary;

    // Shared state: NetBIOS name -> IP knowledge.
    const st = state.ext.nbns ||= { names: new Map(), byName: new Map() };
    const learn = (name, sfx, ip) => {
      if (!name || !ip || ip === '0.0.0.0' || sfx === null) return;
      let set = st.names.get(ip); if (!set) st.names.set(ip, set = new Set());
      set.add(`${name}<${hex(sfx)}>`);
      let ips = st.byName.get(name); if (!ips) st.byName.set(name, ips = new Set());
      ips.add(ip);
    };
    for (const rr of [...l.answers, ...l.additionals]) if (rr.type === 32) for (const ip of rr.addrs) learn(rr.name, rr.suffix, ip);
    for (const rr of l.answers) if (rr.type === 33 && rr.nodeNames) { const ip = packet.ip?.src; for (const e of rr.nodeNames) if (!e.group) learn(e.name, e.suffix, ip); }
    const s = packet.stream && state.udp.list[packet.stream.id];
    if (s && !s.proto) s.proto = 'nbns';
    return l;
  },
};

// ---------------------------------------------------------------- NetBIOS Datagram Service

const DGM_TYPES = { 0x10: 'Direct_unique datagram', 0x11: 'Direct_group datagram', 0x12: 'Broadcast datagram', 0x13: 'Datagram error', 0x14: 'Datagram query request', 0x15: 'Datagram positive query response', 0x16: 'Datagram negative query response' };
const DGM_ERRORS = { 0x82: 'Destination name not present', 0x83: 'Invalid source name format', 0x84: 'Invalid destination name format' };
const BROWSER_CMDS = { 1: 'Host Announcement', 2: 'Announcement Request', 8: 'Browser Election Request', 9: 'Get Backup List Request', 10: 'Get Backup List Response', 11: 'Become Backup Browser', 12: 'Domain/Workgroup Announcement', 13: 'Master Announcement', 14: 'Reset Browser State', 15: 'Local Master Announcement' };
const SERVER_TYPES = [
  [0x00000001, 'Workstation'], [0x00000002, 'Server'], [0x00000004, 'SQL Server'], [0x00000008, 'Domain Controller'], [0x00000010, 'Backup Controller'], [0x00000020, 'Time Source'], [0x00000040, 'Apple Server'], [0x00000080, 'Novell Server'],
  [0x00000100, 'Domain Member Server'], [0x00000200, 'Print Queue Server'], [0x00000400, 'Dialin Server'], [0x00000800, 'Xenix Server'], [0x00001000, 'NT Workstation'], [0x00002000, 'WfW'], [0x00004000, 'MFPN'], [0x00008000, 'NT Server'],
  [0x00010000, 'Potential Browser'], [0x00020000, 'Backup Browser'], [0x00040000, 'Master Browser'], [0x00080000, 'Domain Master Browser'], [0x00100000, 'OSF'], [0x00200000, 'VMS'], [0x00400000, 'Windows 95+'], [0x00800000, 'DFS Root'],
  [0x01000000, 'NT Cluster'], [0x02000000, 'Terminal Server'], [0x04000000, 'NT Cluster VS'], [0x40000000, 'Local List Only'], [0x80000000, 'Domain Enum'],
];

function serverTypeNames(v) { const out = []; for (const [bit, n] of SERVER_TYPES) if ((v & bit) >>> 0) out.push(n); return out; }

function parseBrowser(l, data, o, end) {
  if (o >= end) return;
  const cmd = data[o];
  l.browserCommand = cmd; l.browserCommandName = BROWSER_CMDS[cmd] || `Command ${cmd}`;
  const g = l.addGroup('Microsoft Windows Browser Protocol', l.browserCommandName, o, end - o, []);
  g.children.push({ name: 'Command', value: `${l.browserCommandName} (0x${hex(cmd)})`, offset: o, length: 1 });
  if ((cmd === 1 || cmd === 12 || cmd === 15) && o + 33 <= end) {
    // Host / Domain / Local master announcement share the same layout.
    const host = printable(data, o + 6, o + 22).replace(/[\0. ]+$/, '').replace(/\0.*$/, '');
    const osMajor = data[o + 22], osMinor = data[o + 23], st = u32le(data, o + 24);
    const bMajor = data[o + 28], bMinor = data[o + 29], sig = u16le(data, o + 30);
    let ce = o + 32; while (ce < end && data[ce]) ce++;
    l.host = host; l.osVersion = `${osMajor}.${osMinor}`; l.serverType = st; l.serverTypeNames = serverTypeNames(st);
    l.browserVersion = `${bMajor}.${bMinor}`; l.comment = printable(data, o + 32, ce);
    l.updateCount = data[o + 1]; l.periodicity = u32le(data, o + 2);
    g.children.push({ name: 'Update count', value: l.updateCount, offset: o + 1, length: 1 });
    g.children.push({ name: 'Update periodicity', value: `${l.periodicity / 1000} seconds`, offset: o + 2, length: 4 });
    g.children.push({ name: 'Host name', value: host, offset: o + 6, length: 16 });
    g.children.push({ name: 'OS version', value: l.osVersion, offset: o + 22, length: 2 });
    g.children.push({ name: 'Server type', value: `0x${hex(st, 8)} (${l.serverTypeNames.join(', ')})`, offset: o + 24, length: 4 });
    g.children.push({ name: 'Browser protocol version', value: l.browserVersion, offset: o + 28, length: 2 });
    g.children.push({ name: 'Signature', value: `0x${hex(sig, 4)}`, offset: o + 30, length: 2 });
    g.children.push({ name: 'Host comment', value: l.comment, offset: o + 32, length: ce - (o + 32) });
    l.summary = `${l.browserCommandName} ${host}${l.serverTypeNames.length ? ', ' + l.serverTypeNames.join(', ') : ''}`;
  } else if (cmd === 8 && o + 14 <= end) {
    const ver = data[o + 1], crit = u32le(data, o + 2), up = u32le(data, o + 6);
    let ce = o + 14; while (ce < end && data[ce]) ce++;
    l.host = printable(data, o + 14, ce);
    g.children.push({ name: 'Election version', value: ver, offset: o + 1, length: 1 });
    g.children.push({ name: 'Election criteria', value: `0x${hex(crit, 8)}`, offset: o + 2, length: 4 });
    g.children.push({ name: 'Uptime', value: `${up / 1000} seconds`, offset: o + 6, length: 4 });
    g.children.push({ name: 'Server name', value: l.host, offset: o + 14, length: ce - (o + 14) });
    l.summary = `${l.browserCommandName}${l.host ? ' ' + l.host : ''}`;
  } else if (cmd === 2 && o + 2 <= end) {
    let ce = o + 2; while (ce < end && data[ce]) ce++;
    l.host = printable(data, o + 2, ce);
    g.children.push({ name: 'Response computer name', value: l.host, offset: o + 2, length: ce - (o + 2) });
    l.summary = `${l.browserCommandName} ${l.host}`;
  } else l.summary = l.browserCommandName;
}

function parseSmbMailslot(l, data, o, end) {
  // SMB header (32 bytes) followed by a Transaction (0x25) request carrying \MAILSLOT\<name>.
  if (end - o < 33) { l.error('SMB header truncated'); return; }
  const cmd = data[o + 4];
  l.smbCommand = cmd;
  const g = l.addGroup('SMB', `Command 0x${hex(cmd)}`, o, end - o, []);
  g.children.push({ name: 'Command', value: cmd === 0x25 ? 'Trans (0x25)' : `0x${hex(cmd)}`, offset: o + 4, length: 1 });
  if (cmd !== 0x25) return;
  const wct = data[o + 32];
  const p = o + 33;
  if (wct < 14 || p + wct * 2 + 2 > end) { l.error('SMB Trans parameters truncated'); return; }
  const dataCount = u16le(data, p + 22), dataOffset = u16le(data, p + 24), setupCount = data[p + 26];
  const bcc = u16le(data, p + wct * 2);
  let nameStart = p + wct * 2 + 2;
  let ne = nameStart; while (ne < end && data[ne]) ne++;
  l.mailslot = printable(data, nameStart, ne);
  g.children.push({ name: 'Setup count', value: setupCount, offset: p + 26, length: 1 });
  g.children.push({ name: 'Byte count', value: bcc, offset: p + wct * 2, length: 2 });
  g.children.push({ name: 'Mailslot name', value: l.mailslot, offset: nameStart, length: ne - nameStart });
  const ds = o + dataOffset, de = Math.min(end, ds + dataCount);
  if (dataOffset === 0 || ds >= end) { l.error('SMB Trans data offset out of range'); return; }
  if (/\\MAILSLOT\\BROWSE$/i.test(l.mailslot) || /\\MAILSLOT\\LANMAN$/i.test(l.mailslot)) parseBrowser(l, data, ds, de);
  else l.summary = `Mailslot ${l.mailslot}`;
}

const nbdgm = {
  id: 'nbdgm',
  name: 'NetBIOS Datagram Service',
  udpPorts: [138],
  dissect(ctx) {
    const { data, offset, end, packet, state } = ctx;
    if (end - offset < 10) return null;
    const type = data[offset];
    if (type < 0x10 || type > 0x16) return null;
    const l = new Layer('nbdgm', 'NetBIOS Datagram Service', offset, end - offset);
    l.label = 'NBDS';
    const flags = data[offset + 1];
    l.msgType = type; l.msgTypeName = DGM_TYPES[type]; l.dgmId = u16be(data, offset + 2);
    l.srcIp = ipv4(data, offset + 4); l.srcPort = u16be(data, offset + 8);
    l.add('Message type', `${l.msgTypeName} (0x${hex(type)})`, offset, 1);
    l.add('Flags', `0x${hex(flags)} (${['B', 'P', 'M', 'NBDD'][(flags >> 2) & 3]} node${flags & 2 ? ', first' : ''}${flags & 1 ? ', more' : ''})`, offset + 1, 1);
    l.add('Datagram ID', `0x${hex(l.dgmId, 4)}`, offset + 2, 2);
    l.add('Source IP', l.srcIp, offset + 4, 4);
    l.add('Source port', l.srcPort, offset + 8, 2);
    l.summary = l.msgTypeName;
    let o = offset + 10;
    if (type >= 0x10 && type <= 0x12) {
      if (o + 4 > end) { l.error('Datagram header truncated'); return l; }
      l.dgmLength = u16be(data, o); l.packetOffset = u16be(data, o + 2);
      l.add('Datagram length', l.dgmLength, o, 2);
      l.add('Packet offset', l.packetOffset, o + 2, 2);
      o += 4;
      const sn = readNbName(data, o, offset, end);
      if (sn.err) { l.error(`Source name: ${sn.err}`); return l; }
      l.srcName = sn.name; l.srcSuffix = sn.suffix; l.srcDisplay = sn.display;
      l.add('Source name', `${sn.display}${sn.suffixName ? ` (${sn.suffixName})` : ''}`, o, sn.next - o);
      o = sn.next;
      const dn = readNbName(data, o, offset, end);
      if (dn.err) { l.error(`Destination name: ${dn.err}`); return l; }
      l.dstName = dn.name; l.dstSuffix = dn.suffix; l.dstDisplay = dn.display;
      l.add('Destination name', `${dn.display}${dn.suffixName ? ` (${dn.suffixName})` : ''}`, o, dn.next - o);
      o = dn.next;
      l.summary = `${l.msgTypeName} from ${sn.display} to ${dn.display}`;
      if (o + 4 <= end && data[o] === 0xff && data[o + 1] === 0x53 && data[o + 2] === 0x4d && data[o + 3] === 0x42) parseSmbMailslot(l, data, o, end);
      else if (o < end) l.add('User data', `${end - o} bytes`, o, end - o);
      const st = state.ext.nbns ||= { names: new Map(), byName: new Map() };
      if (sn.suffix !== null && l.srcIp !== '0.0.0.0') {
        let set = st.names.get(l.srcIp); if (!set) st.names.set(l.srcIp, set = new Set());
        set.add(sn.display);
      }
    } else if (type === 0x13) {
      const ec = data[o];
      l.errorCode = ec;
      l.add('Error code', `${DGM_ERRORS[ec] || ec} (0x${hex(ec)})`, o, 1);
      l.summary = `${l.msgTypeName}: ${DGM_ERRORS[ec] || ec}`;
    } else {
      const dn = readNbName(data, o, offset, end);
      if (dn.err) l.error(`Destination name: ${dn.err}`);
      else { l.dstName = dn.name; l.dstDisplay = dn.display; l.add('Destination name', dn.display, o, dn.next - o); l.summary = `${l.msgTypeName} ${dn.display}`; }
    }
    const s = packet.stream && state.udp.list[packet.stream.id];
    if (s && !s.proto) s.proto = 'nbdgm';
    return l;
  },
};

export default [nbns, nbdgm];
