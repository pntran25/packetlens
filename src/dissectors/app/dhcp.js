// BOOTP/DHCPv4 (UDP 67/68) and DHCPv6 (UDP 546/547).
import { Layer } from '../../core/packet.js';
import { u16be, u32be, ipv4, ipv6, mac, hex, toHex, printable } from '../../core/bytes.js';
import { readName } from './dns.js';

const MSG_TYPES = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform', 9: 'Force Renew', 10: 'Lease Query', 11: 'Lease Unassigned', 12: 'Lease Unknown', 13: 'Lease Active', 14: 'Bulk Lease Query', 15: 'Lease Query Done', 16: 'Active Lease Query', 17: 'Lease Query Status', 18: 'TLS' };
const HTYPES = { 1: 'Ethernet', 6: 'IEEE 802', 7: 'ARCNET', 15: 'Frame Relay', 16: 'ATM', 17: 'HDLC', 18: 'Fibre Channel', 20: 'Serial Line', 32: 'InfiniBand' };
export const OPTION_NAMES = {
  0: 'Pad', 1: 'Subnet Mask', 2: 'Time Offset', 3: 'Router', 4: 'Time Server', 5: 'Name Server', 6: 'Domain Name Server', 7: 'Log Server', 8: 'Quotes Server', 9: 'LPR Server', 10: 'Impress Server', 11: 'Resource Location Server',
  12: 'Host Name', 13: 'Boot File Size', 14: 'Merit Dump File', 15: 'Domain Name', 16: 'Swap Server', 17: 'Root Path', 18: 'Extensions Path', 19: 'IP Forwarding', 20: 'Non-Local Source Routing', 21: 'Policy Filter', 22: 'Maximum Datagram Reassembly Size',
  23: 'Default IP TTL', 24: 'Path MTU Aging Timeout', 25: 'Path MTU Plateau Table', 26: 'Interface MTU', 27: 'All Subnets are Local', 28: 'Broadcast Address', 29: 'Perform Mask Discovery', 30: 'Mask Supplier', 31: 'Perform Router Discovery', 32: 'Router Solicitation Address',
  33: 'Static Route', 34: 'Trailer Encapsulation', 35: 'ARP Cache Timeout', 36: 'Ethernet Encapsulation', 37: 'TCP Default TTL', 38: 'TCP Keepalive Interval', 39: 'TCP Keepalive Garbage', 40: 'NIS Domain', 41: 'NIS Servers', 42: 'NTP Servers', 43: 'Vendor-Specific Information',
  44: 'NetBIOS over TCP/IP Name Server', 45: 'NetBIOS over TCP/IP Datagram Distribution Server', 46: 'NetBIOS over TCP/IP Node Type', 47: 'NetBIOS over TCP/IP Scope', 48: 'X Window System Font Server', 49: 'X Window System Display Manager',
  50: 'Requested IP Address', 51: 'IP Address Lease Time', 52: 'Option Overload', 53: 'DHCP Message Type', 54: 'DHCP Server Identifier', 55: 'Parameter Request List', 56: 'Message', 57: 'Maximum DHCP Message Size', 58: 'Renewal Time Value', 59: 'Rebinding Time Value',
  60: 'Vendor class identifier', 61: 'Client identifier', 64: 'NIS+ Domain', 65: 'NIS+ Servers', 66: 'TFTP Server Name', 67: 'Bootfile name', 68: 'Mobile IP Home Agent', 69: 'SMTP Server', 70: 'POP3 Server', 71: 'NNTP Server', 72: 'WWW Server', 73: 'Finger Server', 74: 'IRC Server',
  77: 'User Class Information', 78: 'SLP Directory Agent', 79: 'SLP Service Scope', 80: 'Rapid Commit', 81: 'Client Fully Qualified Domain Name', 82: 'Relay Agent Information', 85: 'NDS Servers', 86: 'NDS Tree Name', 87: 'NDS Context', 91: 'Client Last Transaction Time', 92: 'Associated IP',
  93: 'Client System Architecture', 94: 'Client Network Interface Identifier', 97: 'Client Machine Identifier', 100: 'PCode', 101: 'TCode', 108: 'IPv6-Only Preferred', 114: 'Captive Portal', 116: 'DHCP Auto-Configuration', 117: 'Name Service Search', 118: 'Subnet Selection', 119: 'Domain Search',
  120: 'SIP Servers', 121: 'Classless Static Route', 122: 'CableLabs Client Configuration', 124: 'V-I Vendor Class', 125: 'V-I Vendor-specific Information', 138: 'CAPWAP Access Controller', 145: 'Forcerenew Nonce', 150: 'TFTP Server Address', 159: 'Portparams', 160: 'Captive Portal (legacy)',
  161: 'MUD URL', 208: 'PXELINUX Magic', 209: 'PXELINUX Config File', 210: 'PXELINUX Path Prefix', 211: 'PXELINUX Reboot Time', 212: '6RD', 213: 'V4 Access Domain', 249: 'Classless Static Route (Microsoft)', 252: 'Private/Proxy autodiscovery', 255: 'End',
};
const ARCH = { 0: 'IA x86 PC', 1: 'NEC/PC98', 2: 'IA64 PC', 3: 'DEC Alpha', 4: 'ArcX86', 5: 'Intel Lean Client', 6: 'EFI IA32', 7: 'EFI x64', 8: 'EFI Xscale', 9: 'EFI BC', 10: 'ARM 32-bit UEFI', 11: 'ARM 64-bit UEFI' };

function ipList(data, o, e) { const a = []; for (let p = o; p + 4 <= e; p += 4) a.push(ipv4(data, p)); return a; }
function secs(n) {
  if (n === 0xffffffff) return 'infinity';
  let s = `${n}s`;
  if (n >= 86400) s += ` (${(n / 86400).toFixed(n % 86400 ? 1 : 0)} days)`;
  else if (n >= 3600) s += ` (${(n / 3600).toFixed(n % 3600 ? 1 : 0)} hours)`;
  else if (n >= 60) s += ` (${(n / 60).toFixed(n % 60 ? 1 : 0)} minutes)`;
  return s;
}
function cstr(data, o, e) { let z = o; while (z < e && data[z]) z++; return printable(data, o, z); }

function classlessRoutes(data, o, e) {
  const out = [];
  while (o < e) {
    const width = data[o]; if (width > 32) break;
    const n = Math.ceil(width / 8);
    if (o + 1 + n + 4 > e) break;
    const pre = new Uint8Array(4); pre.set(data.subarray(o + 1, o + 1 + n));
    out.push(`${ipv4(pre, 0)}/${width} -> ${ipv4(data, o + 1 + n)}`);
    o += 1 + n + 4;
  }
  return out;
}

function domainSearch(data, o, e) {
  const names = [];
  let p = o, guard = 0;
  while (p < e && guard++ < 64) {
    const n = readName(data, p, o, e);
    if (n.err) break;
    names.push(n.name);
    if (n.next <= p) break;
    p = n.next;
  }
  return names;
}

/** Render one DHCPv4 option as a display string; also returns structured bits. */
function renderOption(code, data, o, e, l) {
  const len = e - o;
  const r = { text: '' };
  switch (code) {
    case 1: case 28: case 50: case 54: case 118: r.text = len >= 4 ? ipv4(data, o) : `${len} bytes`; break;
    case 3: case 4: case 5: case 6: case 7: case 41: case 42: case 44: case 45: case 65: case 69: case 70: case 71: case 72: case 150: r.text = ipList(data, o, e).join(', '); r.list = ipList(data, o, e); break;
    case 12: case 14: case 15: case 17: case 18: case 40: case 56: case 60: case 64: case 66: case 67: case 86: case 87: case 100: case 101: case 114: case 161: case 209: case 210: case 252:
      r.text = printable(data, o, e).replace(/\0+$/, ''); break;
    case 2: r.text = `${u32be(data, o) | 0}s`; break;
    case 13: case 22: case 26: case 57: r.text = len >= 2 ? String(u16be(data, o)) : '?'; break;
    case 23: case 37: case 46: r.text = String(data[o]); break;
    case 19: case 20: case 27: case 29: case 30: case 31: case 34: case 36: case 39: case 116: r.text = data[o] ? 'Enabled' : 'Disabled'; break;
    case 24: case 35: case 38: case 51: case 58: case 59: case 91: case 108: case 211: r.text = len >= 4 ? secs(u32be(data, o)) : '?'; r.seconds = len >= 4 ? u32be(data, o) : null; break;
    case 25: { const a = []; for (let p = o; p + 2 <= e; p += 2) a.push(u16be(data, p)); r.text = a.join(', '); break; }
    case 33: { const a = []; for (let p = o; p + 8 <= e; p += 8) a.push(`${ipv4(data, p)} -> ${ipv4(data, p + 4)}`); r.text = a.join(', '); break; }
    case 52: r.text = ['none', 'file', 'sname', 'file and sname'][data[o] & 3]; r.overload = data[o] & 3; break;
    case 53: r.text = `${MSG_TYPES[data[o]] || 'Unknown'} (${data[o]})`; r.msgType = data[o]; break;
    case 55: { const a = []; for (let p = o; p < e; p++) a.push(`${data[p]} (${OPTION_NAMES[data[p]] || 'Unknown'})`); r.text = a.join(', '); r.list = [...data.subarray(o, e)]; break; }
    case 61: {
      if (len >= 7 && data[o] === 1) { r.text = `Ethernet ${mac(data, o + 1)}`; r.mac = mac(data, o + 1); }
      else if (len >= 2 && data[o] === 0xff && len >= 5) r.text = `IAID/DUID ${toHex(data, o + 1, e)}`;
      else if (len >= 1 && data[o] === 0) r.text = `"${printable(data, o + 1, e)}"`;
      else r.text = toHex(data, o, e, ':');
      break;
    }
    case 77: r.text = printable(data, o, e); break;
    case 81: {
      if (len < 3) { r.text = `${len} bytes`; break; }
      const fl = data[o];
      const flags = [fl & 1 ? 'S' : '', fl & 2 ? 'O' : '', fl & 4 ? 'E' : '', fl & 8 ? 'N' : ''].filter(Boolean).join('');
      let name;
      if (fl & 4) name = domainSearch(data, o + 3, e).join(' ') || readName(data, o + 3, o + 3, e).name;
      else name = printable(data, o + 3, e);
      r.text = `flags 0x${hex(fl)}${flags ? ` (${flags})` : ''}, rcode1 ${data[o + 1]}, rcode2 ${data[o + 2]}, name "${name}"`; r.fqdn = name;
      break;
    }
    case 82: {
      const subs = []; let p = o;
      while (p + 2 <= e) { const t = data[p], sl = data[p + 1], se = Math.min(e, p + 2 + sl); subs.push(`${t === 1 ? 'Circuit ID' : t === 2 ? 'Remote ID' : `sub ${t}`}=${printable(data, p + 2, se)} (0x${toHex(data, p + 2, se)})`); p = se; }
      r.text = subs.join('; '); break;
    }
    case 93: { const a = []; for (let p = o; p + 2 <= e; p += 2) { const v = u16be(data, p); a.push(`${ARCH[v] || v} (${v})`); } r.text = a.join(', '); break; }
    case 94: r.text = len >= 3 ? `type ${data[o]}, version ${data[o + 1]}.${data[o + 2]}` : toHex(data, o, e); break;
    case 97: r.text = len === 17 && data[o] === 0 ? `GUID ${toHex(data, o + 1, e)}` : toHex(data, o, e); break;
    case 119: r.list = domainSearch(data, o, e); r.text = r.list.join(', '); break;
    case 121: case 249: r.list = classlessRoutes(data, o, e); r.text = r.list.join(', '); break;
    case 43: case 125: case 124: r.text = `${len} bytes: ${toHex(data, o, Math.min(e, o + 24))}${len > 24 ? '…' : ''}`; break;
    default: r.text = len ? `${len} bytes: ${toHex(data, o, Math.min(e, o + 24))}${len > 24 ? '…' : ''}` : '(empty)';
  }
  void l;
  return r;
}

function parseOptions(l, data, o, end, opts, group, seen) {
  let overload = 0;
  let guard = 0;
  while (o < end && guard++ < 512) {
    const code = data[o];
    if (code === 0) { o++; continue; }
    if (code === 255) { group.children.push({ name: 'Option: (255) End', value: '', offset: o, length: 1 }); l.hasEnd = true; break; }
    if (o + 1 >= end) { l.error('DHCP option truncated'); break; }
    const len = data[o + 1];
    const e = o + 2 + len;
    if (e > end) { l.error(`DHCP option ${code} (${OPTION_NAMES[code] || 'Unknown'}) truncated`); }
    const ee = Math.min(e, end);
    const r = renderOption(code, data, o + 2, ee, l);
    const name = OPTION_NAMES[code] || 'Unknown';
    const opt = { code, name, value: r.text, offset: o, length: ee - o };
    if (r.list) opt.list = r.list;
    if (r.seconds !== undefined) opt.seconds = r.seconds;
    if (r.msgType !== undefined) opt.msgType = r.msgType;
    opts.push(opt);
    seen.add(code);
    group.children.push({ name: `Option: (${code}) ${name}`, value: r.text, offset: o, length: ee - o, children: [
      { name: 'Length', value: len, offset: o + 1, length: 1 },
      { name: name, value: r.text, offset: o + 2, length: ee - (o + 2) },
    ] });
    if (r.overload) overload = r.overload;
    if (r.mac) l.clientIdMac = r.mac;
    if (r.fqdn) l.clientFqdn = r.fqdn;
    o = ee;
  }
  return overload;
}

const dhcp = {
  id: 'dhcp',
  name: 'Dynamic Host Configuration Protocol',
  udpPorts: [67, 68],
  dissect(ctx) {
    const { data, offset, end, packet, state } = ctx;
    const len = end - offset;
    if (len < 44) return null;
    const op = data[offset];
    if (op !== 1 && op !== 2) return null;
    const l = new Layer('dhcp', 'Dynamic Host Configuration Protocol', offset, len);
    l.label = 'DHCP';
    const htype = data[offset + 1], hlen = data[offset + 2], hops = data[offset + 3];
    const xid = u32be(data, offset + 4), secsV = u16be(data, offset + 8), flags = u16be(data, offset + 10);
    l.op = op; l.opName = op === 1 ? 'Boot Request' : 'Boot Reply';
    l.htype = htype; l.hlen = hlen; l.hops = hops; l.xid = xid; l.secs = secsV; l.flags = flags; l.broadcast = !!(flags & 0x8000);
    l.clientIp = ipv4(data, offset + 12); l.yourIp = ipv4(data, offset + 16); l.serverIp = ipv4(data, offset + 20); l.relayIp = ipv4(data, offset + 24);
    l.clientMac = (htype === 1 && hlen === 6) ? mac(data, offset + 28) : toHex(data, offset + 28, offset + 28 + Math.min(16, hlen || 16), ':');
    l.add('Message type', `${l.opName} (${op})`, offset, 1);
    l.add('Hardware type', `${HTYPES[htype] || 'Unknown'} (0x${hex(htype)})`, offset + 1, 1);
    l.add('Hardware address length', hlen, offset + 2, 1);
    l.add('Hops', hops, offset + 3, 1);
    l.add('Transaction ID', `0x${hex(xid, 8)}`, offset + 4, 4);
    l.add('Seconds elapsed', secsV, offset + 8, 2);
    l.add('Bootp flags', `0x${hex(flags, 4)} (${l.broadcast ? 'Broadcast' : 'Unicast'})`, offset + 10, 2);
    l.add('Client IP address', l.clientIp, offset + 12, 4);
    l.add('Your (client) IP address', l.yourIp, offset + 16, 4);
    l.add('Next server IP address', l.serverIp, offset + 20, 4);
    l.add('Relay agent IP address', l.relayIp, offset + 24, 4);
    l.add('Client MAC address', l.clientMac, offset + 28, 16);
    l.options = [];
    l.msgType = 0; l.msgTypeName = '';
    if (len < 236) {
      l.error(`BOOTP header truncated (${len} bytes, need 236)`);
      l.summary = `${l.opName} - Transaction ID 0x${xid.toString(16)} [truncated]`;
      return l;
    }
    l.sname = cstr(data, offset + 44, offset + 108);
    l.file = cstr(data, offset + 108, offset + 236);
    l.add('Server host name', l.sname || 'not given', offset + 44, 64);
    l.add('Boot file name', l.file || 'not given', offset + 108, 128);
    const seen = new Set();
    if (len >= 240 && u32be(data, offset + 236) === 0x63825363) {
      l.add('Magic cookie', 'DHCP', offset + 236, 4);
      const g = l.addGroup('Options', '', offset + 240, end - (offset + 240), []);
      const overload = parseOptions(l, data, offset + 240, end, l.options, g, seen);
      if (overload & 1) { const g2 = l.addGroup('Options (file field)', '', offset + 108, 128, []); parseOptions(l, data, offset + 108, offset + 236, l.options, g2, seen); }
      if (overload & 2) { const g3 = l.addGroup('Options (sname field)', '', offset + 44, 64, []); parseOptions(l, data, offset + 44, offset + 108, l.options, g3, seen); }
      if (!l.hasEnd) l.error('DHCP options missing End option');
    } else if (len >= 240) {
      l.add('Magic cookie', `0x${hex(u32be(data, offset + 236), 8)} (not DHCP)`, offset + 236, 4);
      l.isBootp = true;
    } else l.isBootp = true;

    // Pull the well-known options up as properties.
    const opt = (c) => l.options.find(x => x.code === c);
    const mt = opt(53);
    if (mt) { l.msgType = mt.msgType; l.msgTypeName = MSG_TYPES[mt.msgType] || `Unknown (${mt.msgType})`; }
    l.hostname = opt(12)?.value; l.requestedIp = opt(50)?.value; l.serverId = opt(54)?.value;
    l.leaseTime = opt(51)?.seconds; l.subnetMask = opt(1)?.value; l.routers = opt(3)?.list; l.dnsServers = opt(6)?.list; l.domain = opt(15)?.value;
    l.vendorClass = opt(60)?.value; l.paramRequestList = opt(55)?.list; l.domainSearch = opt(119)?.list; l.staticRoutes = opt(121)?.list || opt(249)?.list;
    const wpad = opt(252);
    l.notes = [];
    if (wpad && wpad.value) { l.wpad = wpad.value; l.notes.push(`WPAD proxy auto-discovery URL offered via DHCP option 252: ${wpad.value}`); packet.tags.add('dhcp-wpad'); }

    const typeLabel = mt ? `DHCP ${l.msgTypeName.padEnd(8)}` : `BOOTP ${l.opName}`;
    l.summary = `${typeLabel} - Transaction ID 0x${xid.toString(16)}`;
    if (l.msgType === 6 && opt(56)) l.summary += ` (${opt(56).value})`;

    // Shared state: leases, servers, hostname memory.
    const st = state.ext.dhcp ||= { leases: [], servers: new Set(), hostnames: new Map() };
    const srcIp = packet.ip?.src ?? '';
    if (l.hostname) st.hostnames.set(l.clientMac, l.hostname);
    if (op === 2 && (l.msgType === 2 || l.msgType === 5 || l.msgType === 6)) {
      const server = l.serverId || srcIp;
      if (server && server !== '0.0.0.0') st.servers.add(server);
      if (st.servers.size > 1) {
        l.notes.push(`Multiple DHCP servers seen in capture (${[...st.servers].join(', ')}) — possible rogue DHCP server`);
        packet.tags.add('dhcp-multiple-servers');
      }
    }
    if (l.msgType === 5 || l.msgType === 2) {
      st.leases.push({ mac: l.clientMac, ip: l.yourIp, hostname: l.hostname || st.hostnames.get(l.clientMac) || null, server: l.serverId || srcIp, packet: packet.index, ts: packet.ts, tentative: l.msgType === 2, leaseTime: l.leaseTime ?? null });
    }
    if (l.notes.length) l.addGroup('[Notes]', String(l.notes.length), -1, 0, l.notes.map(n => ({ name: n, value: '', offset: -1, length: 0 })));
    const s = packet.stream && state.udp.list[packet.stream.id];
    if (s && !s.proto) s.proto = 'dhcp';
    return l;
  },
};

// ---------------------------------------------------------------- DHCPv6

const V6_TYPES = { 1: 'Solicit', 2: 'Advertise', 3: 'Request', 4: 'Confirm', 5: 'Renew', 6: 'Rebind', 7: 'Reply', 8: 'Release', 9: 'Decline', 10: 'Reconfigure', 11: 'Information-request', 12: 'Relay-forw', 13: 'Relay-repl', 14: 'Leasequery', 15: 'Leasequery-reply', 16: 'Leasequery-done', 17: 'Leasequery-data', 18: 'Reconfigure-request', 19: 'Reconfigure-reply', 20: 'DHCPv4-query', 21: 'DHCPv4-response' };
const V6_OPTIONS = {
  1: 'Client Identifier', 2: 'Server Identifier', 3: 'Identity Association for Non-temporary Address', 4: 'Identity Association for Temporary Address', 5: 'IA Address', 6: 'Option Request', 7: 'Preference', 8: 'Elapsed time', 9: 'Relay Message',
  11: 'Authentication', 12: 'Server unicast', 13: 'Status code', 14: 'Rapid Commit', 15: 'User Class', 16: 'Vendor Class', 17: 'Vendor-specific Information', 18: 'Interface-Id', 19: 'Reconfigure Message', 20: 'Reconfigure Accept',
  21: 'SIP Server Domain Name List', 22: 'SIP Server IPv6 Address List', 23: 'DNS recursive name server', 24: 'Domain Search List', 25: 'Identity Association for Prefix Delegation', 26: 'IA Prefix', 27: 'NIS Servers', 28: 'NIS+ Servers', 29: 'NIS Domain', 30: 'NIS+ Domain',
  31: 'SNTP Servers', 32: 'Information Refresh Time', 36: 'Geoconf Civic', 37: 'Remote Identifier', 38: 'Relay Agent Subscriber-ID', 39: 'Fully Qualified Domain Name', 41: 'New POSIX Timezone', 42: 'New TZDB Timezone', 56: 'NTP Server', 59: 'Boot File URL', 60: 'Boot File Parameters', 61: 'Client System Architecture', 62: 'Client Network Interface Identifier', 64: 'AFTR Name', 82: 'SOL_MAX_RT', 83: 'INF_MAX_RT',
};
const V6_STATUS = { 0: 'Success', 1: 'UnspecFail', 2: 'NoAddrsAvail', 3: 'NoBinding', 4: 'NotOnLink', 5: 'UseMulticast', 6: 'NoPrefixAvail' };
const DUID_TYPES = { 1: 'link-layer address plus time', 2: 'assigned by vendor based on Enterprise number', 3: 'link-layer address', 4: 'UUID' };

function duidText(data, o, e) {
  const hexs = toHex(data, o, e);
  if (e - o < 2) return { text: hexs, hex: hexs };
  const t = u16be(data, o);
  let detail = DUID_TYPES[t] || `type ${t}`;
  if (t === 1 && e - o >= 14) detail += `, ${mac(data, o + 8)}`;
  else if (t === 3 && e - o >= 10) detail += `, ${mac(data, o + 4)}`;
  return { text: `${hexs} (${detail})`, hex: hexs };
}

function parseV6Options(l, data, o, end, group, depth, msg) {
  let guard = 0;
  while (o + 4 <= end && guard++ < 256) {
    const code = u16be(data, o), len = u16be(data, o + 2);
    const s = o + 4, e = s + len;
    if (e > end) l.error(`DHCPv6 option ${code} truncated`);
    const ee = Math.min(e, end);
    const name = V6_OPTIONS[code] || `Unknown (${code})`;
    let text = '';
    const children = [];
    switch (code) {
      case 1: case 2: { const d = duidText(data, s, ee); text = d.text; if (code === 1) msg.clientId = d.hex; else msg.serverId = d.hex; break; }
      case 3: case 25: {
        if (ee - s < 12) { text = 'truncated'; break; }
        const iaid = u32be(data, s), t1 = u32be(data, s + 4), t2 = u32be(data, s + 8);
        text = `IAID 0x${hex(iaid, 8)}, T1 ${t1}, T2 ${t2}`;
        (msg.ia ||= []).push({ type: code === 3 ? 'IA_NA' : 'IA_PD', iaid, t1, t2 });
        const sub = { name: 'Sub-options', value: '', offset: s + 12, length: ee - s - 12, children: [] };
        parseV6Options(l, data, s + 12, ee, sub, depth, msg);
        children.push(sub);
        break;
      }
      case 4: {
        if (ee - s < 4) { text = 'truncated'; break; }
        text = `IAID 0x${hex(u32be(data, s), 8)}`;
        const sub = { name: 'Sub-options', value: '', offset: s + 4, length: ee - s - 4, children: [] };
        parseV6Options(l, data, s + 4, ee, sub, depth, msg);
        children.push(sub);
        break;
      }
      case 5: {
        if (ee - s < 24) { text = 'truncated'; break; }
        const addr = ipv6(data, s);
        text = `${addr}, preferred ${u32be(data, s + 16)}s, valid ${u32be(data, s + 20)}s`;
        (msg.addresses ||= []).push(addr);
        if (ee - s > 24) { const sub = { name: 'Sub-options', value: '', offset: s + 24, length: ee - s - 24, children: [] }; parseV6Options(l, data, s + 24, ee, sub, depth, msg); children.push(sub); }
        break;
      }
      case 26: {
        if (ee - s < 25) { text = 'truncated'; break; }
        const pfx = `${ipv6(data, s + 9)}/${data[s + 8]}`;
        text = `${pfx}, preferred ${u32be(data, s)}s, valid ${u32be(data, s + 4)}s`;
        (msg.prefixes ||= []).push(pfx);
        break;
      }
      case 6: { const a = []; for (let p = s; p + 2 <= ee; p += 2) { const c = u16be(data, p); a.push(`${V6_OPTIONS[c] || 'Unknown'} (${c})`); } text = a.join(', '); break; }
      case 7: text = String(data[s]); break;
      case 8: text = ee - s >= 2 ? `${u16be(data, s) * 10} ms` : '?'; break;
      case 9: {
        if (depth < 4) {
          const inner = parseV6Message(l, data, s, ee, depth + 1);
          text = inner.summary;
          children.push(...inner.fields);
          msg.inner = inner;
        } else text = `${len} bytes (nesting too deep)`;
        break;
      }
      case 12: text = ee - s >= 16 ? ipv6(data, s) : '?'; break;
      case 13: { const c = ee - s >= 2 ? u16be(data, s) : -1; text = `${V6_STATUS[c] || c} (${c})${ee - s > 2 ? `: ${printable(data, s + 2, ee)}` : ''}`; msg.status = c; break; }
      case 14: case 20: text = ''; if (code === 14) msg.rapidCommit = true; break;
      case 18: case 37: case 38: text = `${printable(data, s, ee)} (0x${toHex(data, s, ee)})`; break;
      case 16: case 15: case 17: text = ee - s >= 4 ? `enterprise ${u32be(data, s)}, ${printable(data, s + 4, ee)}` : toHex(data, s, ee); break;
      case 22: case 23: case 27: case 28: case 31: { const a = []; for (let p = s; p + 16 <= ee; p += 16) a.push(ipv6(data, p)); text = a.join(', '); if (code === 23) msg.dns = a; if (code === 31) msg.sntp = a; break; }
      case 21: case 24: case 29: case 30: case 64: { const a = domainSearch(data, s, ee); text = a.join(', '); if (code === 24) msg.domains = a; break; }
      case 32: case 82: case 83: text = ee - s >= 4 ? secs(u32be(data, s)) : '?'; break;
      case 39: {
        if (ee - s < 1) { text = 'truncated'; break; }
        const fl = data[s];
        const nm = domainSearch(data, s + 1, ee).join(' ');
        text = `flags 0x${hex(fl)} (${[fl & 1 ? 'S' : '', fl & 2 ? 'O' : '', fl & 4 ? 'N' : ''].filter(Boolean).join('') || '-'}), name "${nm}"`;
        msg.fqdn = nm;
        break;
      }
      case 41: case 42: case 59: text = printable(data, s, ee); break;
      case 56: {
        const a = []; let p = s;
        while (p + 4 <= ee) { const st = u16be(data, p), sl = u16be(data, p + 2), se = Math.min(ee, p + 4 + sl); if (st === 1 || st === 2) a.push(ipv6(data, p + 4)); else if (st === 3) a.push(readName(data, p + 4, p + 4, se).name); p = se; }
        text = a.join(', '); msg.ntp = a; break;
      }
      case 61: { const a = []; for (let p = s; p + 2 <= ee; p += 2) { const v = u16be(data, p); a.push(`${ARCH[v] || v} (${v})`); } text = a.join(', '); break; }
      default: text = len ? `${len} bytes: ${toHex(data, s, Math.min(ee, s + 24))}${len > 24 ? '…' : ''}` : '';
    }
    msg.options.push({ code, name, value: text });
    group.children.push({ name: `${name} (${code})`, value: text, offset: o, length: ee - o, children: children.length ? children : null });
    o = ee;
    if (e > end) break;
  }
}

function parseV6Message(l, data, o, end, depth) {
  const fields = [];
  const msg = { options: [], fields, summary: '' };
  if (end - o < 4) { l.error('DHCPv6 header truncated'); msg.summary = 'DHCPv6 [truncated]'; return msg; }
  const type = data[o];
  msg.msgType = type; msg.msgTypeName = V6_TYPES[type] || `Unknown (${type})`;
  fields.push({ name: 'Message type', value: `${msg.msgTypeName} (${type})`, offset: o, length: 1 });
  let optStart;
  if (type === 12 || type === 13) {
    if (end - o < 34) { l.error('DHCPv6 relay header truncated'); msg.summary = `${msg.msgTypeName} [truncated]`; return msg; }
    msg.hopCount = data[o + 1]; msg.linkAddr = ipv6(data, o + 2); msg.peerAddr = ipv6(data, o + 18);
    fields.push({ name: 'Hop count', value: msg.hopCount, offset: o + 1, length: 1 });
    fields.push({ name: 'Link address', value: msg.linkAddr, offset: o + 2, length: 16 });
    fields.push({ name: 'Peer address', value: msg.peerAddr, offset: o + 18, length: 16 });
    optStart = o + 34;
  } else {
    msg.xid = ((data[o + 1] << 16) | (data[o + 2] << 8) | data[o + 3]) >>> 0;
    fields.push({ name: 'Transaction ID', value: `0x${hex(msg.xid, 6)}`, offset: o + 1, length: 3 });
    optStart = o + 4;
  }
  const g = { name: 'Options', value: '', offset: optStart, length: end - optStart, children: [] };
  fields.push(g);
  parseV6Options(l, data, optStart, end, g, depth, msg);
  if (type === 12 || type === 13) {
    msg.summary = `${msg.msgTypeName} L: ${msg.linkAddr} P: ${msg.peerAddr}${msg.inner ? ' ' + msg.inner.summary : ''}`;
  } else {
    let s = `${msg.msgTypeName} XID: 0x${hex(msg.xid, 6)}`;
    if (msg.clientId) s += ` CID: ${msg.clientId}`;
    if (msg.addresses?.length) s += ` IAA: ${msg.addresses.join(', ')}`;
    if (msg.prefixes?.length) s += ` IAPD: ${msg.prefixes.join(', ')}`;
    msg.summary = s;
  }
  return msg;
}

const dhcpv6 = {
  id: 'dhcpv6',
  name: 'DHCPv6',
  udpPorts: [546, 547],
  dissect(ctx) {
    const { data, offset, end, packet, state } = ctx;
    if (end - offset < 4) return null;
    const type = data[offset];
    if (type === 0 || type > 21) return null;
    const l = new Layer('dhcpv6', 'DHCPv6', offset, end - offset);
    l.label = 'DHCPv6';
    const msg = parseV6Message(l, data, offset, end, 0);
    for (const f of msg.fields) l.fields.push(f);
    l.msgType = msg.msgType ?? 0; l.msgTypeName = msg.msgTypeName ?? ''; l.xid = msg.xid ?? null;
    l.clientId = msg.clientId; l.serverId = msg.serverId; l.addresses = msg.addresses || []; l.prefixes = msg.prefixes || [];
    l.ia = msg.ia || []; l.dnsServers = msg.dns; l.domains = msg.domains; l.fqdn = msg.fqdn; l.status = msg.status; l.options = msg.options;
    l.iaAddr = l.addresses[0]; l.inner = msg.inner || null;
    if (msg.linkAddr) { l.linkAddr = msg.linkAddr; l.peerAddr = msg.peerAddr; l.hopCount = msg.hopCount; }
    l.summary = msg.summary;
    const st = state.ext.dhcpv6 ||= { leases: [], servers: new Set() };
    const src = packet.ip?.src ?? '';
    if (msg.msgType === 2 || msg.msgType === 7) {
      if (src) st.servers.add(src);
      if (msg.msgType === 7 && msg.addresses?.length) st.leases.push({ duid: msg.clientId || null, ip: msg.addresses[0], fqdn: msg.fqdn || null, server: src, packet: packet.index, ts: packet.ts });
    }
    const s = packet.stream && state.udp.list[packet.stream.id];
    if (s && !s.proto) s.proto = 'dhcpv6';
    return l;
  },
};

export default [dhcp, dhcpv6];
