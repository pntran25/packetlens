import { Layer } from '../core/packet.js';
import { u16be, u32be, ipv4, hex, inetChecksum } from '../core/bytes.js';

export const IPPROTO_NAMES = {
  0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 4: 'IPv4', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 43: 'IPv6-Route', 44: 'IPv6-Frag',
  47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 59: 'IPv6-NoNxt', 60: 'IPv6-Opts', 88: 'EIGRP', 89: 'OSPF',
  103: 'PIM', 112: 'VRRP', 115: 'L2TP', 132: 'SCTP', 136: 'UDPLite',
};
export function ipProtoName(p) { return IPPROTO_NAMES[p] || `proto ${p}`; }

const DSCP_NAMES = { 0: 'CS0', 8: 'CS1', 16: 'CS2', 24: 'CS3', 32: 'CS4', 40: 'CS5', 48: 'CS6', 56: 'CS7', 46: 'EF', 10: 'AF11', 12: 'AF12', 14: 'AF13', 18: 'AF21', 20: 'AF22', 22: 'AF23', 26: 'AF31', 28: 'AF32', 30: 'AF33', 34: 'AF41', 36: 'AF42', 38: 'AF43' };

export function isPrivateV4(ip) {
  const p = ip.split('.').map(Number);
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
  return false;
}

export default {
  id: 'ipv4',
  name: 'Internet Protocol Version 4',
  etherTypes: [0x0800],
  ipProtos: [4],
  dissect(ctx) {
    const { data, offset, end, state } = ctx;
    if (end - offset < 20) return null;
    const vihl = data[offset];
    const ver = vihl >> 4;
    if (ver !== 4) return null;
    const ihl = (vihl & 0xf) * 4;
    if (ihl < 20 || offset + ihl > end) return null;
    const l = new Layer('ipv4', 'Internet Protocol Version 4', offset, ihl);
    l.label = 'IPv4';
    const tos = data[offset + 1];
    const totalLen = u16be(data, offset + 2);
    const id = u16be(data, offset + 4);
    const flagsFrag = u16be(data, offset + 6);
    const flags = flagsFrag >> 13, fragOff = (flagsFrag & 0x1fff) * 8;
    const ttl = data[offset + 8];
    const proto = data[offset + 9];
    const csum = u16be(data, offset + 10);
    l.src = ipv4(data, offset + 12);
    l.dst = ipv4(data, offset + 16);
    l.proto_ = proto; l.ttl = ttl; l.id = id; l.totalLen = totalLen; l.fragOff = fragOff; l.mf = !!(flags & 1); l.df = !!(flags & 2);
    l.version = 4;

    l.add('Version', 4, offset, 1);
    l.add('Header length', `${ihl} bytes`, offset, 1);
    const dscp = tos >> 2, ecn = tos & 3;
    l.add('Differentiated Services', `DSCP ${DSCP_NAMES[dscp] || dscp}, ECN ${ecn}`, offset + 1, 1);
    l.add('Total length', totalLen, offset + 2, 2);
    l.add('Identification', `0x${hex(id, 4)} (${id})`, offset + 4, 2);
    const fl = [];
    if (flags & 4) fl.push('Reserved');
    if (flags & 2) fl.push("Don't fragment");
    if (flags & 1) fl.push('More fragments');
    l.add('Flags', fl.length ? fl.join(', ') : 'none', offset + 6, 2);
    l.add('Fragment offset', fragOff, offset + 6, 2);
    l.add('Time to live', ttl, offset + 8, 1);
    l.add('Protocol', `${ipProtoName(proto)} (${proto})`, offset + 9, 1);
    const calc = inetChecksum(data, offset, offset + ihl);
    const csumOk = calc === 0;
    l.add('Header checksum', `0x${hex(csum, 4)} [${csumOk ? 'correct' : 'incorrect'}]`, offset + 10, 2);
    l.checksumOk = csumOk;
    l.add('Source', l.src, offset + 12, 4);
    l.add('Destination', l.dst, offset + 16, 4);

    if (ihl > 20) {
      const g = l.addGroup('Options', `${ihl - 20} bytes`, offset + 20, ihl - 20, []);
      let o = offset + 20;
      const oend = offset + ihl;
      while (o < oend) {
        const t = data[o];
        if (t === 0) { g.children.push({ name: 'End of options', value: '', offset: o, length: 1 }); break; }
        if (t === 1) { g.children.push({ name: 'No-op', value: '', offset: o, length: 1 }); o++; continue; }
        const len = data[o + 1] || 2;
        const names = { 7: 'Record route', 68: 'Timestamp', 131: 'Loose source route', 137: 'Strict source route', 148: 'Router alert', 130: 'Security' };
        g.children.push({ name: names[t] || `Option ${t}`, value: `${len} bytes`, offset: o, length: len });
        if (t === 131 || t === 137) l.error('Source routing option present');
        o += len;
      }
    }

    if (totalLen < ihl) l.error('Total length smaller than header length');
    if (ttl === 0) l.error('TTL is 0');
    if (!csumOk) l.error('Bad header checksum');
    const payloadEnd = totalLen >= ihl ? Math.min(end, offset + totalLen) : end;
    const payloadLen = payloadEnd - (offset + ihl);
    l.payloadLen = payloadLen;
    l.summary = `${l.src} → ${l.dst} ${ipProtoName(proto)}`;

    if (fragOff > 0 || l.mf) {
      l.fragmented = true;
      l.summary = `Fragmented IP protocol (proto=${ipProtoName(proto)}, off=${fragOff}, ID=${hex(id, 4)})${l.mf ? ' [More fragments]' : ''}`;
      // Track fragments; only dissect the first fragment's payload.
      const fr = state.ext.ipfrag ||= new Map();
      const k = `${l.src}|${l.dst}|${id}|${proto}`;
      const fset = fr.get(k) || { packets: [], bytes: 0 };
      fset.packets.push(ctx.packet.index); fset.bytes += payloadLen;
      fr.set(k, fset);
      ctx.packet.tags.add('fragment');
      if (fragOff > 0) return l; // later fragments: no upper-layer header present
    }
    l.next = { table: 'ipProto', key: proto, offset: offset + ihl, end: payloadEnd };
    return l;
  },
};
