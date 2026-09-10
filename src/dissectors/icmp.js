import { Layer } from '../core/packet.js';
import { u16be, u32be, ipv4, ipv6, hex, mac, printable } from '../core/bytes.js';
import { ipProtoName } from './ipv4.js';

const ICMP_TYPES = {
  0: 'Echo reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo request',
  9: 'Router advertisement', 10: 'Router solicitation', 11: 'Time exceeded', 12: 'Parameter problem',
  13: 'Timestamp request', 14: 'Timestamp reply', 15: 'Information request', 16: 'Information reply',
  17: 'Address mask request', 18: 'Address mask reply', 30: 'Traceroute',
};
const UNREACH_CODES = {
  0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable',
  4: 'Fragmentation needed', 5: 'Source route failed', 6: 'Destination network unknown', 7: 'Destination host unknown',
  9: 'Network administratively prohibited', 10: 'Host administratively prohibited', 13: 'Communication administratively filtered',
};

function embeddedIpv4(l, data, o, end) {
  if (end - o < 28 || data[o] >> 4 !== 4) return;
  const ihl = (data[o] & 0xf) * 4;
  const proto = data[o + 9];
  const src = ipv4(data, o + 12), dst = ipv4(data, o + 16);
  const g = l.addGroup('Original datagram', `${src} → ${dst} ${ipProtoName(proto)}`, o, end - o, []);
  l.origSrc = src; l.origDst = dst; l.origProto = proto;
  const p = o + ihl;
  if ((proto === 6 || proto === 17) && p + 4 <= end) {
    l.origSrcPort = u16be(data, p); l.origDstPort = u16be(data, p + 2);
    g.children.push({ name: `${ipProtoName(proto)} ports`, value: `${l.origSrcPort} → ${l.origDstPort}`, offset: p, length: 4 });
  }
}

export const icmp = {
  id: 'icmp',
  name: 'Internet Control Message Protocol',
  ipProtos: [1],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 4) return null;
    const type = data[offset], code = data[offset + 1];
    const l = new Layer('icmp', 'Internet Control Message Protocol', offset, end - offset);
    l.label = 'ICMP';
    l.type = type; l.code = code;
    const tname = ICMP_TYPES[type] || `Type ${type}`;
    l.add('Type', `${tname} (${type})`, offset, 1);
    let cname = String(code);
    if (type === 3) cname = `${UNREACH_CODES[code] || code} (${code})`;
    else if (type === 11) cname = code === 0 ? 'TTL exceeded in transit (0)' : 'Fragment reassembly time exceeded (1)';
    else if (type === 5) cname = ['Redirect for network', 'Redirect for host', 'Redirect for TOS and network', 'Redirect for TOS and host'][code] || code;
    l.add('Code', cname, offset + 1, 1);
    l.add('Checksum', `0x${hex(u16be(data, offset + 2), 4)}`, offset + 2, 2);
    let summary = tname;
    if (type === 0 || type === 8) {
      const id = u16be(data, offset + 4), seq = u16be(data, offset + 6);
      l.id = id; l.seq = seq;
      l.add('Identifier', `${id} (0x${hex(id, 4)})`, offset + 4, 2);
      l.add('Sequence number', `${seq} (0x${hex(seq, 4)})`, offset + 6, 2);
      const dl = end - (offset + 8);
      l.add('Data', `${dl} bytes: ${printable(data, offset + 8, Math.min(end, offset + 8 + 32))}`, offset + 8, dl);
      summary = `${tname} id=${hex(id, 4)}, seq=${seq}, ttl=${ctx.parent?.ttl ?? '?'}`;
      // Detect suspicious payload sizes (tunnelling / exfil).
      if (dl > 64) l.hint = 'large-icmp-payload';
    } else if (type === 3 || type === 11 || type === 12 || type === 4 || type === 5) {
      if (type === 5) l.add('Gateway address', ipv4(data, offset + 4), offset + 4, 4);
      if (type === 3 && code === 4) l.add('MTU of next hop', u16be(data, offset + 6), offset + 6, 2);
      embeddedIpv4(l, data, offset + 8, end);
      summary = `${tname}${type === 3 ? ` (${UNREACH_CODES[code] || code})` : ''}`;
      if (l.origSrc) summary += ` — orig ${l.origSrc}${l.origSrcPort !== undefined ? ':' + l.origSrcPort : ''} → ${l.origDst}${l.origDstPort !== undefined ? ':' + l.origDstPort : ''}`;
    } else if (type === 13 || type === 14) {
      l.add('Originate timestamp', u32be(data, offset + 8), offset + 8, 4);
    }
    l.summary = summary;
    return l;
  },
};

const ICMP6_TYPES = {
  1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem',
  128: 'Echo request', 129: 'Echo reply', 130: 'Multicast listener query', 131: 'Multicast listener report',
  132: 'Multicast listener done', 133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation',
  136: 'Neighbor advertisement', 137: 'Redirect', 143: 'Multicast listener report v2',
};

export const icmpv6 = {
  id: 'icmpv6',
  name: 'Internet Control Message Protocol v6',
  ipProtos: [58],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 4) return null;
    const type = data[offset], code = data[offset + 1];
    const l = new Layer('icmpv6', 'Internet Control Message Protocol v6', offset, end - offset);
    l.label = 'ICMPv6';
    l.type = type; l.code = code;
    const tname = ICMP6_TYPES[type] || `Type ${type}`;
    l.add('Type', `${tname} (${type})`, offset, 1);
    l.add('Code', code, offset + 1, 1);
    l.add('Checksum', `0x${hex(u16be(data, offset + 2), 4)}`, offset + 2, 2);
    let summary = tname;
    if (type === 128 || type === 129) {
      const id = u16be(data, offset + 4), seq = u16be(data, offset + 6);
      l.id = id; l.seq = seq;
      l.add('Identifier', `0x${hex(id, 4)}`, offset + 4, 2);
      l.add('Sequence number', seq, offset + 6, 2);
      summary = `${tname} id=${hex(id, 4)}, seq=${seq}`;
    } else if (type === 135 || type === 136) {
      if (end - offset >= 24) {
        l.target = ipv6(data, offset + 8);
        if (type === 136) {
          const fl = data[offset + 4];
          l.add('Flags', `${fl & 0x80 ? 'R ' : ''}${fl & 0x40 ? 'S ' : ''}${fl & 0x20 ? 'O' : ''}`.trim() || 'none', offset + 4, 1);
        }
        l.add('Target address', l.target, offset + 8, 16);
        summary = type === 135 ? `Neighbor Solicitation for ${l.target}` : `Neighbor Advertisement ${l.target}`;
        parseNdpOptions(l, data, offset + 24, end, summary);
        if (l.llAddr) summary += type === 135 ? ` from ${l.llAddr}` : ` is at ${l.llAddr}`;
      }
    } else if (type === 134) {
      if (end - offset >= 16) {
        l.add('Cur hop limit', data[offset + 4], offset + 4, 1);
        l.add('Flags', `${data[offset + 5] & 0x80 ? 'Managed ' : ''}${data[offset + 5] & 0x40 ? 'Other' : ''}`.trim() || 'none', offset + 5, 1);
        l.add('Router lifetime', `${u16be(data, offset + 6)} s`, offset + 6, 2);
        parseNdpOptions(l, data, offset + 16, end);
        summary = `Router Advertisement from ${ctx.parent?.src || ''}${l.llAddr ? ' (' + l.llAddr + ')' : ''}`;
      }
    } else if (type === 133) {
      parseNdpOptions(l, data, offset + 8, end);
      summary = `Router Solicitation${l.llAddr ? ' from ' + l.llAddr : ''}`;
    } else if (type === 2) {
      l.add('MTU', u32be(data, offset + 4), offset + 4, 4);
    }
    l.summary = summary;
    return l;
  },
};

function parseNdpOptions(l, data, o, end) {
  const names = { 1: 'Source link-layer address', 2: 'Target link-layer address', 3: 'Prefix information', 4: 'Redirected header', 5: 'MTU', 25: 'Recursive DNS server', 31: 'DNS search list' };
  while (o + 8 <= end) {
    const t = data[o], len = data[o + 1] * 8;
    if (!len) break;
    let val = `${len} bytes`;
    if ((t === 1 || t === 2) && len >= 8) { val = mac(data, o + 2); l.llAddr = val; }
    else if (t === 3 && len >= 32) { val = `${ipv6(data, o + 16)}/${data[o + 2]}`; l.prefix = val; }
    else if (t === 5 && len >= 8) val = String(u32be(data, o + 4));
    else if (t === 25 && len >= 24) { const s = []; for (let p = o + 8; p + 16 <= o + len; p += 16) s.push(ipv6(data, p)); val = s.join(', '); l.rdnss = s; }
    l.add(names[t] || `Option ${t}`, val, o, len);
    o += len;
  }
}
