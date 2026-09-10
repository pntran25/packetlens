import { Layer } from '../core/packet.js';
import { u16be, u32be, ipv6, hex } from '../core/bytes.js';
import { ipProtoName } from './ipv4.js';

const EXT_HEADERS = new Set([0, 43, 44, 51, 60, 135]);

export default {
  id: 'ipv6',
  name: 'Internet Protocol Version 6',
  etherTypes: [0x86dd],
  ipProtos: [41],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 40) return null;
    const vtf = u32be(data, offset);
    if (vtf >>> 28 !== 6) return null;
    const l = new Layer('ipv6', 'Internet Protocol Version 6', offset, 40);
    l.label = 'IPv6';
    const tc = (vtf >>> 20) & 0xff, flow = vtf & 0xfffff;
    const payloadLen = u16be(data, offset + 4);
    let nh = data[offset + 6];
    const hop = data[offset + 7];
    l.src = ipv6(data, offset + 8);
    l.dst = ipv6(data, offset + 24);
    l.version = 6; l.ttl = hop;
    l.add('Version', 6, offset, 1);
    l.add('Traffic class', `0x${hex(tc)}`, offset, 2);
    l.add('Flow label', `0x${hex(flow, 5)}`, offset + 1, 3);
    l.add('Payload length', payloadLen, offset + 4, 2);
    l.add('Next header', `${ipProtoName(nh)} (${nh})`, offset + 6, 1);
    l.add('Hop limit', hop, offset + 7, 1);
    l.add('Source', l.src, offset + 8, 16);
    l.add('Destination', l.dst, offset + 24, 16);

    const payloadEnd = Math.min(end, offset + 40 + payloadLen);
    let o = offset + 40;
    // Walk extension headers.
    while (EXT_HEADERS.has(nh) && o + 8 <= payloadEnd) {
      const next = data[o];
      let hlen;
      if (nh === 51) hlen = (data[o + 1] + 2) * 4; // AH
      else hlen = (data[o + 1] + 1) * 8;
      const names = { 0: 'Hop-by-Hop Options', 43: 'Routing Header', 44: 'Fragment Header', 51: 'Authentication Header', 60: 'Destination Options', 135: 'Mobility Header' };
      const g = l.addGroup(names[nh], `next ${ipProtoName(next)}, ${hlen} bytes`, o, hlen, []);
      if (nh === 44) {
        hlen = 8;
        const fo = u16be(data, o + 2);
        const fragOff = fo >> 3, mf = fo & 1;
        const id = u32be(data, o + 4);
        g.children.push({ name: 'Fragment offset', value: fragOff * 8, offset: o + 2, length: 2 });
        g.children.push({ name: 'More fragments', value: mf ? 'yes' : 'no', offset: o + 2, length: 2 });
        g.children.push({ name: 'Identification', value: `0x${hex(id, 8)}`, offset: o + 4, length: 4 });
        ctx.packet.tags.add('fragment');
        if (fragOff > 0) {
          l.length = o + hlen - offset;
          l.summary = `Fragmented IPv6 (off=${fragOff * 8}, ID=${hex(id, 8)})`;
          return l;
        }
      }
      if (nh === 43) {
        const rtype = data[o + 2];
        g.children.push({ name: 'Routing type', value: rtype === 0 ? 'Type 0 (deprecated)' : rtype, offset: o + 2, length: 1 });
        if (rtype === 0) l.error('Deprecated Type 0 routing header');
      }
      o += hlen;
      nh = next;
    }
    l.length = o - offset;
    l.proto_ = nh;
    l.payloadLen = payloadEnd - o;
    l.summary = `${l.src} → ${l.dst} ${ipProtoName(nh)}`;
    if (nh === 59) return l; // No next header
    l.next = { table: 'ipProto', key: nh, offset: o, end: payloadEnd };
    return l;
  },
};
