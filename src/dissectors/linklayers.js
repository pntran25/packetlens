// Less common link layers: Linux cooked capture (SLL/SLL2), BSD loopback, raw IP.
import { Layer } from '../core/packet.js';
import { u16be, u32le, u32be, hex, toHex } from '../core/bytes.js';
import { etherTypeName } from './ethernet.js';

const SLL_PKTTYPE = { 0: 'Unicast to us', 1: 'Broadcast', 2: 'Multicast', 3: 'Unicast to another host', 4: 'Sent by us' };

export const sll = {
  id: 'sll',
  name: 'Linux cooked capture v1',
  linkTypes: [113],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 16) return null;
    const l = new Layer('sll', 'Linux cooked capture v1', offset, 16);
    l.label = 'SLL';
    const pktType = u16be(data, offset);
    const haType = u16be(data, offset + 2);
    const haLen = u16be(data, offset + 4);
    const type = u16be(data, offset + 14);
    l.add('Packet type', `${SLL_PKTTYPE[pktType] || pktType}`, offset, 2);
    l.add('Link-layer address type', haType, offset + 2, 2);
    l.add('Link-layer address', toHex(data, offset + 6, offset + 6 + Math.min(haLen, 8), ':'), offset + 6, 8);
    l.add('Protocol', `${etherTypeName(type)} (0x${hex(type, 4)})`, offset + 14, 2);
    l.src = haLen === 6 ? toHex(data, offset + 6, offset + 12, ':') : '';
    l.summary = `Linux cooked, ${etherTypeName(type)}`;
    l.next = { table: 'etherType', key: type, offset: offset + 16 };
    return l;
  },
};

export const sll2 = {
  id: 'sll2',
  name: 'Linux cooked capture v2',
  linkTypes: [276],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 20) return null;
    const l = new Layer('sll2', 'Linux cooked capture v2', offset, 20);
    l.label = 'SLL2';
    const type = u16be(data, offset);
    const ifindex = u32be(data, offset + 4);
    const pktType = data[offset + 10];
    l.add('Protocol', `${etherTypeName(type)} (0x${hex(type, 4)})`, offset, 2);
    l.add('Interface index', ifindex, offset + 4, 4);
    l.add('Packet type', SLL_PKTTYPE[pktType] || pktType, offset + 10, 1);
    l.add('Link-layer address', toHex(data, offset + 12, offset + 18, ':'), offset + 12, 8);
    l.summary = `Linux cooked v2, ${etherTypeName(type)}`;
    l.next = { table: 'etherType', key: type, offset: offset + 20 };
    return l;
  },
};

export const nullLoop = {
  id: 'null',
  name: 'BSD loopback',
  linkTypes: [0, 108],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 4) return null;
    // Family is in host byte order of the capturing machine; try both.
    let fam = u32le(data, offset);
    if (fam > 0xffff) fam = u32be(data, offset);
    const l = new Layer('null', 'BSD loopback', offset, 4);
    l.label = 'NULL';
    const map = { 2: 0x0800, 24: 0x86dd, 28: 0x86dd, 30: 0x86dd, 10: 0x86dd };
    l.add('Family', fam === 2 ? 'IPv4 (2)' : (map[fam] ? `IPv6 (${fam})` : fam), offset, 4);
    l.summary = 'Loopback';
    if (map[fam]) l.next = { table: 'etherType', key: map[fam], offset: offset + 4 };
    return l;
  },
};

export const rawIp = {
  id: 'rawip',
  name: 'Raw IP',
  linkTypes: [101, 228, 229, 12, 14],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 1) return null;
    const ver = data[offset] >> 4;
    const l = new Layer('rawip', 'Raw IP', offset, 0);
    l.label = 'RAW';
    l.summary = `Raw IPv${ver}`;
    if (ver === 4) l.next = { table: 'etherType', key: 0x0800, offset };
    else if (ver === 6) l.next = { table: 'etherType', key: 0x86dd, offset };
    return l;
  },
};

export const ppp = {
  id: 'ppp',
  name: 'Point-to-Point Protocol',
  linkTypes: [9, 50, 51],
  etherTypes: [0x880b],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 2) return null;
    let o = offset;
    if (data[o] === 0xff && data[o + 1] === 0x03) o += 2; // HDLC address/control
    let proto = data[o];
    let plen = 1;
    if ((proto & 1) === 0) { proto = u16be(data, o); plen = 2; }
    const l = new Layer('ppp', 'Point-to-Point Protocol', offset, o + plen - offset);
    l.label = 'PPP';
    const names = { 0x0021: 'IPv4', 0x0057: 'IPv6', 0xc021: 'LCP', 0x8021: 'IPCP', 0xc023: 'PAP', 0xc223: 'CHAP' };
    l.add('Protocol', `${names[proto] || ''} (0x${hex(proto, 4)})`, o, plen);
    l.summary = `PPP ${names[proto] || hex(proto, 4)}`;
    if (proto === 0x0021) l.next = { table: 'etherType', key: 0x0800, offset: o + plen };
    else if (proto === 0x0057) l.next = { table: 'etherType', key: 0x86dd, offset: o + plen };
    return l;
  },
};

export const pppoe = {
  id: 'pppoe',
  name: 'PPP-over-Ethernet Session',
  etherTypes: [0x8864],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 8) return null;
    const l = new Layer('pppoe', 'PPP-over-Ethernet Session', offset, 6);
    l.label = 'PPPoE';
    l.add('Session ID', `0x${hex(u16be(data, offset + 2), 4)}`, offset + 2, 2);
    l.add('Payload length', u16be(data, offset + 4), offset + 4, 2);
    l.summary = 'PPPoE session';
    l.next = { table: 'linkType', key: 9, offset: offset + 6, end: Math.min(end, offset + 6 + u16be(data, offset + 4)) };
    return l;
  },
};

export const mpls = {
  id: 'mpls',
  name: 'MultiProtocol Label Switching',
  etherTypes: [0x8847, 0x8848],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    let o = offset;
    const l = new Layer('mpls', 'MultiProtocol Label Switching', offset, 0);
    l.label = 'MPLS';
    let bottom = 0;
    const labels = [];
    while (!bottom && o + 4 <= end) {
      const v = u32be(data, o);
      const label = v >>> 12, tc = (v >> 9) & 7, ttl = v & 0xff;
      bottom = (v >> 8) & 1;
      labels.push(label);
      l.add('Label', `${label} (TC ${tc}, TTL ${ttl}${bottom ? ', bottom of stack' : ''})`, o, 4);
      o += 4;
    }
    l.length = o - offset;
    l.summary = `MPLS labels ${labels.join('/')}`;
    if (o < end) {
      const ver = data[o] >> 4;
      if (ver === 4) l.next = { table: 'etherType', key: 0x0800, offset: o };
      else if (ver === 6) l.next = { table: 'etherType', key: 0x86dd, offset: o };
      else l.next = { table: 'linkType', key: 1, offset: o }; // pseudowire Ethernet
    }
    return l;
  },
};
