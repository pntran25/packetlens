// Small network-layer protocols: GRE, IGMP.
import { Layer } from '../core/packet.js';
import { u16be, u32be, ipv4, hex } from '../core/bytes.js';
import { etherTypeName } from './ethernet.js';

export const gre = {
  id: 'gre',
  name: 'Generic Routing Encapsulation',
  ipProtos: [47],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 4) return null;
    const fl = u16be(data, offset);
    const proto = u16be(data, offset + 2);
    const ver = fl & 7;
    let hlen = 4;
    const l = new Layer('gre', 'Generic Routing Encapsulation', offset, 4);
    l.label = 'GRE';
    l.add('Flags', `${fl & 0x8000 ? 'C ' : ''}${fl & 0x2000 ? 'K ' : ''}${fl & 0x1000 ? 'S ' : ''}v${ver}`.trim(), offset, 2);
    l.add('Protocol type', `${etherTypeName(proto)} (0x${hex(proto, 4)})`, offset + 2, 2);
    if (fl & 0x8000) { l.add('Checksum', `0x${hex(u16be(data, offset + hlen), 4)}`, offset + hlen, 2); hlen += 4; }
    if (fl & 0x2000) { l.add('Key', `0x${hex(u32be(data, offset + hlen), 8)}`, offset + hlen, 4); hlen += 4; }
    if (fl & 0x1000) { l.add('Sequence number', u32be(data, offset + hlen), offset + hlen, 4); hlen += 4; }
    l.length = hlen;
    l.summary = `GRE encapsulated ${etherTypeName(proto)}`;
    if (proto === 0x6558) l.next = { table: 'linkType', key: 1, offset: offset + hlen }; // transparent Ethernet bridging
    else l.next = { table: 'etherType', key: proto, offset: offset + hlen };
    return l;
  },
};

const IGMP_TYPES = { 0x11: 'Membership query', 0x12: 'Membership report v1', 0x16: 'Membership report v2', 0x17: 'Leave group', 0x22: 'Membership report v3' };

export const igmp = {
  id: 'igmp',
  name: 'Internet Group Management Protocol',
  ipProtos: [2],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 8) return null;
    const type = data[offset];
    const l = new Layer('igmp', 'Internet Group Management Protocol', offset, end - offset);
    l.label = 'IGMP';
    l.add('Type', `${IGMP_TYPES[type] || 'unknown'} (0x${hex(type)})`, offset, 1);
    l.add('Max response time', data[offset + 1], offset + 1, 1);
    l.add('Checksum', `0x${hex(u16be(data, offset + 2), 4)}`, offset + 2, 2);
    const group = ipv4(data, offset + 4);
    l.add('Group address', group, offset + 4, 4);
    l.summary = `${IGMP_TYPES[type] || 'IGMP'}${type === 0x11 && group === '0.0.0.0' ? ' (general)' : ' ' + group}`;
    return l;
  },
};
