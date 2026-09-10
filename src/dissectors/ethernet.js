import { Layer } from '../core/packet.js';
import { mac, u16be, hex } from '../core/bytes.js';

export const ETHERTYPE_NAMES = {
  0x0800: 'IPv4', 0x0806: 'ARP', 0x8035: 'RARP', 0x86dd: 'IPv6', 0x8100: '802.1Q VLAN', 0x88a8: '802.1ad QinQ',
  0x8847: 'MPLS unicast', 0x8848: 'MPLS multicast', 0x888e: '802.1X EAPOL', 0x88cc: 'LLDP', 0x8863: 'PPPoE Discovery',
  0x8864: 'PPPoE Session', 0x9000: 'Loopback', 0x88e5: 'MACsec', 0x8809: 'Slow Protocols (LACP)', 0x8902: 'CFM',
};

export function etherTypeName(t) {
  return ETHERTYPE_NAMES[t] || `0x${hex(t, 4)}`;
}

export function macKind(d, o) {
  if (d[o] === 0xff && d[o + 1] === 0xff && d[o + 2] === 0xff && d[o + 3] === 0xff && d[o + 4] === 0xff && d[o + 5] === 0xff) return 'broadcast';
  if (d[o] & 1) return 'multicast';
  if (d[o] & 2) return 'locally administered';
  return 'unicast';
}

export default {
  id: 'eth',
  name: 'Ethernet II',
  linkTypes: [1],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 14) return null;
    const l = new Layer('eth', 'Ethernet II', offset, end - offset);
    l.label = 'ETH';
    l.dst = mac(data, offset);
    l.src = mac(data, offset + 6);
    let type = u16be(data, offset + 12);
    l.add('Destination', `${l.dst} (${macKind(data, offset)})`, offset, 6);
    l.add('Source', `${l.src} (${macKind(data, offset + 6)})`, offset + 6, 6);
    let hdr = 14;
    if (type <= 1500) {
      // IEEE 802.3 length field followed by LLC/SNAP
      l.name = 'IEEE 802.3 Ethernet';
      l.add('Length', type, offset + 12, 2);
      l.summary = `802.3 frame, length ${type}`;
      const dsap = data[offset + 14], ssap = data[offset + 15];
      if (dsap === 0xaa && ssap === 0xaa && end - offset >= 22) {
        type = u16be(data, offset + 20);
        l.add('LLC/SNAP', `DSAP 0x${hex(dsap)} SSAP 0x${hex(ssap)} type ${etherTypeName(type)}`, offset + 14, 8);
        hdr = 22;
      } else {
        l.add('LLC', `DSAP 0x${hex(dsap)} SSAP 0x${hex(ssap)}`, offset + 14, 3);
        if (dsap === 0x42) l.summary = 'Spanning Tree Protocol (LLC)';
        l.type = 0;
        return l;
      }
    } else {
      l.add('Type', `${etherTypeName(type)} (0x${hex(type, 4)})`, offset + 12, 2);
      l.summary = `${l.src} → ${l.dst}, type ${etherTypeName(type)}`;
    }
    l.type = type;
    l.length = hdr;
    l.next = { table: 'etherType', key: type, offset: offset + hdr };
    return l;
  },
};
