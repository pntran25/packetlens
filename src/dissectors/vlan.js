import { Layer } from '../core/packet.js';
import { u16be, hex } from '../core/bytes.js';
import { etherTypeName } from './ethernet.js';

export default {
  id: 'vlan',
  name: '802.1Q Virtual LAN',
  etherTypes: [0x8100, 0x88a8, 0x9100],
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 4) return null;
    const tci = u16be(data, offset);
    const type = u16be(data, offset + 2);
    const l = new Layer('vlan', '802.1Q Virtual LAN', offset, 4);
    l.label = 'VLAN';
    l.id = tci & 0x0fff;
    l.priority = tci >> 13;
    l.dei = (tci >> 12) & 1;
    l.add('Priority', l.priority, offset, 2);
    l.add('DEI', l.dei, offset, 2);
    l.add('VLAN ID', l.id, offset, 2);
    l.add('Type', `${etherTypeName(type)} (0x${hex(type, 4)})`, offset + 2, 2);
    l.summary = `VLAN ${l.id}, type ${etherTypeName(type)}`;
    l.next = { table: 'etherType', key: type, offset: offset + 4 };
    return l;
  },
};
