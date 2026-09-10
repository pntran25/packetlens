import { Layer } from '../core/packet.js';
import { u16be, hex } from '../core/bytes.js';
import { trackFlow } from './tcp.js';

export default {
  id: 'udp',
  name: 'User Datagram Protocol',
  ipProtos: [17],
  dissect(ctx) {
    const { data, offset, end, parent, state, packet } = ctx;
    if (end - offset < 8) return null;
    const sport = u16be(data, offset), dport = u16be(data, offset + 2);
    const len = u16be(data, offset + 4);
    const csum = u16be(data, offset + 6);
    const l = new Layer('udp', 'User Datagram Protocol', offset, 8);
    l.label = 'UDP';
    l.srcPort = sport; l.dstPort = dport;
    const payloadEnd = len >= 8 ? Math.min(end, offset + len) : end;
    l.payloadLen = payloadEnd - (offset + 8);
    l.payloadOffset = offset + 8;
    if (len < 8) l.error('UDP length less than 8');
    const src = parent?.src ?? '', dst = parent?.dst ?? '';
    const [s, dir] = trackFlow(state, 'udp', src, sport, dst, dport, packet);
    packet.stream = { kind: 'udp', id: s.id, dir };
    l.stream = s.id; l.dir = dir;
    s.bytes[dir] += l.payloadLen;
    if (l.payloadLen > 0) s.segs.push({ pkt: packet.index, dir, len: l.payloadLen, off: offset + 8, ts: packet.ts });
    l.add('Source port', sport, offset, 2);
    l.add('Destination port', dport, offset + 2, 2);
    l.add('Length', len, offset + 4, 2);
    l.add('Checksum', csum ? `0x${hex(csum, 4)}` : '0x0000 (none)', offset + 6, 2);
    l.add('Stream index', s.id, -1, 0);
    l.summary = `${sport} → ${dport} Len=${l.payloadLen}`;
    if (l.payloadLen > 0) l.next = { table: 'udpPort', key: [sport, dport], offset: offset + 8, end: payloadEnd };
    return l;
  },
};
