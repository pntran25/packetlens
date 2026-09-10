import { Layer } from '../core/packet.js';
import { u16be, u32be, hex } from '../core/bytes.js';

export const TCP_FLAGS = [
  [0x001, 'FIN'], [0x002, 'SYN'], [0x004, 'RST'], [0x008, 'PSH'], [0x010, 'ACK'], [0x020, 'URG'], [0x040, 'ECE'], [0x080, 'CWR'], [0x100, 'NS'],
];

export function flagNames(f) {
  const out = [];
  for (const [bit, name] of TCP_FLAGS) if (f & bit) out.push(name);
  return out;
}

export function streamKey(ipA, portA, ipB, portB) {
  const ea = `${ipA}:${portA}`, eb = `${ipB}:${portB}`;
  return ea < eb ? `${ea}|${eb}` : `${eb}|${ea}`;
}

/** Get or create a flow record in state.<kind>.streams. Returns [stream, dir] where dir 0 = a→b. */
export function trackFlow(state, kind, src, sport, dst, dport, pkt) {
  const table = state[kind];
  const key = streamKey(src, sport, dst, dport);
  let s = table.streams.get(key);
  if (!s) {
    s = {
      id: table.list.length, kind, key,
      a: { ip: src, port: sport }, b: { ip: dst, port: dport },
      packets: [], segs: [],
      bytes: [0, 0], pkts: [0, 0],
      start: pkt.ts, end: pkt.ts,
      isn: [null, null], nextSeq: [null, null], maxSeq: [null, null],
      synSeen: false, synAckSeen: false, fin: [false, false], rst: false,
      retrans: 0, ooo: 0,
      proto: null, // application protocol label, set by app dissectors/analysis
      tags: new Set(),
    };
    table.streams.set(key, s);
    table.list.push(s);
  }
  const dir = (src === s.a.ip && sport === s.a.port) ? 0 : 1;
  s.packets.push(pkt.index);
  s.pkts[dir]++;
  s.end = pkt.ts;
  return [s, dir];
}

const OPT_NAMES = { 0: 'End of option list', 1: 'No-operation', 2: 'Maximum segment size', 3: 'Window scale', 4: 'SACK permitted', 5: 'SACK', 8: 'Timestamps', 28: 'User timeout', 29: 'TCP-AO', 30: 'Multipath TCP', 34: 'TCP Fast Open' };

export default {
  id: 'tcp',
  name: 'Transmission Control Protocol',
  ipProtos: [6],
  dissect(ctx) {
    const { data, offset, end, parent, state, packet } = ctx;
    if (end - offset < 20) return null;
    const sport = u16be(data, offset), dport = u16be(data, offset + 2);
    const seq = u32be(data, offset + 4), ack = u32be(data, offset + 8);
    const doff = (data[offset + 12] >> 4) * 4;
    const flags = ((data[offset + 12] & 1) << 8) | data[offset + 13];
    const win = u16be(data, offset + 14);
    const csum = u16be(data, offset + 16);
    const urg = u16be(data, offset + 18);
    if (doff < 20) return null;
    const hdrEnd = Math.min(offset + doff, end);
    const payloadLen = Math.max(0, end - (offset + doff));

    const l = new Layer('tcp', 'Transmission Control Protocol', offset, doff);
    l.label = 'TCP';
    l.srcPort = sport; l.dstPort = dport; l.seq = seq; l.ack = ack; l.flags = flags; l.window = win; l.payloadLen = payloadLen;
    l.payloadOffset = offset + doff;
    l.flagNames = flagNames(flags);

    // Flow tracking (needs IP parent).
    const src = parent?.src ?? '', dst = parent?.dst ?? '';
    const [s, dir] = trackFlow(state, 'tcp', src, sport, dst, dport, packet);
    packet.stream = { kind: 'tcp', id: s.id, dir };
    l.stream = s.id; l.dir = dir;
    if (flags & 0x02) {
      if (flags & 0x10) s.synAckSeen = true;
      else { s.synSeen = true; if (dir === 1) { /* SYN from b: swap so initiator is a */ const t = s.a; s.a = s.b; s.b = t; s.bytes.reverse(); s.pkts.reverse(); s.isn.reverse(); s.nextSeq.reverse(); s.maxSeq.reverse(); s.fin.reverse(); for (const g of s.segs) g.dir ^= 1; } }
    }
    const d2 = (src === s.a.ip && sport === s.a.port) ? 0 : 1; // recompute after possible swap
    l.dir = d2; packet.stream.dir = d2;
    if (s.isn[d2] === null) s.isn[d2] = seq;
    const relSeq = (seq - s.isn[d2]) >>> 0;
    const otherIsn = s.isn[d2 ^ 1];
    const relAck = otherIsn === null ? ack : (ack - otherIsn) >>> 0;
    l.relSeq = relSeq; l.relAck = relAck;

    // Retransmission / out-of-order heuristics (relative sequence space).
    const analysis = [];
    if (payloadLen > 0 || (flags & 0x03)) {
      const segLen = payloadLen + ((flags & 0x02) ? 1 : 0) + ((flags & 0x01) ? 1 : 0);
      const nextExpected = s.nextSeq[d2];
      if (nextExpected !== null) {
        const diff = (relSeq - nextExpected) | 0;
        if (diff < 0 && payloadLen > 0) {
          analysis.push('Retransmission');
          s.retrans++;
          packet.tags.add('retransmission');
        } else if (diff > 0 && payloadLen > 0) {
          analysis.push('Previous segment not captured / out-of-order');
          s.ooo++;
          packet.tags.add('out-of-order');
        }
      }
      if (nextExpected === null || ((relSeq + segLen) | 0) > nextExpected || diffWrap(relSeq + segLen, nextExpected) > 0) {
        s.nextSeq[d2] = (relSeq + segLen) >>> 0;
      }
    }
    if (flags & 0x04) { s.rst = true; packet.tags.add('rst'); }
    if (flags & 0x01) s.fin[d2] = true;
    if (win === 0 && !(flags & 0x04)) { analysis.push('Zero window'); packet.tags.add('zero-window'); }
    s.bytes[d2] += payloadLen;
    if (payloadLen > 0) {
      s.segs.push({ pkt: packet.index, dir: d2, seq: relSeq, len: payloadLen, off: offset + doff, ts: packet.ts, retrans: packet.tags.has('retransmission') });
    }

    l.add('Source port', sport, offset, 2);
    l.add('Destination port', dport, offset + 2, 2);
    l.add('Stream index', s.id, -1, 0);
    l.add('Sequence number', `${relSeq} (relative)  raw: ${seq}`, offset + 4, 4);
    if (flags & 0x10) l.add('Acknowledgment number', `${relAck} (relative)  raw: ${ack}`, offset + 8, 4);
    l.add('Header length', `${doff} bytes`, offset + 12, 1);
    l.add('Flags', `0x${hex(flags, 3)} (${l.flagNames.join(', ') || 'none'})`, offset + 12, 2);
    l.add('Window', win, offset + 14, 2);
    l.add('Checksum', `0x${hex(csum, 4)}`, offset + 16, 2);
    if (flags & 0x20) l.add('Urgent pointer', urg, offset + 18, 2);

    if (doff > 20) {
      const g = l.addGroup('Options', `${doff - 20} bytes`, offset + 20, doff - 20, []);
      let o = offset + 20;
      l.options = {};
      while (o < hdrEnd) {
        const k = data[o];
        if (k === 0) { g.children.push({ name: OPT_NAMES[0], value: '', offset: o, length: 1 }); break; }
        if (k === 1) { g.children.push({ name: OPT_NAMES[1], value: '', offset: o, length: 1 }); o++; continue; }
        const len = data[o + 1];
        if (!len || o + len > hdrEnd) { l.error('Malformed TCP option'); break; }
        let val = `${len} bytes`;
        if (k === 2 && len === 4) { val = u16be(data, o + 2); l.options.mss = val; }
        else if (k === 3 && len === 3) { val = `${data[o + 2]} (multiply by ${1 << data[o + 2]})`; l.options.wscale = data[o + 2]; }
        else if (k === 4) { val = ''; l.options.sackOk = true; }
        else if (k === 5) { const blocks = []; for (let p = o + 2; p + 8 <= o + len; p += 8) blocks.push(`${u32be(data, p)}-${u32be(data, p + 4)}`); val = blocks.join(' '); }
        else if (k === 8 && len === 10) { val = `TSval ${u32be(data, o + 2)}, TSecr ${u32be(data, o + 6)}`; l.options.ts = [u32be(data, o + 2), u32be(data, o + 6)]; }
        g.children.push({ name: OPT_NAMES[k] || `Option ${k}`, value: val, offset: o, length: len });
        o += len;
      }
    }
    if (analysis.length) l.addGroup('Analysis', analysis.join('; '), -1, 0, analysis.map(a => ({ name: a, value: '', offset: -1, length: 0 })));
    l.analysis = analysis;

    let summary = `${sport} → ${dport} [${l.flagNames.join(', ')}] Seq=${relSeq}`;
    if (flags & 0x10) summary += ` Ack=${relAck}`;
    summary += ` Win=${win} Len=${payloadLen}`;
    if (l.options?.mss) summary += ` MSS=${l.options.mss}`;
    if (analysis.length) summary = `[${analysis[0]}] ` + summary;
    l.summary = summary;

    if (payloadLen > 0) l.next = { table: 'tcpPort', key: [sport, dport], offset: offset + doff, end };
    return l;
  },
};

function diffWrap(a, b) { return ((a - b) | 0); }
