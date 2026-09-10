// TCP/UDP stream reassembly, run on demand after dissection.
//
// A stream record (state.tcp.list[id] / state.udp.list[id]) carries `segs`, one
// entry per payload-bearing segment: { pkt, dir, seq?, len, off, ts, retrans? }.
// `off` is the byte offset of the payload within that packet's raw bytes, so the
// bytes are packets[pkt-1].data.subarray(off, off+len).

import { concat } from '../core/bytes.js';

export const MAX_REASSEMBLY = 8 * 1024 * 1024; // ~8MB cap per stream (both dirs)

function segBytes(seg, packets) {
  const p = packets[seg.pkt - 1];
  if (!p || !p.data) return new Uint8Array(0);
  const end = Math.min(seg.off + seg.len, p.data.length);
  return p.data.subarray(seg.off, end);
}

/**
 * Rebuild both directions of a TCP stream in sequence order, dropping pure
 * retransmissions / overlaps and recording gaps for missing ranges.
 * @returns {{a2b:Uint8Array,b2a:Uint8Array,gaps:Array,segmentsUsed:number,follow:Array,truncated:boolean}}
 */
export function reassembleTcp(stream, packets) {
  const gaps = [];
  const follow = [];
  let segmentsUsed = 0;
  let truncated = false;
  let budget = MAX_REASSEMBLY;

  const build = (dir) => {
    const segs = (stream.segs || []).filter((s) => s.dir === dir && s.len > 0);
    // Sequence order; on ties keep the earlier arrival (packet index) first.
    segs.sort((a, b) => (a.seq - b.seq) || (a.pkt - b.pkt));
    const chunks = [];
    let outLen = 0;
    let expected = segs.length ? segs[0].seq : 0;
    for (const seg of segs) {
      const segEnd = seg.seq + seg.len;
      if (segEnd <= expected) continue; // fully retransmitted / overlapped
      let trim = expected - seg.seq;
      if (trim < 0) {
        // Gap: bytes [expected, seg.seq) were never captured.
        gaps.push({ dir, at: outLen, len: seg.seq - expected });
        expected = seg.seq;
        trim = 0;
      }
      let bytes = segBytes(seg, packets);
      if (trim > 0) bytes = bytes.subarray(trim);
      if (bytes.length === 0) { expected = segEnd; continue; }
      if (budget <= 0) { truncated = true; break; }
      if (bytes.length > budget) { bytes = bytes.subarray(0, budget); truncated = true; }
      budget -= bytes.length;
      chunks.push(bytes);
      follow.push({ dir, ts: seg.ts, offset: outLen, len: bytes.length, pkt: seg.pkt });
      outLen += bytes.length;
      expected = segEnd;
      segmentsUsed++;
    }
    return concat(chunks);
  };

  const a2b = build(0);
  const b2a = build(1);
  follow.sort((x, y) => (x.ts - y.ts) || (x.pkt - y.pkt));
  return { a2b, b2a, gaps, segmentsUsed, follow, truncated };
}

/**
 * Wire-order chunks for the "Follow TCP Stream" UI: client and server bytes
 * interleaved by timestamp. Pure retransmissions are dropped.
 * @returns {Array<{dir:number, ts:number, pkt:number, bytes:Uint8Array}>}
 */
export function followStream(stream, packets) {
  const segs = (stream.segs || []).filter((s) => s.len > 0 && !s.retrans);
  segs.sort((a, b) => (a.ts - b.ts) || (a.pkt - b.pkt));
  const out = [];
  let budget = MAX_REASSEMBLY;
  for (const seg of segs) {
    if (budget <= 0) break;
    let bytes = segBytes(seg, packets);
    if (bytes.length === 0) continue;
    if (bytes.length > budget) bytes = bytes.subarray(0, budget);
    budget -= bytes.length;
    out.push({ dir: seg.dir, ts: seg.ts, pkt: seg.pkt, bytes });
  }
  return out;
}

/**
 * Reassemble a UDP "stream" by concatenating datagrams per direction (order of
 * arrival). UDP segs have no seq; ordering is by timestamp/packet.
 */
export function reassembleUdp(stream, packets) {
  const follow = [];
  let segmentsUsed = 0;
  let budget = MAX_REASSEMBLY;
  let truncated = false;

  const build = (dir) => {
    const segs = (stream.segs || []).filter((s) => s.dir === dir && s.len > 0);
    segs.sort((a, b) => (a.ts - b.ts) || (a.pkt - b.pkt));
    const chunks = [];
    let outLen = 0;
    for (const seg of segs) {
      if (budget <= 0) { truncated = true; break; }
      let bytes = segBytes(seg, packets);
      if (bytes.length === 0) continue;
      if (bytes.length > budget) { bytes = bytes.subarray(0, budget); truncated = true; }
      budget -= bytes.length;
      chunks.push(bytes);
      follow.push({ dir, ts: seg.ts, offset: outLen, len: bytes.length, pkt: seg.pkt });
      outLen += bytes.length;
      segmentsUsed++;
    }
    return concat(chunks);
  };

  const a2b = build(0);
  const b2a = build(1);
  follow.sort((x, y) => (x.ts - y.ts) || (x.pkt - y.pkt));
  return { a2b, b2a, follow, segmentsUsed, truncated };
}
