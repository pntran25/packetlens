// Public entry point for the post-dissection analysis engine.
//
// `analyze(packets, state, capture)` runs every pass and returns a single result
// object. Stream reassembly is exported for on-demand use by the UI (the follow
// view and file carving), but is not run eagerly here except where extraction
// needs HTTP bodies.

import { reassembleTcp, reassembleUdp, followStream } from './streams.js';
import { buildConversations } from './conversations.js';
import { extractArtifacts } from './extract.js';
import { collectIocs } from './iocs.js';

/** Build a Wireshark-style protocol hierarchy tree by walking each packet's layers. */
export function protocolHierarchy(packets) {
  const root = { packets: 0, bytes: 0, children: {} };
  for (const p of packets) {
    if (!p) continue;
    const bytes = p.origLen || p.capLen || 0;
    root.packets++; root.bytes += bytes;
    let node = root;
    for (const l of p.layers) {
      let child = node.children[l.proto];
      if (!child) { child = { packets: 0, bytes: 0, children: {} }; node.children[l.proto] = child; }
      child.packets++; child.bytes += bytes;
      node = child;
    }
  }
  return root;
}

/**
 * Run all analysis passes over a dissected capture.
 * @param {Array} packets  dissectCapture(...).packets
 * @param {object} state   dissectCapture(...).state
 * @param {object} capture the raw capture (optional)
 */
export function analyze(packets, state, capture) {
  const conversations = buildConversations(packets, state);
  const extraction = extractArtifacts(packets, state, capture);
  const iocs = collectIocs(packets, state, conversations, extraction);

  let first = Infinity, last = -Infinity, bytes = 0;
  for (const p of packets) {
    if (!p) continue;
    if (p.ts < first) first = p.ts;
    if (p.ts > last) last = p.ts;
    bytes += p.origLen || p.capLen || 0;
  }
  const summary = {
    packetCount: packets.length,
    duration: first === Infinity ? 0 : last - first,
    bytes,
    protocolHierarchy: protocolHierarchy(packets),
  };

  return {
    conversations,
    extraction,
    iocs,
    summary,
    // On-demand reassembly helpers, bound so callers can pass just a stream.
    reassembleTcp: (stream) => reassembleTcp(stream, packets),
    reassembleUdp: (stream) => reassembleUdp(stream, packets),
    followStream: (stream) => followStream(stream, packets),
  };
}

export { reassembleTcp, reassembleUdp, followStream } from './streams.js';
export { buildConversations } from './conversations.js';
export { extractArtifacts } from './extract.js';
export { collectIocs } from './iocs.js';
