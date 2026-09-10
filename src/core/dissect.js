// Dissection pipeline: walks a packet from the link layer up, picking dissectors
// from the registry and chaining through Layer.next.

import { Packet, Layer } from './packet.js';
import { lookup, heuristics } from './registry.js';

export function createState(capture) {
  return {
    capture,
    tcp: { streams: new Map(), list: [] },
    udp: { streams: new Map(), list: [] },
    dns: { pending: new Map(), answers: new Map(), names: new Map() }, // names: ip -> Set(hostnames)
    hosts: capture?.nameResolution?.ipv4 || new Map(),
    ext: {}, // free-form per-dissector state
  };
}

/** Dissect a whole capture. Returns { packets, state }. Optionally reports progress. */
export function dissectCapture(capture, onProgress) {
  const state = createState(capture);
  const packets = new Array(capture.records.length);
  let first = null, prevTs = null;
  const n = capture.records.length;
  for (let i = 0; i < n; i++) {
    const rec = capture.records[i];
    const pkt = new Packet(rec, i + 1);
    if (first === null) first = pkt.ts;
    pkt.rel = pkt.ts - first;
    pkt.delta = prevTs === null ? 0 : pkt.ts - prevTs;
    prevTs = pkt.ts;
    const iface = capture.interfaces[rec.iface] || capture.interfaces[0];
    dissectPacket(pkt, iface, state);
    packets[i] = pkt;
    if (onProgress && (i & 4095) === 4095) onProgress(i + 1, n);
  }
  return { packets, state };
}

export function dissectPacket(pkt, iface, state) {
  const data = pkt.data;
  let table = 'linkType', key = iface.linkType, offset = 0, end = data.length, parent = null;
  if (iface.fcsLen && end - iface.fcsLen > 0) end -= iface.fcsLen;
  for (let depth = 0; depth < 32; depth++) {
    const candidates = pickCandidates(table, key);
    let layer = null;
    const ctx = { data, offset, end, packet: pkt, parent, state, key };
    for (const dis of candidates) {
      try {
        if (dis._heur && !dis._heur(ctx)) continue;
        layer = dis.dissect(ctx);
      } catch (e) {
        pkt.errors.push(`${dis.id}: ${e.message}`);
        layer = null;
      }
      if (layer) break;
    }
    if (!layer) {
      if (offset < end) pkt.layers.push(dataLayer(data, offset, end));
      break;
    }
    if (layer.errors.length) for (const e of layer.errors) pkt.errors.push(`${layer.proto}: ${e}`);
    pkt.layers.push(layer);
    const nx = layer.next;
    if (!nx) break;
    const nEnd = Math.min(nx.end ?? end, data.length);
    if (nx.offset >= nEnd) break;
    table = nx.table; key = nx.key; offset = nx.offset; end = nEnd; parent = layer;
  }
  finalize(pkt);
  return pkt;
}

function pickCandidates(table, key) {
  if (table === 'tcpPort' || table === 'udpPort') {
    const kind = table === 'tcpPort' ? 'tcp' : 'udp';
    const [sp, dp] = key;
    const out = [];
    const a = lookup(table, dp), b = lookup(table, sp);
    if (a) out.push(a);
    if (b && b !== a) out.push(b);
    for (const h of heuristics[kind]) {
      if (out.includes(h)) continue;
      // Wrap so the heuristic check runs before dissect.
      out.push({ id: h.id, dissect: h.dissect, _heur: h.heuristic[kind] });
    }
    return out;
  }
  const d = lookup(table, key);
  return d ? [d] : [];
}

export function dataLayer(data, offset, end) {
  const l = new Layer('data', 'Data', offset, end - offset);
  l.payload = data.subarray(offset, end);
  l.add('Data', `${end - offset} bytes`, offset, end - offset);
  l.summary = `Len=${end - offset}`;
  return l;
}

function finalize(pkt) {
  const ip = pkt.layer('ipv4') || pkt.layer('ipv6');
  const eth = pkt.layer('eth');
  if (ip) { pkt.src = ip.src; pkt.dst = ip.dst; }
  else if (eth) { pkt.src = eth.src; pkt.dst = eth.dst; }
  else {
    const arp = pkt.layer('arp');
    if (arp) { pkt.src = arp.senderIp; pkt.dst = arp.targetIp; }
  }
  // Highest non-data layer gives the protocol label and Info column.
  let top = null;
  for (let i = pkt.layers.length - 1; i >= 0; i--) {
    if (pkt.layers[i].proto !== 'data') { top = pkt.layers[i]; break; }
  }
  if (top) {
    pkt.proto = top.label || top.proto.toUpperCase();
    pkt.info = top.summary || top.name;
  } else if (pkt.layers.length) {
    pkt.proto = 'DATA';
    pkt.info = pkt.layers[0].summary;
  }
  if (pkt.errors.length) pkt.tags.add('malformed');
}
