// Web Worker: reads, dissects and analyzes a capture off the main thread, then
// streams a compact packet summary table back to the UI. The full Packet objects
// stay in the worker; the UI requests detail/hex/stream for one packet at a time.

import '../dissectors/index.js';
import { readCapture } from '../core/reader.js';
import { dissectCapture } from '../core/dissect.js';
import { LINKTYPE_NAMES } from '../core/reader.js';

let PACKETS = null;   // full Packet[]
let STATE = null;
let CAPTURE = null;
let ANALYSIS = null;
let filterMod = null; // lazily imported

function post(msg, transfer) { self.postMessage(msg, transfer || []); }

async function loadAnalysis() {
  if (!ANALYSIS) ANALYSIS = await import('../analysis/index.js');
  return ANALYSIS;
}
async function loadFilter() {
  if (!filterMod) filterMod = await import('../analysis/filter.js');
  return filterMod;
}

// Compact row for the packet list: fixed fields the table needs.
function toRow(p) {
  return {
    n: p.index, ts: p.ts, rel: p.rel, delta: p.delta,
    src: p.src, dst: p.dst, proto: p.proto, len: p.origLen,
    info: p.info,
    stream: p.stream ? p.stream.id : -1,
    skind: p.stream ? p.stream.kind : '',
    tags: [...p.tags],
    err: p.errors.length > 0,
  };
}

self.onmessage = async (e) => {
  const { type, id } = e.data;
  try {
    if (type === 'load') {
      const buf = new Uint8Array(e.data.buffer);
      const t0 = performance.now();
      CAPTURE = readCapture(buf);
      post({ type: 'progress', phase: 'dissect', done: 0, total: CAPTURE.records.length });
      const res = dissectCapture(CAPTURE, (done, total) => post({ type: 'progress', phase: 'dissect', done, total }));
      PACKETS = res.packets; STATE = res.state;
      post({ type: 'progress', phase: 'analyze', done: 0, total: 1 });
      const A = await loadAnalysis();
      let analysis = null;
      try { analysis = A.analyze(PACKETS, STATE, CAPTURE); }
      catch (err) { analysis = { error: String(err && err.stack || err) }; }
      self._analysis = analysis;
      const rows = PACKETS.map(toRow);
      const t1 = performance.now();
      const meta = {
        format: CAPTURE.format,
        packetCount: PACKETS.length,
        interfaces: CAPTURE.interfaces.map(i => ({ name: i.name, link: LINKTYPE_NAMES[i.linkType] || `type ${i.linkType}`, linkType: i.linkType })),
        warnings: CAPTURE.warnings || [],
        parseMs: Math.round(t1 - t0),
        firstTs: PACKETS.length ? PACKETS[0].ts : 0,
        lastTs: PACKETS.length ? PACKETS[PACKETS.length - 1].ts : 0,
        bytes: buf.length,
      };
      post({ type: 'loaded', id, meta, rows, analysis: summarizeAnalysis(analysis) });
    } else if (type === 'detail') {
      const p = PACKETS[e.data.n - 1];
      post({ type: 'detail', id, n: e.data.n, layers: serializeLayers(p), hex: [...p.data.subarray(0, Math.min(p.data.length, 65535))], tags: [...p.tags], errors: p.errors });
    } else if (type === 'filter') {
      const F = await loadFilter();
      const c = F.compileFilter(e.data.expr);
      if (!c.ok) { post({ type: 'filter', id, ok: false, error: c.error }); return; }
      const matched = [];
      for (let i = 0; i < PACKETS.length; i++) if (c.predicate(PACKETS[i])) matched.push(PACKETS[i].index);
      post({ type: 'filter', id, ok: true, matched });
    } else if (type === 'validateFilter') {
      const F = await loadFilter();
      post({ type: 'validateFilter', id, result: F.validateFilter(e.data.expr) });
    } else if (type === 'stream') {
      const A = await loadAnalysis();
      const kind = e.data.kind, sid = e.data.sid;
      const list = kind === 'udp' ? STATE.udp.list : STATE.tcp.list;
      const stream = list[sid];
      if (!stream) { post({ type: 'stream', id, error: 'no such stream' }); return; }
      const chunks = (kind === 'udp' ? A.reassembleUdp : A.followStream)(stream, PACKETS);
      const follow = kind === 'udp'
        ? [{ dir: 0, bytes: chunks.a2b }, { dir: 1, bytes: chunks.b2a }].filter(c => c.bytes && c.bytes.length)
        : chunks;
      post({ type: 'stream', id, kind, sid, meta: streamMeta(stream), chunks: follow.map(c => ({ dir: c.dir, ts: c.ts, pkt: c.pkt, bytes: [...c.bytes] })) });
    } else if (type === 'artifact') {
      const art = self._analysis?.extraction?.files?.[e.data.idx];
      if (!art || !art.data) { post({ type: 'artifact', id, error: 'unavailable' }); return; }
      const bytes = art.data instanceof Uint8Array ? art.data : new Uint8Array(art.data);
      const copy = bytes.slice();
      post({ type: 'artifact', id, name: art.filename, mime: art.contentType, buffer: copy.buffer }, [copy.buffer]);
    } else if (type === 'exportFilter') {
      // Build a new pcap of the matched packets.
      const F = await loadFilter();
      const c = F.compileFilter(e.data.expr || '');
      const { writePcap } = await import('../core/reader.js');
      const recs = [];
      for (const p of PACKETS) if (!e.data.expr || (c.ok && c.predicate(p))) recs.push({ ts: p.ts, data: p.data, origLen: p.origLen });
      const linkType = CAPTURE.interfaces[0]?.linkType ?? 1;
      const out = writePcap(recs, linkType);
      post({ type: 'exportFilter', id, buffer: out.buffer, count: recs.length }, [out.buffer]);
    }
  } catch (err) {
    post({ type: 'error', id, message: String(err && err.stack || err) });
  }
};

function serializeLayers(p) {
  return p.layers.map(l => ({
    proto: l.proto, name: l.name, offset: l.offset, length: l.length,
    summary: l.summary, errors: l.errors,
    fields: l.fields.map(serializeField),
  }));
}
function serializeField(f) {
  const o = { name: f.name, value: fmtVal(f.value), offset: f.offset, length: f.length };
  if (f.children) o.children = f.children.map(serializeField);
  return o;
}
function fmtVal(v) {
  if (v == null) return '';
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch { return String(v); } }
  return String(v);
}

function streamMeta(s) {
  return {
    id: s.id, kind: s.kind, a: s.a, b: s.b, bytes: s.bytes, pkts: s.pkts,
    start: s.start, end: s.end, proto: s.proto, retrans: s.retrans || 0,
    packets: s.packets,
  };
}

// Trim analysis to a JSON-serializable summary (drop raw byte buffers).
function summarizeAnalysis(a) {
  if (!a || a.error) return a || null;
  const clean = (obj) => JSON.parse(JSON.stringify(obj, (k, v) => {
    if (v instanceof Uint8Array) return undefined;
    if (v instanceof Set) return [...v];
    if (v instanceof Map) return Object.fromEntries(v);
    return v;
  }));
  const out = {};
  out.summary = clean(a.summary || {});
  out.conversations = clean(a.conversations || {});
  out.iocs = clean(a.iocs || {});
  // Files: keep metadata, index for on-demand download.
  out.extraction = {
    files: (a.extraction?.files || []).map((f, i) => ({
      idx: i, filename: f.filename, contentType: f.contentType, size: f.size,
      sha256: f.sha256, fileType: f.fileType, host: f.host, uri: f.uri,
      statusCode: f.statusCode, source: f.source, stream: f.stream, packet: f.packet,
      truncated: f.truncated, executable: f.executable,
    })),
    emails: clean(a.extraction?.emails || []),
    smbFiles: clean(a.extraction?.smbFiles || []),
    totalBytes: a.extraction?.totalBytes || 0,
  };
  return out;
}
