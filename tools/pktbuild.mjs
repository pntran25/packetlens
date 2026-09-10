// Tiny packet builder for fixtures and tests. Produces raw Ethernet frames with
// correct IPv4/TCP/UDP/ICMP checksums.
import { inetChecksum, concat } from '../src/core/bytes.js';
export { writePcap } from '../src/core/reader.js';

const te = new TextEncoder();
export const str = (s) => te.encode(s);
export const hexBytes = (h) => new Uint8Array(h.replace(/[^0-9a-f]/gi, '').match(/../g).map(x => parseInt(x, 16)));

export function parseMac(m) { return new Uint8Array(m.split(':').map(x => parseInt(x, 16))); }
export function parseIp4(ip) { return new Uint8Array(ip.split('.').map(Number)); }
export function parseIp6(ip) {
  const out = new Uint8Array(16);
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t];
  groups.forEach((g, i) => { const v = parseInt(g, 16); out[i * 2] = v >> 8; out[i * 2 + 1] = v & 0xff; });
  return out;
}

function be16(v) { return [(v >> 8) & 0xff, v & 0xff]; }
function be32(v) { return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]; }

export function eth({ src = '00:11:22:33:44:55', dst = '66:77:88:99:aa:bb', type = 0x0800, payload }) {
  const hdr = new Uint8Array(14);
  hdr.set(parseMac(dst), 0); hdr.set(parseMac(src), 6); hdr.set(be16(type), 12);
  return concat([hdr, payload]);
}

export function vlan({ id = 1, type = 0x0800, payload }) {
  return concat([new Uint8Array([...be16(id & 0xfff), ...be16(type)]), payload]);
}

export function ip4({ src, dst, proto, ttl = 64, id = 0x1234, flags = 2, fragOff = 0, tos = 0, payload, options = new Uint8Array(0) }) {
  const ihl = 20 + options.length;
  const hdr = new Uint8Array(ihl);
  hdr[0] = 0x40 | (ihl / 4); hdr[1] = tos;
  hdr.set(be16(ihl + payload.length), 2);
  hdr.set(be16(id), 4);
  hdr.set(be16((flags << 13) | (fragOff / 8)), 6);
  hdr[8] = ttl; hdr[9] = proto;
  hdr.set(parseIp4(src), 12); hdr.set(parseIp4(dst), 16);
  hdr.set(options, 20);
  const cs = inetChecksum(hdr, 0, ihl);
  hdr.set(be16(cs), 10);
  return concat([hdr, payload]);
}

export function ip6({ src, dst, nextHeader, hop = 64, payload }) {
  const hdr = new Uint8Array(40);
  hdr[0] = 0x60;
  hdr.set(be16(payload.length), 4);
  hdr[6] = nextHeader; hdr[7] = hop;
  hdr.set(parseIp6(src), 8); hdr.set(parseIp6(dst), 24);
  return concat([hdr, payload]);
}

function pseudoSum4(src, dst, proto, len) {
  const p = new Uint8Array(12);
  p.set(parseIp4(src), 0); p.set(parseIp4(dst), 4); p[9] = proto; p.set(be16(len), 10);
  let sum = 0;
  for (let i = 0; i < 12; i += 2) sum += (p[i] << 8) | p[i + 1];
  return sum;
}

export function tcp({ src, dst, sport, dport, seq = 0, ack = 0, flags = 0x10, win = 65535, payload = new Uint8Array(0), options = new Uint8Array(0) }) {
  const optLen = (options.length + 3) & ~3;
  const doff = 20 + optLen;
  const hdr = new Uint8Array(doff);
  hdr.set(be16(sport), 0); hdr.set(be16(dport), 2);
  hdr.set(be32(seq), 4); hdr.set(be32(ack), 8);
  hdr[12] = (doff / 4) << 4; hdr[13] = flags & 0xff;
  hdr.set(be16(win), 14);
  hdr.set(options, 20);
  const seg = concat([hdr, payload]);
  const cs = inetChecksum(seg, 0, seg.length, pseudoSum4(src, dst, 6, seg.length));
  seg.set(be16(cs), 16);
  return seg;
}

export function udp({ src, dst, sport, dport, payload }) {
  const hdr = new Uint8Array(8);
  hdr.set(be16(sport), 0); hdr.set(be16(dport), 2); hdr.set(be16(8 + payload.length), 4);
  const dg = concat([hdr, payload]);
  let cs = inetChecksum(dg, 0, dg.length, pseudoSum4(src, dst, 17, dg.length));
  if (cs === 0) cs = 0xffff;
  dg.set(be16(cs), 6);
  return dg;
}

export function icmp({ type = 8, code = 0, id = 1, seq = 1, payload = str('abcdefghijklmnopqrstuvwabcdefghi') }) {
  const hdr = new Uint8Array(8);
  hdr[0] = type; hdr[1] = code; hdr.set(be16(id), 4); hdr.set(be16(seq), 6);
  const m = concat([hdr, payload]);
  m.set(be16(inetChecksum(m, 0, m.length)), 2);
  return m;
}

export function arp({ op = 1, senderMac, senderIp, targetMac = '00:00:00:00:00:00', targetIp }) {
  return new Uint8Array([0, 1, 8, 0, 6, 4, ...be16(op), ...parseMac(senderMac), ...parseIp4(senderIp), ...parseMac(targetMac), ...parseIp4(targetIp)]);
}

/** Build an IPv4/TCP frame in one call. */
export function tcpFrame(o) {
  const seg = tcp(o);
  return eth({ src: o.srcMac, dst: o.dstMac, payload: ip4({ src: o.src, dst: o.dst, proto: 6, ttl: o.ttl, id: o.id, payload: seg }) });
}
export function udpFrame(o) {
  const dg = udp(o);
  return eth({ src: o.srcMac, dst: o.dstMac, payload: ip4({ src: o.src, dst: o.dst, proto: 17, ttl: o.ttl, id: o.id, payload: dg }) });
}
export function icmpFrame(o) {
  return eth({ src: o.srcMac, dst: o.dstMac, payload: ip4({ src: o.src, dst: o.dst, proto: 1, ttl: o.ttl, payload: icmp(o) }) });
}

/**
 * Build a complete TCP session: handshake, data exchanges, FIN teardown.
 * exchanges: array of [dir, bytes] where dir is 'c' (client→server) or 's'.
 * Large payloads are split into MSS-sized segments.
 * Returns array of { ts, data } records.
 */
export function tcpSession({ client, server, cport = 49152, sport, t0 = 1700000000, dt = 0.001, exchanges, mss = 1460, clientMac = '00:0c:29:aa:bb:cc', serverMac = '00:50:56:11:22:33', teardown = true, cseq0 = 1000, sseq0 = 5000 }) {
  const recs = [];
  let t = t0;
  let cseq = cseq0, sseq = sseq0;
  const push = (data) => { recs.push({ ts: t, data }); t += dt; };
  const c2s = (o) => tcpFrame({ src: client, dst: server, sport: cport, dport: sport, srcMac: clientMac, dstMac: serverMac, ...o });
  const s2c = (o) => tcpFrame({ src: server, dst: client, sport, dport: cport, srcMac: serverMac, dstMac: clientMac, ...o });
  const synOpts = new Uint8Array([2, 4, ...be16(mss), 4, 2, 1, 3, 3, 7]);
  push(c2s({ seq: cseq, flags: 0x02, options: synOpts })); cseq++;
  push(s2c({ seq: sseq, ack: cseq, flags: 0x12, options: synOpts })); sseq++;
  push(c2s({ seq: cseq, ack: sseq, flags: 0x10 }));
  for (const [dir, bytes] of exchanges) {
    const data = typeof bytes === 'string' ? str(bytes) : bytes;
    for (let off = 0; off < data.length; off += mss) {
      const chunk = data.subarray(off, Math.min(off + mss, data.length));
      const last = off + chunk.length >= data.length;
      if (dir === 'c') {
        push(c2s({ seq: cseq, ack: sseq, flags: last ? 0x18 : 0x10, payload: chunk })); cseq += chunk.length;
        push(s2c({ seq: sseq, ack: cseq, flags: 0x10 }));
      } else {
        push(s2c({ seq: sseq, ack: cseq, flags: last ? 0x18 : 0x10, payload: chunk })); sseq += chunk.length;
        push(c2s({ seq: cseq, ack: sseq, flags: 0x10 }));
      }
    }
  }
  if (teardown) {
    push(c2s({ seq: cseq, ack: sseq, flags: 0x11 })); cseq++;
    push(s2c({ seq: sseq, ack: cseq, flags: 0x11 })); sseq++;
    push(c2s({ seq: cseq, ack: sseq, flags: 0x10 }));
  }
  return recs;
}

/** Build a UDP request/response pair (or more) as records. */
export function udpExchange({ client, server, cport = 50000, sport, t0 = 1700000000, dt = 0.001, exchanges, clientMac = '00:0c:29:aa:bb:cc', serverMac = '00:50:56:11:22:33' }) {
  const recs = [];
  let t = t0;
  for (const [dir, bytes] of exchanges) {
    const payload = typeof bytes === 'string' ? str(bytes) : bytes;
    const data = dir === 'c'
      ? udpFrame({ src: client, dst: server, sport: cport, dport: sport, srcMac: clientMac, dstMac: serverMac, payload })
      : udpFrame({ src: server, dst: client, sport, dport: cport, srcMac: serverMac, dstMac: clientMac, payload });
    recs.push({ ts: t, data }); t += dt;
  }
  return recs;
}

/** DNS message builder (queries and simple A/AAAA/CNAME answers). */
export function dnsName(name) {
  const parts = name.replace(/\.$/, '').split('.').filter(Boolean);
  const out = [];
  for (const p of parts) { const b = str(p); out.push(b.length, ...b); }
  out.push(0);
  return new Uint8Array(out);
}
export function dnsMessage({ id = 0x1234, flags = 0x0100, questions = [], answers = [] }) {
  const parts = [new Uint8Array([...be16(id), ...be16(flags), ...be16(questions.length), ...be16(answers.length), 0, 0, 0, 0])];
  for (const q of questions) parts.push(dnsName(q.name), new Uint8Array([...be16(q.type ?? 1), ...be16(q.cls ?? 1)]));
  for (const a of answers) {
    let rdata;
    if (a.type === 1) rdata = parseIp4(a.data);
    else if (a.type === 28) rdata = parseIp6(a.data);
    else if (a.type === 5 || a.type === 2 || a.type === 12) rdata = dnsName(a.data);
    else if (a.type === 16) { const b = str(a.data); rdata = new Uint8Array([b.length, ...b]); }
    else if (a.type === 15) { const b = dnsName(a.data); rdata = new Uint8Array([...be16(a.pref ?? 10), ...b]); }
    else rdata = a.data;
    parts.push(dnsName(a.name), new Uint8Array([...be16(a.type), ...be16(a.cls ?? 1), ...be32(a.ttl ?? 300), ...be16(rdata.length)]), rdata);
  }
  return concat(parts);
}
