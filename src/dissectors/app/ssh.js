// SSH: identification banner + KEXINIT parsing + HASSH fingerprints.
// One TCP segment at a time; never throws on short/fragmented framing.
import { Layer } from '../../core/packet.js';
import { latin1, u32be } from '../../core/bytes.js';
import { md5 } from '../../core/hash.js';

const MSG = { 1: 'DISCONNECT', 2: 'IGNORE', 3: 'UNIMPLEMENTED', 4: 'DEBUG', 5: 'SERVICE_REQUEST', 6: 'SERVICE_ACCEPT', 20: 'KEXINIT', 21: 'NEWKEYS', 30: 'KEXDH_INIT', 31: 'KEXDH_REPLY' };

function sshState(state) { return state.ext.ssh ||= { clients: [], servers: [], streams: {} }; }
function markProto(state, sid) { const s = state.tcp?.list?.[sid]; if (s) s.proto = 'ssh'; }

const ssh = {
  id: 'ssh',
  name: 'Secure Shell',
  tcpPorts: [22, 2222],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end } = ctx;
      if (end - offset < 4) return false;
      return data[offset] === 0x53 && data[offset + 1] === 0x53 && data[offset + 2] === 0x48 && data[offset + 3] === 0x2d; // 'SSH-'
    },
  },
  dissect(ctx) {
    const { data, offset, end, packet } = ctx;
    if (end - offset < 1) return null;
    const stream = packet.stream || { id: -1, dir: 0 };
    const sid = stream.id ?? -1, dir = stream.dir ?? 0;
    const st = sshState(ctx.state);
    const per = st.streams[sid] ||= {};
    const l = new Layer('ssh', 'Secure Shell', offset, end - offset);
    l.label = 'SSH';
    try {
      markProto(ctx.state, sid);
      const isBanner = data[offset] === 0x53 && data[offset + 1] === 0x53 && data[offset + 2] === 0x48 && data[offset + 3] === 0x2d;
      if (isBanner) {
        let nl = offset; while (nl < end && data[nl] !== 0x0a) nl++;
        let bannerEnd = nl; if (bannerEnd > offset && data[bannerEnd - 1] === 0x0d) bannerEnd--;
        const banner = latin1(data, offset, bannerEnd);
        l.banner = banner;
        const m = banner.match(/^SSH-([^-]+)-(.*)$/);
        l.protoversion = m ? m[1] : null;
        l.software = m ? m[2] : null;
        (per.sw ||= {})[dir] = l.software;
        l.add('Protocol', banner, offset, bannerEnd - offset);
        l.summary = dir === 1 ? `Server Protocol: ${banner}` : `Client: ${banner}`;
        // A KEXINIT may follow the banner in the same segment.
        const after = (nl < end) ? nl + 1 : end;
        if (end - after >= 6) tryKexinit(ctx, l, data, after, end, dir, per, st, sid);
        return l;
      }
      // Binary packet framing.
      parseBinary(ctx, l, data, offset, end, dir, per, st, sid);
      return l;
    } catch { l.summary ||= 'SSH'; return l; }
  },
};

function parseBinary(ctx, l, data, offset, end, dir, per, st, sid) {
  if (end - offset < 6) { l.summary = `Encrypted packet (len=${end - offset})`; return; }
  const pktLen = u32be(data, offset);
  if (pktLen < 2 || pktLen > 35000 || offset + 4 + pktLen > end) {
    l.summary = `Encrypted packet (len=${end - offset})`;
    l.add('Length', end - offset, offset, end - offset);
    return;
  }
  const padLen = data[offset + 4];
  const payloadStart = offset + 5;
  const payloadEnd = payloadStart + (pktLen - padLen - 1);
  if (payloadEnd > end || payloadEnd < payloadStart) { l.summary = `Encrypted packet (len=${end - offset})`; return; }
  const msg = data[payloadStart];
  l.msgCode = msg; l.msgName = MSG[msg] || `msg ${msg}`;
  if (msg === 20) {
    parseKexinit(ctx, l, data, payloadStart, payloadEnd, dir, per, st, sid);
  } else {
    l.summary = `${l.msgName} (len=${pktLen})`;
  }
}

function tryKexinit(ctx, l, data, offset, end, dir, per, st, sid) {
  try {
    if (end - offset < 6) return;
    const pktLen = u32be(data, offset);
    if (pktLen < 2 || pktLen > 35000 || offset + 4 + pktLen > end) return;
    const padLen = data[offset + 4];
    const payloadStart = offset + 5;
    const payloadEnd = payloadStart + (pktLen - padLen - 1);
    if (payloadEnd > end) return;
    if (data[payloadStart] !== 20) return;
    parseKexinit(ctx, l, data, payloadStart, payloadEnd, dir, per, st, sid);
  } catch { /* ignore trailing */ }
}

function readNameList(data, o, limit) {
  if (o + 4 > limit) return null;
  const len = u32be(data, o);
  if (o + 4 + len > limit) return null;
  return { s: latin1(data, o + 4, o + 4 + len), next: o + 4 + len };
}

function parseKexinit(ctx, l, data, payloadStart, payloadEnd, dir, per, st, sid) {
  let o = payloadStart + 1 + 16; // skip msg byte + 16-byte cookie
  const names = [];
  for (let i = 0; i < 10; i++) {
    const r = readNameList(data, o, payloadEnd);
    if (!r) break;
    names.push(r.s); o = r.next;
  }
  if (names.length < 8) { l.summary = 'Key Exchange Init'; return; }
  const kex = {
    kex: names[0], hostKey: names[1],
    ciphers: { c2s: names[2], s2c: names[3] },
    macs: { c2s: names[4], s2c: names[5] },
    compression: { c2s: names[6], s2c: names[7] },
  };
  l.kex = kex;
  const software = (per.sw && per.sw[dir]) || null;
  if (dir === 0) {
    const h = md5(`${kex.kex};${kex.ciphers.c2s};${kex.macs.c2s};${kex.compression.c2s}`);
    l.hassh = h;
    st.clients.push({ hassh: h, software, packet: ctx.packet.index });
    l.summary = `Client: Key Exchange Init (HASSH=${h})`;
  } else {
    const h = md5(`${kex.kex};${kex.ciphers.s2c};${kex.macs.s2c};${kex.compression.s2c}`);
    l.hasshServer = h;
    st.servers.push({ hasshServer: h, software, packet: ctx.packet.index });
    l.summary = `Server: Key Exchange Init (HASSHServer=${h})`;
  }
  const g = l.addGroup('Algorithms', '', -1, 0, []);
  g.children.push({ name: 'kex_algorithms', value: kex.kex, offset: -1, length: 0 });
  g.children.push({ name: 'server_host_key_algorithms', value: kex.hostKey, offset: -1, length: 0 });
  g.children.push({ name: 'ciphers c2s', value: kex.ciphers.c2s, offset: -1, length: 0 });
  g.children.push({ name: 'ciphers s2c', value: kex.ciphers.s2c, offset: -1, length: 0 });
  g.children.push({ name: 'macs c2s', value: kex.macs.c2s, offset: -1, length: 0 });
  g.children.push({ name: 'macs s2c', value: kex.macs.s2c, offset: -1, length: 0 });
}

export default [ssh];
