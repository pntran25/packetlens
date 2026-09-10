// pcap and pcapng file readers.
//
// readCapture(bytes) -> {
//   format: 'pcap' | 'pcapng',
//   interfaces: [{ linkType, name, snapLen, tsResolution }],
//   records: [{ ts (seconds, float), capLen, origLen, data: Uint8Array, iface: number, comment? }],
//   warnings: string[]
// }

import { u16be, u16le, u32be, u32le, u64be, u64le, utf8 } from './bytes.js';

export const LINKTYPE = {
  NULL: 0,
  ETHERNET: 1,
  PPP: 9,
  RAW: 101,
  IEEE802_11: 105,
  LOOP: 108,
  LINUX_SLL: 113,
  IEEE802_11_RADIOTAP: 127,
  IPV4: 228,
  IPV6: 229,
  LINUX_SLL2: 276,
};

export const LINKTYPE_NAMES = {
  0: 'BSD loopback', 1: 'Ethernet', 9: 'PPP', 101: 'Raw IP', 105: 'IEEE 802.11', 108: 'OpenBSD loopback',
  113: 'Linux cooked (SLL)', 127: '802.11 Radiotap', 228: 'Raw IPv4', 229: 'Raw IPv6', 276: 'Linux cooked v2 (SLL2)',
};

export function detectFormat(d) {
  if (d.length < 4) return null;
  const m = u32be(d, 0);
  if (m === 0x0a0d0d0a) return 'pcapng';
  if (m === 0xa1b2c3d4 || m === 0xd4c3b2a1 || m === 0xa1b23c4d || m === 0x4d3cb2a1) return 'pcap';
  return null;
}

export function readCapture(input) {
  const d = input instanceof Uint8Array ? input : new Uint8Array(input);
  const fmt = detectFormat(d);
  if (fmt === 'pcap') return readPcap(d);
  if (fmt === 'pcapng') return readPcapng(d);
  throw new Error('Not a pcap or pcapng file (unrecognized magic number)');
}

export function readPcap(d) {
  const magic = u32be(d, 0);
  let le, nano;
  switch (magic) {
    case 0xa1b2c3d4: le = false; nano = false; break;
    case 0xd4c3b2a1: le = true; nano = false; break;
    case 0xa1b23c4d: le = false; nano = true; break;
    case 0x4d3cb2a1: le = true; nano = true; break;
    default: throw new Error('Bad pcap magic');
  }
  const r16 = le ? u16le : u16be;
  const r32 = le ? u32le : u32be;
  const major = r16(d, 4), minor = r16(d, 6);
  const snapLen = r32(d, 16);
  const linkType = r32(d, 20) & 0x0fffffff; // upper bits may hold FCS info
  const fcsBits = (r32(d, 20) >>> 28) & 0x0f;
  const warnings = [];
  if (major !== 2) warnings.push(`Unexpected pcap version ${major}.${minor}`);
  const records = [];
  let o = 24;
  let idx = 0;
  while (o + 16 <= d.length) {
    const sec = r32(d, o);
    const frac = r32(d, o + 4);
    const capLen = r32(d, o + 8);
    const origLen = r32(d, o + 12);
    o += 16;
    if (o + capLen > d.length) {
      warnings.push(`Truncated packet at record ${idx + 1}; stopped reading`);
      break;
    }
    const ts = sec + frac / (nano ? 1e9 : 1e6);
    records.push({ ts, capLen, origLen, data: d.subarray(o, o + capLen), iface: 0 });
    o += capLen;
    idx++;
  }
  if (o !== d.length && !warnings.length) warnings.push('Trailing bytes after last record');
  return {
    format: 'pcap',
    interfaces: [{ linkType, name: 'if0', snapLen, tsResolution: nano ? 1e-9 : 1e-6, fcsLen: fcsBits & 0x8 ? (fcsBits & 0x7) * 2 : 0 }],
    records,
    warnings,
  };
}

// ---- pcapng -----------------------------------------------------------------

const BT = {
  SHB: 0x0a0d0d0a,
  IDB: 0x00000001,
  PB: 0x00000002,
  SPB: 0x00000003,
  NRB: 0x00000004,
  ISB: 0x00000005,
  EPB: 0x00000006,
};

function parseOptions(d, start, end, le) {
  const r16 = le ? u16le : u16be;
  const opts = [];
  let o = start;
  while (o + 4 <= end) {
    const code = r16(d, o), len = r16(d, o + 2);
    o += 4;
    if (code === 0) break;
    if (o + len > end) break;
    opts.push({ code, value: d.subarray(o, o + len) });
    o += (len + 3) & ~3;
  }
  return opts;
}

export function readPcapng(d) {
  const records = [];
  const interfaces = [];
  const warnings = [];
  const nameResolution = { ipv4: new Map(), ipv6: new Map() };
  let comments = [];
  let le = true;
  let o = 0;
  let sectionCount = 0;
  let ifaceBase = 0; // interfaces are per-section; keep global index

  while (o + 12 <= d.length) {
    // Block type is written in section byte order; SHB detection is endian-agnostic.
    const typeBE = u32be(d, o);
    if (typeBE === BT.SHB) {
      const bom = u32be(d, o + 8);
      if (bom === 0x1a2b3c4d) le = false;
      else if (bom === 0x4d3c2b1a) le = true;
      else { warnings.push('Bad byte-order magic in Section Header Block'); break; }
      sectionCount++;
      ifaceBase = interfaces.length;
    }
    const r16 = le ? u16le : u16be;
    const r32 = le ? u32le : u32be;
    const r64 = le ? u64le : u64be;
    const type = r32(d, o);
    const totalLen = r32(d, o + 4);
    if (totalLen < 12 || o + totalLen > d.length) {
      warnings.push(`Truncated block at offset ${o}; stopped reading`);
      break;
    }
    const body = o + 8, bodyEnd = o + totalLen - 4;

    switch (type) {
      case BT.SHB: {
        const opts = parseOptions(d, body + 16, bodyEnd, le);
        for (const op of opts) if (op.code === 1) comments.push(utf8(op.value));
        break;
      }
      case BT.IDB: {
        const linkType = r16(d, body);
        const snapLen = r32(d, body + 4);
        const iface = { linkType, snapLen, name: `if${interfaces.length}`, tsResolution: 1e-6, fcsLen: 0 };
        for (const op of parseOptions(d, body + 8, bodyEnd, le)) {
          if (op.code === 2) iface.name = utf8(op.value);
          else if (op.code === 3) iface.description = utf8(op.value);
          else if (op.code === 9 && op.value.length >= 1) {
            const v = op.value[0];
            iface.tsResolution = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v);
          } else if (op.code === 13 && op.value.length >= 1) iface.fcsLen = op.value[0];
          else if (op.code === 12) iface.os = utf8(op.value);
        }
        interfaces.push(iface);
        break;
      }
      case BT.EPB: {
        const ifaceId = r32(d, body);
        const tsHigh = r32(d, body + 4), tsLow = r32(d, body + 8);
        const capLen = r32(d, body + 12), origLen = r32(d, body + 16);
        const ifaceIdx = ifaceBase + ifaceId;
        const iface = interfaces[ifaceIdx];
        const res = iface ? iface.tsResolution : 1e-6;
        const ts = (tsHigh * 4294967296 + tsLow) * res;
        const dataStart = body + 20;
        if (dataStart + capLen > bodyEnd) { warnings.push(`Truncated EPB at offset ${o}`); break; }
        const rec = { ts, capLen, origLen, data: d.subarray(dataStart, dataStart + capLen), iface: ifaceIdx };
        const optStart = dataStart + ((capLen + 3) & ~3);
        for (const op of parseOptions(d, optStart, bodyEnd, le)) {
          if (op.code === 1) rec.comment = utf8(op.value);
        }
        records.push(rec);
        break;
      }
      case BT.SPB: {
        const origLen = r32(d, body);
        const iface = interfaces[ifaceBase];
        const snap = iface ? iface.snapLen : 0;
        const capLen = snap && snap < origLen ? snap : Math.min(origLen, bodyEnd - (body + 4));
        records.push({ ts: 0, capLen, origLen, data: d.subarray(body + 4, body + 4 + capLen), iface: ifaceBase });
        break;
      }
      case BT.PB: { // obsolete Packet Block
        const ifaceId = r16(d, body);
        const tsHigh = r32(d, body + 4), tsLow = r32(d, body + 8);
        const capLen = r32(d, body + 12), origLen = r32(d, body + 16);
        const ifaceIdx = ifaceBase + ifaceId;
        const res = interfaces[ifaceIdx] ? interfaces[ifaceIdx].tsResolution : 1e-6;
        records.push({ ts: (tsHigh * 4294967296 + tsLow) * res, capLen, origLen, data: d.subarray(body + 20, body + 20 + capLen), iface: ifaceIdx });
        break;
      }
      case BT.NRB: {
        let p = body;
        while (p + 4 <= bodyEnd) {
          const rt = r16(d, p), rl = r16(d, p + 2);
          p += 4;
          if (rt === 0) break;
          if (rt === 1 && rl >= 4) {
            const ip = `${d[p]}.${d[p + 1]}.${d[p + 2]}.${d[p + 3]}`;
            const names = utf8(d, p + 4, p + rl).split('\0').filter(Boolean);
            nameResolution.ipv4.set(ip, names);
          }
          p += (rl + 3) & ~3;
        }
        break;
      }
      default:
        break; // ISB, custom blocks, etc.
    }
    o += totalLen;
  }
  if (!interfaces.length) {
    warnings.push('No Interface Description Block found; assuming Ethernet');
    interfaces.push({ linkType: 1, snapLen: 0, name: 'if0', tsResolution: 1e-6, fcsLen: 0 });
  }
  return { format: 'pcapng', interfaces, records, warnings, comments, nameResolution, sections: sectionCount };
}

// ---- writer (used for fixtures and "export selected packets") ------------------

export function writePcap(records, linkType = 1, snapLen = 262144) {
  let total = 24;
  for (const r of records) total += 16 + r.data.length;
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 0xa1b2c3d4, true);
  dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
  dv.setUint32(8, 0, true); dv.setUint32(12, 0, true);
  dv.setUint32(16, snapLen, true); dv.setUint32(20, linkType, true);
  let o = 24;
  for (const r of records) {
    const sec = Math.floor(r.ts);
    const usec = Math.round((r.ts - sec) * 1e6);
    dv.setUint32(o, sec, true); dv.setUint32(o + 4, usec, true);
    dv.setUint32(o + 8, r.data.length, true); dv.setUint32(o + 12, r.origLen ?? r.data.length, true);
    out.set(r.data, o + 16);
    o += 16 + r.data.length;
  }
  return out;
}
