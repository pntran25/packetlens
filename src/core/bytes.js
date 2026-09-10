// Byte-level helpers shared by every dissector.

export function u8(d, o) { return d[o]; }
export function u16be(d, o) { return (d[o] << 8) | d[o + 1]; }
export function u16le(d, o) { return d[o] | (d[o + 1] << 8); }
export function u32be(d, o) { return ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0; }
export function u32le(d, o) { return (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0; }
export function u64be(d, o) { return u32be(d, o) * 0x100000000 + u32be(d, o + 4); }
export function u64le(d, o) { return u32le(d, o + 4) * 0x100000000 + u32le(d, o); }

export function hex(n, width = 2) { return n.toString(16).padStart(width, '0'); }

export function toHex(d, start = 0, end = d.length, sep = '') {
  let s = [];
  for (let i = start; i < end; i++) s.push(hex(d[i]));
  return s.join(sep);
}

export function mac(d, o) {
  return toHex(d, o, o + 6, ':');
}

export function ipv4(d, o) {
  return `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;
}

export function ipv6(d, o) {
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(u16be(d, o + i * 2));
  // Find longest run of zeros for :: compression.
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart < 0) { curStart = i; curLen = 1; } else curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return groups.map(g => g.toString(16)).join(':');
  const head = groups.slice(0, bestStart).map(g => g.toString(16)).join(':');
  const tail = groups.slice(bestStart + bestLen).map(g => g.toString(16)).join(':');
  return `${head}::${tail}`;
}

const asciiDecoder = new TextDecoder('latin1');
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

export function latin1(d, start = 0, end = d.length) {
  return asciiDecoder.decode(d.subarray(start, end));
}
export function utf8(d, start = 0, end = d.length) {
  return utf8Decoder.decode(d.subarray(start, end));
}

/** Printable representation: non-printables become '.' */
export function printable(d, start = 0, end = d.length) {
  let s = '';
  for (let i = start; i < end; i++) {
    const c = d[i];
    s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
  }
  return s;
}

/** Bytes → text for display, keeping newlines and tabs, replacing other control chars. */
export function textish(d, start = 0, end = d.length) {
  let s = '';
  for (let i = start; i < end; i++) {
    const c = d[i];
    if (c === 0x0a || c === 0x0d || c === 0x09 || (c >= 0x20 && c < 0x7f)) s += String.fromCharCode(c);
    else if (c >= 0x80) s += String.fromCharCode(c); // latin1 passthrough
    else s += '.';
  }
  return s;
}

export function concat(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function indexOfBytes(hay, needle, from = 0) {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

export function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function fmtTime(ts, opts = {}) {
  const d = new Date(ts * 1000);
  const iso = d.toISOString();
  const frac = ((ts % 1) + 1) % 1;
  const us = Math.round(frac * 1e6).toString().padStart(6, '0');
  if (opts.dateOnly) return iso.slice(0, 10);
  return iso.slice(0, 19).replace('T', ' ') + '.' + us;
}

export function fmtRel(sec) {
  return sec.toFixed(6);
}

/** Shannon entropy in bits per byte for a buffer. */
export function entropy(d, start = 0, end = d.length) {
  if (end <= start) return 0;
  const counts = new Uint32Array(256);
  for (let i = start; i < end; i++) counts[d[i]]++;
  const n = end - start;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Internet checksum (RFC 1071). */
export function inetChecksum(d, start, end, initial = 0) {
  let sum = initial;
  let i = start;
  for (; i + 1 < end; i += 2) sum += (d[i] << 8) | d[i + 1];
  if (i < end) sum += d[i] << 8;
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}
