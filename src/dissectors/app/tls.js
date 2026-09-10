// TLS / SSL dissector.
//
// Sees ONE TCP segment at a time. A TLS record (or a handshake message inside
// one) may be fragmented across segments; we do best-effort on the bytes
// present and never throw — every nested length prefix is bounds-checked.

import { Layer } from '../../core/packet.js';
import { u16be, toHex, latin1 } from '../../core/bytes.js';
import { md5, sha1, sha256 } from '../../core/hash.js';

function u24be(d, o) { return (d[o] << 16) | (d[o + 1] << 8) | d[o + 2]; }

const CONTENT_TYPES = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat' };
const HANDSHAKE_TYPES = {
  0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 3: 'Hello Verify Request', 4: 'New Session Ticket',
  5: 'End Of Early Data', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange',
  13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange',
  20: 'Finished', 24: 'Key Update', 254: 'Message Hash',
};
const ALERT_LEVELS = { 1: 'Warning', 2: 'Fatal' };
const ALERT_DESCRIPTIONS = {
  0: 'Close Notify', 10: 'Unexpected Message', 20: 'Bad Record MAC', 21: 'Decryption Failed', 22: 'Record Overflow',
  30: 'Decompression Failure', 40: 'Handshake Failure', 41: 'No Certificate', 42: 'Bad Certificate',
  43: 'Unsupported Certificate', 44: 'Certificate Revoked', 45: 'Certificate Expired', 46: 'Certificate Unknown',
  47: 'Illegal Parameter', 48: 'Unknown CA', 49: 'Access Denied', 50: 'Decode Error', 51: 'Decrypt Error',
  60: 'Export Restriction', 70: 'Protocol Version', 71: 'Insufficient Security', 80: 'Internal Error',
  86: 'Inappropriate Fallback', 90: 'User Canceled', 100: 'No Renegotiation', 109: 'Missing Extension',
  110: 'Unsupported Extension', 112: 'Unrecognized Name', 113: 'Bad Certificate Status Response',
  115: 'Unknown PSK Identity', 116: 'Certificate Required', 120: 'No Application Protocol',
};

const CIPHER_NAMES = {
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0x1304: 'TLS_AES_128_CCM_SHA256', 0x1305: 'TLS_AES_128_CCM_8_SHA256',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256', 0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA', 0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256', 0x003d: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 0xc028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 0x0005: 'TLS_RSA_WITH_RC4_128_SHA', 0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
  0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
};
function cipherName(v) { return CIPHER_NAMES[v] || `0x${v.toString(16).padStart(4, '0')}`; }

function versionName(v) {
  switch (v) {
    case 0x0002: return 'SSL 2.0';
    case 0x0300: return 'SSL 3.0';
    case 0x0301: return 'TLS 1.0';
    case 0x0302: return 'TLS 1.1';
    case 0x0303: return 'TLS 1.2';
    case 0x0304: return 'TLS 1.3';
    default: return `0x${v.toString(16).padStart(4, '0')}`;
  }
}

// GREASE values (RFC 8701): both bytes equal and of the form 0x?a.
function isGrease(v) {
  return (v & 0x0f0f) === 0x0a0a && ((v >> 8) & 0xff) === (v & 0xff);
}

const tls = {
  id: 'tls',
  name: 'Transport Layer Security',
  tcpPorts: [443, 8443, 993, 995, 465, 587, 990, 636, 989, 992, 5061],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end } = ctx;
      if (end - offset < 5) return false;
      const t = data[offset];
      if (t < 20 || t > 23) return false;
      if (data[offset + 1] !== 3) return false;
      if (data[offset + 2] > 4) return false;
      const len = u16be(data, offset + 3);
      return len > 0 && len <= 0x4800; // plausible record length (<= 16640-ish + slack)
    },
  },
  dissect(ctx) {
    const { data, offset, end, packet, parent, state } = ctx;
    if (end - offset < 5) return null;
    // Guard against mid-record continuation segments on a port match.
    const t0 = data[offset];
    if (t0 < 20 || t0 > 24 || data[offset + 1] !== 3 || data[offset + 2] > 4) return null;

    const l = new Layer('tls', 'Transport Layer Security', offset, end - offset);
    l.label = 'TLS';
    l.records = [];
    const summaries = [];
    let negVersion = null; // best negotiated/hello version we learn

    const streamId = packet.stream ? packet.stream.id : -1;
    const ip = packet.ip;
    const src = ip ? ip.src : '';
    const dst = ip ? ip.dst : '';

    let pos = offset;
    let guard = 0;
    while (pos + 5 <= end && guard++ < 64) {
      const type = data[pos];
      if (!CONTENT_TYPES[type] || data[pos + 1] !== 3) break;
      const ver = u16be(data, pos + 1);
      const recLen = u16be(data, pos + 3);
      const fragStart = pos + 5;
      const declaredEnd = fragStart + recLen;
      const fragEnd = Math.min(declaredEnd, end); // available bytes (may be fragmented)
      const rec = { type, typeName: CONTENT_TYPES[type], version: versionName(ver), length: recLen };
      l.records.push(rec);
      if (negVersion === null && ver >= 0x0300 && ver <= 0x0304) negVersion = ver;

      const rg = l.addGroup(rec.typeName, `${versionName(ver)}, Len=${recLen}`, pos, Math.min(5 + recLen, end - pos), []);

      try {
        if (type === 22) {
          // One or more handshake messages inside this fragment.
          let hp = fragStart;
          let hfirst = true;
          while (hp + 4 <= fragEnd) {
            const hType = data[hp];
            const hLen = u24be(data, hp + 1); // 3-byte handshake length
            const bodyStart = hp + 4;
            const bodyEnd = Math.min(bodyStart + hLen, fragEnd);
            const name = HANDSHAKE_TYPES[hType] || `Handshake (${hType})`;
            if (hfirst) { rec.handshakeType = hType; rec.handshakeName = name; hfirst = false; }
            rg.children.push({ name, value: `Len=${hLen}`, offset: hp, length: Math.min(4 + hLen, fragEnd - hp) });

            const negFromMsg = parseHandshake(l, hType, data, bodyStart, bodyEnd, ver, { state, streamId, src, dst, packet, summaries });
            if (negFromMsg) negVersion = negFromMsg;

            if (hLen === 0 && hType !== 14 && hType !== 0) break;
            hp = bodyStart + hLen; // advance by declared length even if fragmented (then loop ends)
            if (hp > fragEnd) break;
          }
          if (hfirst) summaries.push(rec.typeName);
        } else if (type === 21) {
          if (fragStart + 2 <= fragEnd) {
            const level = data[fragStart], desc = data[fragStart + 1];
            const levelName = ALERT_LEVELS[level] || `Level ${level}`;
            const descName = ALERT_DESCRIPTIONS[desc] || `Description ${desc}`;
            rg.add('Level', levelName, fragStart, 1);
            rg.add('Description', descName, fragStart + 1, 1);
            summaries.push(`Alert (Level: ${levelName}, Description: ${descName})`);
          } else summaries.push('Alert');
        } else if (type === 20) {
          summaries.push('Change Cipher Spec');
        } else if (type === 23) {
          summaries.push('Application Data');
        } else if (type === 24) {
          summaries.push('Heartbeat');
        }
      } catch {
        rec.parseError = true;
      }

      if (declaredEnd > end) { rec.truncated = true; break; } // record spans into next segment
      pos = declaredEnd;
    }

    if (negVersion !== null) l.version = versionName(negVersion);
    else if (l.records.length) l.version = l.records[0].version;

    // Recognition + stream annotation.
    if (streamId >= 0 && state.tcp.list[streamId]) {
      state.tcp.list[streamId].proto = 'tls';
      if (l.sni) state.tcp.list[streamId].tlsSni = l.sni;
    }

    l.summary = summaries.length ? summaries.join(', ') : (l.records[0]?.typeName || 'TLS');
    return l;
  },
};

// Parse a single handshake message body [start,end). Returns a negotiated
// version number if it learned one, else null. Never throws (caller wraps too).
function parseHandshake(l, hType, data, start, end, recVer, ctx) {
  if (hType === 1) return parseClientHello(l, data, start, end, ctx);
  if (hType === 2) return parseServerHello(l, data, start, end, ctx);
  if (hType === 11) { parseCertificate(l, data, start, end, ctx); return null; }
  return null;
}

function parseClientHello(l, data, start, end, ctx) {
  l.isClientHello = true;
  let p = start;
  if (p + 2 > end) { ctx.summaries.push('Client Hello'); return null; }
  const clientVer = u16be(data, p); p += 2;
  // random (32)
  if (p + 32 <= end) {
    const rnd = toHex(data, p, p + 32);
    l.clientRandom = rnd;
    // First 4 bytes are gmt_unix_time in older clients; GREASE-ish randoms vary.
    const gmt = (data[p] << 24 | data[p + 1] << 16 | data[p + 2] << 8 | data[p + 3]) >>> 0;
    if (gmt > 0x40000000 && gmt < 0x80000000) l.randomNote = 'time';
  }
  p += 32;
  // session id
  if (p + 1 > end) return finishClientHello(l, clientVer, [], [], [], [], null, ctx);
  const sidLen = data[p]; p += 1 + sidLen;
  // cipher suites
  if (p + 2 > end) return finishClientHello(l, clientVer, [], [], [], [], null, ctx);
  const csLen = u16be(data, p); p += 2;
  const ciphers = [];
  const csEnd = Math.min(p + csLen, end);
  for (let q = p; q + 2 <= csEnd; q += 2) ciphers.push(u16be(data, q));
  p += csLen;
  // compression
  if (p + 1 > end) return finishClientHello(l, clientVer, ciphers, [], [], [], null, ctx);
  const compLen = data[p]; p += 1 + compLen;
  // extensions
  const exts = [];
  let curves = [], ecpf = [], supportedVersions = [];
  const alpn = [];
  let sni = null;
  if (p + 2 <= end) {
    const extLen = u16be(data, p); p += 2;
    const extEnd = Math.min(p + extLen, end);
    while (p + 4 <= extEnd) {
      const etype = u16be(data, p);
      const elen = u16be(data, p + 2);
      const edStart = p + 4;
      const edEnd = Math.min(edStart + elen, extEnd);
      exts.push(etype);
      if (etype === 0) sni = parseSNI(data, edStart, edEnd) ?? sni;
      else if (etype === 16) parseALPN(data, edStart, edEnd, alpn);
      else if (etype === 10) curves = parse2ByteList(data, edStart + (edStart + 2 <= edEnd ? 2 : 0), edEnd);
      else if (etype === 11) ecpf = parse1ByteList(data, edStart + (edStart + 1 <= edEnd ? 1 : 0), edEnd);
      else if (etype === 43) supportedVersions = parseSupportedVersions(data, edStart, edEnd);
      p = edStart + elen;
    }
  }
  if (sni) { l.sni = sni; }
  if (alpn.length) l.alpn = alpn;

  // Negotiated preference: highest non-GREASE supported_version (TLS 1.3 aware).
  let neg = clientVer;
  for (const v of supportedVersions) if (!isGrease(v) && v > neg && v <= 0x0304) neg = v;

  return finishClientHello(l, clientVer, ciphers, exts, curves, ecpf, neg, ctx);
}

function finishClientHello(l, clientVer, ciphers, exts, curves, ecpf, neg, ctx) {
  // JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats (GREASE removed).
  const nog = (arr) => arr.filter((v) => !isGrease(v));
  const ja3 = [
    String(clientVer),
    nog(ciphers).join('-'),
    nog(exts).join('-'),
    nog(curves).join('-'),
    nog(ecpf).join('-'),
  ].join(',');
  l.ja3 = ja3;
  l.ja3Hash = md5(ja3);
  l.ciphers = ciphers;

  const st = ensureTlsExt(ctx.state);
  st.ja3.push({ hash: l.ja3Hash, string: ja3, sni: l.sni || null, packet: ctx.packet.index, src: ctx.src, dst: ctx.dst });

  ctx.summaries.push(l.sni ? `Client Hello (SNI=${l.sni})` : 'Client Hello');
  return neg;
}

function parseServerHello(l, data, start, end, ctx) {
  l.isServerHello = true;
  let p = start;
  if (p + 2 > end) { ctx.summaries.push('Server Hello'); return null; }
  const serverVer = u16be(data, p); p += 2;
  p += 32; // random
  if (p + 1 > end) { ctx.summaries.push('Server Hello'); return null; }
  const sidLen = data[p]; p += 1 + sidLen;
  if (p + 2 > end) { ctx.summaries.push('Server Hello'); return null; }
  const cipher = u16be(data, p); p += 2;
  l.cipher = cipher;
  l.cipherName = cipherName(cipher);
  p += 1; // compression method
  const exts = [];
  let chosen = serverVer;
  if (p + 2 <= end) {
    const extLen = u16be(data, p); p += 2;
    const extEnd = Math.min(p + extLen, end);
    while (p + 4 <= extEnd) {
      const etype = u16be(data, p);
      const elen = u16be(data, p + 2);
      const edStart = p + 4;
      const edEnd = Math.min(edStart + elen, extEnd);
      exts.push(etype);
      if (etype === 43 && edStart + 2 <= edEnd) chosen = u16be(data, edStart); // selected_version
      p = edStart + elen;
    }
  }

  // JA3S = SSLVersion,Cipher,Extensions (GREASE removed from extensions).
  const nog = (arr) => arr.filter((v) => !isGrease(v));
  const ja3s = [String(serverVer), String(cipher), nog(exts).join('-')].join(',');
  l.ja3s = ja3s;
  l.ja3sHash = md5(ja3s);

  const st = ensureTlsExt(ctx.state);
  if (ctx.src) st.servers.set(ctx.src, { cipher, cipherName: l.cipherName, version: versionName(chosen) });

  ctx.summaries.push(`Server Hello (${l.cipherName})`);
  return chosen >= 0x0300 && chosen <= 0x0304 ? chosen : serverVer;
}

function parseCertificate(l, data, start, end, ctx) {
  let p = start;
  if (p + 3 > end) return;
  const listLen = u24be(data, p); p += 3;
  const listEnd = Math.min(p + listLen, end);
  const certs = [];
  const st = ensureTlsExt(ctx.state);
  while (p + 3 <= listEnd) {
    const clen = u24be(data, p); p += 3;
    const cStart = p, cEnd = Math.min(p + clen, listEnd);
    const der = data.subarray(cStart, cEnd);
    p += clen;
    const cert = { subjectCN: null, issuerCN: null, notBefore: null, notAfter: null, sans: [], serial: null, sha1: sha1(der), sha256: sha256(der), selfSigned: false };
    try { parseCert(der, cert); }
    catch { cert.parseError = true; }
    certs.push(cert);
    st.certs.push({ ...cert, packet: ctx.packet.index, src: ctx.src, dst: ctx.dst });
    if (cEnd < p) break;
  }
  l.certs = certs;
  const cn = certs[0]?.subjectCN;
  ctx.summaries.push(cn ? `Certificate (CN=${cn})` : `Certificate (${certs.length} cert${certs.length === 1 ? '' : 's'})`);
}

// ---- TLS extension helpers ----
function parseSNI(data, start, end) {
  // server_name_list: list_len(2), then entries type(1) name_len(2) name.
  let p = start;
  if (p + 2 > end) return null;
  const listLen = u16be(data, p); p += 2;
  const listEnd = Math.min(p + listLen, end);
  while (p + 3 <= listEnd) {
    const nameType = data[p];
    const nameLen = u16be(data, p + 1);
    const nStart = p + 3, nEnd = Math.min(nStart + nameLen, listEnd);
    if (nameType === 0) return latin1(data, nStart, nEnd);
    p = nStart + nameLen;
  }
  return null;
}
function parseALPN(data, start, end, out) {
  let p = start;
  if (p + 2 > end) return;
  const listLen = u16be(data, p); p += 2;
  const listEnd = Math.min(p + listLen, end);
  while (p + 1 <= listEnd) {
    const len = data[p]; p += 1;
    if (p + len > listEnd) break;
    out.push(latin1(data, p, p + len));
    p += len;
  }
}
function parseSupportedVersions(data, start, end) {
  // ClientHello form: list_len(1) then 2-byte versions.
  const out = [];
  if (start >= end) return out;
  const listLen = data[start];
  let p = start + 1;
  const listEnd = Math.min(p + listLen, end);
  for (; p + 2 <= listEnd; p += 2) out.push(u16be(data, p));
  return out;
}
function parse2ByteList(data, start, end) {
  const out = [];
  for (let p = start; p + 2 <= end; p += 2) out.push(u16be(data, p));
  return out;
}
function parse1ByteList(data, start, end) {
  const out = [];
  for (let p = start; p < end; p++) out.push(data[p]);
  return out;
}

function ensureTlsExt(state) {
  return (state.ext.tls ||= { certs: [], ja3: [], servers: new Map() });
}

// ---- Minimal X.509 DER parsing ----
// Reads just enough to reach subject/issuer CN, validity and SANs.
function readTLV(d, pos, limit) {
  if (pos + 2 > limit) return null;
  const tag = d[pos];
  let len = d[pos + 1];
  let hlen = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || pos + 2 + n > limit) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | d[pos + 2 + i];
    hlen = 2 + n;
  }
  const cStart = pos + hlen;
  const cEnd = cStart + len;
  if (cEnd > limit) return null;
  return { tag, len, start: cStart, end: cEnd, next: cEnd };
}

const OID_CN = [0x55, 0x04, 0x03];
const OID_SAN = [0x55, 0x1d, 0x11];

function oidEquals(d, start, end, oid) {
  if (end - start !== oid.length) return false;
  for (let i = 0; i < oid.length; i++) if (d[start + i] !== oid[i]) return false;
  return true;
}

function extractCN(d, nameStart, nameEnd) {
  // Name ::= SEQUENCE OF RDN (SET OF AttributeTypeAndValue SEQUENCE).
  let cn = null;
  let p = nameStart;
  while (p < nameEnd) {
    const set = readTLV(d, p, nameEnd);
    if (!set) break;
    if (set.tag === 0x31) {
      let q = set.start;
      while (q < set.end) {
        const atv = readTLV(d, q, set.end);
        if (!atv) break;
        if (atv.tag === 0x30) {
          const oid = readTLV(d, atv.start, atv.end);
          if (oid && oid.tag === 0x06 && oidEquals(d, oid.start, oid.end, OID_CN)) {
            const val = readTLV(d, oid.next, atv.end);
            if (val) cn = latin1(d, val.start, val.end);
          }
        }
        q = atv.next;
      }
    }
    p = set.next;
  }
  return cn;
}

function parseTime(d, tlv) {
  const s = latin1(d, tlv.start, tlv.end);
  // UTCTime YYMMDDHHMMSSZ (tag 0x17) or GeneralizedTime YYYYMMDDHHMMSSZ (0x18).
  let yr, rest;
  if (tlv.tag === 0x17) {
    const yy = parseInt(s.slice(0, 2), 10);
    yr = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = s.slice(2);
  } else {
    yr = parseInt(s.slice(0, 4), 10);
    rest = s.slice(4);
  }
  const mo = rest.slice(0, 2), da = rest.slice(2, 4), hh = rest.slice(4, 6) || '00', mi = rest.slice(6, 8) || '00', se = rest.slice(8, 10) || '00';
  return `${yr}-${mo}-${da}T${hh}:${mi}:${se}Z`;
}

function extractSANs(d, extnValueStart, extnValueEnd, out) {
  // extnValue OCTET STRING wraps GeneralNames SEQUENCE OF GeneralName.
  const seq = readTLV(d, extnValueStart, extnValueEnd);
  if (!seq || seq.tag !== 0x30) return;
  let p = seq.start;
  while (p < seq.end) {
    const gn = readTLV(d, p, seq.end);
    if (!gn) break;
    if (gn.tag === 0x82) out.push(latin1(d, gn.start, gn.end)); // dNSName [2] IA5String
    p = gn.next;
  }
}

function parseCert(der, cert) {
  const limit = der.length;
  const outer = readTLV(der, 0, limit);
  if (!outer || outer.tag !== 0x30) { cert.parseError = true; return; }
  const tbs = readTLV(der, outer.start, outer.end);
  if (!tbs || tbs.tag !== 0x30) { cert.parseError = true; return; }
  let p = tbs.start;
  const tbsEnd = tbs.end;

  // Optional version [0] EXPLICIT.
  let first = readTLV(der, p, tbsEnd);
  if (first && first.tag === 0xa0) p = first.next;

  // serialNumber INTEGER
  const serial = readTLV(der, p, tbsEnd);
  if (serial && serial.tag === 0x02) { cert.serial = toHex(der, serial.start, serial.end, ':'); p = serial.next; }

  // signature AlgorithmIdentifier SEQUENCE
  const sig = readTLV(der, p, tbsEnd);
  if (sig) p = sig.next;

  // issuer Name
  const issuer = readTLV(der, p, tbsEnd);
  if (issuer) { cert.issuerCN = extractCN(der, issuer.start, issuer.end); p = issuer.next; }

  // validity SEQUENCE { notBefore, notAfter }
  const validity = readTLV(der, p, tbsEnd);
  if (validity && validity.tag === 0x30) {
    const nb = readTLV(der, validity.start, validity.end);
    if (nb) { cert.notBefore = parseTime(der, nb); const na = readTLV(der, nb.next, validity.end); if (na) cert.notAfter = parseTime(der, na); }
    p = validity.next;
  }

  // subject Name
  const subject = readTLV(der, p, tbsEnd);
  if (subject) { cert.subjectCN = extractCN(der, subject.start, subject.end); p = subject.next; }

  // self-signed: issuer DN bytes == subject DN bytes.
  if (issuer && subject && issuer.end - issuer.start === subject.end - subject.start) {
    let eq = true;
    for (let i = 0; i < issuer.end - issuer.start; i++) if (der[issuer.start + i] !== der[subject.start + i]) { eq = false; break; }
    cert.selfSigned = eq;
  }

  // subjectPublicKeyInfo SEQUENCE
  const spki = readTLV(der, p, tbsEnd);
  if (spki) p = spki.next;

  // Remaining optional fields; find extensions [3].
  while (p < tbsEnd) {
    const tlv = readTLV(der, p, tbsEnd);
    if (!tlv) break;
    if (tlv.tag === 0xa3) {
      const extsSeq = readTLV(der, tlv.start, tlv.end);
      if (extsSeq && extsSeq.tag === 0x30) {
        let q = extsSeq.start;
        while (q < extsSeq.end) {
          const ext = readTLV(der, q, extsSeq.end);
          if (!ext) break;
          if (ext.tag === 0x30) {
            const oid = readTLV(der, ext.start, ext.end);
            if (oid && oid.tag === 0x06 && oidEquals(der, oid.start, oid.end, OID_SAN)) {
              // optional BOOLEAN critical, then OCTET STRING.
              let r = oid.next;
              let node = readTLV(der, r, ext.end);
              if (node && node.tag === 0x01) { r = node.next; node = readTLV(der, r, ext.end); }
              if (node && node.tag === 0x04) extractSANs(der, node.start, node.end, cert.sans);
            }
          }
          q = ext.next;
        }
      }
    }
    p = tlv.next;
  }
}

export default [tls];
