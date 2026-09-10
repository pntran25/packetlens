// Artifact extraction: files transferred over HTTP, plus emails and SMB files
// surfaced by their dissectors. Reuses TCP reassembly from streams.js.

import { sha256 } from '../core/hash.js';
import { latin1 } from '../core/bytes.js';
import { reassembleTcp } from './streams.js';

export const MAX_FILE_BYTES = 16 * 1024 * 1024; // hash/keep cap per file

// ---- magic-byte file typing ---------------------------------------------

function detectFileType(d) {
  const b = (i) => (i < d.length ? d[i] : -1);
  if (b(0) === 0x4d && b(1) === 0x5a) return { fileType: 'pe', executable: true };            // MZ
  if (b(0) === 0x7f && b(1) === 0x45 && b(2) === 0x4c && b(3) === 0x46) return { fileType: 'elf', executable: true };
  if (b(0) === 0x25 && b(1) === 0x50 && b(2) === 0x44 && b(3) === 0x46) return { fileType: 'pdf', executable: false }; // %PDF
  if (b(0) === 0x50 && b(1) === 0x4b && (b(2) === 0x03 || b(2) === 0x05 || b(2) === 0x07)) return { fileType: 'zip', executable: false }; // PK (zip/office/jar)
  if (b(0) === 0x89 && b(1) === 0x50 && b(2) === 0x4e && b(3) === 0x47) return { fileType: 'png', executable: false };
  if (b(0) === 0xff && b(1) === 0xd8 && b(2) === 0xff) return { fileType: 'jpeg', executable: false };
  if (b(0) === 0x47 && b(1) === 0x49 && b(2) === 0x46 && b(3) === 0x38) return { fileType: 'gif', executable: false };
  if (b(0) === 0x1f && b(1) === 0x8b) return { fileType: 'gzip', executable: false };
  if (b(0) === 0x52 && b(1) === 0x49 && b(2) === 0x46 && b(3) === 0x46) return { fileType: 'riff', executable: false };
  if (b(0) === 0xca && b(1) === 0xfe && b(2) === 0xba && b(3) === 0xbe) return { fileType: 'macho', executable: true }; // fat/Mach-O
  if ((b(0) === 0xfe && b(1) === 0xed && b(2) === 0xfa) || (b(0) === 0xcf && b(1) === 0xfa && b(2) === 0xed)) return { fileType: 'macho', executable: true };
  if (b(0) === 0x23 && b(1) === 0x21) return { fileType: 'script', executable: false, script: true }; // #!
  return { fileType: 'unknown', executable: false };
}

// ---- HTTP message parsing over a reassembled byte stream ------------------

function findCRLFCRLF(d, from) {
  for (let i = from; i + 3 < d.length; i++) {
    if (d[i] === 0x0d && d[i + 1] === 0x0a && d[i + 2] === 0x0d && d[i + 3] === 0x0a) return i;
  }
  return -1;
}

function parseHeaders(text) {
  const lines = text.split('\r\n');
  const startLine = lines.shift() || '';
  const headers = [];
  const map = new Map();
  for (const ln of lines) {
    if (!ln) continue;
    const idx = ln.indexOf(':');
    if (idx < 0) continue;
    const name = ln.slice(0, idx).trim();
    const value = ln.slice(idx + 1).trim();
    headers.push([name, value]);
    map.set(name.toLowerCase(), value);
  }
  return { startLine, headers, map };
}

function parseChunked(d, start) {
  const out = [];
  let pos = start;
  while (pos < d.length) {
    let lineEnd = pos;
    while (lineEnd + 1 < d.length && !(d[lineEnd] === 0x0d && d[lineEnd + 1] === 0x0a)) lineEnd++;
    if (lineEnd + 1 >= d.length) break;
    const sizeStr = latin1(d, pos, lineEnd).split(';')[0].trim();
    const size = parseInt(sizeStr, 16);
    if (!Number.isFinite(size)) break;
    pos = lineEnd + 2;
    if (size === 0) { pos += 2; break; } // trailer CRLF
    const chunkEnd = Math.min(d.length, pos + size);
    for (let i = pos; i < chunkEnd; i++) out.push(d[i]);
    pos = chunkEnd + 2; // skip trailing CRLF
  }
  return { body: Uint8Array.from(out), next: pos };
}

/** Parse a sequence of HTTP messages from one reassembled direction. */
function parseHttpMessages(d) {
  const msgs = [];
  let pos = 0;
  let guard = 0;
  while (pos < d.length && guard++ < 1000) {
    const hdrEnd = findCRLFCRLF(d, pos);
    if (hdrEnd < 0) break;
    const headerText = latin1(d, pos, hdrEnd);
    const { startLine, headers, map } = parseHeaders(headerText);
    const bodyStart = hdrEnd + 4;
    const isResponse = /^HTTP\//i.test(startLine);
    let body = new Uint8Array(0);
    let next = bodyStart;
    const te = (map.get('transfer-encoding') || '').toLowerCase();
    const clRaw = map.get('content-length');
    if (te.includes('chunked')) {
      const r = parseChunked(d, bodyStart);
      body = r.body; next = r.next;
    } else if (clRaw != null) {
      const cl = parseInt(clRaw, 10) || 0;
      const end = Math.min(d.length, bodyStart + cl);
      body = d.subarray(bodyStart, end);
      next = bodyStart + cl;
    } else if (isResponse) {
      // No length: 1xx/204/304 have no body; otherwise assume close-delimited.
      const m = /^HTTP\/\d\.\d\s+(\d{3})/.exec(startLine);
      const code = m ? parseInt(m[1], 10) : 0;
      if (code === 204 || code === 304 || (code >= 100 && code < 200)) { body = new Uint8Array(0); next = bodyStart; }
      else { body = d.subarray(bodyStart); next = d.length; }
    } else {
      body = new Uint8Array(0); next = bodyStart;
    }
    const msg = { kind: isResponse ? 'response' : 'request', startLine, headers, map, bodyStart, body };
    if (isResponse) {
      const m = /^HTTP\/\d\.\d\s+(\d{3})\s*(.*)$/.exec(startLine);
      msg.statusCode = m ? parseInt(m[1], 10) : 0;
      msg.statusText = m ? m[2] : '';
    } else {
      const m = /^(\S+)\s+(\S+)\s+HTTP/.exec(startLine);
      msg.method = m ? m[1] : '';
      msg.uri = m ? m[2] : '';
      msg.host = map.get('host') || '';
    }
    msgs.push(msg);
    if (next <= pos) break;
    pos = next;
  }
  return msgs;
}

function offsetToPkt(follow, dir, off) {
  let best = null;
  for (const f of follow) {
    if (f.dir !== dir) continue;
    if (off >= f.offset && off < f.offset + f.len) return f.pkt;
    if (f.offset <= off) best = f.pkt;
  }
  return best;
}

function filenameFrom(disposition, uri, fallback) {
  if (disposition) {
    const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
    if (m) return decodeURIComponent(m[1].trim()).replace(/^.*[\\/]/, '');
  }
  if (uri) {
    let path = uri.split('?')[0].split('#')[0];
    const base = path.replace(/\/+$/, '').split('/').pop();
    if (base) return base;
  }
  return fallback;
}

function makeFile(body, { source, direction, filename, contentType, uri, host, statusCode, stream, packet }) {
  const truncated = body.length > MAX_FILE_BYTES;
  const data = truncated ? body.subarray(0, MAX_FILE_BYTES) : body;
  const ft = detectFileType(data);
  const file = {
    source, direction,
    filename, contentType: contentType || null,
    size: body.length,
    fileType: ft.fileType,
    executable: !!ft.executable,
    script: !!ft.script,
    truncated,
    data,
    uri: uri || null, host: host || null,
    statusCode: statusCode ?? null,
    stream, packet,
  };
  file.sha256 = truncated ? null : sha256(data);
  return file;
}

/**
 * @returns {{files:Array, emails:Array, smbFiles:Array, totalBytes:number}}
 */
export function extractArtifacts(packets, state, capture) {
  const files = [];
  const streams = state?.tcp?.list || [];
  for (const s of streams) {
    if (s.proto !== 'http') continue;
    let reasm;
    try { reasm = reassembleTcp(s, packets); } catch { continue; }
    const requests = parseHttpMessages(reasm.a2b).filter((m) => m.kind === 'request');
    const responses = parseHttpMessages(reasm.b2a).filter((m) => m.kind === 'response');

    let ri = 0;
    for (const resp of responses) {
      const req = requests[ri++] || null;
      if (!resp.body || resp.body.length === 0) continue;
      const disp = resp.map.get('content-disposition');
      const uri = req ? req.uri : null;
      const host = req ? req.host : null;
      const fname = filenameFrom(disp, uri, `http-stream${s.id}-${ri}`);
      const pkt = offsetToPkt(reasm.follow, 1, resp.bodyStart);
      files.push(makeFile(resp.body, {
        source: 'http', direction: 'download',
        filename: fname, contentType: resp.map.get('content-type'),
        uri, host, statusCode: resp.statusCode, stream: s.id, packet: pkt,
      }));
    }
    // Request bodies (uploads).
    for (const req of requests) {
      if (!req.body || req.body.length === 0) continue;
      const disp = req.map.get('content-disposition');
      const fname = filenameFrom(disp, req.uri, `upload-stream${s.id}`);
      const pkt = offsetToPkt(reasm.follow, 0, req.bodyStart);
      files.push(makeFile(req.body, {
        source: 'http', direction: 'upload',
        filename: fname, contentType: req.map.get('content-type'),
        uri: req.uri, host: req.host, statusCode: null, stream: s.id, packet: pkt,
      }));
    }
  }

  const emails = Array.isArray(state?.ext?.smtp?.messages) ? state.ext.smtp.messages : [];
  const smbFiles = Array.isArray(state?.ext?.smb?.files) ? state.ext.smb.files : [];
  const totalBytes = files.reduce((sum, f) => sum + f.size, 0);

  return { files, emails, smbFiles, totalBytes };
}
