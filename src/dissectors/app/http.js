// HTTP/1.x dissector.
//
// Sees ONE TCP segment at a time (ctx bytes [offset,end) are this segment's
// payload). A message may span segments or several messages may share a
// segment; we do best-effort on the bytes present. Full body reassembly is
// done later in src/analysis/streams.js.

import { Layer } from '../../core/packet.js';
import { latin1 } from '../../core/bytes.js';

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'];
const METHOD_SET = new Set(METHODS);
const REQ_RE = new RegExp('^(' + METHODS.join('|') + ') ');
const RESP_RE = /^HTTP\/1\.\d[ \t]/;

// User-Agent substrings that flag known scanners / tooling (case-insensitive).
const UA_TOOLS = ['sqlmap', 'nikto', 'nmap', 'curl', 'python-requests', 'wget', 'masscan', 'metasploit', 'havij', 'nessus'];

// Cookie names that look like session / auth tokens.
const SESSION_NAMES = new Set(['sessionid', 'phpsessid', 'jsessionid', 'asp.net_sessionid', 'sid', 'auth', 'token']);

const FORM_USER_FIELDS = new Set(['user', 'username', 'login', 'email']);
const FORM_PASS_FIELDS = new Set(['pass', 'passwd', 'password', 'pwd']);

const B64_LOOKUP = (() => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < chars.length; i++) t[chars.charCodeAt(i)] = i;
  return t;
})();

/** Decode base64 (tolerant) to a Uint8Array. Returns null on malformed input. */
function b64decode(str) {
  if (!str) return new Uint8Array(0);
  const s = str.replace(/[^A-Za-z0-9+/]/g, '');
  const out = new Uint8Array((s.length * 3) >> 2);
  let bits = 0, nbits = 0, o = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B64_LOOKUP[s.charCodeAt(i)];
    if (v < 0) continue;
    bits = (bits << 6) | v;
    nbits += 6;
    if (nbits >= 8) { nbits -= 8; out[o++] = (bits >> nbits) & 0xff; }
  }
  return out.subarray(0, o);
}
function b64ToText(str) {
  const bytes = b64decode(str);
  return latin1(bytes, 0, bytes.length);
}

function truncate(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }

const http = {
  id: 'http',
  name: 'Hypertext Transfer Protocol',
  tcpPorts: [80, 8080, 8000, 8888, 591, 8081],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end } = ctx;
      if (end - offset < 5) return false;
      // 'HTTP/1.'
      if (data[offset] === 0x48 && data[offset + 1] === 0x54 && data[offset + 2] === 0x54 &&
          data[offset + 3] === 0x50 && data[offset + 4] === 0x2f && data[offset + 5] === 0x31 && data[offset + 6] === 0x2e) return true;
      // METHOD followed by a space.
      const s = latin1(data, offset, Math.min(offset + 10, end));
      const sp = s.indexOf(' ');
      return sp > 0 && METHOD_SET.has(s.slice(0, sp));
    },
  },
  dissect(ctx) {
    const { data, offset, end, packet, parent, state } = ctx;
    if (end - offset < 4) return null;

    const text = latin1(data, offset, end);
    const firstNl = text.indexOf('\n');
    const firstLine = (firstNl >= 0 ? text.slice(0, firstNl) : text).replace(/\r$/, '');

    const isRequest = REQ_RE.test(firstLine);
    const isResponse = !isRequest && RESP_RE.test(firstLine);
    if (!isRequest && !isResponse) return null;

    // Locate the header/body boundary (CRLFCRLF or LFLF).
    const crlf2 = text.indexOf('\r\n\r\n');
    const lf2 = text.indexOf('\n\n');
    let headerEndRel = -1, bodyStartRel = -1;
    if (crlf2 >= 0 && (lf2 < 0 || crlf2 < lf2)) { headerEndRel = crlf2; bodyStartRel = crlf2 + 4; }
    else if (lf2 >= 0) { headerEndRel = lf2; bodyStartRel = lf2 + 2; }

    const headerBlock = headerEndRel >= 0 ? text.slice(0, headerEndRel) : text;
    const lines = headerBlock.split(/\r\n|\n/);

    const l = new Layer('http', 'Hypertext Transfer Protocol', offset, end - offset);
    l.label = 'HTTP';
    l.isRequest = isRequest;
    l.headers = [];
    l.bodyOffset = bodyStartRel >= 0 ? offset + bodyStartRel : -1;
    l.bodyLength = l.bodyOffset >= 0 ? end - l.bodyOffset : 0;

    if (headerEndRel < 0) l.error('HTTP headers span multiple segments');

    // --- Request / status line ---
    if (isRequest) {
      const parts = firstLine.split(' ');
      l.method = parts[0];
      l.uri = parts[1] || '';
      l.version = parts[2] || '';
      l.add('Request method', l.method, offset, l.method.length);
      l.add('Request URI', l.uri, -1, 0);
      l.add('Request version', l.version, -1, 0);
    } else {
      const m = firstLine.match(/^(HTTP\/1\.\d)[ \t]+(\d{3})[ \t]*(.*)$/);
      l.version = m ? m[1] : 'HTTP/1.1';
      l.status = m ? parseInt(m[2], 10) : NaN;
      l.statusText = m ? m[3].trim() : '';
      l.add('Response version', l.version, offset, l.version.length);
      l.add('Status code', l.status, -1, 0);
      l.add('Reason phrase', l.statusText, -1, 0);
    }

    // --- Headers (RFC folding tolerated) ---
    const hmap = new Map();
    const setCookies = [];
    const hg = l.addGroup('Headers', `${Math.max(0, lines.length - 1)}`, -1, 0, []);
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line === '') break;
      if ((line[0] === ' ' || line[0] === '\t') && l.headers.length) {
        // Continuation of previous header value.
        const prev = l.headers[l.headers.length - 1];
        prev[1] += ' ' + line.trim();
        continue;
      }
      const ci = line.indexOf(':');
      if (ci < 0) continue; // partial / malformed header line
      const name = line.slice(0, ci).trim();
      const value = line.slice(ci + 1).trim();
      if (!name) continue;
      l.headers.push([name, value]);
      hg.children.push({ name, value, offset: -1, length: 0 });
      const lname = name.toLowerCase();
      if (lname === 'set-cookie') setCookies.push(value);
      else if (!hmap.has(lname)) hmap.set(lname, value);
    }
    const H = (n) => hmap.get(n);

    l.host = H('host');
    l.userAgent = H('user-agent');
    l.authorization = H('authorization');
    const ctHeader = H('content-type');
    l.contentType = ctHeader;
    const mediaType = ctHeader ? ctHeader.split(';')[0].trim() : '';
    const clen = H('content-length');
    if (clen != null) { const n = parseInt(clen, 10); if (!Number.isNaN(n)) l.contentLength = n; }
    const te = H('transfer-encoding');
    if (te && /chunked/i.test(te)) l.note = 'chunked';

    // --- Cookies ---
    const cookies = [];
    const cookieHdr = H('cookie');
    if (cookieHdr) for (const part of cookieHdr.split(';')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      cookies.push([part.slice(0, eq).trim(), part.slice(eq + 1).trim()]);
    }
    for (const sc of setCookies) {
      const first = sc.split(';')[0];
      const eq = first.indexOf('=');
      if (eq < 0) continue;
      cookies.push([first.slice(0, eq).trim(), first.slice(eq + 1).trim()]);
    }
    if (cookies.length) l.cookies = cookies;

    // --- URL ---
    const httpsPort = (parent && (parent.srcPort === 443 || parent.dstPort === 443));
    const scheme = httpsPort ? 'https' : 'http';
    if (isRequest && l.host) {
      if (/^https?:\/\//i.test(l.uri)) l.url = l.uri;
      else if (l.method === 'CONNECT') l.url = l.host; // authority form
      else l.url = `${scheme}://${l.host}${l.uri.startsWith('/') ? '' : '/'}${l.uri}`;
    } else if (isRequest && l.method === 'CONNECT') {
      l.url = l.uri;
    }

    // --- Recognition + cross-packet state ---
    const streamId = packet.stream ? packet.stream.id : -1;
    if (streamId >= 0 && state.tcp.list[streamId]) state.tcp.list[streamId].proto = 'http';
    const httpExt = (state.ext.http ||= {});
    if (streamId >= 0) {
      const rec = (httpExt[streamId] ||= {});
      if (isRequest) { rec.lastMethod = l.method; rec.lastUri = l.uri; if (l.host) rec.host = l.host; }
      if (ctHeader) rec.contentType = ctHeader;
    }

    // --- User-Agent tool flag ---
    if (l.userAgent) {
      const ua = l.userAgent.toLowerCase();
      for (const tool of UA_TOOLS) if (ua.includes(tool)) { l.uaFlag = tool; break; }
    }

    // --- Credentials ---
    const ip = packet.ip;
    const src = ip ? ip.src : '';
    const dst = ip ? ip.dst : '';
    const noteUrl = l.url || l.host || l.uri || '';
    const pushCred = (cred) => {
      (state.ext.credentials ||= []).push({
        proto: 'http', src, dst, packet: packet.index, stream: streamId, ...cred,
      });
      packet.tags.add('credential');
    };

    if (l.authorization) {
      const sp = l.authorization.indexOf(' ');
      const authScheme = (sp > 0 ? l.authorization.slice(0, sp) : l.authorization).toLowerCase();
      const authData = sp > 0 ? l.authorization.slice(sp + 1).trim() : '';
      if (authScheme === 'basic') {
        const creds = b64ToText(authData);
        const ci = creds.indexOf(':');
        pushCred({ kind: 'basic', user: ci >= 0 ? creds.slice(0, ci) : creds, secret: ci >= 0 ? creds.slice(ci + 1) : '', note: noteUrl });
      } else if (authScheme === 'bearer') {
        pushCred({ kind: 'token', user: undefined, secret: authData, note: truncate(noteUrl, 80) });
      } else if (authScheme === 'ntlm' || authScheme === 'negotiate') {
        const raw = b64decode(authData);
        let note = noteUrl;
        // NTLMSSP\0 signature then a 4-byte little-endian message type.
        if (raw.length >= 12 && latin1(raw, 0, 7) === 'NTLMSSP' && raw[7] === 0) {
          const msgType = raw[8] | (raw[9] << 8) | (raw[10] << 16) | (raw[11] << 24);
          note = `NTLM type${msgType} ${noteUrl}`.trim();
        }
        pushCred({ kind: 'ntlm', user: undefined, secret: authData, note: truncate(note, 80) });
      }
    }

    // --- Login form bodies ---
    if (isRequest && (l.method === 'POST' || l.method === 'PUT') && l.bodyOffset >= 0 && l.bodyLength > 0) {
      const looksForm = !ctHeader || /x-www-form-urlencoded/i.test(ctHeader);
      if (looksForm) {
        const body = latin1(data, l.bodyOffset, end);
        if (body.includes('=') && body.length < 4096) {
          let user, pass;
          for (const pair of body.split('&')) {
            const eq = pair.indexOf('=');
            if (eq < 0) continue;
            const k = pair.slice(0, eq).toLowerCase();
            const v = decodeForm(pair.slice(eq + 1));
            if (FORM_USER_FIELDS.has(k) && user === undefined) user = v;
            else if (FORM_PASS_FIELDS.has(k) && pass === undefined) pass = v;
          }
          if (pass !== undefined) pushCred({ kind: 'form', user, secret: pass, note: noteUrl });
        }
      }
    }

    // --- Session cookies ---
    for (const [cname, cval] of cookies) {
      const lc = cname.toLowerCase();
      if (SESSION_NAMES.has(lc) || lc.includes('session')) {
        pushCred({ kind: 'cookie', user: cname, secret: cval, note: noteUrl });
      }
    }

    // --- Summary ---
    if (isRequest) {
      let s = `${l.method} ${l.uri} ${l.version} `;
      if (ctHeader) s += ` (${mediaType})`;
      l.summary = s;
    } else {
      let s = `${l.version} ${l.status} ${l.statusText}`;
      if (ctHeader) s += `  (${mediaType})`;
      l.summary = s;
    }

    return l;
  },
};

function decodeForm(v) {
  try { return decodeURIComponent(v.replace(/\+/g, ' ')); }
  catch { return v; }
}

export default [http];
