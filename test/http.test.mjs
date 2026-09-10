import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import * as B from '../tools/pktbuild.mjs';

function analyze(records, linkType = 1) {
  const cap = readCapture(writePcap(records, linkType));
  return dissectCapture(cap);
}
const b64 = (s) => Buffer.from(s, 'latin1').toString('base64');

// One request + one response over a full TCP session on port 80.
function httpSession(req, resp, opts = {}) {
  return analyze(B.tcpSession({
    client: '10.0.0.5', server: '93.184.216.34', sport: 80,
    exchanges: [['c', req], ['s', resp]], ...opts,
  }));
}
const findReq = (packets) => packets.find((p) => p.layer('http')?.isRequest);
const findResp = (packets) => packets.find((p) => { const h = p.layer('http'); return h && !h.isRequest; });

test('HTTP GET request: request line, headers, url, cookies, ua flag', () => {
  const req = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\nCookie: sessionid=abc123; theme=dark\r\n\r\n';
  const resp = 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 5\r\nSet-Cookie: JSESSIONID=deadbeef; Path=/\r\n\r\nhello';
  const { packets, state } = httpSession(req, resp);

  const rq = findReq(packets);
  assert.ok(rq, 'request packet found');
  const h = rq.layer('http');
  assert.equal(h.isRequest, true);
  assert.equal(h.method, 'GET');
  assert.equal(h.uri, '/index.html');
  assert.equal(h.version, 'HTTP/1.1');
  assert.equal(h.host, 'example.com');
  assert.equal(h.userAgent, 'curl/7.68.0');
  assert.equal(h.uaFlag, 'curl');
  assert.equal(h.url, 'http://example.com/index.html');
  assert.equal(rq.proto, 'HTTP');
  assert.equal(h.summary, 'GET /index.html HTTP/1.1 ');
  assert.deepEqual(h.cookies[0], ['sessionid', 'abc123']);
  assert.equal(state.tcp.list[0].proto, 'http');
  assert.equal(state.ext.http[0].host, 'example.com');

  // Response.
  const rp = findResp(packets);
  const r = rp.layer('http');
  assert.equal(r.status, 200);
  assert.equal(r.statusText, 'OK');
  assert.equal(r.contentType, 'text/html; charset=utf-8');
  assert.equal(r.contentLength, 5);
  assert.equal(r.bodyLength, 5);
  assert.equal(r.summary, 'HTTP/1.1 200 OK  (text/html)');

  // Session cookies collected as credentials (request sessionid + response JSESSIONID).
  const cookieCreds = state.ext.credentials.filter((c) => c.kind === 'cookie');
  assert.ok(cookieCreds.some((c) => c.user === 'sessionid' && c.secret === 'abc123'));
  assert.ok(cookieCreds.some((c) => c.user === 'JSESSIONID' && c.secret === 'deadbeef'));
});

test('HTTP Basic authorization decodes credentials', () => {
  const req = `GET /secret HTTP/1.1\r\nHost: h.test\r\nAuthorization: Basic ${b64('alice:s3cr3t')}\r\n\r\n`;
  const { packets, state } = httpSession(req, 'HTTP/1.1 401 Unauthorized\r\n\r\n');
  const rq = findReq(packets);
  assert.ok(rq.tags.has('credential'));
  const cred = state.ext.credentials.find((c) => c.kind === 'basic');
  assert.equal(cred.proto, 'http');
  assert.equal(cred.user, 'alice');
  assert.equal(cred.secret, 's3cr3t');
  assert.equal(cred.src, '10.0.0.5');
});

test('HTTP Bearer token credential', () => {
  const req = 'GET /api HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer abc.def.ghi\r\n\r\n';
  const { state } = httpSession(req, 'HTTP/1.1 200 OK\r\n\r\n');
  const cred = state.ext.credentials.find((c) => c.kind === 'token');
  assert.equal(cred.secret, 'abc.def.ghi');
});

test('HTTP POST login form credential + summary media type', () => {
  const body = 'username=bob&password=hunter2';
  const req = `POST /login HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  const { packets, state } = httpSession(req, 'HTTP/1.1 302 Found\r\n\r\n');
  const rq = findReq(packets);
  const h = rq.layer('http');
  assert.equal(h.method, 'POST');
  assert.equal(h.summary, 'POST /login HTTP/1.1  (application/x-www-form-urlencoded)');
  const cred = state.ext.credentials.find((c) => c.kind === 'form');
  assert.equal(cred.user, 'bob');
  assert.equal(cred.secret, 'hunter2');
});

test('HTTP CONNECT and chunked response note', () => {
  const req = 'CONNECT proxy.host:443 HTTP/1.1\r\nHost: proxy.host:443\r\n\r\n';
  const resp = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n';
  const { packets } = httpSession(req, resp);
  const h = findReq(packets).layer('http');
  assert.equal(h.method, 'CONNECT');
  assert.equal(h.uri, 'proxy.host:443');
  assert.equal(h.summary, 'CONNECT proxy.host:443 HTTP/1.1 ');
  const r = findResp(packets).layer('http');
  assert.equal(r.note, 'chunked');
});

test('HTTP headers spanning segments still emit a layer with an error', () => {
  const partial = B.str('GET /x HTTP/1.1\r\nHost: a.b\r\n'); // no terminating blank line
  const frame = B.tcpFrame({ src: '10.0.0.1', dst: '10.0.0.2', sport: 5000, dport: 80, flags: 0x18, payload: partial });
  const { packets } = analyze([{ ts: 1, data: frame }]);
  const h = packets[0].layer('http');
  assert.ok(h, 'layer emitted despite incomplete headers');
  assert.equal(h.bodyOffset, -1);
  assert.ok(h.errors.some((e) => /span multiple segments/.test(e)));
});

test('HTTP recognized by heuristic on a non-standard port', () => {
  const req = 'GET / HTTP/1.1\r\nHost: odd.port\r\nUser-Agent: sqlmap/1.5\r\n\r\n';
  const { packets, state } = analyze(B.tcpSession({
    client: '10.0.0.5', server: '10.0.0.9', sport: 9999, exchanges: [['c', req]],
  }));
  const rq = findReq(packets);
  assert.ok(rq, 'http recognized on port 9999 via heuristic');
  assert.equal(rq.layer('http').uaFlag, 'sqlmap');
  assert.equal(state.tcp.list[0].proto, 'http');
});
