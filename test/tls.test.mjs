import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import { md5, sha1 } from '../src/core/hash.js';
import * as B from '../tools/pktbuild.mjs';

function analyze(records, linkType = 1) {
  const cap = readCapture(writePcap(records, linkType));
  return dissectCapture(cap);
}
// Deliver a raw TLS payload as a single TCP segment (PSH+ACK) toward a port.
function tlsPacket(payload, { sport = 50000, dport = 443, src = '10.0.0.5', dst = '93.184.216.34' } = {}) {
  const frame = B.tcpFrame({ src, dst, sport, dport, flags: 0x18, payload: new Uint8Array(payload) });
  return analyze([{ ts: 1, data: frame }]);
}

// --- byte builders ---
const u16 = (v) => [(v >> 8) & 0xff, v & 0xff];
const u24 = (v) => [(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff];
const record = (type, ver, body) => [type, ...u16(ver), ...u16(body.length), ...body];
const handshake = (type, body) => [type, ...u24(body.length), ...body];
const ext = (type, data) => [...u16(type), ...u16(data.length), ...data];
const bytesOf = (s) => [...B.str(s)];

function clientHelloBody() {
  const sni = bytesOf('example.com');
  const sniExt = ext(0, [...u16(3 + sni.length), 0, ...u16(sni.length), ...sni]);
  const groupsExt = ext(10, [...u16(4), ...u16(0x001d), ...u16(0x0017)]);
  const ecpfExt = ext(11, [1, 0]);
  const greaseExt = ext(0x0a0a, []);
  const svExt = ext(43, [4, ...u16(0x0304), ...u16(0x0303)]);
  const exts = [...sniExt, ...groupsExt, ...ecpfExt, ...greaseExt, ...svExt];
  return [
    ...u16(0x0303),
    ...new Array(32).fill(0x11),
    0, // session id length
    ...u16(6), ...u16(0x1a1a), ...u16(0xc02f), ...u16(0x009c), // cipher suites (GREASE first)
    1, 0, // compression
    ...u16(exts.length), ...exts,
  ];
}

test('TLS ClientHello: SNI, JA3 string + hash, TLS 1.3 via supported_versions', () => {
  const payload = record(22, 0x0301, handshake(1, clientHelloBody()));
  const { packets, state } = tlsPacket(payload);
  const p = packets[0];
  const l = p.layer('tls');
  assert.ok(l, 'tls layer present');
  assert.equal(l.isClientHello, true);
  assert.equal(l.sni, 'example.com');
  assert.equal(l.records[0].typeName, 'Handshake');
  assert.equal(l.records[0].handshakeName, 'Client Hello');
  assert.equal(l.version, 'TLS 1.3'); // from supported_versions ext

  // JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats (GREASE removed).
  const expected = '771,49199-156,0-10-11-43,29-23,0';
  assert.equal(l.ja3, expected);
  assert.equal(l.ja3Hash, md5(expected));
  assert.equal(l.summary, 'Client Hello (SNI=example.com)');

  assert.equal(state.tcp.list[0].proto, 'tls');
  assert.equal(state.tcp.list[0].tlsSni, 'example.com');
  assert.equal(state.ext.tls.ja3[0].sni, 'example.com');
  assert.equal(state.ext.tls.ja3[0].hash, md5(expected));
});

test('TLS ServerHello: cipher name, JA3S, negotiated 1.3', () => {
  const shExts = [...ext(43, [...u16(0x0304)]), ...ext(0xff01, [])];
  const shBody = [
    ...u16(0x0303),
    ...new Array(32).fill(0x22),
    0,
    ...u16(0xc02f),
    0, // compression
    ...u16(shExts.length), ...shExts,
  ];
  const payload = record(22, 0x0303, handshake(2, shBody));
  const { packets } = tlsPacket(payload, { sport: 443, dport: 50000, src: '93.184.216.34', dst: '10.0.0.5' });
  const l = packets[0].layer('tls');
  assert.equal(l.isServerHello, true);
  assert.equal(l.cipher, 0xc02f);
  assert.equal(l.cipherName, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256');
  assert.equal(l.version, 'TLS 1.3');
  const expected = '771,49199,43-65281';
  assert.equal(l.ja3s, expected);
  assert.equal(l.ja3sHash, md5(expected));
  assert.equal(l.summary, 'Server Hello (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)');
});

test('TLS Alert record parsed', () => {
  const payload = record(21, 0x0303, [2, 40]);
  const { packets } = tlsPacket(payload);
  const l = packets[0].layer('tls');
  assert.equal(l.records[0].typeName, 'Alert');
  assert.equal(l.summary, 'Alert (Level: Fatal, Description: Handshake Failure)');
});

test('TLS Application Data and multiple records in one segment', () => {
  const payload = [...record(20, 0x0303, [1]), ...record(23, 0x0303, [0xaa, 0xbb, 0xcc])];
  const { packets } = tlsPacket(payload);
  const l = packets[0].layer('tls');
  assert.equal(l.records.length, 2);
  assert.equal(l.records[0].typeName, 'Change Cipher Spec');
  assert.equal(l.records[1].typeName, 'Application Data');
  assert.equal(l.summary, 'Change Cipher Spec, Application Data');
});

test('TLS Certificate: minimal X.509 DER parse (CN, issuer, validity, SAN, self-signed)', () => {
  // Tiny DER builder.
  const der = (tag, content) => {
    const c = content;
    let lb;
    if (c.length < 0x80) lb = [c.length];
    else if (c.length < 0x100) lb = [0x81, c.length];
    else lb = [0x82, (c.length >> 8) & 0xff, c.length & 0xff];
    return [tag, ...lb, ...c];
  };
  const seq = (...items) => der(0x30, items.flat());
  const set = (...items) => der(0x31, items.flat());
  const oid = (b) => der(0x06, b);
  const int = (b) => der(0x02, b);
  const pstr = (s) => der(0x13, bytesOf(s));
  const utc = (s) => der(0x17, bytesOf(s));
  const octet = (c) => der(0x04, c);
  const bit = (c) => der(0x03, [0, ...c]);
  const ctx3 = (c) => der(0xa3, c);
  const dnsName = (s) => der(0x82, bytesOf(s));
  const cnName = (val) => seq(set(seq(oid([0x55, 0x04, 0x03]), pstr(val))));

  const tbs = seq(
    int([0x2a]),                                   // serialNumber = 0x2a
    seq(oid([0x2a, 0x86])),                         // signature algorithm
    cnName('Test CA'),                              // issuer
    seq(utc('230101000000Z'), utc('330101000000Z')), // validity
    cnName('test.example.com'),                     // subject
    seq(seq(oid([0x2a, 0x86])), bit([0x00])),       // subjectPublicKeyInfo
    ctx3(seq(seq(oid([0x55, 0x1d, 0x11]), octet(seq(dnsName('alt.example.com')))))), // extensions: SAN
  );
  const certDer = seq(tbs, seq(oid([0x2a, 0x86])), bit([0x00]));
  const certBytes = new Uint8Array(certDer);

  const certMsg = handshake(11, [...u24(3 + certDer.length), ...u24(certDer.length), ...certDer]);
  const payload = record(22, 0x0303, certMsg);
  const { packets, state } = tlsPacket(payload, { sport: 443, dport: 50000, src: '93.184.216.34', dst: '10.0.0.5' });
  const l = packets[0].layer('tls');
  assert.equal(l.certs.length, 1);
  const c = l.certs[0];
  assert.equal(c.subjectCN, 'test.example.com');
  assert.equal(c.issuerCN, 'Test CA');
  assert.equal(c.notBefore, '2023-01-01T00:00:00Z');
  assert.equal(c.notAfter, '2033-01-01T00:00:00Z');
  assert.deepEqual(c.sans, ['alt.example.com']);
  assert.equal(c.serial, '2a');
  assert.equal(c.selfSigned, false);
  assert.equal(c.sha1, sha1(certBytes));
  assert.equal(l.summary, 'Certificate (CN=test.example.com)');
  assert.equal(state.ext.tls.certs.length, 1);
});

test('TLS truncated ClientHello does not throw and still emits a layer', () => {
  const full = record(22, 0x0301, handshake(1, clientHelloBody()));
  const truncated = full.slice(0, 12); // header + a few handshake bytes only
  const { packets } = tlsPacket(truncated);
  const p = packets[0];
  const l = p.layer('tls');
  assert.ok(l, 'layer emitted for truncated record');
  assert.ok(l.records.length >= 1);
  assert.equal(l.records[0].truncated, true);
  assert.ok(!p.errors.some((e) => e.startsWith('tls:')), 'tls dissector did not throw');
});

test('TLS heuristic recognizes handshake on a non-standard port', () => {
  const payload = record(22, 0x0301, handshake(1, clientHelloBody()));
  const { packets, state } = tlsPacket(payload, { dport: 4443 });
  assert.ok(packets[0].layer('tls'), 'tls recognized on port 4443 via heuristic');
  assert.equal(state.tcp.list[0].proto, 'tls');
});
