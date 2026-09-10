import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import * as B from '../tools/pktbuild.mjs';
import { readName } from '../src/dissectors/app/dns.js';

function analyze(records, linkType = 1) {
  return dissectCapture(readCapture(writePcap(records, linkType)));
}
const be16 = (v) => [(v >> 8) & 0xff, v & 0xff];
const be32 = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
const client = '10.0.0.5', server = '8.8.8.8';
const exch = (exchanges, o = {}) => B.udpExchange({ client, server, sport: 53, cport: 40001, exchanges, ...o });

test('DNS query and response: summary, properties, names map, transactions', () => {
  const q = B.dnsMessage({ id: 0x1a2b, flags: 0x0100, questions: [{ name: 'example.com', type: 1 }] });
  const r = B.dnsMessage({ id: 0x1a2b, flags: 0x8180, questions: [{ name: 'example.com', type: 1 }], answers: [
    { name: 'example.com', type: 5, data: 'foo.example.net', ttl: 60 },
    { name: 'foo.example.net', type: 1, data: '93.184.216.34', ttl: 300 },
  ] });
  const { packets, state } = analyze(exch([['c', q], ['s', r]]));
  const [p1, p2] = packets;
  assert.equal(p1.proto, 'DNS');
  assert.equal(p1.info, 'Standard query 0x1a2b A example.com');
  assert.equal(p2.info, 'Standard query response 0x1a2b A example.com CNAME foo.example.net A 93.184.216.34');
  const d1 = p1.layer('dns'), d2 = p2.layer('dns');
  assert.equal(d1.id, 0x1a2b);
  assert.equal(d1.isResponse, false);
  assert.equal(d1.flags.rd, true);
  assert.deepEqual(d1.queries, [{ name: 'example.com', type: 1, typeName: 'A', cls: 1, clsName: 'IN' }]);
  assert.equal(d2.isResponse, true);
  assert.equal(d2.rcode, 0);
  assert.equal(d2.rcodeName, 'No error');
  assert.equal(d2.flags.ra, true);
  assert.equal(d2.answers.length, 2);
  assert.equal(d2.answers[0].typeName, 'CNAME');
  assert.equal(d2.answers[0].data, 'foo.example.net');
  assert.equal(d2.answers[1].ttl, 300);
  assert.equal(d2.answers[1].data, '93.184.216.34');
  assert.deepEqual(d2.respAddr, ['93.184.216.34']);
  // names map includes A owner and the CNAME alias.
  const names = state.dns.names.get('93.184.216.34');
  assert.ok(names.has('foo.example.net') && names.has('example.com'));
  // transaction matched.
  assert.equal(state.dns.transactions.length, 1);
  const t = state.dns.transactions[0];
  assert.equal(t.query, 1); assert.equal(t.response, 2);
  assert.equal(t.src, client); assert.equal(t.server, server);
  assert.ok(t.rtt > 0 && t.rtt < 0.01);
  assert.deepEqual(t.answers, ['CNAME foo.example.net', 'A 93.184.216.34']);
  assert.equal(state.udp.list[0].proto, 'dns');
});

test('DNS NXDOMAIN, SOA authority, and rcode name in summary', () => {
  const soa = new Uint8Array([...B.dnsName('ns1.example'), ...B.dnsName('hostmaster.example'), ...be32(2024010101), ...be32(3600), ...be32(900), ...be32(604800), ...be32(86400)]);
  const r = B.dnsMessage({ id: 0x77, flags: 0x8183, questions: [{ name: 'nope.example', type: 1 }] });
  // Append an authority SOA record by hand: patch nscount and append RR.
  const rr = new Uint8Array([...B.dnsName('example'), ...be16(6), ...be16(1), ...be32(3600), ...be16(soa.length), ...soa]);
  const msg = new Uint8Array(r.length + rr.length); msg.set(r); msg.set(rr, r.length); msg[9] = 1;
  const { packets } = analyze(exch([['s', msg]]));
  const p = packets[0];
  assert.equal(p.info, 'Standard query response 0x0077 No such name A nope.example');
  const d = p.layer('dns');
  assert.equal(d.rcode, 3);
  assert.equal(d.authorities.length, 1);
  assert.equal(d.authorities[0].typeName, 'SOA');
  assert.equal(d.authorities[0].data, 'ns1.example hostmaster.example 2024010101 3600 900 604800 86400');
  assert.ok(!p.tags.has('malformed'));
});

test('DNS rich record types: MX, TXT, SRV, AAAA, PTR, OPT (EDNS)', () => {
  const srv = new Uint8Array([...be16(0), ...be16(5), ...be16(5060), ...B.dnsName('sip.example.com')]);
  const r = B.dnsMessage({ id: 1, flags: 0x8180, questions: [{ name: 'example.com', type: 255 }], answers: [
    { name: 'example.com', type: 15, pref: 10, data: 'mail.example.com' },
    { name: 'example.com', type: 16, data: 'v=spf1 -all' },
    { name: '_sip._udp.example.com', type: 33, data: srv },
    { name: 'example.com', type: 28, data: '2606:2800:220:1:248:1893:25c8:1946' },
    { name: '34.216.184.93.in-addr.arpa', type: 12, data: 'example.com' },
  ] });
  // OPT pseudo-RR in additional section: name root, type 41, class 4096, ttl DO bit, rdlen 0.
  const opt = new Uint8Array([0, ...be16(41), ...be16(4096), 0, 0, 0x80, 0, ...be16(0)]);
  const msg = new Uint8Array(r.length + opt.length); msg.set(r); msg.set(opt, r.length); msg[11] = 1;
  const { packets, state } = analyze(exch([['s', msg]]));
  const d = packets[0].layer('dns');
  assert.equal(d.queries[0].typeName, 'ANY');
  const byType = Object.fromEntries(d.answers.map(a => [a.typeName, a.data]));
  assert.equal(byType.MX, '10 mail.example.com');
  assert.equal(byType.TXT, '"v=spf1 -all"');
  assert.equal(byType.SRV, '0 5 5060 sip.example.com');
  assert.equal(byType.AAAA, '2606:2800:220:1:248:1893:25c8:1946');
  assert.equal(byType.PTR, 'example.com');
  assert.equal(d.additionals[0].typeName, 'OPT');
  assert.deepEqual([d.edns.udpSize, d.edns.do], [4096, true]);
  assert.ok(state.dns.names.get('2606:2800:220:1:248:1893:25c8:1946').has('example.com'));
  assert.match(packets[0].info, /MX 10 mail\.example\.com TXT "v=spf1 -all"/);
});

test('DNS name compression with pointers and pointer-loop protection', () => {
  // Manual message: question example.com, answer uses pointer 0xc00c to the question name.
  const hdr = [...be16(0xbeef), ...be16(0x8180), ...be16(1), ...be16(1), 0, 0, 0, 0];
  const q = [...B.dnsName('example.com'), ...be16(1), ...be16(1)];
  const ans = [0xc0, 0x0c, ...be16(1), ...be16(1), ...be32(60), ...be16(4), 1, 2, 3, 4];
  const msg = new Uint8Array([...hdr, ...q, ...ans]);
  const { packets } = analyze(exch([['s', msg]]));
  const d = packets[0].layer('dns');
  assert.equal(d.answers[0].name, 'example.com');
  assert.equal(d.answers[0].data, '1.2.3.4');
  assert.ok(!packets[0].tags.has('malformed'));

  // Pointer loop: label points to itself.
  const loop = new Uint8Array([0xc0, 0x00, 0xc0, 0x00]);
  const n = readName(loop, 0, 0, loop.length);
  assert.match(n.err, /loop/);
  const loopMsg = new Uint8Array([...be16(1), ...be16(0x0100), ...be16(1), 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, ...be16(1), ...be16(1)]);
  const r2 = analyze(exch([['c', loopMsg]]));
  assert.ok(r2.packets[0].layer('dns'), 'layer is returned even for a looping name');
  assert.ok(r2.packets[0].tags.has('malformed'));
});

test('DNS truncated message does not throw and yields partial layer', () => {
  const full = B.dnsMessage({ id: 5, flags: 0x8180, questions: [{ name: 'example.com', type: 1 }], answers: [{ name: 'example.com', type: 1, data: '1.1.1.1' }] });
  const cut = full.subarray(0, full.length - 3);
  const { packets } = analyze(exch([['s', cut]]));
  const d = packets[0].layer('dns');
  assert.ok(d);
  assert.equal(d.queries.length, 1);
  assert.ok(packets[0].tags.has('malformed'));
  assert.ok(packets[0].errors.some(e => /truncated/i.test(e)));
});

test('DNS over TCP with length prefix and two messages in one segment', () => {
  const m1 = B.dnsMessage({ id: 1, flags: 0x0100, questions: [{ name: 'a.example', type: 1 }] });
  const m2 = B.dnsMessage({ id: 2, flags: 0x0100, questions: [{ name: 'b.example', type: 28 }] });
  const payload = new Uint8Array([...be16(m1.length), ...m1, ...be16(m2.length), ...m2]);
  const recs = B.tcpSession({ client, server, sport: 53, exchanges: [['c', payload]] });
  const { packets, state } = analyze(recs);
  const p = packets[3];
  const layers = p.layers.filter(l => l.proto === 'dns');
  assert.equal(layers.length, 2);
  assert.equal(layers[0].id, 1);
  assert.equal(layers[1].qryName, 'b.example');
  assert.equal(p.info, 'Standard query 0x0002 AAAA b.example');
  assert.equal(state.tcp.list[0].proto, 'dns');
  // A partial TCP message (declared longer than present) is not marked malformed.
  const partial = new Uint8Array([...be16(m1.length + 50), ...m1]);
  const r2 = analyze(B.tcpSession({ client, server, sport: 53, exchanges: [['c', partial]] }));
  assert.ok(!r2.packets[3].tags.has('malformed'));
  assert.match(r2.packets[3].info, /reassembled PDU/);
});

test('MDNS and LLMNR labels, QU/cache-flush class bits', () => {
  const q = B.dnsMessage({ id: 0, flags: 0, questions: [{ name: '_services._dns-sd._udp.local', type: 12, cls: 0x8001 }] });
  const mdns = B.udpFrame({ src: '192.168.1.20', dst: '224.0.0.251', sport: 5353, dport: 5353, payload: q });
  const llq = B.dnsMessage({ id: 0x99, flags: 0, questions: [{ name: 'printer', type: 1 }] });
  const llmnr = B.udpFrame({ src: '192.168.1.20', dst: '224.0.0.252', sport: 51000, dport: 5355, payload: llq });
  const { packets } = analyze([{ ts: 1, data: mdns }, { ts: 2, data: llmnr }]);
  assert.equal(packets[0].proto, 'MDNS');
  assert.equal(packets[0].layer('dns').queries[0].unicast, true);
  assert.equal(packets[0].layer('dns').queries[0].cls, 1);
  assert.equal(packets[0].info, 'Standard query 0x0000 PTR _services._dns-sd._udp.local "QU" question');
  assert.equal(packets[1].proto, 'LLMNR');
  assert.equal(packets[1].info, 'Standard query 0x0099 A printer');
});

test('DNS suspicious names are tagged and recorded in state.ext.dns', () => {
  const longLabel = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6';
  const q1 = B.dnsMessage({ id: 10, flags: 0x0100, questions: [{ name: `${longLabel}.tunnel.example.com`, type: 16 }] });
  const q2 = B.dnsMessage({ id: 11, flags: 0x0100, questions: [{ name: 'www.example.com', type: 1 }] });
  const q3 = B.dnsMessage({ id: 12, flags: 0x0100, questions: [{ name: 'data.x.y.example.com', type: 10 }] });
  const { packets, state } = analyze(exch([['c', q1], ['c', q2], ['c', q3]]));
  assert.ok(packets[0].tags.has('dns-suspicious'));
  assert.ok(packets[0].layer('dns').notes.some(n => /label length/.test(n)));
  assert.ok(packets[0].layer('dns').notes.some(n => /high-entropy/.test(n)));
  assert.ok(!packets[1].tags.has('dns-suspicious'));
  assert.ok(packets[2].tags.has('dns-suspicious'));
  assert.ok(packets[2].layer('dns').notes.some(n => /NULL query/.test(n)));
  assert.ok(state.ext.dns.suspicious.length >= 3);
  assert.equal(state.ext.dns.suspicious[0].packet, 1);
  assert.ok(!packets[0].tags.has('malformed'), 'suspicious is not malformed');
});
