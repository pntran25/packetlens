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

test('pcap reader round-trips records', () => {
  const frame = B.icmpFrame({ src: '10.0.0.1', dst: '10.0.0.2' });
  const cap = readCapture(writePcap([{ ts: 1700000000.5, data: frame }]));
  assert.equal(cap.format, 'pcap');
  assert.equal(cap.records.length, 1);
  assert.equal(cap.records[0].data.length, frame.length);
  assert.ok(Math.abs(cap.records[0].ts - 1700000000.5) < 1e-5);
  assert.equal(cap.interfaces[0].linkType, 1);
});

test('rejects garbage', () => {
  assert.throws(() => readCapture(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])));
});

test('ICMP echo dissects through eth/ipv4', () => {
  const { packets } = analyze([{ ts: 1, data: B.icmpFrame({ src: '10.0.0.1', dst: '10.0.0.2', id: 7, seq: 3 }) }]);
  const p = packets[0];
  assert.deepEqual(p.layers.map(l => l.proto), ['eth', 'ipv4', 'icmp']);
  assert.equal(p.src, '10.0.0.1');
  assert.equal(p.dst, '10.0.0.2');
  assert.equal(p.proto, 'ICMP');
  assert.match(p.info, /Echo request/);
  assert.equal(p.layer('ipv4').checksumOk, true);
  assert.equal(p.layer('icmp').seq, 3);
});

test('ARP request/reply and conflict detection', () => {
  const mk = (o) => B.eth({ type: 0x0806, src: o.senderMac, payload: B.arp(o) });
  const { packets, state } = analyze([
    { ts: 1, data: mk({ op: 1, senderMac: 'aa:aa:aa:aa:aa:aa', senderIp: '192.168.1.10', targetIp: '192.168.1.1' }) },
    { ts: 2, data: mk({ op: 2, senderMac: 'bb:bb:bb:bb:bb:bb', senderIp: '192.168.1.1', targetMac: 'aa:aa:aa:aa:aa:aa', targetIp: '192.168.1.10' }) },
    { ts: 3, data: mk({ op: 2, senderMac: 'cc:cc:cc:cc:cc:cc', senderIp: '192.168.1.1', targetMac: 'aa:aa:aa:aa:aa:aa', targetIp: '192.168.1.10' }) },
  ]);
  assert.equal(packets[0].info, 'Who has 192.168.1.1? Tell 192.168.1.10');
  assert.equal(packets[1].info, '192.168.1.1 is at bb:bb:bb:bb:bb:bb');
  assert.ok(packets[2].tags.has('arp-conflict'));
  assert.equal(state.ext.arp.conflicts.length, 1);
});

test('TCP session: handshake, relative seq, streams, retransmission', () => {
  const recs = B.tcpSession({ client: '10.0.0.5', server: '93.184.216.34', sport: 8081, exchanges: [['c', 'hello'], ['s', 'world!']] });
  // Duplicate the data packet to simulate a retransmission.
  recs.push({ ts: recs[recs.length - 1].ts + 0.5, data: recs[3].data });
  const { packets, state } = analyze(recs);
  assert.equal(packets[0].tcp.flagNames.join(','), 'SYN');
  assert.equal(packets[1].tcp.flagNames.join(','), 'SYN,ACK');
  assert.equal(packets[0].tcp.relSeq, 0);
  assert.equal(packets[3].tcp.relSeq, 1);
  assert.equal(packets[3].tcp.payloadLen, 5);
  assert.equal(packets[3].layers.at(-1).proto, 'data');
  assert.equal(state.tcp.list.length, 1);
  const s = state.tcp.list[0];
  assert.equal(s.a.ip, '10.0.0.5');
  assert.equal(s.b.port, 8081);
  assert.deepEqual(s.bytes, [10, 6]);
  assert.ok(packets.at(-1).tags.has('retransmission'), 'retransmission tagged');
  assert.equal(s.retrans, 1);
  assert.equal(packets[0].tcp.options.mss, 1460);
});

test('UDP flow tracking and vlan', () => {
  const dg = B.udp({ src: '10.1.1.1', dst: '10.1.1.2', sport: 1111, dport: 2222, payload: B.str('ping') });
  const frame = B.eth({ type: 0x8100, payload: B.vlan({ id: 42, payload: B.ip4({ src: '10.1.1.1', dst: '10.1.1.2', proto: 17, payload: dg }) }) });
  const { packets, state } = analyze([{ ts: 1, data: frame }]);
  assert.deepEqual(packets[0].layers.map(l => l.proto), ['eth', 'vlan', 'ipv4', 'udp', 'data']);
  assert.equal(packets[0].layer('vlan').id, 42);
  assert.equal(state.udp.list.length, 1);
  assert.equal(packets[0].info, '1111 → 2222 Len=4');
});

test('IPv6 + ICMPv6 neighbor solicitation', () => {
  const ns = new Uint8Array([135, 0, 0, 0, 0, 0, 0, 0, ...B.parseIp6('fe80::1'), 1, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
  const frame = B.eth({ type: 0x86dd, payload: B.ip6({ src: 'fe80::2', dst: 'ff02::1:ff00:1', nextHeader: 58, hop: 255, payload: ns }) });
  const { packets } = analyze([{ ts: 1, data: frame }]);
  const p = packets[0];
  assert.equal(p.src, 'fe80::2');
  assert.equal(p.dst, 'ff02::1:ff00:1');
  assert.equal(p.layer('icmpv6').target, 'fe80::1');
  assert.match(p.info, /Neighbor Solicitation for fe80::1 from aa:bb:cc:dd:ee:ff/);
});

test('Ethernet padding is trimmed by IP total length', () => {
  const frame = B.icmpFrame({ src: '10.0.0.1', dst: '10.0.0.2', payload: new Uint8Array(0) });
  const padded = new Uint8Array(60); padded.set(frame);
  const { packets } = analyze([{ ts: 1, data: padded }]);
  const icmp = packets[0].layer('icmp');
  assert.equal(icmp.length, 8);
  assert.equal(packets[0].layers.at(-1).proto, 'icmp');
});

test('pcapng with IDB and EPB parses', () => {
  const frame = B.icmpFrame({ src: '10.0.0.1', dst: '10.0.0.2' });
  const buf = buildPcapng([{ ts: 1700000000.25, data: frame }]);
  const cap = readCapture(buf);
  assert.equal(cap.format, 'pcapng');
  assert.equal(cap.records.length, 1);
  assert.equal(cap.interfaces[0].linkType, 1);
  assert.ok(Math.abs(cap.records[0].ts - 1700000000.25) < 1e-5);
  assert.equal(cap.records[0].data.length, frame.length);
  assert.equal(cap.records[0].comment, 'hello');
});

function buildPcapng(records) {
  const blocks = [];
  const block = (type, body) => {
    const len = 12 + ((body.length + 3) & ~3);
    const b = new Uint8Array(len);
    const dv = new DataView(b.buffer);
    dv.setUint32(0, type, true); dv.setUint32(4, len, true); b.set(body, 8); dv.setUint32(len - 4, len, true);
    return b;
  };
  // SHB
  const shb = new Uint8Array(16); const sdv = new DataView(shb.buffer);
  sdv.setUint32(0, 0x1a2b3c4d, true); sdv.setUint16(4, 1, true); sdv.setUint16(6, 0, true); sdv.setUint32(8, 0xffffffff, true); sdv.setUint32(12, 0xffffffff, true);
  blocks.push(block(0x0a0d0d0a, shb));
  const idb = new Uint8Array(8); new DataView(idb.buffer).setUint16(0, 1, true); new DataView(idb.buffer).setUint32(4, 65535, true);
  blocks.push(block(1, idb));
  for (const r of records) {
    const us = Math.round(r.ts * 1e6);
    const hi = Math.floor(us / 4294967296), lo = us >>> 0;
    const comment = new TextEncoder().encode('hello');
    const optLen = 4 + ((comment.length + 3) & ~3) + 4;
    const body = new Uint8Array(20 + ((r.data.length + 3) & ~3) + optLen);
    const dv = new DataView(body.buffer);
    dv.setUint32(0, 0, true); dv.setUint32(4, hi, true); dv.setUint32(8, lo, true); dv.setUint32(12, r.data.length, true); dv.setUint32(16, r.data.length, true);
    body.set(r.data, 20);
    let o = 20 + ((r.data.length + 3) & ~3);
    dv.setUint16(o, 1, true); dv.setUint16(o + 2, comment.length, true); body.set(comment, o + 4);
    blocks.push(block(6, body));
  }
  let total = 0; for (const b of blocks) total += b.length;
  const out = new Uint8Array(total); let o = 0; for (const b of blocks) { out.set(b, o); o += b.length; }
  return out;
}
