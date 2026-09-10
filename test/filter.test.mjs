import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import * as B from '../tools/pktbuild.mjs';
import { compileFilter, filterPackets, validateFilter, FIELDS } from '../src/analysis/filter.js';

// ---------------------------------------------------------------------------
// Build a varied capture: two TCP flows (HTTP GET on :80, a :443 flow),
// a UDP DNS query, an ARP request/reply pair, an ICMP echo, and IPv6/ICMPv6.
function buildCapture() {
  const recs = [];

  // TCP flow A: HTTP GET, client 10.0.0.5 -> server 93.184.216.34:80
  const getReq = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n';
  const getResp = 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n';
  recs.push(...B.tcpSession({ client: '10.0.0.5', server: '93.184.216.34', sport: 80, cport: 40000,
    exchanges: [['c', getReq], ['s', getResp]] }));

  // TCP flow B: :443 flow, client 10.0.0.9 -> server 1.1.1.1:443
  recs.push(...B.tcpSession({ client: '10.0.0.9', server: '1.1.1.1', sport: 443, cport: 40001,
    t0: 1700000100, exchanges: [['c', B.hexBytes('160301002a')]] }));

  // UDP DNS query for example.com, client 10.0.0.5 -> 8.8.8.8:53
  const dnsQ = B.dnsMessage({ id: 0x1a2b, flags: 0x0100, questions: [{ name: 'example.com', type: 1 }] });
  recs.push({ ts: 1700000200, data: B.udpFrame({ src: '10.0.0.5', dst: '8.8.8.8', sport: 53000, dport: 53, payload: dnsQ }) });

  // ARP request + reply.
  const mkArp = (o) => B.eth({ type: 0x0806, src: o.senderMac, payload: B.arp(o) });
  recs.push({ ts: 1700000300, data: mkArp({ op: 1, senderMac: 'aa:aa:aa:aa:aa:aa', senderIp: '192.168.1.10', targetIp: '192.168.1.1' }) });
  recs.push({ ts: 1700000301, data: mkArp({ op: 2, senderMac: 'bb:bb:bb:bb:bb:bb', senderIp: '192.168.1.1', targetMac: 'aa:aa:aa:aa:aa:aa', targetIp: '192.168.1.10' }) });

  // ICMP echo request 10.0.0.1 -> 10.0.0.2
  recs.push({ ts: 1700000400, data: B.icmpFrame({ src: '10.0.0.1', dst: '10.0.0.2', id: 7, seq: 3 }) });

  // IPv6 + ICMPv6 echo request fe80::1 -> fe80::2
  const echo6 = new Uint8Array([128, 0, 0, 0, 0, 1, 0, 1, ...B.str('abcdefgh')]);
  recs.push({ ts: 1700000500, data: B.eth({ type: 0x86dd, payload: B.ip6({ src: 'fe80::1', dst: 'fe80::2', nextHeader: 58, hop: 64, payload: echo6 }) }) });

  const cap = readCapture(writePcap(recs, 1));
  return dissectCapture(cap).packets;
}

const packets = buildCapture();
const total = packets.length;

// Helpers.
const count = (expr) => { const r = filterPackets(packets, expr); assert.ok(Array.isArray(r), `expected array for: ${expr}`); return r.length; };
const manual = (fn) => packets.filter(fn).length;
const ipL = (p) => p.layer('ipv4') || p.layer('ipv6');
const isTen = (ip) => typeof ip === 'string' && ip.split('.')[0] === '10';

// ---------------------------------------------------------------------------
test('filter: catalog + basic API shape', () => {
  assert.ok(Array.isArray(FIELDS) && FIELDS.length > 20);
  assert.ok(FIELDS.some(f => f.name === 'tcp.port'));
  assert.ok(FIELDS.some(f => f.name === 'ip.addr' && f.type === 'address'));
  const c = compileFilter('tcp.port == 80 and ip.src == 10.0.0.5');
  assert.equal(c.ok, true);
  assert.equal(typeof c.predicate, 'function');
  assert.ok(c.fields.includes('tcp.port') && c.fields.includes('ip.src'));
});

test('filter: protocol existence primaries', () => {
  assert.ok(total >= 15, 'expected a non-trivial capture');
  assert.equal(count('tcp'), manual(p => p.has('tcp')));
  assert.ok(count('tcp') > 0);
  assert.equal(count('udp'), manual(p => p.has('udp')));
  assert.equal(count('arp'), 2);
  assert.equal(count('icmp'), 1);
  assert.equal(count('ipv6'), 1);
  assert.equal(count('eth'), manual(p => p.has('eth')));
  assert.equal(count('ip'), manual(p => !!(p.layer('ipv4') || p.layer('ipv6'))));
});

test('filter: boolean logic and precedence', () => {
  assert.equal(count('tcp || udp'), manual(p => p.has('tcp') || p.has('udp')));
  assert.equal(count('tcp or udp'), manual(p => p.has('tcp') || p.has('udp')));
  assert.equal(count('not arp'), total - 2);
  assert.equal(count('!arp'), total - 2);
  assert.equal(count('tcp && ip'), manual(p => p.has('tcp')));
  assert.equal(count('icmp or arp'), manual(p => p.has('icmp') || p.has('arp')));
  // not binds looser than the whole comparison
  assert.equal(count('not tcp.port == 80'), manual(p => !(p.tcp && (p.tcp.srcPort === 80 || p.tcp.dstPort === 80))));
});

test('filter: numeric field comparisons', () => {
  assert.equal(count('tcp.port == 80'), manual(p => p.tcp && (p.tcp.srcPort === 80 || p.tcp.dstPort === 80)));
  assert.ok(count('tcp.port == 80') > 0);
  assert.equal(count('tcp.srcport == 80'), manual(p => p.tcp && p.tcp.srcPort === 80));
  assert.equal(count('tcp.dstport == 80'), manual(p => p.tcp && p.tcp.dstPort === 80));
  assert.equal(count('tcp.port != 80'), manual(p => p.tcp && (p.tcp.srcPort !== 80 || p.tcp.dstPort !== 80)));
  assert.equal(count('frame.len > 100'), manual(p => p.origLen > 100));
  assert.equal(count('frame.len >= 60'), manual(p => p.origLen >= 60));
  assert.equal(count('ip.ttl <= 64'), manual(p => { const l = ipL(p); return l && l.ttl <= 64; }));
  assert.equal(count('icmp.type == 8'), manual(p => p.layer('icmp')?.type === 8));
  assert.equal(count('frame.number == 1'), 1);
  assert.equal(count('tcp.port == 0x50'), manual(p => p.tcp && (p.tcp.srcPort === 80 || p.tcp.dstPort === 80)));
});

test('filter: address fields, CIDR and eth', () => {
  assert.equal(count('ip.src == 10.0.0.5'), manual(p => p.layer('ipv4')?.src === '10.0.0.5'));
  assert.ok(count('ip.src == 10.0.0.5') > 0);
  assert.equal(count('ip.addr == 10.0.0.0/8'), manual(p => { const l = ipL(p); return l && (isTen(l.src) || isTen(l.dst)); }));
  assert.equal(count('ip.addr == 93.184.216.34'), manual(p => { const l = p.layer('ipv4'); return l && (l.src === '93.184.216.34' || l.dst === '93.184.216.34'); }));
  assert.equal(count('ipv6.addr == fe80::2'), manual(p => { const l = p.layer('ipv6'); return l && (l.src === 'fe80::2' || l.dst === 'fe80::2'); }));
  assert.equal(count('eth.addr == aa:aa:aa:aa:aa:aa'), manual(p => { const e = p.layer('eth'); return e && (e.src === 'aa:aa:aa:aa:aa:aa' || e.dst === 'aa:aa:aa:aa:aa:aa'); }));
  assert.equal(count('arp.opcode == 1'), 1);
  assert.equal(count('arp.src.proto_ipv4 == 192.168.1.10'), 1);
});

test('filter: boolean/flag fields', () => {
  const syn = manual(p => p.tcp && (p.tcp.flags & 0x02));
  assert.equal(count('tcp.flags.syn == true'), syn);
  assert.equal(count('tcp.flags.syn'), syn);
  assert.equal(count('tcp.flags.syn == 1'), syn);
  assert.ok(syn >= 2);
  assert.equal(count('tcp.flags.ack'), manual(p => p.tcp && (p.tcp.flags & 0x10)));
  assert.equal(count('!tcp.flags.syn and tcp'), manual(p => p.tcp && !(p.tcp.flags & 0x02)));
});

test('filter: set membership and grouping', () => {
  const inSet = manual(p => p.tcp && [80, 443, 8080].some(x => p.tcp.srcPort === x || p.tcp.dstPort === x));
  assert.equal(count('tcp.port in {80 443 8080}'), inSet);
  assert.ok(inSet > 0);
  const grp = manual(p => { const l = ipL(p); const ten = l && (isTen(l.src) || isTen(l.dst)); const t = p.tcp && (p.tcp.srcPort === 443 || p.tcp.dstPort === 443 || p.tcp.srcPort === 80 || p.tcp.dstPort === 80); return t && ten; });
  assert.equal(count('(tcp.port == 443 or tcp.port == 80) and ip.addr == 10.0.0.0/8'), grp);
});

test('filter: contains / matches on frame.protocols', () => {
  assert.equal(count('frame.protocols contains "tcp"'), manual(p => p.layers.some(l => l.proto === 'tcp')));
  assert.equal(count('frame.protocols contains "arp"'), 2);
  assert.equal(count('frame.protocols matches "eth"'), manual(p => p.has('eth')));
  assert.equal(count('eth.addr matches "^aa:"'), manual(p => { const e = p.layer('eth'); return e && (/^aa:/.test(e.src) || /^aa:/.test(e.dst)); }));
});

test('filter: app-layer fields tolerate stub dissectors', () => {
  // These depend on other agents' dissectors. If the layer is produced, assert
  // real semantics; otherwise just confirm the filter compiles and returns [].
  for (const expr of ['dns', 'dns.qry.name contains "example"', 'http.request.method == GET', 'http.request', 'tls', 'dhcp.option.dhcp == 3']) {
    assert.equal(validateFilter(expr).ok, true, `should compile: ${expr}`);
    assert.ok(Array.isArray(filterPackets(packets, expr)), `should return array: ${expr}`);
  }
  if (packets.some(p => p.has('dns'))) {
    assert.equal(count('dns'), manual(p => p.has('dns')));
    assert.equal(count('dns.qry.name contains "example"'),
      manual(p => p.layer('dns')?.queries?.some(q => /example/i.test(q.name))));
  } else {
    assert.equal(count('dns'), 0);
    assert.equal(count('dns.qry.name contains "example"'), 0);
  }
  if (packets.some(p => p.layer('http')?.method)) {
    assert.equal(count('http.request.method == GET'), manual(p => p.layer('http')?.method === 'GET'));
  } else {
    assert.equal(count('http.request.method == GET'), 0);
  }
});

test('filter: invalid expressions report ok:false with a position', () => {
  const bad = [
    'tcp.port ==',            // missing value
    'foo.bar == 1',           // unknown field
    'tcp.frobnicate',         // unknown field/protocol
    '(tcp',                   // unbalanced paren
    'tcp.port == "80',        // unterminated string
    'ip.addr == 999.1.1.1',   // bad IPv4
    'ip.addr == 10.0.0.0/40', // bad CIDR
    'dns.qry.name matches "([" ', // bad regex
    'tcp &&',                 // dangling operator
    'tcp ==',                 // protocol used with operator + missing value
    '== 5',                   // starts with operator
    'tcp.port in 80',         // set without braces
  ];
  for (const expr of bad) {
    const r = compileFilter(expr);
    assert.equal(r.ok, false, `expected failure: ${expr}`);
    assert.equal(typeof r.error.message, 'string');
    assert.ok(r.error.message.length > 0, `message for: ${expr}`);
    assert.equal(typeof r.error.position, 'number');
    assert.ok(r.error.position >= 0);
    assert.equal(validateFilter(expr).ok, false);
  }
});

test('filter: comparing a protocol name is rejected', () => {
  const r = compileFilter('tcp == 1');
  assert.equal(r.ok, false);
  assert.match(r.error.message, /protocol/i);
});

test('filter: empty filter matches everything', () => {
  assert.equal(validateFilter('').ok, true);
  assert.equal(count(''), total);
  assert.equal(count('   '), total);
});

test('filter: valid expressions validate green', () => {
  for (const expr of ['tcp', 'ip.addr == 10.0.0.0/8', 'tcp.flags.syn', 'tcp || udp',
    'frame.len > 100', 'icmp.type == 8', 'ipv6', 'tcp.port in {80 443 8080}',
    '(tcp.port == 443 or tcp.port == 80) and ip.addr == 10.0.0.5']) {
    assert.equal(validateFilter(expr).ok, true, `should be valid: ${expr}`);
  }
});
