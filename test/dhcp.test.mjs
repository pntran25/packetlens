import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import * as B from '../tools/pktbuild.mjs';

function analyze(records, linkType = 1) {
  return dissectCapture(readCapture(writePcap(records, linkType)));
}
const be16 = (v) => [(v >> 8) & 0xff, v & 0xff];
const be32 = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];

/** Build a BOOTP/DHCP message. options: [[code, bytes], ...] */
function dhcpMsg({ op = 1, xid = 0x1234, flags = 0, ciaddr = '0.0.0.0', yiaddr = '0.0.0.0', siaddr = '0.0.0.0', giaddr = '0.0.0.0', mac = '00:0c:29:aa:bb:cc', options = [], cookie = true, end = true }) {
  const b = new Uint8Array(236);
  b[0] = op; b[1] = 1; b[2] = 6; b[3] = 0;
  b.set(be32(xid), 4); b.set(be16(flags), 10);
  b.set(B.parseIp4(ciaddr), 12); b.set(B.parseIp4(yiaddr), 16); b.set(B.parseIp4(siaddr), 20); b.set(B.parseIp4(giaddr), 24);
  b.set(B.parseMac(mac), 28);
  const opts = [];
  for (const [code, bytes] of options) opts.push(code, bytes.length, ...bytes);
  if (end) opts.push(255);
  return new Uint8Array([...b, ...(cookie ? [0x63, 0x82, 0x53, 0x63] : []), ...opts]);
}
const clientFrame = (payload, mac = '00:0c:29:aa:bb:cc') => B.udpFrame({ src: '0.0.0.0', dst: '255.255.255.255', sport: 68, dport: 67, srcMac: mac, dstMac: 'ff:ff:ff:ff:ff:ff', payload });
const serverFrame = (payload, src = '192.168.1.1') => B.udpFrame({ src, dst: '255.255.255.255', sport: 67, dport: 68, srcMac: '00:50:56:11:22:33', dstMac: 'ff:ff:ff:ff:ff:ff', payload });

test('DHCP Discover/Offer/Request/ACK: summaries, options, leases, WPAD note', () => {
  const mac = '00:0c:29:aa:bb:cc';
  const discover = dhcpMsg({ op: 1, xid: 0x3d1d, options: [[53, [1]], [61, [1, ...B.parseMac(mac)]], [12, [...B.str('mypc')]], [55, [1, 3, 6, 15, 252]], [60, [...B.str('MSFT 5.0')]]] });
  const offer = dhcpMsg({ op: 2, xid: 0x3d1d, yiaddr: '192.168.1.100', siaddr: '192.168.1.1', options: [[53, [2]], [54, [192, 168, 1, 1]], [51, be32(86400)], [1, [255, 255, 255, 0]], [3, [192, 168, 1, 1]], [6, [8, 8, 8, 8, 1, 1, 1, 1]], [15, [...B.str('lan.local')]], [252, [...B.str('http://wpad.lan/wpad.dat')]]] });
  const request = dhcpMsg({ op: 1, xid: 0x3d1d, options: [[53, [3]], [50, [192, 168, 1, 100]], [54, [192, 168, 1, 1]], [12, [...B.str('mypc')]]] });
  const ack = dhcpMsg({ op: 2, xid: 0x3d1d, yiaddr: '192.168.1.100', options: [[53, [5]], [54, [192, 168, 1, 1]], [51, be32(86400)], [58, be32(43200)], [59, be32(75600)], [121, [24, 10, 0, 0, 192, 168, 1, 254, 0, 192, 168, 1, 1]], [119, [...B.dnsName('corp.example'), ...B.dnsName('example.com')]]] });
  const { packets, state } = analyze([
    { ts: 1, data: clientFrame(discover) }, { ts: 2, data: serverFrame(offer) }, { ts: 3, data: clientFrame(request) }, { ts: 4, data: serverFrame(ack) },
  ]);
  assert.deepEqual(packets.map(p => p.info), [
    'DHCP Discover - Transaction ID 0x3d1d',
    'DHCP Offer    - Transaction ID 0x3d1d',
    'DHCP Request  - Transaction ID 0x3d1d',
    'DHCP ACK      - Transaction ID 0x3d1d',
  ]);
  assert.equal(packets[0].proto, 'DHCP');
  const d = packets[0].layer('dhcp');
  assert.equal(d.op, 1); assert.equal(d.msgType, 1); assert.equal(d.msgTypeName, 'Discover');
  assert.equal(d.xid, 0x3d1d);
  assert.equal(d.clientMac, mac);
  assert.equal(d.hostname, 'mypc');
  assert.equal(d.vendorClass, 'MSFT 5.0');
  assert.deepEqual(d.paramRequestList, [1, 3, 6, 15, 252]);
  assert.match(d.options.find(o => o.code === 55).value, /1 \(Subnet Mask\), 3 \(Router\)/);
  assert.equal(d.options.find(o => o.code === 61).value, `Ethernet ${mac}`);
  const o = packets[1].layer('dhcp');
  assert.equal(o.yourIp, '192.168.1.100');
  assert.equal(o.serverId, '192.168.1.1');
  assert.equal(o.leaseTime, 86400);
  assert.deepEqual(o.dnsServers, ['8.8.8.8', '1.1.1.1']);
  assert.equal(o.subnetMask, '255.255.255.0');
  assert.equal(o.wpad, 'http://wpad.lan/wpad.dat');
  assert.ok(packets[1].tags.has('dhcp-wpad'));
  assert.ok(o.notes.some(n => /WPAD/.test(n)));
  assert.equal(packets[2].layer('dhcp').requestedIp, '192.168.1.100');
  const a = packets[3].layer('dhcp');
  assert.deepEqual(a.staticRoutes, ['10.0.0.0/24 -> 192.168.1.254', '0.0.0.0/0 -> 192.168.1.1']);
  assert.deepEqual(a.domainSearch, ['corp.example', 'example.com']);
  assert.equal(a.options.find(x => x.code === 58).value, '43200s (12 hours)');
  // Shared state.
  assert.equal(state.ext.dhcp.leases.length, 2);
  assert.equal(state.ext.dhcp.leases[0].tentative, true);
  const lease = state.ext.dhcp.leases[1];
  assert.deepEqual([lease.mac, lease.ip, lease.hostname, lease.server, lease.packet], [mac, '192.168.1.100', 'mypc', '192.168.1.1', 4]);
  assert.deepEqual([...state.ext.dhcp.servers], ['192.168.1.1']);
  assert.ok(!packets.some(p => p.tags.has('malformed')));
});

test('DHCP multiple servers are noted as possible rogue, NAK message shown', () => {
  const offer1 = dhcpMsg({ op: 2, xid: 1, yiaddr: '192.168.1.50', options: [[53, [2]], [54, [192, 168, 1, 1]]] });
  const offer2 = dhcpMsg({ op: 2, xid: 1, yiaddr: '192.168.1.66', options: [[53, [2]], [54, [192, 168, 1, 66]]] });
  const nak = dhcpMsg({ op: 2, xid: 2, options: [[53, [6]], [54, [192, 168, 1, 1]], [56, [...B.str('requested address not available')]]] });
  const { packets, state } = analyze([{ ts: 1, data: serverFrame(offer1) }, { ts: 2, data: serverFrame(offer2, '192.168.1.66') }, { ts: 3, data: serverFrame(nak) }]);
  assert.ok(!packets[0].tags.has('dhcp-multiple-servers'));
  assert.ok(packets[1].tags.has('dhcp-multiple-servers'));
  assert.match(packets[1].layer('dhcp').notes[0], /rogue/);
  assert.equal(state.ext.dhcp.servers.size, 2);
  assert.equal(packets[2].info, 'DHCP NAK      - Transaction ID 0x2 (requested address not available)');
});

test('DHCP malformed/truncated input never throws', () => {
  const full = dhcpMsg({ op: 1, xid: 9, options: [[53, [1]], [12, [...B.str('host')]]] });
  const cutHeader = full.subarray(0, 100);
  const cutOption = full.subarray(0, full.length - 3); // option 12 length says 4 but only 2 present, no End
  const bootp = dhcpMsg({ op: 1, xid: 7, cookie: false, end: false });
  const { packets } = analyze([{ ts: 1, data: clientFrame(cutHeader) }, { ts: 2, data: clientFrame(cutOption) }, { ts: 3, data: clientFrame(bootp) }]);
  assert.ok(packets[0].layer('dhcp'));
  assert.ok(packets[0].tags.has('malformed'));
  assert.match(packets[0].info, /truncated/);
  assert.ok(packets[1].layer('dhcp'));
  assert.ok(packets[1].tags.has('malformed'));
  assert.equal(packets[1].layer('dhcp').msgType, 1);
  assert.equal(packets[2].info, 'BOOTP Boot Request - Transaction ID 0x7');
  assert.equal(packets[2].layer('dhcp').isBootp, true);
  assert.ok(!packets[2].tags.has('malformed'));
});

function v6opt(code, bytes) { return [...be16(code), ...be16(bytes.length), ...bytes]; }
const v6frame = (src, dst, sport, dport, payload) => B.eth({ type: 0x86dd, payload: B.ip6({ src, dst, nextHeader: 17, payload: B.udp({ src: '0.0.0.0', dst: '0.0.0.0', sport, dport, payload }) }) });

test('DHCPv6 Solicit and Reply with IA_NA, DNS, domain list, FQDN', () => {
  const duid = [0, 1, 0, 1, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95];
  const sduid = [0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
  const solicit = new Uint8Array([1, 0x12, 0x34, 0x56, ...v6opt(1, duid), ...v6opt(3, [...be32(1), ...be32(0), ...be32(0)]), ...v6opt(6, [...be16(23), ...be16(24)]), ...v6opt(8, [0, 0])]);
  const iaAddr = v6opt(5, [...B.parseIp6('2001:db8::100'), ...be32(3600), ...be32(7200)]);
  const reply = new Uint8Array([7, 0x12, 0x34, 0x56, ...v6opt(1, duid), ...v6opt(2, sduid),
    ...v6opt(3, [...be32(1), ...be32(1800), ...be32(2880), ...iaAddr]),
    ...v6opt(23, [...B.parseIp6('2001:4860:4860::8888')]),
    ...v6opt(24, [...B.dnsName('example.com')]),
    ...v6opt(39, [1, ...B.dnsName('host1.example.com')]),
    ...v6opt(13, [...be16(0), ...B.str('ok')])]);
  const { packets, state } = analyze([
    { ts: 1, data: v6frame('fe80::1', 'ff02::1:2', 546, 547, solicit) },
    { ts: 2, data: v6frame('fe80::2', 'fe80::1', 547, 546, reply) },
  ]);
  assert.equal(packets[0].proto, 'DHCPv6');
  assert.equal(packets[0].info, 'Solicit XID: 0x123456 CID: 000100011c39cf88080027fe8f95');
  const s = packets[0].layer('dhcpv6');
  assert.equal(s.msgType, 1); assert.equal(s.msgTypeName, 'Solicit'); assert.equal(s.xid, 0x123456);
  assert.match(s.options.find(o => o.code === 6).value, /DNS recursive name server \(23\)/);
  const r = packets[1].layer('dhcpv6');
  assert.equal(r.msgTypeName, 'Reply');
  assert.equal(r.serverId, '00030001aabbccddeeff');
  assert.equal(r.iaAddr, '2001:db8::100');
  assert.deepEqual(r.dnsServers, ['2001:4860:4860::8888']);
  assert.deepEqual(r.domains, ['example.com']);
  assert.equal(r.fqdn, 'host1.example.com');
  assert.equal(r.status, 0);
  assert.match(packets[1].info, /^Reply XID: 0x123456 CID: 000100011c39cf88080027fe8f95 IAA: 2001:db8::100$/);
  assert.equal(state.ext.dhcpv6.leases[0].ip, '2001:db8::100');
  // Truncated option does not throw.
  const bad = new Uint8Array([1, 1, 2, 3, ...be16(1), ...be16(40), 1, 2]);
  const r2 = analyze([{ ts: 1, data: v6frame('fe80::1', 'ff02::1:2', 546, 547, bad) }]);
  assert.ok(r2.packets[0].layer('dhcpv6'));
  assert.ok(r2.packets[0].tags.has('malformed'));
});
