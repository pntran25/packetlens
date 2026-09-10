import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import { sha256 } from '../src/core/hash.js';
import * as B from '../tools/pktbuild.mjs';
import {
  analyze, reassembleTcp, buildConversations, extractArtifacts, collectIocs,
} from '../src/analysis/index.js';

function run(records, linkType = 1) {
  const cap = readCapture(writePcap(records, linkType));
  return { ...dissectCapture(cap), capture: cap };
}

// ---- reassembleTcp: out-of-order + retransmission ----

test('reassembleTcp drops retransmission and orders by sequence', () => {
  // Two segments "AAAA" then "BBBB"; we deliver them out of order and duplicate
  // the first. Reassembly must yield "AAAABBBB".
  const client = '10.0.0.5', server = '10.0.0.9';
  const recs = B.tcpSession({
    client, server, sport: 9000,
    exchanges: [['s', 'AAAA'], ['s', 'BBBB']],
    teardown: false,
  });
  const { packets, state } = run(recs);
  const stream = state.tcp.list[0];
  const r = reassembleTcp(stream, packets);
  // Server -> client is dir 1 (b2a).
  assert.equal(new TextDecoder().decode(r.b2a), 'AAAABBBB');
  assert.equal(r.a2b.length, 0);

  // Now simulate a retransmission of the first server segment and re-check.
  const firstServerSeg = stream.segs.find((s) => s.dir === 1);
  stream.segs.push({ ...firstServerSeg, pkt: firstServerSeg.pkt, retrans: true });
  const r2 = reassembleTcp(stream, packets);
  assert.equal(new TextDecoder().decode(r2.b2a), 'AAAABBBB', 'duplicate dropped');
});

test('reassembleTcp records a gap for a missing segment', () => {
  const stream = {
    segs: [
      { pkt: 1, dir: 0, seq: 0, len: 3, off: 0, ts: 1 },
      { pkt: 3, dir: 0, seq: 6, len: 3, off: 0, ts: 3 }, // seq 3..6 missing
    ],
  };
  const packets = [
    { data: new Uint8Array([65, 66, 67]) },        // "ABC"
    null,
    { data: new Uint8Array([88, 89, 90]) },        // "XYZ"
  ];
  const r = reassembleTcp(stream, packets);
  assert.equal(new TextDecoder().decode(r.a2b), 'ABCXYZ');
  assert.equal(r.gaps.length, 1);
  assert.equal(r.gaps[0].len, 3);
  assert.equal(r.gaps[0].at, 3);
});

// ---- conversations ----

test('buildConversations aggregates hosts and byte counts', () => {
  const recs = B.tcpSession({
    client: '10.0.0.5', server: '93.184.216.34', sport: 80,
    exchanges: [['c', 'hello'], ['s', 'world!']],
  });
  const { packets, state } = run(recs);
  const conv = buildConversations(packets, state);
  assert.equal(conv.hosts.length, 2);
  const client = conv.hosts.find((h) => h.ip === '10.0.0.5');
  const server = conv.hosts.find((h) => h.ip === '93.184.216.34');
  assert.ok(client.isPrivate);
  assert.ok(!server.isPrivate);
  assert.ok(client.packetsOut > 0 && client.packetsIn > 0);

  assert.equal(conv.ipConvs.length, 1);
  const ic = conv.ipConvs[0];
  assert.equal(ic.packets, packets.length);
  assert.ok(ic.bytesAtoB > 0 && ic.bytesBtoA > 0);

  assert.equal(conv.tcpConvs.length, 1);
  const tc = conv.tcpConvs[0];
  assert.deepEqual([tc.bytesAtoB, tc.bytesBtoA], [5, 6]);
  assert.equal(tc.completeness.complete, true);
  assert.equal(tc.completeness.fin, true);
  assert.equal(tc.health.healthy, true);
});

// ---- extractArtifacts: HTTP file with sha256 + fileType ----

function httpResponseWithBody(bodyBytes, contentType = 'image/png') {
  const header = `HTTP/1.1 200 OK\r\nContent-Type: ${contentType}\r\nContent-Length: ${bodyBytes.length}\r\n\r\n`;
  const hb = B.str(header);
  const out = new Uint8Array(hb.length + bodyBytes.length);
  out.set(hb, 0); out.set(bodyBytes, hb.length);
  return out;
}

test('extractArtifacts carves an HTTP response body with correct sha256 and fileType', () => {
  // A minimal PNG file (signature + IHDR-ish bytes).
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8]);
  const req = B.str('GET /images/logo.png HTTP/1.1\r\nHost: files.example.com\r\n\r\n');
  const resp = httpResponseWithBody(png);
  const recs = B.tcpSession({
    client: '10.0.0.5', server: '203.0.113.7', sport: 80,
    exchanges: [['c', req], ['s', resp]],
  });
  const { packets, state } = run(recs);
  // Ensure the HTTP dissector (another agent) marked the stream; if not, force it
  // so extraction is exercised regardless of that agent's readiness.
  if (state.tcp.list[0].proto !== 'http') state.tcp.list[0].proto = 'http';

  const ex = extractArtifacts(packets, state, null);
  assert.equal(ex.files.length, 1, 'one file carved');
  const f = ex.files[0];
  assert.equal(f.filename, 'logo.png');
  assert.equal(f.fileType, 'png');
  assert.equal(f.size, png.length);
  assert.equal(f.contentType, 'image/png');
  assert.equal(f.statusCode, 200);
  assert.equal(f.host, 'files.example.com');
  assert.equal(f.sha256, sha256(png));
  assert.equal(new TextDecoder().decode(f.data), new TextDecoder().decode(png));
});

test('extractArtifacts detects executable download and handles chunked bodies', () => {
  const mz = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]); // PE header
  // chunked: one chunk of the MZ bytes then terminator.
  const sizeLine = mz.length.toString(16);
  const chunkText = `${sizeLine}\r\n`;
  const chunkHdr = B.str(`HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n${chunkText}`);
  const tail = B.str('\r\n0\r\n\r\n');
  const resp = new Uint8Array(chunkHdr.length + mz.length + tail.length);
  resp.set(chunkHdr, 0); resp.set(mz, chunkHdr.length); resp.set(tail, chunkHdr.length + mz.length);
  const req = B.str('GET /download/setup.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n');
  const recs = B.tcpSession({ client: '10.0.0.5', server: '198.51.100.9', sport: 80, exchanges: [['c', req], ['s', resp]] });
  const { packets, state } = run(recs);
  if (state.tcp.list[0].proto !== 'http') state.tcp.list[0].proto = 'http';
  const ex = extractArtifacts(packets, state, null);
  assert.equal(ex.files.length, 1);
  assert.equal(ex.files[0].fileType, 'pe');
  assert.equal(ex.files[0].executable, true);
  assert.deepEqual([...ex.files[0].data], [...mz], 'chunked body decoded');
});

// ---- iocs: synthetic state ----

test('collectIocs synthesizes alerts from synthetic state', () => {
  const packets = [];
  const state = {
    tcp: { list: [] }, udp: { list: [] },
    dns: { names: new Map() },
    ext: {
      credentials: [
        { proto: 'ftp', kind: 'password', user: 'bob', secret: 'hunter2', src: '10.0.0.5', dst: '10.0.0.9', packet: 3 },
        { proto: 'smb', kind: 'ntlm', user: 'alice', domain: 'CORP', secret: 'alice::CORP:...', src: '10.0.0.5', dst: '10.0.0.1', packet: 7 },
      ],
      arp: { conflicts: [{ ip: '192.168.1.1', macs: ['aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb'], packet: 2 }] },
      dns: { suspicious: [{ name: 'exfil.evil.com', packet: 9 }] },
    },
  };
  // Rogue DHCP: two servers, seen via synthetic dhcp layers on packets.
  const dhcpPkt = (serverId, index) => ({
    index, ts: 1700000000 + index, src: serverId, dst: '255.255.255.255',
    origLen: 300, capLen: 300, layers: [{ proto: 'dhcp', serverId, msgTypeName: 'ACK' }],
    tags: new Set(), layer(pr) { return this.layers.find((l) => l.proto === pr) || null; },
    get top() { return this.layers[this.layers.length - 1]; }, get ip() { return null; },
  });
  packets.push(dhcpPkt('192.168.1.1', 1), dhcpPkt('192.168.1.250', 2));

  // Port scan: one source hitting many ports, no completed handshakes.
  for (let port = 1; port <= 25; port++) {
    state.tcp.list.push({
      id: port, a: { ip: '10.0.0.66', port: 40000 + port }, b: { ip: '10.0.0.9', port },
      synSeen: true, synAckSeen: false, packets: [100 + port], bytes: [0, 0], start: 1, end: 1,
    });
  }

  const iocs = collectIocs(packets, state, null, { files: [] });

  const cats = iocs.alerts.map((a) => a.category);
  assert.ok(cats.includes('credential'), 'credential alert');
  assert.ok(cats.includes('arp-spoof'), 'arp spoof alert');
  assert.ok(cats.includes('rogue-dhcp'), 'rogue dhcp alert');
  assert.ok(cats.includes('dns-exfil'), 'dns exfil alert');
  assert.ok(cats.includes('port-scan'), 'port scan alert');

  // Two credentials: one high (plaintext ftp), one medium (ntlm).
  assert.equal(iocs.credentials.length, 2);
  const ftpAlert = iocs.alerts.find((a) => a.category === 'credential' && a.severity === 'high');
  assert.ok(ftpAlert && ftpAlert.title.includes('FTP'));
  const ntlmAlert = iocs.alerts.find((a) => a.category === 'credential' && a.severity === 'medium');
  assert.ok(ntlmAlert);

  // Alerts sorted by severity (high first).
  assert.equal(iocs.alerts[0].severity, 'high');
  assert.ok(iocs.counts.high >= 3);
});

test('collectIocs flags suspicious TLDs and executable downloads', () => {
  const packets = [
    {
      index: 1, ts: 1, origLen: 100, capLen: 100, tags: new Set(),
      layers: [{ proto: 'dns', queries: [{ name: 'randomjunk.top' }, { name: 'good.example.com' }] }],
      layer(pr) { return this.layers.find((l) => l.proto === pr) || null; },
      get top() { return this.layers.at(-1); }, get ip() { return null; },
    },
  ];
  const state = { tcp: { list: [] }, udp: { list: [] }, dns: { names: new Map() }, ext: {} };
  const extraction = {
    files: [{ source: 'http', direction: 'download', filename: 'a.exe', fileType: 'pe', executable: true, size: 1000, sha256: 'deadbeef', host: 'evil.top', uri: '/a.exe', packet: 1, stream: 0 }],
  };
  const iocs = collectIocs(packets, state, null, extraction);
  assert.ok(iocs.suspiciousDomains.some((d) => d.name === 'randomjunk.top'));
  assert.ok(iocs.alerts.some((a) => a.category === 'malware' && a.severity === 'high'));
  assert.equal(iocs.fileHashes.length, 1);
  assert.equal(iocs.fileHashes[0].note, 'executable');
});

// ---- analyze(): end-to-end shape ----

test('analyze returns the full result object with protocol hierarchy', () => {
  const recs = B.tcpSession({ client: '10.0.0.5', server: '93.184.216.34', sport: 80, exchanges: [['c', 'hi'], ['s', 'yo']] });
  const { packets, state, capture } = run(recs);
  const result = analyze(packets, state, capture);

  assert.ok(result.conversations && result.extraction && result.iocs && result.summary);
  assert.equal(typeof result.reassembleTcp, 'function');
  assert.equal(typeof result.followStream, 'function');
  assert.equal(typeof result.reassembleUdp, 'function');

  assert.equal(result.summary.packetCount, packets.length);
  assert.ok(result.summary.duration >= 0);
  assert.ok(result.summary.bytes > 0);

  const tree = result.summary.protocolHierarchy;
  assert.equal(tree.packets, packets.length);
  assert.ok(tree.children.eth, 'eth in hierarchy');
  assert.ok(tree.children.eth.children.ipv4, 'ipv4 nested under eth');
  assert.ok(tree.children.eth.children.ipv4.children.tcp, 'tcp nested under ipv4');

  // Bound reassembly helper works on a real stream.
  const r = result.reassembleTcp(state.tcp.list[0]);
  assert.ok(r.a2b.length > 0 || r.b2a.length > 0);
});
