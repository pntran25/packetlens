// End-to-end: build the demo capture, dissect it, run the full analysis engine,
// and assert the seeded protocols and threats are all recovered. This is the
// canary that the whole system fits together.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import { buildSample } from '../fixtures/sample.js';
import * as A from '../src/analysis/index.js';

function run() {
  const cap = readCapture(buildSample());
  const { packets, state } = dissectCapture(cap);
  const analysis = A.analyze(packets, state, cap);
  return { cap, packets, state, analysis };
}

test('sample capture dissects into the expected protocol mix', () => {
  const { packets } = run();
  const seen = new Set(packets.map(p => p.proto));
  for (const proto of ['ARP', 'DNS', 'HTTP', 'FTP', 'TLS', 'ICMP', 'TCP']) {
    assert.ok(seen.has(proto), `expected ${proto} in capture, saw ${[...seen].join(',')}`);
  }
});

test('full analysis is JSON-serializable (worker transport contract)', () => {
  const { analysis } = run();
  const clean = (o) => JSON.stringify(o, (k, v) => {
    if (v instanceof Uint8Array) return undefined;
    if (v instanceof Set) return [...v];
    if (v instanceof Map) return Object.fromEntries(v);
    return v;
  });
  assert.doesNotThrow(() => clean({ summary: analysis.summary, conversations: analysis.conversations, iocs: analysis.iocs }));
});

test('threats seeded into the sample are all detected', () => {
  const { analysis } = run();
  const alerts = analysis.iocs.alerts || [];
  const titles = alerts.map(a => a.title.toLowerCase());
  const has = (re) => titles.some(t => re.test(t));
  assert.ok(has(/arp spoof/), 'ARP spoofing');
  assert.ok(has(/port scan/), 'port scan');
  assert.ok(has(/(plaintext|cleartext).*(credential|ftp|http)/), 'plaintext credentials');
  assert.ok(has(/dns (tunnel|exfil)/), 'DNS tunneling');
  assert.ok(alerts.some(a => a.severity === 'high'), 'at least one high-severity alert');
});

test('credentials from HTTP Basic and FTP are recovered', () => {
  const { analysis } = run();
  const creds = analysis.iocs.credentials || [];
  assert.ok(creds.some(c => c.proto === 'ftp' && c.user === 'alice'), 'FTP creds');
  assert.ok(creds.some(c => c.proto === 'http' && c.user === 'admin'), 'HTTP basic creds');
});

test('the PNG transferred over HTTP is carved with a correct hash', () => {
  const { analysis } = run();
  const files = analysis.extraction.files || [];
  const png = files.find(f => (f.fileType || '').includes('png') || (f.contentType || '').includes('png'));
  assert.ok(png, 'PNG extracted');
  assert.ok(png.sha256 && png.sha256.length === 64, 'sha256 present');
  assert.ok(png.size > 0, 'non-empty');
});

test('conversations and protocol hierarchy are populated', () => {
  const { analysis } = run();
  assert.ok((analysis.conversations.hosts || []).length >= 4, 'hosts');
  assert.ok((analysis.conversations.tcpConvs || []).length >= 3, 'tcp conversations');
  assert.ok(analysis.summary.protocolHierarchy, 'hierarchy tree exists');
  assert.ok(analysis.summary.packetCount > 0);
});

test('exported pcap of the whole capture round-trips', () => {
  const { packets, cap } = run();
  const out = writePcap(packets.map(p => ({ ts: p.ts, data: p.data, origLen: p.origLen })), cap.interfaces[0].linkType);
  const reparsed = readCapture(out);
  assert.equal(reparsed.records.length, packets.length);
});
