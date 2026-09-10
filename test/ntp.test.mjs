import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import * as B from '../tools/pktbuild.mjs';

function analyze(records, linkType = 1) {
  return dissectCapture(readCapture(writePcap(records, linkType)));
}
const be32 = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
const NTP_EPOCH = 2208988800;
const ts = (unix, frac = 0) => [...be32(unix + NTP_EPOCH), ...be32(frac)];

function ntpMsg({ li = 0, vn = 4, mode = 3, stratum = 0, poll = 6, precision = 0xe9, rootDelay = 0, rootDisp = 0, refId = [0, 0, 0, 0], ref = [0, 0, 0, 0, 0, 0, 0, 0], orig = ref, rx = ref, tx }) {
  return new Uint8Array([(li << 6) | (vn << 3) | mode, stratum, poll, precision, ...be32(rootDelay), ...be32(rootDisp), ...refId, ...ref, ...orig, ...rx, ...tx]);
}
const exch = (exchanges) => B.udpExchange({ client: '10.0.0.5', server: '129.6.15.28', sport: 123, cport: 123, exchanges });

test('NTP client/server exchange: summary, mode names, stratum, ref id, timestamps', () => {
  const t0 = 1700000000;
  const client = ntpMsg({ mode: 3, stratum: 0, tx: ts(t0, 0x80000000) });
  const server = ntpMsg({ mode: 4, stratum: 2, poll: 6, precision: 0xe9, rootDelay: 0x00000a3d, rootDisp: 0x000002f0, refId: [10, 0, 0, 1], ref: ts(t0 - 100), orig: ts(t0, 0x80000000), rx: ts(t0 + 1), tx: ts(t0 + 1, 0x40000000) });
  const { packets } = analyze(exch([['c', client], ['s', server]]));
  assert.equal(packets[0].proto, 'NTP');
  assert.equal(packets[0].info, 'NTP Version 4, client');
  assert.equal(packets[1].info, 'NTP Version 4, server');
  const c = packets[0].layer('ntp'), s = packets[1].layer('ntp');
  assert.equal(c.mode, 3); assert.equal(c.modeName, 'client'); assert.equal(c.version, 4); assert.equal(c.leap, 0);
  assert.equal(c.txTime, '2023-11-14T22:13:20.500000Z');
  assert.equal(c.refTime, 'NULL');
  assert.equal(s.mode, 4); assert.equal(s.modeName, 'server'); assert.equal(s.stratum, 2);
  assert.equal(s.refId, '10.0.0.1');
  assert.equal(s.poll, 6); assert.equal(s.precision, -23);
  assert.ok(Math.abs(s.rootDelay - 0x0a3d / 65536) < 1e-9);
  assert.equal(s.origTime, '2023-11-14T22:13:20.500000Z');
  assert.equal(s.rxTime, '2023-11-14T22:13:21.000000Z');
  assert.equal(s.txTime, '2023-11-14T22:13:21.250000Z');
  assert.equal(s.refTime, '2023-11-14T22:11:40.000000Z');
  assert.ok(!packets[1].tags.has('malformed'));
});

test('NTP stratum 1 and kiss-o-death reference ids render as ASCII', () => {
  const gps = ntpMsg({ mode: 4, stratum: 1, refId: [...B.str('GPS ')], tx: ts(1700000000) });
  const kod = ntpMsg({ li: 3, mode: 4, stratum: 0, refId: [...B.str('RATE')], tx: ts(1700000000) });
  const { packets } = analyze(exch([['s', gps], ['s', kod]]));
  assert.equal(packets[0].layer('ntp').refId, 'GPS');
  assert.match(packets[1].layer('ntp').refId, /^RATE \(kiss-o'-death/);
  assert.ok(packets[1].tags.has('ntp-kod'));
  assert.equal(packets[1].layer('ntp').leapName, 'unknown (clock unsynchronized)');
  assert.match(packets[1].info, /KoD RATE/);
});

test('NTP mode 7 monlist request/response are flagged, mode 6 control decoded', () => {
  const monlist = new Uint8Array([0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0, ...new Array(40).fill(0)]);
  // monlist response: R bit set, 1 item of 72 bytes with src addr at +16.
  const item = new Uint8Array(72); item.set([192, 168, 5, 5], 16);
  const monResp = new Uint8Array([0x97, 0x00, 0x03, 0x2a, 0x00, 0x01, 0x00, 72, ...item]);
  const ctrl = new Uint8Array([0x16, 0x02, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
  const { packets } = analyze(exch([['c', monlist], ['s', monResp], ['c', ctrl]]));
  assert.match(packets[0].info, /^NTP private message \(mode 7\), MON_GETLIST_1 \(42\) request/);
  assert.ok(packets[0].tags.has('ntp-monlist'));
  assert.equal(packets[0].layer('ntp').requestCode, 42);
  assert.equal(packets[0].layer('ntp').mode, 7);
  assert.equal(packets[0].layer('ntp').modeName, 'private');
  assert.ok(packets[1].tags.has('ntp-monlist'));
  assert.deepEqual(packets[1].layer('ntp').monlist, ['192.168.5.5']);
  assert.match(packets[1].info, /response, 1 items/);
  assert.match(packets[2].info, /^NTP control message, read variables request/);
  assert.equal(packets[2].layer('ntp').modeName, 'control');
  assert.equal(packets[2].layer('ntp').opcode, 2);
  assert.ok(packets[2].tags.has('ntp-control'));
});

test('NTP truncated packet yields partial layer without throwing', () => {
  const short = ntpMsg({ mode: 3, tx: ts(1700000000) }).subarray(0, 20);
  const { packets } = analyze(exch([['c', short]]));
  const l = packets[0].layer('ntp');
  assert.ok(l);
  assert.equal(l.modeName, 'client');
  assert.ok(packets[0].tags.has('malformed'));
  assert.match(packets[0].info, /truncated/);
  // Non-NTP on port 123 (version 0) is declined.
  const junk = new Uint8Array(48);
  const r2 = analyze(exch([['c', junk]]));
  assert.equal(r2.packets[0].layers.at(-1).proto, 'data');
});
