import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import * as B from '../tools/pktbuild.mjs';
import { decodeNbName } from '../src/dissectors/app/nbns.js';

function analyze(records, linkType = 1) {
  return dissectCapture(readCapture(writePcap(records, linkType)));
}
const be16 = (v) => [(v >> 8) & 0xff, v & 0xff];
const be32 = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
const le16 = (v) => [v & 0xff, (v >> 8) & 0xff];
const le32 = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];

/** First-level encode a NetBIOS name into a DNS-style label sequence. */
function nbName(name, suffix, pad = 0x20) {
  const bytes = new Array(16).fill(pad);
  for (let i = 0; i < Math.min(15, name.length); i++) bytes[i] = name.charCodeAt(i);
  bytes[15] = suffix;
  const label = bytes.map(b => String.fromCharCode(65 + (b >> 4)) + String.fromCharCode(65 + (b & 15))).join('');
  return [32, ...B.str(label), 0];
}
const hdr = (id, flags, qd, an, ns, ar) => [...be16(id), ...be16(flags), ...be16(qd), ...be16(an), ...be16(ns), ...be16(ar)];
const nbRR = (name, suffix, ip, flags = 0x6000, ttl = 300000) => [...nbName(name, suffix), ...be16(32), ...be16(1), ...be32(ttl), ...be16(6), ...be16(flags), ...B.parseIp4(ip)];
const frame = (src, dst, sport, dport, payload) => B.udpFrame({ src, dst, sport, dport, payload: new Uint8Array(payload) });

test('NBNS name query, response, registration, NBSTAT', () => {
  const query = [...hdr(0x8001, 0x0110, 1, 0, 0, 0), ...nbName('WORKSTATION', 0x20), ...be16(32), ...be16(1)];
  const resp = [...hdr(0x8001, 0x8580, 0, 1, 0, 0), ...nbRR('WORKSTATION', 0x20, '10.0.0.5')];
  const reg = [...hdr(0x8002, 0x2910, 1, 0, 0, 1), ...nbName('HOSTNAME', 0x00), ...be16(32), ...be16(1), ...nbRR('HOSTNAME', 0x00, '10.0.0.7')];
  const nxdom = [...hdr(0x8003, 0x8583, 0, 0, 0, 0)];
  const nbstatQ = [...hdr(0x8004, 0x0000, 1, 0, 0, 0), ...nbName('*', 0x00, 0x00), ...be16(33), ...be16(1)];
  const { packets, state } = analyze([
    { ts: 1, data: frame('10.0.0.9', '10.0.0.255', 137, 137, query) },
    { ts: 2, data: frame('10.0.0.5', '10.0.0.9', 137, 137, resp) },
    { ts: 3, data: frame('10.0.0.7', '10.0.0.255', 137, 137, reg) },
    { ts: 4, data: frame('10.0.0.1', '10.0.0.9', 137, 137, nxdom) },
    { ts: 5, data: frame('10.0.0.9', '10.0.0.5', 137, 137, nbstatQ) },
  ]);
  assert.equal(packets[0].proto, 'NBNS');
  assert.equal(packets[0].info, 'Name query NB WORKSTATION<20>');
  assert.equal(packets[1].info, 'Name query response NB 10.0.0.5');
  assert.match(packets[2].info, /^Registration NB HOSTNAME<00>/);
  assert.equal(packets[3].info, 'Name query response, Requested name does not exist');
  assert.equal(packets[4].info, 'Name query NBSTAT *<00>');
  const q = packets[0].layer('nbns');
  assert.equal(q.id, 0x8001); assert.equal(q.isResponse, false); assert.equal(q.opcode, 0); assert.equal(q.flags.b, true);
  assert.deepEqual([q.queries[0].name, q.queries[0].suffix, q.queries[0].suffixName, q.queries[0].typeName], ['WORKSTATION', 0x20, 'File Server', 'NB']);
  const r = packets[1].layer('nbns');
  assert.equal(r.isResponse, true); assert.equal(r.flags.aa, true);
  assert.equal(r.answers[0].display, 'WORKSTATION<20>');
  assert.deepEqual(r.answers[0].addrs, ['10.0.0.5']);
  assert.equal(r.answers[0].flags.nodeType, 'H-node');
  assert.equal(r.addr, '10.0.0.5');
  const g = packets[2].layer('nbns');
  assert.equal(g.opcodeName, 'Registration');
  assert.equal(g.additionals[0].addrs[0], '10.0.0.7');
  assert.equal(packets[3].layer('nbns').rcode, 3);
  assert.ok(state.ext.nbns.names.get('10.0.0.5').has('WORKSTATION<20>'));
  assert.ok(state.ext.nbns.byName.get('HOSTNAME').has('10.0.0.7'));
  assert.equal(state.udp.list[0].proto, 'nbns');
  assert.ok(!packets.some(p => p.tags.has('malformed')));
});

test('NBNS name decoding and truncated input', () => {
  // 'FHEPFCELEHFCEPFFFACACACACACACABN' is WORKGROUP padded with spaces, suffix 0x1d.
  const d = decodeNbName('FHEPFCELEHFCEPFFFACACACACACACABN');
  assert.equal(d.display, 'WORKGROUP<1d>');
  assert.equal(d.suffix, 0x1d);
  assert.equal(decodeNbName('notencoded').display, 'notencoded');
  const enc = nbName('WIN10', 0x1d).slice(1, 33).map(c => String.fromCharCode(c)).join('');
  assert.deepEqual([decodeNbName(enc).name, decodeNbName(enc).suffixName], ['WIN10', 'Master Browser']);
  const full = [...hdr(1, 0x0110, 1, 0, 0, 0), ...nbName('WORKSTATION', 0x20), ...be16(32), ...be16(1)];
  const { packets } = analyze([{ ts: 1, data: frame('10.0.0.9', '10.0.0.255', 137, 137, full.slice(0, 30)) }]);
  assert.ok(packets[0].layer('nbns'));
  assert.ok(packets[0].tags.has('malformed'));
  assert.equal(packets[0].layer('nbns').queries.length, 0);
});

function smbMailslotBrowse(browserData) {
  const smbHdr = [0xff, 0x53, 0x4d, 0x42, 0x25, 0, 0, 0, 0, 0x18, 0x03, 0x00, ...new Array(20).fill(0)];
  const name = [...B.str('\\MAILSLOT\\BROWSE'), 0];
  const wct = 17;
  const dataOffset = 32 + 1 + wct * 2 + 2 + name.length;
  const params = [...le16(0), ...le16(browserData.length), ...le16(0), ...le16(0), 0, 0, ...le16(0), ...le32(1000), ...le16(0), ...le16(0), ...le16(dataOffset), ...le16(browserData.length), ...le16(dataOffset), 3, 0, ...le16(1), ...le16(0), ...le16(2)];
  const bcc = name.length + browserData.length;
  return [...smbHdr, wct, ...params, ...le16(bcc), ...name, ...browserData];
}

test('NBDGM direct group datagram with SMB MailSlot Host Announcement', () => {
  const host = 'WIN10PC';
  const hostBytes = new Array(16).fill(0); for (let i = 0; i < host.length; i++) hostBytes[i] = host.charCodeAt(i);
  const browser = [1, 0, ...le32(720000), ...hostBytes, 6, 1, ...le32(0x00011003), 15, 1, ...le16(0xaa55), ...B.str('Office PC'), 0];
  const smb = smbMailslotBrowse(browser);
  const srcName = nbName('WIN10PC', 0x00), dstName = nbName('WORKGROUP', 0x1d);
  const payload = [0x11, 0x02, ...be16(0x1234), ...B.parseIp4('10.0.0.20'), ...be16(138), ...be16(smb.length + srcName.length + dstName.length), ...be16(0), ...srcName, ...dstName, ...smb];
  const { packets, state } = analyze([{ ts: 1, data: frame('10.0.0.20', '10.0.0.255', 138, 138, payload) }]);
  const p = packets[0];
  assert.equal(p.proto, 'NBDS');
  assert.equal(p.info, 'Host Announcement WIN10PC, Workstation, Server, NT Workstation, Potential Browser');
  const l = p.layer('nbdgm');
  assert.equal(l.msgType, 0x11); assert.equal(l.msgTypeName, 'Direct_group datagram');
  assert.equal(l.srcIp, '10.0.0.20'); assert.equal(l.srcPort, 138); assert.equal(l.dgmId, 0x1234);
  assert.equal(l.srcDisplay, 'WIN10PC<00>'); assert.equal(l.dstDisplay, 'WORKGROUP<1d>');
  assert.equal(l.mailslot, '\\MAILSLOT\\BROWSE');
  assert.equal(l.browserCommand, 1);
  assert.equal(l.host, 'WIN10PC'); assert.equal(l.osVersion, '6.1'); assert.equal(l.comment, 'Office PC');
  assert.equal(l.serverType, 0x00011003);
  assert.ok(state.ext.nbns.names.get('10.0.0.20').has('WIN10PC<00>'));
  assert.ok(!p.tags.has('malformed'));
  // Truncated datagram (cut inside the SMB header) does not throw.
  const cut = payload.slice(0, payload.length - smb.length + 10);
  const r2 = analyze([{ ts: 1, data: frame('10.0.0.20', '10.0.0.255', 138, 138, cut) }]);
  assert.ok(r2.packets[0].layer('nbdgm'));
  assert.ok(r2.packets[0].tags.has('malformed'));
  assert.equal(r2.packets[0].layer('nbdgm').srcDisplay, 'WIN10PC<00>');
});
