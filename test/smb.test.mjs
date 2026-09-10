import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import * as B from '../tools/pktbuild.mjs';

function run(records, linkType = 1) {
  const cap = readCapture(writePcap(records, linkType));
  return dissectCapture(cap);
}

// ---- SMB2 message builders ----

function u16le(v) { return [v & 0xff, (v >> 8) & 0xff]; }
function u32le(v) { return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]; }
function utf16le(s) { const out = []; for (const ch of s) { const c = ch.charCodeAt(0); out.push(c & 0xff, (c >> 8) & 0xff); } return out; }

function nbss(msg) {
  const len = msg.length;
  return new Uint8Array([0x00, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, ...msg]);
}

function smb2Header({ command, flags = 0, messageId = 0, treeId = 0, sessionId = 0, status = 0 }) {
  const h = new Uint8Array(64);
  h.set([0xfe, 0x53, 0x4d, 0x42], 0);      // \xfeSMB
  h.set(u16le(64), 4);                      // StructureSize
  h.set(u32le(status), 8);                  // Status
  h.set(u16le(command), 12);                // Command
  h.set(u32le(flags), 16);                  // Flags
  h.set(u32le(messageId), 24);              // MessageId (low 32)
  h.set(u32le(treeId), 36);                 // TreeId
  h.set(u32le(sessionId), 40);              // SessionId (low 32)
  return h;
}

function smb2Negotiate() {
  const body = new Uint8Array([...u16le(36), ...u16le(2), 0, 0, ...u32le(0)]); // minimal
  return nbss(new Uint8Array([...smb2Header({ command: 0, messageId: 1 }), ...body]));
}

function smb2TreeConnect(path) {
  const pathBytes = utf16le(path);
  const pathOffset = 64 + 8; // header + fixed body
  const body = [
    ...u16le(9),          // StructureSize
    ...u16le(0),          // Flags/Reserved
    ...u16le(pathOffset), // PathOffset
    ...u16le(pathBytes.length), // PathLength
    ...pathBytes,
  ];
  return nbss(new Uint8Array([...smb2Header({ command: 3, messageId: 4, treeId: 0, sessionId: 1 }), ...body]));
}

function smb2Create(name) {
  const nameBytes = utf16le(name);
  const nameOffset = 64 + 56;
  const body = new Uint8Array(56 + nameBytes.length);
  body.set(u16le(57), 0);           // StructureSize
  body.set(u16le(nameOffset), 44);  // NameOffset
  body.set(u16le(nameBytes.length), 46); // NameLength
  body.set(nameBytes, 56);
  return nbss(new Uint8Array([...smb2Header({ command: 5, messageId: 5, treeId: 1, sessionId: 1 }), ...body]));
}

// NTLMSSP Type2 (Challenge) with a fixed 8-byte server challenge.
function ntlmType2(challenge) {
  const m = new Uint8Array(48);
  m.set([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00], 0);
  m.set(u32le(2), 8);
  m.set(u32le(0x00000001), 20); // flags: unicode
  m.set(challenge, 24);
  return m;
}

// NTLMSSP Type3 (Authenticate) with NTLMv2 response.
function ntlmType3({ domain, user, workstation, lm, nt }) {
  const dom = utf16le(domain), usr = utf16le(user), ws = utf16le(workstation);
  const payloadParts = [
    { name: 'lm', bytes: lm, fieldOff: 12 },
    { name: 'nt', bytes: nt, fieldOff: 20 },
    { name: 'dom', bytes: dom, fieldOff: 28 },
    { name: 'usr', bytes: usr, fieldOff: 36 },
    { name: 'ws', bytes: ws, fieldOff: 44 },
  ];
  let total = 64;
  for (const p of payloadParts) { p.off = total; total += p.bytes.length; }
  const m = new Uint8Array(total);
  m.set([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00], 0);
  m.set(u32le(3), 8);
  for (const p of payloadParts) {
    m.set(u16le(p.bytes.length), p.fieldOff);
    m.set(u16le(p.bytes.length), p.fieldOff + 2);
    m.set(u32le(p.off), p.fieldOff + 4);
    m.set(p.bytes, p.off);
  }
  m.set(u16le(0), 52); m.set(u32le(total), 56); // session key (empty)
  m.set(u32le(0x00000001), 60); // flags: unicode
  return m;
}

function smb2SessionSetup(ntlmMsg, { isResponse = false, messageId = 2 } = {}) {
  const secOffset = 64 + 24;
  const body = [
    ...u16le(25),        // StructureSize (request form; length not validated on scan path)
    0, 0,                // Flags / SecurityMode
    ...u32le(0),         // Capabilities
    ...u32le(0),         // Channel
    ...u16le(secOffset), // SecurityBufferOffset
    ...u16le(ntlmMsg.length), // SecurityBufferLength
    ...u32le(0), ...u32le(0), // PreviousSessionId
    ...ntlmMsg,
  ];
  return nbss(new Uint8Array([...smb2Header({ command: 1, messageId, sessionId: 1, flags: isResponse ? 1 : 0 }), ...body]));
}

test('SMB2 NEGOTIATE and TREE_CONNECT over NBSS', () => {
  const recs = B.tcpSession({
    client: '10.0.0.5', server: '10.0.0.1', sport: 445,
    exchanges: [['c', smb2Negotiate()], ['c', smb2TreeConnect('\\\\10.0.0.1\\C$')]],
  });
  const { packets, state } = run(recs);
  const smbPkts = packets.filter((p) => p.has('smb2'));
  assert.ok(smbPkts.length >= 2, 'two SMB2 packets dissected');

  const neg = smbPkts[0].layer('smb2');
  assert.equal(neg.commandName, 'NEGOTIATE');
  assert.equal(neg.isResponse, false);
  assert.equal(neg.summary, 'Negotiate Protocol Request');

  const tc = smbPkts[1].layer('smb2');
  assert.equal(tc.commandName, 'TREE_CONNECT');
  assert.equal(tc.tree, '\\\\10.0.0.1\\C$');
  assert.equal(tc.summary, 'Tree Connect Request Tree: \\\\10.0.0.1\\C$');

  assert.ok(state.ext.smb, 'smb state created');
  assert.ok(state.ext.smb.trees.has('\\\\10.0.0.1\\C$'));
  // Stream marked as smb2.
  assert.equal(state.tcp.list[0].proto, 'smb2');
});

test('SMB2 CREATE captures filename', () => {
  const recs = B.tcpSession({
    client: '10.0.0.5', server: '10.0.0.1', sport: 445,
    exchanges: [['c', smb2Create('windows\\system32\\calc.exe')]],
  });
  const { packets, state } = run(recs);
  const cr = packets.find((p) => p.has('smb2')).layer('smb2');
  assert.equal(cr.commandName, 'CREATE');
  assert.equal(cr.filename, 'windows\\system32\\calc.exe');
  assert.match(cr.summary, /Create Request File: windows\\system32\\calc\.exe/);
  assert.equal(state.ext.smb.files[0].name, 'windows\\system32\\calc.exe');
});

test('SMB2 SESSION_SETUP NTLMSSP Type3 captures a credential', () => {
  const challenge = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const nt = new Uint8Array(44);
  for (let i = 0; i < 44; i++) nt[i] = (0x10 + i) & 0xff; // 44 bytes -> NTLMv2
  const lm = new Uint8Array(24);
  const type2 = ntlmType2(challenge);
  const type3 = ntlmType3({ domain: 'CORP', user: 'alice', workstation: 'WS01', lm, nt });
  const recs = B.tcpSession({
    client: '10.0.0.5', server: '10.0.0.1', sport: 445,
    exchanges: [
      ['s', smb2SessionSetup(type2, { isResponse: true, messageId: 2 })],
      ['c', smb2SessionSetup(type3, { isResponse: false, messageId: 3 })],
    ],
  });
  const { packets, state } = run(recs);

  const setupPkts = packets.filter((p) => p.has('smb2') && p.layer('smb2').commandName === 'SESSION_SETUP');
  assert.ok(setupPkts.length >= 2);
  const authLayer = setupPkts.find((p) => p.layer('smb2').ntlm === 'NTLMSSP_AUTH').layer('smb2');
  assert.equal(authLayer.user, 'alice');
  assert.equal(authLayer.domain, 'CORP');
  assert.match(authLayer.summary, /Session Setup Request, NTLMSSP_AUTH User: CORP\\alice/);

  assert.ok(Array.isArray(state.ext.credentials), 'credentials array exists');
  const cred = state.ext.credentials.find((c) => c.proto === 'smb');
  assert.ok(cred, 'smb credential captured');
  assert.equal(cred.kind, 'ntlm');
  assert.equal(cred.user, 'alice');
  assert.equal(cred.domain, 'CORP');
  assert.equal(cred.note, 'netntlmv2');
  // hashcat -m 5600: user::domain:challenge:NTProof:blob
  assert.ok(cred.secret.startsWith('alice::CORP:0102030405060708:'), `secret was ${cred.secret}`);
  const ntHex = [...nt].map((b) => b.toString(16).padStart(2, '0')).join('');
  assert.ok(cred.secret.endsWith(`${ntHex.slice(0, 32)}:${ntHex.slice(32)}`));

  // SMB session tracked.
  assert.ok(state.ext.smb.sessions.some((s) => s.user === 'alice' && s.domain === 'CORP'));
});

test('SMB dissector never throws on truncated input', () => {
  const recs = B.tcpSession({
    client: '10.0.0.5', server: '10.0.0.1', sport: 445,
    exchanges: [['c', new Uint8Array([0x00, 0, 0, 8, 0xfe, 0x53, 0x4d, 0x42, 0, 0])]], // NBSS + partial SMB2
  });
  const { packets } = run(recs);
  const p = packets.find((x) => x.has('smb2'));
  assert.ok(p, 'still produced an smb2 layer');
  assert.match(p.layer('smb2').summary, /truncated|SMB2/);
});
