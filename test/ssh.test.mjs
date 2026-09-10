import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/dissectors/index.js';
import { readCapture, writePcap } from '../src/core/reader.js';
import { dissectCapture } from '../src/core/dissect.js';
import { md5 } from '../src/core/hash.js';
import { concat } from '../src/core/bytes.js';
import * as B from '../tools/pktbuild.mjs';

function analyze(records, linkType = 1) {
  const cap = readCapture(writePcap(records, linkType));
  return dissectCapture(cap);
}
function findLayer(packets, proto, pred) {
  for (const p of packets) { const l = p.layer(proto); if (l && (!pred || pred(l, p))) return { l, p }; }
  return { l: null, p: null };
}
function be32(v) { return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]); }
function nameList(s) { const b = B.str(s); return concat([be32(b.length), b]); }

// Build an SSH_MSG_KEXINIT binary packet from 10 name-lists.
function kexinit(lists) {
  const parts = [new Uint8Array([20]), new Uint8Array(16)]; // msg code + cookie
  for (const s of lists) parts.push(nameList(s));
  parts.push(new Uint8Array([0, 0, 0, 0, 0])); // first_kex_packet_follows + reserved uint32
  const payload = concat(parts);
  const padLen = 8 - ((payload.length + 5) % 8) || 8; // keep (4+pktLen) a multiple of 8
  const packetLen = payload.length + padLen + 1;
  return concat([be32(packetLen), new Uint8Array([padLen]), payload, new Uint8Array(padLen)]);
}

const CLIENT_LISTS = [
  'curve25519-sha256', 'ssh-ed25519',
  'aes128-ctr', 'aes128-ctr',
  'hmac-sha2-256', 'hmac-sha2-256',
  'none', 'none', '', '',
];
const SERVER_LISTS = [
  'curve25519-sha256', 'rsa-sha2-512',
  'chacha20-poly1305@openssh.com', 'chacha20-poly1305@openssh.com',
  'hmac-sha2-256', 'hmac-sha2-256',
  'none', 'none', '', '',
];

test('SSH: banners, KEXINIT, HASSH fingerprints', () => {
  const clientBanner = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n';
  const serverBanner = 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4\r\n';
  const recs = B.tcpSession({
    client: '10.0.0.10', server: '10.0.0.11', sport: 22, teardown: false,
    exchanges: [
      ['c', B.str(clientBanner)],
      ['s', B.str(serverBanner)],
      ['c', kexinit(CLIENT_LISTS)],
      ['s', kexinit(SERVER_LISTS)],
      // A post-KEX / encrypted-looking packet (bogus large length).
      ['c', new Uint8Array([0xde, 0xad, 0xbe, 0xef, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])],
    ],
  });
  const { packets, state } = analyze(recs);

  const cb = findLayer(packets, 'ssh', (l) => l.banner && /8\.9p1/.test(l.banner));
  assert.equal(cb.l.banner, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1');
  assert.equal(cb.l.protoversion, '2.0');
  assert.equal(cb.l.software, 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.1');
  assert.equal(cb.l.summary, 'Client: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1');

  const sb = findLayer(packets, 'ssh', (l) => l.banner && /8\.2p1/.test(l.banner));
  assert.equal(sb.l.summary, 'Server Protocol: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4');

  const ck = findLayer(packets, 'ssh', (l) => l.hassh);
  const expectClient = md5('curve25519-sha256;aes128-ctr;hmac-sha2-256;none');
  assert.equal(ck.l.hassh, expectClient);
  assert.equal(ck.l.kex.ciphers.c2s, 'aes128-ctr');
  assert.equal(ck.l.kex.kex, 'curve25519-sha256');

  const sk = findLayer(packets, 'ssh', (l) => l.hasshServer);
  const expectServer = md5('curve25519-sha256;chacha20-poly1305@openssh.com;hmac-sha2-256;none');
  assert.equal(sk.l.hasshServer, expectServer);

  // State records.
  assert.equal(state.ext.ssh.clients.length, 1);
  assert.equal(state.ext.ssh.clients[0].hassh, expectClient);
  assert.equal(state.ext.ssh.clients[0].software, 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.1');
  assert.equal(state.ext.ssh.servers.length, 1);
  assert.equal(state.ext.ssh.servers[0].software, 'OpenSSH_8.2p1 Ubuntu-4');
  assert.equal(state.tcp.list[0].proto, 'ssh');

  const enc = findLayer(packets, 'ssh', (l) => /Encrypted packet/.test(l.summary));
  assert.ok(enc.l, 'encrypted packet labeled');
});

test('SSH: banner and KEXINIT in one segment', () => {
  const banner = B.str('SSH-2.0-libssh_0.9.6\r\n');
  const recs = B.tcpSession({
    client: '10.0.8.1', server: '10.0.8.2', sport: 2222, teardown: false,
    exchanges: [['c', concat([banner, kexinit(CLIENT_LISTS)])]],
  });
  const { packets, state } = analyze(recs);
  const l = findLayer(packets, 'ssh', (x) => x.banner).l;
  assert.equal(l.banner, 'SSH-2.0-libssh_0.9.6');
  assert.ok(l.hassh, 'HASSH computed from trailing KEXINIT');
  assert.equal(state.ext.ssh.clients.length, 1);
});

test('SSH: does not throw on truncated framing', () => {
  const recs = B.tcpSession({
    client: '10.0.9.1', server: '10.0.9.2', sport: 22, teardown: false,
    exchanges: [['c', B.str('SSH-2.0-x')], ['s', new Uint8Array([0, 0, 1])]],
  });
  const { packets } = analyze(recs);
  assert.ok(packets.every(p => !p.tags.has('malformed')));
});
