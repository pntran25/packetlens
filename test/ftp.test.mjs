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
function findLayer(packets, proto, pred) {
  for (const p of packets) { const l = p.layer(proto); if (l && (!pred || pred(l, p))) return { l, p }; }
  return { l: null, p: null };
}

test('FTP control: requests, replies, credentials, data channel', () => {
  const control = B.tcpSession({
    client: '10.0.0.9', server: '10.0.0.20', sport: 21, teardown: false,
    exchanges: [
      ['s', '220 Welcome FTP\r\n'],
      ['c', 'USER alice\r\n'],
      ['s', '331 Password required\r\n'],
      ['c', 'PASS s3cr3t\r\n'],
      ['s', '230-Multi line\r\n230 Login successful\r\n'],
      ['c', 'PASV\r\n'],
      ['s', '227 Entering Passive Mode (10,0,0,20,195,80)\r\n'], // 195*256+80 = 50000
      ['c', 'RETR secret.bin\r\n'],
      ['s', '150 Opening data connection\r\n'],
    ],
  });
  // Data connection to the advertised passive endpoint 10.0.0.20:50000.
  const dataConn = B.tcpSession({
    client: '10.0.0.9', server: '10.0.0.20', cport: 51000, sport: 50000, teardown: false,
    t0: 1700000100,
    exchanges: [['s', new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])]],
  });
  const { packets, state } = analyze([...control, ...dataConn]);

  const req = findLayer(packets, 'ftp', (l) => l.command === 'USER');
  assert.equal(req.l.isRequest, true);
  assert.equal(req.l.summary, 'Request: USER alice');
  assert.equal(req.l.command, 'USER');
  assert.equal(req.l.args, 'alice');

  const rep = findLayer(packets, 'ftp', (l) => l.code === 331);
  assert.equal(rep.l.isRequest, false);
  assert.equal(rep.l.summary, 'Response: 331 Password required');
  assert.equal(rep.l.message, 'Password required');

  // Multiline reply resolves to the final code line.
  const multi = findLayer(packets, 'ftp', (l) => l.code === 230);
  assert.equal(multi.l.message, 'Login successful');

  // Credential captured.
  const cred = state.ext.credentials.find(c => c.proto === 'ftp');
  assert.ok(cred, 'ftp credential present');
  assert.equal(cred.user, 'alice');
  assert.equal(cred.secret, 's3cr3t');
  assert.ok(req.p.tags.has('credential') || packets.some(p => p.tags.has('credential')));

  // Data channel + last file recorded on the control stream (stream 0).
  assert.equal(state.ext.ftp.dataChannels.length, 1);
  const dc = state.ext.ftp.dataChannels[0];
  assert.equal(dc.ip, '10.0.0.20');
  assert.equal(dc.port, 50000);
  assert.equal(dc.mode, 'pasv');
  assert.equal(state.ext.ftp[0].lastFile, 'secret.bin');

  // FTP-DATA passive recognition.
  const fd = findLayer(packets, 'ftpdata');
  assert.ok(fd.l, 'ftp-data layer recognized');
  assert.equal(fd.l.bytes, 8);
  assert.match(fd.l.summary, /FTP Data: 8 B \(for secret\.bin\)/);
  assert.equal(fd.l.label, 'FTP-DATA');

  // Control stream tagged as ftp.
  assert.equal(state.tcp.list[0].proto, 'ftp');
});

test('FTP EPSV and PORT parsing', () => {
  const recs = B.tcpSession({
    client: '10.1.1.1', server: '10.1.1.2', sport: 21, teardown: false,
    exchanges: [
      ['c', 'EPSV\r\n'],
      ['s', '229 Entering Extended Passive Mode (|||62000|)\r\n'],
      ['c', 'PORT 10,1,1,1,200,100\r\n'], // 200*256+100 = 51300
      ['s', '200 PORT command successful\r\n'],
    ],
  });
  const { state } = analyze(recs);
  const modes = state.ext.ftp.dataChannels.map(d => d.mode);
  assert.ok(modes.includes('epsv'));
  assert.ok(modes.includes('port'));
  const epsv = state.ext.ftp.dataChannels.find(d => d.mode === 'epsv');
  assert.equal(epsv.port, 62000);
  assert.equal(epsv.ip, '10.1.1.2'); // server ip for EPSV
  const port = state.ext.ftp.dataChannels.find(d => d.mode === 'port');
  assert.equal(port.port, 51300);
  assert.equal(port.ip, '10.1.1.1');
});

test('FTP does not throw on truncated payload', () => {
  const recs = B.tcpSession({
    client: '10.2.2.1', server: '10.2.2.2', sport: 21, teardown: false,
    exchanges: [['c', 'USER'], ['s', '22']],
  });
  const { packets } = analyze(recs);
  assert.ok(packets.every(p => !p.tags.has('malformed')));
});
