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
const b64 = (s) => Buffer.from(s, 'binary').toString('base64');

test('SMTP: commands, AUTH LOGIN credentials, envelope, message', () => {
  const recs = B.tcpSession({
    client: '10.0.0.5', server: '10.0.0.6', sport: 25, teardown: false,
    exchanges: [
      ['s', '220 mail.example.com ESMTP\r\n'],
      ['c', 'EHLO client.example.com\r\n'],
      ['s', '250-mail.example.com\r\n250 AUTH LOGIN PLAIN\r\n'],
      ['c', 'AUTH LOGIN\r\n'],
      ['s', '334 VXNlcm5hbWU6\r\n'],
      ['c', b64('bob@example.com') + '\r\n'],
      ['s', '334 UGFzc3dvcmQ6\r\n'],
      ['c', b64('hunter2') + '\r\n'],
      ['s', '235 2.7.0 Authentication successful\r\n'],
      ['c', 'MAIL FROM:<bob@example.com>\r\n'],
      ['s', '250 OK\r\n'],
      ['c', 'RCPT TO:<carol@example.com>\r\n'],
      ['s', '250 OK\r\n'],
      ['c', 'DATA\r\n'],
      ['s', '354 End data with <CR><LF>.<CR><LF>\r\n'],
      ['c', 'From: bob@example.com\r\nTo: carol@example.com\r\nSubject: Hello World\r\n\r\nBody text here.\r\n.\r\n'],
      ['s', '250 2.0.0 Queued\r\n'],
    ],
  });
  const { packets, state } = analyze(recs);

  const ehlo = findLayer(packets, 'smtp', (l) => l.command === 'EHLO');
  assert.equal(ehlo.l.summary, 'C: EHLO client.example.com');
  assert.equal(ehlo.l.isRequest, true);

  const banner = findLayer(packets, 'smtp', (l) => l.code === 220);
  assert.equal(banner.l.summary, 'S: 220 mail.example.com ESMTP');

  const multi = findLayer(packets, 'smtp', (l) => l.code === 250 && /AUTH/.test(l.message || ''));
  assert.ok(multi.l, 'multiline 250 parsed to final line');

  const cred = state.ext.credentials.find(c => c.proto === 'smtp');
  assert.ok(cred, 'smtp credential present');
  assert.equal(cred.kind, 'basic');
  assert.equal(cred.user, 'bob@example.com');
  assert.equal(cred.secret, 'hunter2');

  const st = state.ext.smtp;
  assert.equal(st[0].from, 'bob@example.com');
  assert.deepEqual(st[0].to, ['carol@example.com']);
  assert.equal(st[0].helo, 'client.example.com');

  assert.equal(st.messages.length, 1);
  assert.equal(st.messages[0].subject, 'Hello World');
  assert.equal(st.messages[0].from, 'bob@example.com');
  assert.equal(state.tcp.list[0].proto, 'smtp');
});

test('SMTP AUTH PLAIN inline credential', () => {
  const plain = b64('\x00user1\x00passw0rd');
  const recs = B.tcpSession({
    client: '10.0.1.1', server: '10.0.1.2', sport: 25, teardown: false,
    exchanges: [
      ['s', '220 ready\r\n'],
      ['c', 'EHLO me\r\n'],
      ['s', '250 ok\r\n'],
      ['c', 'AUTH PLAIN ' + plain + '\r\n'],
      ['s', '235 ok\r\n'],
    ],
  });
  const { state } = analyze(recs);
  const cred = state.ext.credentials.find(c => c.proto === 'smtp');
  assert.equal(cred.kind, 'plain');
  assert.equal(cred.user, 'user1');
  assert.equal(cred.secret, 'passw0rd');
});

test('POP3: USER/PASS credentials and +OK responses', () => {
  const recs = B.tcpSession({
    client: '10.0.2.1', server: '10.0.2.2', sport: 110, teardown: false,
    exchanges: [
      ['s', '+OK POP3 server ready\r\n'],
      ['c', 'USER dave\r\n'],
      ['s', '+OK\r\n'],
      ['c', 'PASS opensesame\r\n'],
      ['s', '+OK logged in\r\n'],
      ['c', 'STAT\r\n'],
      ['s', '+OK 2 320\r\n'],
    ],
  });
  const { packets, state } = analyze(recs);
  const user = findLayer(packets, 'pop', (l) => l.command === 'USER');
  assert.equal(user.l.summary, 'C: USER dave');
  const ok = findLayer(packets, 'pop', (l) => /logged in/.test(l.summary));
  assert.equal(ok.l.summary, 'S: +OK logged in');
  const cred = state.ext.credentials.find(c => c.proto === 'pop');
  assert.equal(cred.user, 'dave');
  assert.equal(cred.secret, 'opensesame');
  assert.equal(cred.kind, 'password');
});

test('IMAP: tagged LOGIN credential and untagged responses', () => {
  const recs = B.tcpSession({
    client: '10.0.3.1', server: '10.0.3.2', sport: 143, teardown: false,
    exchanges: [
      ['s', '* OK [CAPABILITY IMAP4rev1] Ready\r\n'],
      ['c', 'a001 LOGIN alice wonderland\r\n'],
      ['s', 'a001 OK LOGIN completed\r\n'],
      ['c', 'a002 SELECT INBOX\r\n'],
      ['s', '* 3 EXISTS\r\na002 OK [READ-WRITE] SELECT completed\r\n'],
    ],
  });
  const { packets, state } = analyze(recs);
  const login = findLayer(packets, 'imap', (l) => l.command === 'LOGIN');
  assert.equal(login.l.summary, 'Request: a001 LOGIN alice wonderland');
  assert.equal(login.l.tag, 'a001');
  const banner = findLayer(packets, 'imap', (l) => /IMAP4rev1/.test(l.summary));
  assert.equal(banner.l.summary, 'Response: * OK [CAPABILITY IMAP4rev1] Ready');
  assert.equal(banner.l.command, 'OK');
  const cred = state.ext.credentials.find(c => c.proto === 'imap');
  assert.equal(cred.user, 'alice');
  assert.equal(cred.secret, 'wonderland');
});

test('mail dissectors do not throw on truncated payload', () => {
  const recs = B.tcpSession({
    client: '10.0.4.1', server: '10.0.4.2', sport: 25, teardown: false,
    exchanges: [['c', 'MAI'], ['s', '2']],
  });
  const { packets } = analyze(recs);
  assert.ok(packets.every(p => !p.tags.has('malformed')));
});
