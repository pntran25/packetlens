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

test('Telnet: IAC option negotiation parsing', () => {
  const recs = B.tcpSession({
    client: '10.0.0.1', server: '10.0.0.2', sport: 23, teardown: false,
    exchanges: [
      // Server: IAC DO ECHO(1), IAC DO SGA(3)
      ['s', new Uint8Array([255, 253, 1, 255, 253, 3])],
      // Client: IAC WILL ECHO, IAC WILL SGA
      ['c', new Uint8Array([255, 251, 1, 255, 251, 3])],
    ],
  });
  const { packets, state } = analyze(recs);
  const srv = findLayer(packets, 'telnet', (l) => l.options.some(o => o.command === 'Do'));
  assert.ok(srv.l, 'server negotiation parsed');
  assert.deepEqual(srv.l.options.map(o => `${o.command} ${o.option}`), ['Do Echo', 'Do Suppress Go Ahead']);
  assert.equal(srv.l.summary, 'Telnet: Do Echo, Do Suppress Go Ahead');
  const cli = findLayer(packets, 'telnet', (l) => l.options.some(o => o.command === 'Will'));
  assert.equal(cli.l.summary, 'Telnet: Will Echo, Will Suppress Go Ahead');
  assert.equal(state.tcp.list[0].proto, 'telnet');
});

test('Telnet: heuristic credential reconstruction from char stream', () => {
  const recs = B.tcpSession({
    client: '10.0.5.1', server: '10.0.5.2', sport: 23, teardown: false,
    exchanges: [
      ['s', B.str('\r\nUbuntu 22.04\r\nlogin: ')],
      ['c', B.str('root\r\n')],
      ['s', B.str('Password: ')],
      ['c', B.str('toor123\r\n')],
      ['s', B.str('\r\nWelcome!\r\n')],
    ],
  });
  const { state } = analyze(recs);
  const cred = state.ext.credentials.find(c => c.proto === 'telnet');
  assert.ok(cred, 'telnet credential reconstructed');
  assert.equal(cred.user, 'root');
  assert.equal(cred.secret, 'toor123');
  assert.match(cred.note, /heuristic/);
});

test('Telnet: data segment exposes text, no throw on lone IAC', () => {
  const recs = B.tcpSession({
    client: '10.0.6.1', server: '10.0.6.2', sport: 23, teardown: false,
    exchanges: [['s', B.str('hello world')], ['c', new Uint8Array([255])]],
  });
  const { packets } = analyze(recs);
  const data = findLayer(packets, 'telnet', (l) => l.text.includes('hello'));
  assert.equal(data.l.text, 'hello world');
  assert.match(data.l.summary, /Telnet Data: hello world/);
  assert.ok(packets.every(p => !p.tags.has('malformed')));
});

test('IRC: commands, credentials, channels, C2 flag', () => {
  const recs = B.tcpSession({
    client: '10.0.7.1', server: '10.0.7.2', sport: 6667, teardown: false,
    exchanges: [
      ['c', B.str('PASS serverpass\r\n')],
      ['c', B.str('NICK evilbot\r\n')],
      ['c', B.str('USER bot 0 * :bot realname\r\n')],
      ['s', B.str('PING :irc.example.net\r\n')],
      ['c', B.str('PONG :irc.example.net\r\n')],
      ['c', B.str('JOIN #botnet\r\n')],
      ['c', B.str('PRIVMSG #botnet :!exec whoami\r\n')],
    ],
  });
  const { packets, state } = analyze(recs);

  const cred = state.ext.credentials.find(c => c.proto === 'irc');
  assert.ok(cred, 'irc PASS credential');
  assert.equal(cred.secret, 'serverpass');

  const nick = findLayer(packets, 'irc', (l) => l.command === 'NICK');
  assert.equal(nick.l.summary, 'Request: NICK evilbot');
  assert.equal(nick.l.isRequest, true);

  const ping = findLayer(packets, 'irc', (l) => l.command === 'PING' && !l.isRequest);
  assert.equal(ping.l.summary, 'Response: PING :irc.example.net');
  assert.equal(ping.l.message, 'irc.example.net');

  assert.ok(state.ext.irc.channels.includes('#botnet'));

  const c2 = findLayer(packets, 'irc', (l) => l.command === 'PRIVMSG');
  assert.equal(c2.l.note, 'possible C2 / bot command channel');
  assert.ok(c2.p.tags.has('anomaly'));
});
