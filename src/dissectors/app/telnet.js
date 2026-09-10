// Telnet + IRC. One TCP segment at a time; never throws.
import { Layer } from '../../core/packet.js';
import { latin1, printable } from '../../core/bytes.js';

function ctxInfo(ctx) {
  const { data, offset, end, packet } = ctx;
  const ip = packet.ip || {};
  const stream = packet.stream || { id: -1, dir: 0 };
  return {
    data, offset, end, packet,
    dir: stream.dir ?? 0, sid: stream.id ?? -1,
    src: ip.src || '', dst: ip.dst || '',
  };
}
function creds(state) { return state.ext.credentials ||= []; }
function markProto(state, sid, proto) { const s = state.tcp?.list?.[sid]; if (s && !s.proto) s.proto = proto; }

// -------- Telnet --------
const IAC = 255, SB = 250, SE = 240;
const CMD_NAMES = { 240: 'SE', 241: 'NOP', 242: 'Data Mark', 243: 'Break', 244: 'IP', 245: 'AO', 246: 'AYT', 247: 'EC', 248: 'EL', 249: 'GA', 250: 'SB', 251: 'WILL', 252: 'WONT', 253: 'DO', 254: 'DONT' };
const CMD_WORD = { 251: 'Will', 252: "Won't", 253: 'Do', 254: "Don't" };
const OPT_NAMES = {
  0: 'Binary Transmission', 1: 'Echo', 3: 'Suppress Go Ahead', 5: 'Status', 6: 'Timing Mark',
  24: 'Terminal Type', 31: 'Window Size', 32: 'Terminal Speed', 33: 'Remote Flow Control',
  34: 'Linemode', 35: 'X Display Location', 36: 'Environment', 39: 'New Environment', 40: 'TN3270E',
};
function optName(n) { return OPT_NAMES[n] || `Option ${n}`; }

function parseTelnet(data, offset, end) {
  const options = []; let text = ''; const raw = [];
  let i = offset;
  while (i < end) {
    const b = data[i];
    if (b === IAC) {
      if (i + 1 >= end) break;
      const c = data[i + 1];
      if (c === IAC) { text += '\xff'; raw.push(0xff); i += 2; continue; }
      if (c >= 251 && c <= 254) {
        if (i + 2 >= end) break;
        const opt = data[i + 2];
        options.push({ command: CMD_WORD[c] || CMD_NAMES[c], option: optName(opt), code: opt });
        i += 3; continue;
      }
      if (c === SB) {
        let j = i + 2; const start = j;
        while (j < end && !(data[j] === IAC && j + 1 < end && data[j + 1] === SE)) j++;
        const opt = data[start];
        options.push({ command: 'Subnegotiation', option: optName(opt), code: opt });
        i = (j < end) ? j + 2 : end; continue;
      }
      // Other 2-byte command.
      options.push({ command: CMD_NAMES[c] || `Cmd ${c}`, option: null, code: null });
      i += 2; continue;
    }
    text += String.fromCharCode(b); raw.push(b); i++;
  }
  return { options, text, raw: Uint8Array.from(raw) };
}

const telnet = {
  id: 'telnet',
  name: 'Telnet',
  tcpPorts: [23],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end } = ctx;
      if (end - offset < 1) return false;
      if (data[offset] === IAC && end - offset >= 2) return true;
      return false;
    },
  },
  dissect(ctx) {
    const info = ctxInfo(ctx);
    if (info.end - info.offset < 1) return null;
    const l = new Layer('telnet', 'Telnet', info.offset, info.end - info.offset);
    l.label = 'TELNET';
    try {
      markProto(ctx.state, info.sid, 'telnet');
      const { options, text, raw } = parseTelnet(info.data, info.offset, info.end);
      l.isRequest = info.dir === 0;
      l.options = options;
      l.text = printable(raw, 0, raw.length);
      l.command = null; l.code = null; l.message = l.text;
      l.lines = text.split(/\r\n|\r|\n/).filter(x => x.length);
      const negs = options.filter(o => o.option !== null).map(o => `${o.command} ${o.option}`);
      const dataTrim = l.text.trim();
      if (dataTrim) l.summary = `Telnet Data: ${dataTrim.length > 40 ? dataTrim.slice(0, 40) + '…' : dataTrim}`;
      else if (negs.length) l.summary = `Telnet: ${negs.join(', ')}`;
      else l.summary = 'Telnet';
      if (options.length) {
        const g = l.addGroup('Negotiations', `${options.length}`, -1, 0, []);
        for (const o of options) g.children.push({ name: o.command, value: o.option || '', offset: -1, length: 0 });
      }
      telnetCreds(ctx, info, text);
    } catch { /* keep layer */ }
    return l;
  },
};

function telnetCreds(ctx, info, text) {
  const st = ctx.state.ext.telnet ||= {};
  const per = st[info.sid] ||= { c2s: '', s2c: '', cbuf: '', promptType: null, user: null };
  if (info.dir === 1) {
    // Server output: watch for login/password prompts.
    per.s2c += text;
    const low = text.toLowerCase();
    if (/pass\s*word/.test(low) || /passcode/.test(low)) per.promptType = 'password';
    else if (/login|user\s*name|user:/.test(low)) per.promptType = 'login';
    return;
  }
  // Client input, char-at-a-time. Reconstruct typed lines.
  per.c2s += text;
  for (const ch of text) {
    if (ch === '\r' || ch === '\n') {
      const tok = per.cbuf; per.cbuf = '';
      if (!tok) continue;
      if (per.promptType === 'login') { per.user = tok; }
      else if (per.promptType === 'password') {
        creds(ctx.state).push({
          proto: 'telnet', kind: 'password', user: per.user || '', secret: tok,
          src: info.src, dst: info.dst, packet: ctx.packet.index, stream: info.sid,
          note: 'heuristic: reconstructed from char-mode telnet stream',
        });
        ctx.packet.tags.add('credential');
        per.promptType = null;
      }
    } else if (ch >= ' ') { per.cbuf += ch; }
  }
}

// -------- IRC --------
const IRC_CMDS = new Set(['NICK', 'USER', 'PASS', 'JOIN', 'PART', 'PRIVMSG', 'NOTICE', 'PING', 'PONG', 'MODE', 'QUIT', 'TOPIC', 'KICK', 'WHO', 'CAP', 'AUTHENTICATE']);
function parseIrcLine(line) {
  let rest = line; let prefix = null;
  if (rest[0] === ':') { const sp = rest.indexOf(' '); prefix = rest.slice(1, sp < 0 ? undefined : sp); rest = sp < 0 ? '' : rest.slice(sp + 1); }
  let trailing = null; const ti = rest.indexOf(' :');
  if (rest.startsWith(':')) { trailing = rest.slice(1); rest = ''; }
  else if (ti >= 0) { trailing = rest.slice(ti + 2); rest = rest.slice(0, ti); }
  const parts = rest.split(/\s+/).filter(Boolean);
  const command = parts.shift() || '';
  if (trailing !== null) parts.push(trailing);
  return { prefix, command, params: parts, trailing };
}

const irc = {
  id: 'irc',
  name: 'Internet Relay Chat',
  tcpPorts: [6667, 6660, 6669, 6697, 7000],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end } = ctx;
      if (end - offset < 4) return false;
      const t = latin1(data, offset, Math.min(end, offset + 12));
      return /^(NICK |USER |PASS |JOIN |PRIVMSG |NOTICE |PING |PONG |CAP |:)/.test(t);
    },
  },
  dissect(ctx) {
    const info = ctxInfo(ctx);
    if (info.end - info.offset < 1) return null;
    const text = latin1(info.data, info.offset, info.end);
    const lines = text.split(/\r\n|\r|\n/).filter(x => x.length);
    if (!lines.length) return null;
    const l = new Layer('irc', 'Internet Relay Chat', info.offset, info.end - info.offset);
    l.label = 'IRC';
    try {
      markProto(ctx.state, info.sid, 'irc');
      const st = ctx.state.ext.irc ||= { channels: [] };
      const first = parseIrcLine(lines[0]);
      const cmd = first.command.toUpperCase();
      const numeric = /^\d{3}$/.test(first.command) ? +first.command : null;
      l.isRequest = info.dir === 0;
      l.command = cmd; l.code = numeric; l.args = first.params.join(' ');
      l.message = first.trailing; l.lines = lines;
      l.prefix = first.prefix;
      l.summary = `${info.dir === 0 ? 'Request' : 'Response'}: ${lines[0]}`;
      if (cmd === 'PASS') {
        creds(ctx.state).push({
          proto: 'irc', kind: 'password', user: null, secret: first.params[0] || '',
          src: info.src, dst: info.dst, packet: ctx.packet.index, stream: info.sid,
        });
        ctx.packet.tags.add('credential');
      } else if (cmd === 'JOIN') {
        for (const c of (first.params[0] || '').split(',')) if (c && !st.channels.includes(c)) st.channels.push(c);
      } else if (cmd === 'PRIVMSG') {
        const target = first.params[0] || ''; const msg = first.trailing || '';
        if (/^[#&]/.test(target) && (/^[.!]/.test(msg) || (msg.length >= 16 && /^[A-Za-z0-9+/=]+$/.test(msg)))) {
          l.note = 'possible C2 / bot command channel';
          ctx.packet.tags.add('anomaly');
        }
      }
    } catch { /* keep layer */ }
    return l;
  },
};

export default [telnet, irc];
