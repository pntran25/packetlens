// Mail protocols: SMTP + POP3 + IMAP. One TCP segment at a time; never throws.
import { Layer } from '../../core/packet.js';
import { latin1 } from '../../core/bytes.js';

const NUL = String.fromCharCode(0);
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64decode(s) {
  s = (s || '').replace(/[^A-Za-z0-9+/=]/g, '');
  if (!s) return '';
  const core = s.replace(/=+$/, '');
  try { if (typeof atob === 'function') return atob(core + '='.repeat((4 - core.length % 4) % 4)); } catch { /* fall through */ }
  let out = '', bits = 0, val = 0;
  for (const ch of core) {
    const idx = B64.indexOf(ch); if (idx < 0) continue;
    val = (val << 6) | idx; bits += 6;
    if (bits >= 8) { bits -= 8; out += String.fromCharCode((val >> bits) & 0xff); }
  }
  return out;
}

function ctxInfo(ctx) {
  const { data, offset, end, packet } = ctx;
  const ip = packet.ip || {};
  const stream = packet.stream || { id: -1, dir: 0 };
  return {
    data, offset, end, packet,
    text: latin1(data, offset, end),
    dir: stream.dir ?? 0, sid: stream.id ?? -1,
    src: ip.src || '', dst: ip.dst || '',
  };
}
function creds(state) { return state.ext.credentials ||= []; }
function markProto(state, sid, proto) { const s = state.tcp?.list?.[sid]; if (s && !s.proto) s.proto = proto; }
function firstLine(text) { return text.split(/\r\n|\r|\n/)[0] || ''; }
function allLines(text) { return text.split(/\r\n|\r|\n/); }
function keepLines(text) { return allLines(text).filter((x, i, a) => x.length || i < a.length - 1); }
function pushCred(ctx, proto, kind, user, secret, info) {
  creds(ctx.state).push({ proto, kind, user, secret, src: info.src, dst: info.dst, packet: ctx.packet.index, stream: info.sid });
  ctx.packet.tags.add('credential');
}

// -------- SMTP --------
const SMTP_CMDS = new Set(['EHLO', 'HELO', 'MAIL', 'RCPT', 'DATA', 'RSET', 'VRFY', 'EXPN', 'HELP', 'AUTH', 'STARTTLS', 'QUIT', 'NOOP']);
const smtp = {
  id: 'smtp',
  name: 'Simple Mail Transfer Protocol',
  tcpPorts: [25, 587, 465],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end, state, packet } = ctx;
      if (end - offset < 1) return false;
      if (state.tcp?.list?.[packet.stream?.id]?.proto === 'smtp') return true; // sticky
      if (end - offset < 4) return false;
      const t = latin1(data, offset, Math.min(end, offset + 10));
      return /^(EHLO |HELO |MAIL FROM|RCPT TO|220[ -]|STARTTLS)/i.test(t);
    },
  },
  dissect(ctx) {
    const info = ctxInfo(ctx);
    if (info.end - info.offset < 1) return null;
    const l = new Layer('smtp', 'Simple Mail Transfer Protocol', info.offset, info.end - info.offset);
    l.label = 'SMTP';
    try { smtpParse(ctx, l, info); } catch { /* keep layer */ }
    return l;
  },
};
function smtpState(state) { return state.ext.smtp ||= { messages: [] }; }
function smtpParse(ctx, l, info) {
  markProto(ctx.state, info.sid, 'smtp');
  const st = smtpState(ctx.state); const per = st[info.sid] ||= { from: null, to: [], helo: null };
  l.isRequest = info.dir === 0;
  l.lines = keepLines(info.text);

  if (info.dir === 0) {
    const line = firstLine(info.text);
    const verb = line.toUpperCase().split(/\s+/)[0];
    if (per.inData) { smtpBody(ctx, l, info, per, st); return; }
    if (per.authState) { smtpAuthContinue(ctx, l, info, per, line); return; }
    if (SMTP_CMDS.has(verb)) {
      const args = line.slice(verb.length).trim();
      l.command = verb; l.args = args; l.code = null; l.message = args;
      l.summary = `C: ${line}`;
      l.add('Command', verb, info.offset, verb.length);
      if (args) l.add('Arg', args, -1, 0);
      if (verb === 'HELO' || verb === 'EHLO') per.helo = args;
      else if (verb === 'MAIL') { const m = line.match(/FROM:\s*<?([^>\s]*)>?/i); if (m) per.from = m[1]; }
      else if (verb === 'RCPT') { const m = line.match(/TO:\s*<?([^>\s]*)>?/i); if (m) per.to.push(m[1]); }
      else if (verb === 'DATA') per.inData = true;
      else if (verb === 'AUTH') smtpAuthStart(ctx, l, info, per, args);
      return;
    }
    l.command = null; l.code = null; l.message = line; l.summary = `C: ${line}`;
    return;
  }
  // Server -> client: numeric replies (possibly multiline).
  const lines = allLines(info.text).filter(x => x.length);
  let code = null, message = '';
  for (const ln of lines) { const m = ln.match(/^(\d{3})([ -])(.*)$/); if (m) { code = +m[1]; message = m[3]; } }
  l.command = null; l.code = code; l.message = message;
  l.summary = code !== null ? `S: ${code} ${message}`.trim() : `S: ${lines[0] || ''}`;
  if (code !== null) l.add('Response code', code, info.offset, 3);
}
function smtpAuthStart(ctx, l, info, per, args) {
  const parts = args.split(/\s+/);
  const mech = (parts[0] || '').toUpperCase();
  if (mech === 'LOGIN') {
    if (parts[1]) { per.authUser = b64decode(parts[1]); per.authState = 'login-pass'; }
    else per.authState = 'login-user';
  } else if (mech === 'PLAIN') {
    if (parts[1]) smtpAuthPlain(ctx, info, per, parts[1]);
    else per.authState = 'plain';
  }
}
function smtpAuthContinue(ctx, l, info, per, line) {
  const tok = line.trim();
  l.command = null; l.code = null; l.message = tok; l.summary = `C: ${tok} (SASL)`;
  if (per.authState === 'login-user') { per.authUser = b64decode(tok); per.authState = 'login-pass'; }
  else if (per.authState === 'login-pass') {
    pushCred(ctx, 'smtp', 'basic', per.authUser || '', b64decode(tok), info);
    per.authState = null;
  } else if (per.authState === 'plain') { smtpAuthPlain(ctx, info, per, tok); per.authState = null; }
}
function smtpAuthPlain(ctx, info, per, b64) {
  const parts = b64decode(b64).split(NUL); // authzid \0 authcid \0 passwd
  const user = parts.length >= 3 ? parts[1] : parts[0];
  const secret = parts.length >= 3 ? parts[2] : (parts[1] || '');
  pushCred(ctx, 'smtp', 'plain', user || '', secret, info);
}
function smtpBody(ctx, l, info, per, st) {
  const lines = allLines(info.text);
  per.hdr ||= { from: null, to: null, subject: null };
  let ended = false;
  for (const ln of lines) {
    if (ln === '.') { ended = true; break; }
    const m = ln.match(/^(Subject|From|To):\s?(.*)$/i);
    if (m) per.hdr[m[1].toLowerCase()] = m[2];
  }
  l.command = 'DATA'; l.code = null; l.message = '[Message Body]';
  l.summary = per.hdr.subject ? `C: [Body] Subject: ${per.hdr.subject}` : 'C: [Message Body]';
  if (ended) {
    st.messages.push({
      from: per.hdr.from || per.from, to: per.hdr.to || per.to.join(', '),
      subject: per.hdr.subject, packet: ctx.packet.index, stream: info.sid,
    });
    per.inData = false; per.hdr = null;
  }
}

// -------- POP3 --------
const POP_CMDS = new Set(['USER', 'PASS', 'APOP', 'STAT', 'RETR', 'LIST', 'DELE', 'QUIT', 'TOP', 'UIDL', 'CAPA', 'NOOP', 'RSET']);
const pop = {
  id: 'pop',
  name: 'Post Office Protocol',
  tcpPorts: [110, 995],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end, state, packet } = ctx;
      if (end - offset < 1) return false;
      if (state.tcp?.list?.[packet.stream?.id]?.proto === 'pop') return true; // sticky
      if (end - offset < 3) return false;
      const t = latin1(data, offset, Math.min(end, offset + 6));
      return /^(\+OK|-ERR|APOP |UIDL|CAPA)/i.test(t);
    },
  },
  dissect(ctx) {
    const info = ctxInfo(ctx);
    if (info.end - info.offset < 1) return null;
    const l = new Layer('pop', 'Post Office Protocol', info.offset, info.end - info.offset);
    l.label = 'POP';
    try {
      markProto(ctx.state, info.sid, 'pop');
      const st = ctx.state.ext.pop ||= {}; const per = st[info.sid] ||= {};
      l.isRequest = info.dir === 0;
      l.lines = keepLines(info.text);
      const line = firstLine(info.text);
      if (info.dir === 0) {
        const verb = line.split(/\s+/)[0].toUpperCase();
        const args = line.slice(verb.length).trim();
        l.command = verb; l.args = args; l.code = null; l.message = args;
        l.summary = `C: ${line}`;
        if (verb === 'USER') per.user = args;
        else if (verb === 'PASS') pushCred(ctx, 'pop', 'password', per.user || '', args, info);
      } else {
        l.command = null; l.code = null;
        l.message = /^(\+OK|-ERR)/i.test(line) ? line.replace(/^(\+OK|-ERR)\s?/i, '') : line;
        l.summary = `S: ${line}`;
      }
    } catch { /* keep layer */ }
    return l;
  },
};

// -------- IMAP --------
const imap = {
  id: 'imap',
  name: 'Internet Message Access Protocol',
  tcpPorts: [143, 993],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end, state, packet } = ctx;
      if (end - offset < 1) return false;
      if (state.tcp?.list?.[packet.stream?.id]?.proto === 'imap') return true; // sticky
      if (end - offset < 4) return false;
      const t = latin1(data, offset, Math.min(end, offset + 40));
      if (/^\*\s+(OK|NO|BAD|PREAUTH|BYE)/i.test(t)) return true;
      return /^[A-Za-z0-9]+\s+(LOGIN|CAPABILITY|SELECT|LIST|FETCH|LOGOUT|AUTHENTICATE|STARTTLS|EXAMINE|STATUS|NOOP)\b/i.test(t);
    },
  },
  dissect(ctx) {
    const info = ctxInfo(ctx);
    if (info.end - info.offset < 1) return null;
    const l = new Layer('imap', 'Internet Message Access Protocol', info.offset, info.end - info.offset);
    l.label = 'IMAP';
    try {
      markProto(ctx.state, info.sid, 'imap');
      const st = ctx.state.ext.imap ||= {}; const per = st[info.sid] ||= {};
      l.isRequest = info.dir === 0;
      l.lines = keepLines(info.text);
      const line = firstLine(info.text);
      const toks = line.split(/\s+/);
      if (info.dir === 0) {
        const tag = toks[0] || '';
        const command = (toks[1] || '').toUpperCase();
        l.command = command; l.tag = tag; l.args = line.slice((tag + ' ' + toks[1]).length).trim();
        l.code = null; l.message = l.args;
        l.summary = `Request: ${line}`;
        if (command === 'LOGIN') {
          const user = unquote(toks[2] || ''); const secret = unquote(toks[3] || '');
          per.user = user;
          pushCred(ctx, 'imap', 'password', user, secret, info);
        }
      } else {
        const tag = toks[0] || '';
        const status = (toks[1] || '').toUpperCase();
        l.command = status; l.tag = tag; l.code = null; l.message = line.slice(tag.length).trim();
        l.summary = `Response: ${line}`;
      }
    } catch { /* keep layer */ }
    return l;
  },
};
function unquote(s) { return s.replace(/^"(.*)"$/, '$1'); }

export default [smtp, pop, imap];
