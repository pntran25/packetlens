// FTP control channel + passive FTP-DATA recognition.
// One TCP segment at a time; best-effort per segment. Never throws.
import { Layer } from '../../core/packet.js';
import { latin1, fmtBytes } from '../../core/bytes.js';

function ctxInfo(ctx) {
  const { data, offset, end, packet } = ctx;
  const ip = packet.ip || {};
  const stream = packet.stream || { id: -1, dir: 0 };
  return {
    data, offset, end, packet,
    text: latin1(data, offset, end),
    dir: stream.dir ?? 0,
    sid: stream.id ?? -1,
    src: ip.src || '', dst: ip.dst || '',
  };
}
function ftpState(state) { return state.ext.ftp ||= { dataChannels: [] }; }
function creds(state) { return state.ext.credentials ||= []; }
function markProto(state, sid, proto) {
  const s = state.tcp?.list?.[sid];
  if (s && !s.proto) s.proto = proto;
}
function nonEmptyLines(text) { return text.split(/\r\n|\r|\n/).filter(l => l.length); }

const ftp = {
  id: 'ftp',
  name: 'File Transfer Protocol',
  tcpPorts: [21],
  heuristic: {
    tcp(ctx) {
      const { data, offset, end, state, packet } = ctx;
      if (end - offset < 3) return false;
      const t = latin1(data, offset, Math.min(end, offset + 6));
      // FTP-specific client commands (kept narrow to avoid stealing SMTP/POP).
      if (/^(USER |PASS |ACCT |CWD |CDUP|QUIT|REIN|PORT |PASV|TYPE |STRU |MODE |RETR |STOR |STOU|APPE|REST |RNFR |RNTO |ABOR|DELE |RMD |MKD |PWD|LIST|NLST|SYST|FEAT|OPTS |EPSV|EPRT |SIZE |MDTM )/i.test(t)) return true;
      // Server reply codes only once the stream is already known to be FTP.
      const s = state.tcp?.list?.[packet.stream?.id];
      return !!(s && s.proto === 'ftp' && /^\d{3}[ -]/.test(t));
    },
  },
  dissect(ctx) {
    const { data, offset, end } = ctx;
    if (end - offset < 1) return null;
    const info = ctxInfo(ctx);
    const l = new Layer('ftp', 'File Transfer Protocol', offset, end - offset);
    l.label = 'FTP';
    try {
      markProto(ctx.state, info.sid, 'ftp');
      const isRequest = info.dir === 0;
      l.isRequest = isRequest;
      l.lines = info.text.split(/\r\n|\r|\n/).filter((x, i, a) => x.length || i < a.length - 1);
      if (isRequest) parseRequest(ctx, l, info);
      else parseReply(ctx, l, info);
    } catch (e) { /* best-effort; keep the layer */ }
    return l;
  },
};

function parseRequest(ctx, l, info) {
  const line = nonEmptyLines(info.text)[0] || '';
  const sp = line.indexOf(' ');
  const verb = (sp < 0 ? line : line.slice(0, sp)).toUpperCase();
  const args = sp < 0 ? '' : line.slice(sp + 1);
  l.command = verb; l.args = args; l.code = null; l.message = args;
  l.summary = `Request: ${line}`;
  l.add('Request command', verb, l.offset, verb.length);
  if (args) l.add('Request arg', args, -1, 0);

  const st = ftpState(ctx.state); const per = st[info.sid] ||= {};
  if (verb === 'USER') { per.user = args; }
  else if (verb === 'PASS') {
    creds(ctx.state).push({
      proto: 'ftp', kind: 'password', user: per.user || '', secret: args,
      src: info.src, dst: info.dst, packet: ctx.packet.index, stream: info.sid,
    });
    ctx.packet.tags.add('credential');
  } else if (verb === 'RETR' || verb === 'STOR') {
    per.lastFile = args;
  } else if (verb === 'PORT') {
    const m = args.match(/(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/);
    if (m) recordChannel(st, `${m[1]}.${m[2]}.${m[3]}.${m[4]}`, (+m[5] << 8) + +m[6], 'port', info.sid, ctx.packet.index);
  } else if (verb === 'EPRT') {
    const m = args.match(/\|(\d)\|([^|]*)\|(\d+)\|/);
    if (m) recordChannel(st, m[2], +m[3], 'eprt', info.sid, ctx.packet.index);
  }
}

function parseReply(ctx, l, info) {
  const lines = info.text.split(/\r\n|\r|\n/).filter(x => x.length);
  let code = null, message = '';
  for (const ln of lines) {
    const m = ln.match(/^(\d{3})([ -])(.*)$/);
    if (m) { code = +m[1]; message = m[3]; }
  }
  l.command = null; l.code = code; l.message = message;
  l.summary = code !== null ? `Response: ${code} ${message}`.trim() : `Response: ${lines[0] || ''}`;
  if (code !== null) l.add('Response code', code, l.offset, 3);
  if (message) l.add('Response arg', message, -1, 0);

  const st = ftpState(ctx.state);
  const joined = info.text;
  // 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
  if (code === 227) {
    const m = joined.match(/(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/);
    if (m) recordChannel(st, `${m[1]}.${m[2]}.${m[3]}.${m[4]}`, (+m[5] << 8) + +m[6], 'pasv', info.sid, ctx.packet.index);
  } else if (code === 229) {
    // 229 Entering Extended Passive Mode (|||port|)
    const m = joined.match(/\(\s*\|\|\|(\d+)\|\s*\)/) || joined.match(/\|\|\|(\d+)\|/);
    if (m) recordChannel(st, info.src, +m[1], 'epsv', info.sid, ctx.packet.index);
  }
}

function recordChannel(st, ip, port, mode, forStream, packet) {
  if (!ip || !port) return;
  st.dataChannels.push({ ip, port, mode, forStream, packet });
}

// Passive FTP-DATA: match a TCP stream whose endpoint equals a recorded data channel.
const ftpData = {
  id: 'ftpdata',
  name: 'FTP Data',
  heuristic: {
    tcp(ctx) {
      try {
        const st = ctx.state.ext.ftp;
        if (!st || !st.dataChannels.length) return false;
        const s = ctx.state.tcp?.list?.[ctx.packet.stream?.id];
        if (!s) return false;
        return findChannel(st, s) !== null;
      } catch { return false; }
    },
  },
  dissect(ctx) {
    const { offset, end } = ctx;
    const st = ctx.state.ext.ftp;
    const s = ctx.state.tcp?.list?.[ctx.packet.stream?.id];
    const ch = st && s ? findChannel(st, s) : null;
    const n = end - offset;
    const l = new Layer('ftpdata', 'FTP Data', offset, n);
    l.label = 'FTP-DATA';
    l.bytes = n;
    if (s && !s.proto) s.proto = 'ftp-data';
    let forFile = null;
    if (ch) { const per = st[ch.forStream]; forFile = per && per.lastFile; }
    l.summary = `FTP Data: ${fmtBytes(n)}` + (forFile ? ` (for ${forFile})` : '');
    l.add('Length', `${n} bytes`, offset, n);
    if (forFile) l.add('For file', forFile, -1, 0);
    return l;
  },
};

function findChannel(st, s) {
  for (const dc of st.dataChannels) {
    if ((dc.ip === s.a.ip && dc.port === s.a.port) || (dc.ip === s.b.ip && dc.port === s.b.port)) return dc;
  }
  return null;
}

export default [ftp, ftpData];
