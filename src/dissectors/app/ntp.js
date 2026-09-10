// Network Time Protocol (RFC 5905) on UDP 123, including mode 6 (control) and mode 7 (private, e.g. monlist).
import { Layer } from '../../core/packet.js';
import { u16be, u32be, ipv4, hex, toHex, printable } from '../../core/bytes.js';

const MODES = { 0: 'reserved', 1: 'symmetric active', 2: 'symmetric passive', 3: 'client', 4: 'server', 5: 'broadcast', 6: 'control', 7: 'private' };
const LEAP = { 0: 'no warning', 1: 'last minute of the day has 61 seconds', 2: 'last minute of the day has 59 seconds', 3: 'unknown (clock unsynchronized)' };
const CTRL_OPCODES = { 0: 'unspecified', 1: 'read status', 2: 'read variables', 3: 'write variables', 4: 'read clock variables', 5: 'write clock variables', 6: 'set trap address', 7: 'trap response', 8: 'runtime configuration', 9: 'save config', 10: 'read MRU', 11: 'read ordered list', 12: 'request nonce', 13: 'unset trap address' };
const PRIV_IMPL = { 0: 'UNIV', 2: 'XNTPD_OLD', 3: 'XNTPD' };
const PRIV_REQ = {
  0: 'PEER_LIST', 1: 'PEER_LIST_SUM', 2: 'PEER_INFO', 3: 'PEER_STATS', 4: 'SYS_INFO', 5: 'SYS_STATS', 6: 'IO_STATS', 7: 'MEM_STATS', 8: 'LOOP_INFO', 9: 'TIMER_STATS',
  10: 'CONFIG', 11: 'UNCONFIG', 12: 'SET_SYS_FLAG', 13: 'CLR_SYS_FLAG', 16: 'GET_RESTRICT', 17: 'RESADDFLAGS', 18: 'RESSUBFLAGS', 19: 'UNRESTRICT', 20: 'MON_GETLIST',
  21: 'RESET_STATS', 22: 'RESET_PEER', 23: 'REREAD_KEYS', 26: 'TRUSTKEY', 27: 'UNTRUSTKEY', 28: 'AUTHINFO', 29: 'TRAPS', 30: 'ADD_TRAP', 31: 'CLR_TRAP', 32: 'REQUEST_KEY',
  33: 'CONTROL_KEY', 34: 'GET_CTLSTATS', 36: 'GET_CLOCKINFO', 37: 'SET_CLKFUDGE', 38: 'GET_KERNEL', 39: 'GET_CLKBUGINFO', 42: 'MON_GETLIST_1', 43: 'HOSTNAME_ASSOCID', 44: 'IF_STATS', 45: 'IF_RELOAD',
};
const KOD = { RATE: 'rate exceeded', DENY: 'access denied', RSTR: 'access denied due to local policy', INIT: 'association not yet synchronized', STEP: 'step change in system time', ACST: 'manycast server', AUTH: 'authentication failure', AUTO: 'autokey sequence failure', BCST: 'broadcast server', CRYP: 'cryptographic authentication failed', DROP: 'lost peer', NKEY: 'no key found' };

const NTP_EPOCH = 2208988800;

/** 64-bit NTP timestamp -> { iso, unix, raw } (iso 'NULL' when zero). Era 1 assumed for seconds before 1970. */
export function ntpTimestamp(data, o) {
  const sec = u32be(data, o), frac = u32be(data, o + 4);
  if (sec === 0 && frac === 0) return { iso: 'NULL', unix: null, sec, frac };
  let unix = sec - NTP_EPOCH;
  if (sec < NTP_EPOCH) unix += 4294967296;
  const f = frac / 4294967296;
  let iso;
  try { iso = new Date(unix * 1000).toISOString().slice(0, 19) + '.' + Math.floor(f * 1e6).toString().padStart(6, '0') + 'Z'; } catch { iso = `${unix}.${frac}`; }
  return { iso, unix: unix + f, sec, frac };
}

function shortTs(data, o) {
  const raw = u32be(data, o);
  const v = (raw >> 16) + (raw & 0xffff) / 65536; // signed 16.16 (delay may be negative)
  return v;
}

function s8(v) { return v > 127 ? v - 256 : v; }

function refIdText(data, o, stratum, isV6) {
  if (stratum <= 1) {
    const s = printable(data, o, o + 4).replace(/\.+$/, '').replace(/\s+$/, '');
    if (stratum === 0) return { text: s ? `${s}${KOD[s] ? ` (kiss-o'-death: ${KOD[s]})` : ''}` : toHex(data, o, o + 4), kod: KOD[s] ? s : null };
    return { text: s || toHex(data, o, o + 4) };
  }
  if (isV6) return { text: `0x${toHex(data, o, o + 4)}` };
  return { text: ipv4(data, o) };
}

function dissectControl(l, data, o, end, packet) {
  const b1 = data[o + 1];
  const resp = !!(b1 & 0x80), err = !!(b1 & 0x40), more = !!(b1 & 0x20), opcode = b1 & 0x1f;
  const opName = CTRL_OPCODES[opcode] || `opcode ${opcode}`;
  l.opcode = opcode; l.opcodeName = opName; l.isResponse = resp;
  l.add('Flags', `${resp ? 'Response' : 'Request'}${err ? ', Error' : ''}${more ? ', More' : ''}`, o + 1, 1);
  l.add('Opcode', `${opName} (${opcode})`, o + 1, 1);
  if (o + 12 <= end) {
    l.sequence = u16be(data, o + 2);
    l.add('Sequence', l.sequence, o + 2, 2);
    l.add('Status', `0x${hex(u16be(data, o + 4), 4)}`, o + 4, 2);
    l.associationId = u16be(data, o + 6);
    l.add('Association ID', l.associationId, o + 6, 2);
    l.add('Offset', u16be(data, o + 8), o + 8, 2);
    const count = u16be(data, o + 10);
    l.add('Count', count, o + 10, 2);
    const de = Math.min(end, o + 12 + count);
    if (o + 12 + count > end) l.error('NTP control data truncated');
    if (count) { l.data = printable(data, o + 12, de); l.add('Data', l.data.slice(0, 200), o + 12, de - (o + 12)); }
  } else l.error('NTP control header truncated');
  packet.tags.add('ntp-control');
  l.summary = `NTP control message, ${opName} ${resp ? 'response' : 'request'}${err ? ' [error]' : ''}`;
}

function dissectPrivate(l, data, o, end, packet) {
  const b0 = data[o], b1 = data[o + 1];
  const resp = !!(b0 & 0x80), more = !!(b0 & 0x40);
  const auth = !!(b1 & 0x80), seq = b1 & 0x7f;
  l.isResponse = resp;
  l.add('Flags', `${resp ? 'Response' : 'Request'}${more ? ', More' : ''}${auth ? ', Authenticated' : ''}`, o, 2);
  l.add('Sequence', seq, o + 1, 1);
  if (o + 4 <= end) {
    const impl = data[o + 2], req = data[o + 3];
    l.implementation = impl; l.requestCode = req; l.requestName = PRIV_REQ[req] || `request ${req}`;
    l.add('Implementation', `${PRIV_IMPL[impl] || impl} (${impl})`, o + 2, 1);
    l.add('Request code', `${l.requestName} (${req})`, o + 3, 1);
    if (o + 8 <= end) {
      const errCode = data[o + 4] >> 4, items = u16be(data, o + 4) & 0x0fff, itemSize = u16be(data, o + 6) & 0x0fff;
      l.add('Error', errCode, o + 4, 1);
      l.add('Number of items', items, o + 4, 2);
      l.add('Item size', itemSize, o + 6, 2);
      l.items = items;
      if (resp && (req === 42 || req === 20) && items && itemSize >= 32) {
        // monlist entries: ... srcaddr at +16 (v1 layout: avgint, lastint, restr, count, addr, daddr, flags, port, mode, ver, v6flag, addr6, daddr6)
        const addrs = [];
        for (let i = 0, p = o + 8; i < items && p + itemSize <= end && i < 64; i++, p += itemSize) addrs.push(ipv4(data, p + 16));
        if (addrs.length) { l.monlist = addrs; l.add('Monitored clients', addrs.join(', '), o + 8, Math.min(end, o + 8 + items * itemSize) - (o + 8)); }
      }
    }
    if (req === 42 || req === 20) { packet.tags.add('ntp-monlist'); l.notes = [`NTP monlist ${resp ? 'response' : 'request'} (mode 7, ${l.requestName}) — amplification / reconnaissance vector`]; }
    l.summary = `NTP private message (mode 7), ${l.requestName} (${req}) ${resp ? 'response' : 'request'}${l.items ? `, ${l.items} items` : ''}`;
  } else {
    l.error('NTP private header truncated');
    l.summary = `NTP private message (mode 7) ${resp ? 'response' : 'request'}`;
  }
  packet.tags.add('ntp-private');
}

const ntp = {
  id: 'ntp',
  name: 'Network Time Protocol',
  udpPorts: [123],
  dissect(ctx) {
    const { data, offset, end, packet, parent } = ctx;
    const len = end - offset;
    if (len < 4) return null;
    const b0 = data[offset];
    const mode = b0 & 7, version = (b0 >> 3) & 7, leap = b0 >> 6;
    if (version === 0 || version > 4) return null;
    if (mode === 0 && len < 48) return null;
    const l = new Layer('ntp', 'Network Time Protocol', offset, len);
    l.label = 'NTP';
    l.mode = mode; l.modeName = MODES[mode]; l.version = version; l.leap = leap;
    if (mode === 7) {
      l.add('Version', version, offset, 1);
      l.add('Mode', `${MODES[mode]} (${mode})`, offset, 1);
      dissectPrivate(l, data, offset, end, packet);
      return l;
    }
    l.add('Flags', `0x${hex(b0)}`, offset, 1);
    l.add('Leap indicator', `${LEAP[leap]} (${leap})`, offset, 1);
    l.leapName = LEAP[leap];
    l.add('Version number', version, offset, 1);
    l.add('Mode', `${MODES[mode]} (${mode})`, offset, 1);
    if (mode === 6) { dissectControl(l, data, offset, end, packet); return l; }
    if (len < 48) {
      l.error(`NTP packet too short (${len} bytes, need 48)`);
      l.summary = `NTP Version ${version}, ${MODES[mode]} [truncated]`;
      return l;
    }
    const stratum = data[offset + 1], poll = s8(data[offset + 2]), precision = s8(data[offset + 3]);
    l.stratum = stratum; l.poll = poll; l.precision = precision;
    const stratumText = stratum === 0 ? 'unspecified or invalid' : stratum === 1 ? 'primary reference' : stratum <= 15 ? 'secondary reference' : 'unsynchronized';
    l.add('Peer clock stratum', `${stratumText} (${stratum})`, offset + 1, 1);
    l.add('Peer polling interval', `${poll} (${2 ** poll} seconds)`, offset + 2, 1);
    l.add('Peer clock precision', `${(2 ** precision).toExponential(3)} seconds`, offset + 3, 1);
    l.rootDelay = shortTs(data, offset + 4); l.rootDispersion = shortTs(data, offset + 8);
    l.add('Root delay', `${l.rootDelay.toFixed(6)} seconds`, offset + 4, 4);
    l.add('Root dispersion', `${l.rootDispersion.toFixed(6)} seconds`, offset + 8, 4);
    const ref = refIdText(data, offset + 12, stratum, parent?.proto === 'ipv6' || packet.layer('ipv6') !== null);
    l.refId = ref.text;
    l.add('Reference ID', ref.text, offset + 12, 4);
    const ts = [['Reference timestamp', 'refTime', 16], ['Origin timestamp', 'origTime', 24], ['Receive timestamp', 'rxTime', 32], ['Transmit timestamp', 'txTime', 40]];
    for (const [name, prop, off] of ts) {
      const t = ntpTimestamp(data, offset + off);
      l[prop] = t.iso; l[prop + 'Unix'] = t.unix;
      l.add(name, t.iso === 'NULL' ? 'NULL' : `${t.iso} (${t.sec}.${t.frac})`, offset + off, 8);
    }
    let o = offset + 48;
    // Extension fields (v4) followed by an optional MAC (key id + digest).
    while (end - o > 24 && version === 4) {
      const ft = u16be(data, o), fl = u16be(data, o + 2);
      if (fl < 16 || o + fl > end) break;
      l.add('Extension field', `type 0x${hex(ft, 4)}, ${fl} bytes`, o, fl);
      o += fl;
    }
    const rest = end - o;
    if (rest === 4) { l.add('Key ID', u32be(data, o), o, 4); l.cryptoNak = true; l.add('[Crypto-NAK]', 'authentication failed', o, 4); }
    else if (rest === 20 || rest === 24 || rest === 36) {
      l.keyId = u32be(data, o);
      l.add('Key ID', l.keyId, o, 4);
      l.add('Message authentication code', `${rest - 4} bytes: ${toHex(data, o + 4, end)}`, o + 4, rest - 4);
    } else if (rest > 0) l.add('Trailing data', `${rest} bytes`, o, rest);
    let summary = `NTP Version ${version}, ${MODES[mode]}`;
    if (ref.kod) { summary += ` [KoD ${ref.kod}]`; l.kod = ref.kod; packet.tags.add('ntp-kod'); }
    if (l.cryptoNak) summary += ' [Crypto-NAK]';
    l.summary = summary;
    return l;
  },
};

export default [ntp];
