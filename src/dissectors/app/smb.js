// SMB1 / SMB2(3) dissector.
//
// SMB rides on a 4-byte NetBIOS Session Service (NBSS) header — 1 type byte + a
// 3-byte length — on port 139, and the same 4-byte "Direct TCP" length prefix on
// port 445. After that comes the SMB message, whose first four bytes are the
// protocol id: \xffSMB for SMB1 or \xfeSMB for SMB2/3.
//
// Per-packet, best-effort: a segment may hold a partial or multiple messages; we
// decode the first one present. Never throws — every read is bounds-checked.

import { Layer } from '../../core/packet.js';
import { u16le, u32le, u64le, toHex } from '../../core/bytes.js';

const SMB2_COMMANDS = {
  0: 'NEGOTIATE', 1: 'SESSION_SETUP', 2: 'LOGOFF', 3: 'TREE_CONNECT', 4: 'TREE_DISCONNECT',
  5: 'CREATE', 6: 'CLOSE', 7: 'FLUSH', 8: 'READ', 9: 'WRITE', 10: 'LOCK', 11: 'IOCTL',
  12: 'CANCEL', 13: 'ECHO', 14: 'QUERY_DIRECTORY', 15: 'CHANGE_NOTIFY', 16: 'QUERY_INFO',
  17: 'SET_INFO', 18: 'OPLOCK_BREAK',
};
// Wireshark-ish display words for the Info column.
const SMB2_DISPLAY = {
  NEGOTIATE: 'Negotiate Protocol', SESSION_SETUP: 'Session Setup', LOGOFF: 'Logoff',
  TREE_CONNECT: 'Tree Connect', TREE_DISCONNECT: 'Tree Disconnect', CREATE: 'Create',
  CLOSE: 'Close', FLUSH: 'Flush', READ: 'Read', WRITE: 'Write', LOCK: 'Lock', IOCTL: 'Ioctl',
  CANCEL: 'Cancel', ECHO: 'Echo', QUERY_DIRECTORY: 'Find', CHANGE_NOTIFY: 'Notify',
  QUERY_INFO: 'GetInfo', SET_INFO: 'SetInfo', OPLOCK_BREAK: 'Oplock Break',
};

const SMB1_COMMANDS = {
  0x04: 'Close', 0x06: 'Delete', 0x07: 'Query Information', 0x08: 'Set Information',
  0x24: 'Locking AndX', 0x25: 'Trans', 0x2b: 'Echo', 0x2d: 'Open AndX', 0x2e: 'Read AndX',
  0x2f: 'Write AndX', 0x32: 'Trans2', 0x71: 'Tree Disconnect', 0x72: 'Negotiate Protocol',
  0x73: 'Session Setup AndX', 0x74: 'Logoff AndX', 0x75: 'Tree Connect AndX',
  0xa0: 'NT Trans', 0xa2: 'NT Create AndX', 0xa4: 'NT Cancel',
};

const NTLM_SIG = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00]; // "NTLMSSP\0"
const NTLM_TYPE_NAME = { 1: 'NTLMSSP_NEGOTIATE', 2: 'NTLMSSP_CHALLENGE', 3: 'NTLMSSP_AUTH' };

const u16dec = (() => { try { return new TextDecoder('utf-16le'); } catch { return null; } })();
function utf16le(d, start, end) {
  if (end <= start) return '';
  const sub = d.subarray(start, end);
  if (u16dec) return u16dec.decode(sub).replace(/\0+$/, '');
  let s = '';
  for (let i = 0; i + 1 < sub.length; i += 2) s += String.fromCharCode(sub[i] | (sub[i + 1] << 8));
  return s.replace(/\0+$/, '');
}
function latin1(d, start, end) {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(d[i]);
  return s.replace(/\0+$/, '');
}

function isSig(d, p, end) {
  return end - p >= 4 && (d[p] === 0xff || d[p] === 0xfe) && d[p + 1] === 0x53 && d[p + 2] === 0x4d && d[p + 3] === 0x42;
}

/** Locate the SMB message start within [off,end). Returns {smbOff, nbss} or null. */
function locate(d, off, end) {
  // NBSS / Direct-TCP header (type byte 0) then signature.
  if (end - off >= 8 && d[off] === 0x00 && isSig(d, off + 4, end)) return { smbOff: off + 4, nbss: true };
  if (isSig(d, off, end)) return { smbOff: off, nbss: false };
  if (end - off >= 8 && isSig(d, off + 4, end)) return { smbOff: off + 4, nbss: true };
  return null;
}

function findBytes(d, needle, from, end) {
  outer: for (let i = from; i + needle.length <= end; i++) {
    for (let j = 0; j < needle.length; j++) if (d[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function smbState(state) {
  return state.ext.smb ||= { trees: new Set(), files: [], sessions: [], challenges: new Map() };
}

// ---- NTLMSSP -------------------------------------------------------------

function ntlmField(d, base, fieldOff, end) {
  if (base + fieldOff + 8 > end) return null;
  const len = u16le(d, base + fieldOff);
  const off = u32le(d, base + fieldOff + 4);
  const s = base + off, e = s + len;
  if (len === 0 || e > end || s < 0) return { len, off, start: s, end: e, empty: len === 0 };
  return { len, off, start: s, end: e, empty: false };
}

/** Parse an NTLMSSP message starting at `nt`. Returns a descriptor or null. */
function parseNtlm(d, nt, end, unicodeHint) {
  if (nt + 12 > end) return null;
  const type = u32le(d, nt + 8);
  const out = { type, typeName: NTLM_TYPE_NAME[type] || `type${type}` };
  if (type === 2) {
    // Challenge: server challenge is 8 bytes at +24.
    if (nt + 32 <= end) out.challenge = toHex(d, nt + 24, nt + 32);
    return out;
  }
  if (type !== 3) return out;
  // Authenticate.
  const flags = nt + 60 + 4 <= end ? u32le(d, nt + 60) : 0;
  const uni = (flags & 0x00000001) !== 0 || unicodeHint;
  const str = (f) => {
    if (!f || f.empty || f.end > end) return '';
    return uni ? utf16le(d, f.start, f.end) : latin1(d, f.start, f.end);
  };
  const lm = ntlmField(d, nt, 12, end);
  const ntresp = ntlmField(d, nt, 20, end);
  const domain = ntlmField(d, nt, 28, end);
  const user = ntlmField(d, nt, 36, end);
  const workstation = ntlmField(d, nt, 44, end);
  out.domain = str(domain);
  out.user = str(user);
  out.workstation = str(workstation);
  if (ntresp && !ntresp.empty && ntresp.end <= end) {
    out.ntResponse = toHex(d, ntresp.start, ntresp.end);
    out.ntLen = ntresp.len;
  }
  if (lm && !lm.empty && lm.end <= end) out.lmResponse = toHex(d, lm.start, lm.end);
  return out;
}

/** Build a hashcat-style credential secret from a Type3 response + saved challenge. */
function buildSecret(ntlm, challengeHex) {
  const user = ntlm.user || '';
  const domain = ntlm.domain || '';
  if (ntlm.ntResponse && challengeHex && ntlm.ntLen > 24) {
    // NetNTLMv2 (hashcat -m 5600): user::domain:challenge:NTProof:blob
    const ntProof = ntlm.ntResponse.slice(0, 32);
    const blob = ntlm.ntResponse.slice(32);
    return { fmt: 'netntlmv2', secret: `${user}::${domain}:${challengeHex}:${ntProof}:${blob}` };
  }
  if (ntlm.ntResponse && challengeHex && ntlm.ntLen === 24) {
    // NetNTLMv1 (hashcat -m 5500): user::domain:LM:NT:challenge
    return { fmt: 'netntlmv1', secret: `${user}::${domain}:${ntlm.lmResponse || ''}:${ntlm.ntResponse}:${challengeHex}` };
  }
  return { fmt: 'hex', secret: ntlm.ntResponse || '' };
}

function handleSecurityBlob(d, blobStart, blobEnd, l, ctx, streamId) {
  const st = smbState(ctx.state);
  const nt = findBytes(d, NTLM_SIG, blobStart, blobEnd);
  if (nt < 0) return null;
  const ntlm = parseNtlm(d, nt, blobEnd, true);
  if (!ntlm) return null;
  l.ntlm = ntlm.typeName;
  if (ntlm.type === 2 && ntlm.challenge) {
    st.challenges.set(streamId, ntlm.challenge);
    return ntlm;
  }
  if (ntlm.type === 3) {
    l.user = ntlm.user; l.domain = ntlm.domain;
    st.sessions.push({ user: ntlm.user, domain: ntlm.domain, workstation: ntlm.workstation, packet: ctx.packet.index });
    const challengeHex = st.challenges.get(streamId);
    const built = buildSecret(ntlm, challengeHex);
    const creds = ctx.state.ext.credentials ||= [];
    creds.push({
      proto: 'smb', kind: 'ntlm',
      user: ntlm.user, domain: ntlm.domain,
      secret: built.secret, note: built.fmt,
      src: ctx.packet.src, dst: ctx.packet.dst,
      packet: ctx.packet.index, stream: streamId,
    });
    ctx.packet.tags.add('credential');
  }
  return ntlm;
}

// ---- SMB2 ----------------------------------------------------------------

function dissectSmb2(ctx, smbOff, nbss) {
  const { data: d, end, packet, state } = ctx;
  const l = new Layer('smb2', 'SMB2', ctx.offset, end - ctx.offset);
  l.label = 'SMB2';
  if (smbOff + 64 > end) { // header truncated
    l.summary = 'SMB2 (truncated header)';
    return finishSmb2Layer(l, ctx, smbOff);
  }
  const command = u16le(d, smbOff + 12);
  const flags = u32le(d, smbOff + 16);
  const isResponse = (flags & 0x00000001) !== 0;
  const status = u32le(d, smbOff + 8);
  const messageId = u64le(d, smbOff + 24);
  const treeId = u32le(d, smbOff + 36);
  const sessionId = u64le(d, smbOff + 40);
  const cmdName = SMB2_COMMANDS[command] || `CMD_${command}`;

  l.command = command; l.commandName = cmdName; l.isResponse = isResponse;
  l.status = status; l.messageId = messageId; l.treeId = treeId; l.sessionId = sessionId;

  l.add('Protocol Id', '\\xFESMB', smbOff, 4);
  l.add('Header Length', 64, smbOff + 4, 2);
  l.add('Command', `${cmdName} (${command})`, smbOff + 12, 2);
  l.add('Flags', `0x${(flags >>> 0).toString(16).padStart(8, '0')}${isResponse ? ' (Response)' : ' (Request)'}`, smbOff + 16, 4);
  l.add('Message ID', messageId, smbOff + 24, 8);
  l.add('Tree ID', `0x${treeId.toString(16)}`, smbOff + 36, 4);
  l.add('Session ID', `0x${sessionId.toString(16)}`, smbOff + 40, 8);
  if (isResponse) l.add('Status', `0x${(status >>> 0).toString(16).padStart(8, '0')}`, smbOff + 8, 4);

  const body = smbOff + 64;
  const streamId = packet.stream ? packet.stream.id : -1;
  const st = smbState(state);
  const dispWord = SMB2_DISPLAY[cmdName] || cmdName;
  let summary = `${dispWord} ${isResponse ? 'Response' : 'Request'}`;

  try {
    if (command === 3 && !isResponse && body + 8 <= end) {
      // TREE_CONNECT request: StructureSize(2), Flags(2), PathOffset(2), PathLength(2)
      const pathOff = u16le(d, body + 4);
      const pathLen = u16le(d, body + 6);
      const ps = smbOff + pathOff, pe = ps + pathLen;
      if (pathLen > 0 && pe <= end) {
        const tree = utf16le(d, ps, pe);
        l.tree = tree;
        st.trees.add(tree);
        l.add('Tree', tree, ps, pathLen);
        summary += ` Tree: ${tree}`;
      }
    } else if (command === 5 && !isResponse && body + 56 <= end) {
      // CREATE request: NameOffset u16 @ body+44, NameLength u16 @ body+46
      const nameOff = u16le(d, body + 44);
      const nameLen = u16le(d, body + 46);
      const ns = smbOff + nameOff, ne = ns + nameLen;
      if (nameLen > 0 && ne <= end) {
        const filename = utf16le(d, ns, ne);
        l.filename = filename;
        st.files.push({ name: filename, tree: [...st.trees].pop() || null, packet: packet.index });
        l.add('Filename', filename, ns, nameLen);
        summary += ` File: ${filename.replace(/^\\+/, '')}`;
      } else if (nameLen === 0) {
        summary += ' File: (root)';
      }
    } else if (command === 1 && body < end) {
      // SESSION_SETUP: the request/response security-buffer offsets differ, so
      // just scan the message body for the NTLMSSP signature (robust).
      const ntlm = handleSecurityBlob(d, body, end, l, ctx, streamId);
      if (ntlm && l.ntlm) {
        summary += `, ${l.ntlm}`;
        if (l.user) summary += ` User: ${l.domain ? l.domain + '\\' : ''}${l.user}`;
      }
    }
  } catch (e) {
    l.error(`SMB2 body parse: ${e.message}`);
  }

  l.summary = summary;
  return finishSmb2Layer(l, ctx, smbOff);
}

function finishSmb2Layer(l, ctx, smbOff) {
  markStream(ctx, 'smb2');
  return l;
}

// ---- SMB1 ----------------------------------------------------------------

function dissectSmb1(ctx, smbOff, nbss) {
  const { data: d, end, packet, state } = ctx;
  const l = new Layer('smb', 'SMB', ctx.offset, end - ctx.offset);
  l.label = 'SMB';
  if (smbOff + 32 > end) {
    l.summary = 'SMB (truncated header)';
    markStream(ctx, 'smb');
    return l;
  }
  const command = d[smbOff + 4];
  const status = u32le(d, smbOff + 5);
  const flags = d[smbOff + 9];
  const flags2 = u16le(d, smbOff + 10);
  const isResponse = (flags & 0x80) !== 0;
  const tid = u16le(d, smbOff + 24);
  const pid = u16le(d, smbOff + 26);
  const uid = u16le(d, smbOff + 28);
  const mid = u16le(d, smbOff + 30);
  const cmdName = SMB1_COMMANDS[command] || `0x${command.toString(16)}`;
  const unicode = (flags2 & 0x8000) !== 0;

  l.command = command; l.commandName = cmdName; l.isResponse = isResponse;
  l.status = status; l.tid = tid; l.pid = pid; l.uid = uid; l.mid = mid;

  l.add('Server Component', 'SMB', smbOff, 4);
  l.add('Command', `${cmdName} (0x${command.toString(16)})`, smbOff + 4, 1);
  l.add('NT Status', `0x${(status >>> 0).toString(16).padStart(8, '0')}`, smbOff + 5, 4);
  l.add('Flags', `0x${flags.toString(16)}${isResponse ? ' (Response)' : ' (Request)'}`, smbOff + 9, 1);
  l.add('Flags2', `0x${flags2.toString(16)}`, smbOff + 10, 2);
  l.add('Tree ID', tid, smbOff + 24, 2);
  l.add('User ID', uid, smbOff + 28, 2);
  l.add('Multiplex ID', mid, smbOff + 30, 2);

  const streamId = packet.stream ? packet.stream.id : -1;
  let summary = `${cmdName} ${isResponse ? 'Response' : 'Request'}`;

  try {
    // Session Setup AndX: extended security blob may carry NTLMSSP. Scan the
    // whole message body for the signature (robust vs. AndX layout details).
    if (command === 0x73 && !isResponse) {
      const ntlm = handleSecurityBlob(d, smbOff + 32, end, l, ctx, streamId);
      if (ntlm && l.ntlm) {
        summary += `, ${l.ntlm}`;
        if (l.user) summary += ` User: ${l.domain ? l.domain + '\\' : ''}${l.user}`;
      }
    } else if (command === 0x75 && !isResponse) {
      // Tree Connect AndX request: parse the path out of the byte block.
      const tree = parseSmb1TreeConnect(d, smbOff, end, unicode);
      if (tree) {
        l.tree = tree;
        smbState(state).trees.add(tree);
        l.add('Tree', tree, -1, 0);
        summary += ` Tree: ${tree}`;
      }
    }
  } catch (e) {
    l.error(`SMB1 body parse: ${e.message}`);
  }

  l.summary = summary;
  markStream(ctx, 'smb');
  return l;
}

function parseSmb1TreeConnect(d, smbOff, end, unicode) {
  // Body: WordCount(1) at +32. Tree Connect AndX wordcount is 4.
  let o = smbOff + 32;
  if (o >= end) return null;
  const wordCount = d[o]; o += 1;
  o += wordCount * 2; // skip parameter words
  if (o + 2 > end) return null;
  const byteCount = u16le(d, o); o += 2;
  const bend = Math.min(end, o + byteCount);
  // For extended layout the words include PasswordLength at word[3] (offset +6
  // within words). Read it to skip the password field before the Path string.
  let passLen = 0;
  if (wordCount >= 4) passLen = u16le(d, smbOff + 32 + 1 + 6);
  o += passLen;
  if (unicode && (o - (smbOff)) % 2 === 1) o += 1; // 2-byte alignment padding
  if (o >= bend) return null;
  // Path is a null-terminated string.
  if (unicode) {
    let e = o;
    while (e + 1 < bend && !(d[e] === 0 && d[e + 1] === 0)) e += 2;
    return utf16le(d, o, e);
  }
  let e = o;
  while (e < bend && d[e] !== 0) e += 1;
  return latin1(d, o, e);
}

// ---- dispatch ------------------------------------------------------------

function markStream(ctx, proto) {
  const s = ctx.packet.stream;
  if (s && ctx.state.tcp.list[s.id]) {
    ctx.state.tcp.list[s.id].proto = proto;
    ctx.state.tcp.list[s.id].tags?.add(proto);
  }
}

function dissect(ctx) {
  const { data, offset, end } = ctx;
  const loc = locate(data, offset, end);
  if (!loc) return null;
  const isSmb2 = data[loc.smbOff] === 0xfe;
  return isSmb2 ? dissectSmb2(ctx, loc.smbOff, loc.nbss) : dissectSmb1(ctx, loc.smbOff, loc.nbss);
}

const smb = {
  id: 'smb',
  name: 'SMB / SMB2',
  tcpPorts: [445, 139],
  heuristic: { tcp: (ctx) => locate(ctx.data, ctx.offset, ctx.end) !== null },
  dissect,
};

export default [smb];
