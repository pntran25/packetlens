import { Layer } from '../core/packet.js';
import { u16be, mac, ipv4, toHex } from '../core/bytes.js';

const OPCODES = { 1: 'request', 2: 'reply', 3: 'RARP request', 4: 'RARP reply', 8: 'InARP request', 9: 'InARP reply' };

export default {
  id: 'arp',
  name: 'Address Resolution Protocol',
  etherTypes: [0x0806, 0x8035],
  dissect(ctx) {
    const { data, offset, end, state } = ctx;
    if (end - offset < 8) return null;
    const htype = u16be(data, offset), ptype = u16be(data, offset + 2);
    const hlen = data[offset + 4], plen = data[offset + 5];
    const op = u16be(data, offset + 6);
    const need = 8 + 2 * (hlen + plen);
    if (end - offset < need) return null;
    const l = new Layer('arp', 'Address Resolution Protocol', offset, need);
    l.label = 'ARP';
    l.opcode = op;
    l.add('Hardware type', htype === 1 ? 'Ethernet (1)' : htype, offset, 2);
    l.add('Protocol type', ptype === 0x0800 ? 'IPv4 (0x0800)' : `0x${ptype.toString(16)}`, offset + 2, 2);
    l.add('Hardware size', hlen, offset + 4, 1);
    l.add('Protocol size', plen, offset + 5, 1);
    l.add('Opcode', `${OPCODES[op] || 'unknown'} (${op})`, offset + 6, 2);
    let o = offset + 8;
    const fmtHw = (p) => hlen === 6 ? mac(data, p) : toHex(data, p, p + hlen, ':');
    const fmtP = (p) => plen === 4 ? ipv4(data, p) : toHex(data, p, p + plen);
    l.senderMac = fmtHw(o); l.add('Sender MAC address', l.senderMac, o, hlen); o += hlen;
    l.senderIp = fmtP(o); l.add('Sender IP address', l.senderIp, o, plen); o += plen;
    l.targetMac = fmtHw(o); l.add('Target MAC address', l.targetMac, o, hlen); o += hlen;
    l.targetIp = fmtP(o); l.add('Target IP address', l.targetIp, o, plen); o += plen;

    if (op === 1) {
      if (l.senderIp === l.targetIp) l.summary = l.senderIp === '0.0.0.0' ? `ARP Probe for ${l.targetIp}` : `Gratuitous ARP for ${l.senderIp} (Request)`;
      else l.summary = `Who has ${l.targetIp}? Tell ${l.senderIp}`;
    } else if (op === 2) {
      l.summary = l.senderIp === l.targetIp ? `Gratuitous ARP for ${l.senderIp} (Reply)` : `${l.senderIp} is at ${l.senderMac}`;
      // Track IP→MAC bindings for ARP spoof detection.
      const arpState = state.ext.arp ||= { bindings: new Map(), conflicts: [] };
      const prev = arpState.bindings.get(l.senderIp);
      if (prev && prev !== l.senderMac) {
        arpState.conflicts.push({ ip: l.senderIp, macs: [prev, l.senderMac], packet: ctx.packet.index });
        l.error(`IP ${l.senderIp} previously claimed by ${prev}, now ${l.senderMac}`);
        ctx.packet.tags.add('arp-conflict');
      }
      arpState.bindings.set(l.senderIp, l.senderMac);
    } else {
      l.summary = `ARP ${OPCODES[op] || op}`;
    }
    return l;
  },
};
