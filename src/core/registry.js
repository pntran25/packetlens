// Dissector registry.
//
// A dissector is a plain object:
// {
//   id: 'dns',                       // unique protocol id (used as Layer.proto and in filters)
//   name: 'Domain Name System',
//   linkTypes?: [1],                 // registers for pcap link types
//   etherTypes?: [0x0800],           // registers for Ethernet / VLAN payload types
//   ipProtos?: [6],                  // registers for IPv4 protocol / IPv6 next header
//   tcpPorts?: [80, 8080],           // registers for TCP payload by port (either side)
//   udpPorts?: [53],
//   heuristic?: { tcp?: (ctx) => boolean, udp?: (ctx) => boolean }  // tried when no port match
//   dissect(ctx): Layer | null       // return null to decline (then the next candidate is tried)
// }
//
// ctx = { data, offset, end, packet, parent, state, key }
//   data:   Uint8Array of the whole packet
//   offset: where this dissector's bytes begin
//   end:    one past the last byte available to it
//   packet: the Packet being built
//   parent: the Layer that dispatched here (null for link layer)
//   state:  per-capture mutable object shared across packets (conversation tracking etc.)
//   key:    the dispatch key that selected this dissector (port number, ethertype, ...)

export const tables = {
  linkType: new Map(),
  etherType: new Map(),
  ipProto: new Map(),
  tcpPort: new Map(),
  udpPort: new Map(),
};
export const heuristics = { tcp: [], udp: [] };
export const byId = new Map();

export function register(dis) {
  if (!dis || !dis.id || typeof dis.dissect !== 'function') throw new Error('Invalid dissector');
  byId.set(dis.id, dis);
  const put = (table, keys) => { for (const k of keys || []) tables[table].set(k, dis); };
  put('linkType', dis.linkTypes);
  put('etherType', dis.etherTypes);
  put('ipProto', dis.ipProtos);
  put('tcpPort', dis.tcpPorts);
  put('udpPort', dis.udpPorts);
  if (dis.heuristic) {
    if (dis.heuristic.tcp) heuristics.tcp.push(dis);
    if (dis.heuristic.udp) heuristics.udp.push(dis);
  }
  return dis;
}

export function lookup(table, key) {
  return tables[table].get(key) || null;
}

export function allDissectors() {
  return [...byId.values()];
}
