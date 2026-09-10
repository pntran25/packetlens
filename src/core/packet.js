// Packet / Layer / Field model.
//
// A Packet holds raw bytes plus an ordered list of Layers produced by dissectors.
// A Layer has a protocol id, byte range, a tree of display Fields, and decoded
// properties (e.g. ipv4 layer has .src/.dst; tcp layer has .srcPort/.dstPort).

export class Field {
  constructor(name, value, offset = -1, length = 0, children = null) {
    this.name = name;
    this.value = value;
    this.offset = offset;
    this.length = length;
    this.children = children;
  }
  add(name, value, offset, length) {
    const f = new Field(name, value, offset, length);
    (this.children ||= []).push(f);
    return f;
  }
}

export class Layer {
  /**
   * @param {string} proto  short id used for filters, e.g. 'ipv4', 'tcp', 'dns'
   * @param {string} name   human name, e.g. 'Internet Protocol Version 4'
   * @param {number} offset byte offset in packet
   * @param {number} length byte length of this layer (header + payload it owns), may be updated later
   */
  constructor(proto, name, offset, length) {
    this.proto = proto;
    this.name = name;
    this.offset = offset;
    this.length = length;
    this.fields = [];
    this.summary = ''; // one-line description for the Info column
    this.next = null;  // { table, key, offset, end } for chaining
    this.errors = [];  // malformed-ness notes
  }
  add(name, value, offset, length) {
    const f = new Field(name, value, offset, length);
    this.fields.push(f);
    return f;
  }
  addGroup(name, value, offset, length, children) {
    const f = new Field(name, value, offset, length, children);
    this.fields.push(f);
    return f;
  }
  error(msg) { this.errors.push(msg); }
}

export class Packet {
  constructor(record, index) {
    this.index = index;          // 1-based packet number
    this.ts = record.ts;         // absolute seconds
    this.rel = 0;                // seconds since first packet
    this.delta = 0;              // seconds since previous packet
    this.capLen = record.capLen;
    this.origLen = record.origLen;
    this.data = record.data;     // Uint8Array
    this.iface = record.iface;
    this.comment = record.comment || null;
    this.layers = [];
    this.src = '';               // best source address (IP if present, else MAC)
    this.dst = '';
    this.proto = '';             // highest-level protocol label
    this.info = '';              // Info column
    this.errors = [];
    this.stream = null;          // { kind:'tcp'|'udp', id:number } assigned by transport dissector
    this.tags = new Set();       // analysis annotations: 'credential', 'anomaly', ...
  }
  /** First layer with the given proto id, or null. */
  layer(proto) {
    for (const l of this.layers) if (l.proto === proto) return l;
    return null;
  }
  has(proto) { return this.layer(proto) !== null; }
  /** Convenience accessors (cached lazily). */
  get ip() { return this.layer('ipv4') || this.layer('ipv6'); }
  get tcp() { return this.layer('tcp'); }
  get udp() { return this.layer('udp'); }
  get transport() { return this.layer('tcp') || this.layer('udp') || this.layer('sctp'); }
  get top() { return this.layers[this.layers.length - 1] || null; }
}
