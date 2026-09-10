# PacketLens — in-browser PCAP forensic analyzer

Pure ES modules, no framework, no build step needed for development (`npm run serve` serves `index.html` with `src/`).
`npm run build` bundles to a single `dist/index.html` with esbuild. Tests: `npm test` (node:test, files `test/*.test.mjs`).
Node 22. Everything must also run in the browser: never import `node:` modules from `src/`.

## Layout
- `src/core/bytes.js` — byte helpers (u16be, u32be, ipv4(), ipv6(), mac(), latin1(), utf8(), printable(), toHex(), entropy(), inetChecksum()).
- `src/core/reader.js` — `readCapture(Uint8Array) -> { format, interfaces:[{linkType,...}], records:[{ts,capLen,origLen,data,iface,comment?}], warnings }`, `writePcap(records, linkType)`.
- `src/core/packet.js` — `Packet`, `Layer`, `Field` classes (see below).
- `src/core/registry.js` — `register(dissector)`; dispatch tables `linkType`, `etherType`, `ipProto`, `tcpPort`, `udpPort` + heuristics.
- `src/core/dissect.js` — `dissectCapture(capture) -> { packets, state }`, `createState()`.
- `src/dissectors/*.js` — link/network/transport dissectors (eth, vlan, arp, ipv4, ipv6, icmp, icmpv6, tcp, udp, gre, igmp, sll...).
- `src/dissectors/app/*.js` — application dissectors. Each module `export default [dissectorObject, ...]`. `app/index.js` imports them all.
- `src/analysis/*.js` — post-dissection analysis over `{packets, state}`: TCP reassembly, conversations, extraction, IOCs, display filter.
- `src/ui/*` — the web UI (main-thread, vanilla DOM).
- `tools/pktbuild.mjs` — packet/fixture builder used by tests (`eth, ip4, ip6, tcp, udp, icmp, arp, tcpFrame, udpFrame, tcpSession, udpExchange, dnsMessage, str, hexBytes, writePcap`).
- `test/*.test.mjs` — node:test suites. Build captures in-memory with pktbuild; `readCapture(writePcap(records))` then `dissectCapture`.

## Dissector contract
```js
export default [{
  id: 'dns',                          // Layer.proto and filter prefix. lowercase, [a-z0-9_]
  name: 'Domain Name System',
  tcpPorts: [53], udpPorts: [53, 5353],  // any of: linkTypes, etherTypes, ipProtos, tcpPorts, udpPorts
  heuristic: { tcp: (ctx) => bool, udp: (ctx) => bool },   // optional, tried after port match fails
  dissect(ctx) { ... return layer or null }               // null = "not mine", next candidate is tried
}]
```
`ctx = { data: Uint8Array (whole packet), offset, end, packet, parent, state, key }`. Only read bytes in `[offset, end)`.
Return a `Layer`:
```js
const l = new Layer('dns', 'Domain Name System', offset, end - offset);
l.label = 'DNS';            // Protocol column text (defaults to proto uppercased)
l.summary = 'Standard query 0x1a2b A example.com';  // Info column text — mimic Wireshark wording
l.add('Transaction ID', '0x1a2b', offset, 2);       // display field: (name, value, byteOffset, byteLength)
const g = l.addGroup('Queries', '1', offset + 12, n, []); g.children.push({ name, value, offset, length, children? });
l.error('Malformed ...');   // marks packet 'malformed'; keep going if possible
l.next = { table: 'tcpPort', key: [sport, dport], offset: o, end: e }; // optional: chain to another dissector
```
Set decoded values as plain properties on the layer (see "Layer properties" below) — the analysis and UI modules rely on them.
Dissectors must never throw on malformed input — bounds-check everything. Throwing is caught and the packet is marked malformed, but the layer is lost.
Per-packet only: a TCP segment might contain a partial message. Do best-effort on the bytes present; full reassembly happens in `src/analysis/streams.js`.
Cross-packet state goes in `state.ext.<proto>` (free-form object per dissector), created lazily: `const st = state.ext.ftp ||= {...}`.
The stream id is in `ctx.packet.stream` = `{ kind: 'tcp'|'udp', id, dir }` (dir 0 = initiator → responder). Stream records: `state.tcp.list[id]` = `{ id, a:{ip,port}, b:{ip,port}, packets:[], segs:[{pkt,dir,seq,len,off,ts}], bytes:[a,b], start, end, proto, tags:Set }`. Application dissectors should set `stream.proto = 'http'` (the id) the first time they recognize a stream so later packets/analysis know the protocol.

### Credentials
Any dissector that observes an authentication secret pushes to `state.ext.credentials` (array, create if missing):
`{ proto: 'ftp', kind: 'password'|'basic'|'ntlm'|'form'|'token'|'cookie'|'community', user, secret, src, dst, packet: ctx.packet.index, stream: id, note? }`
and does `ctx.packet.tags.add('credential')`.

### Layer properties (contract between dissectors, analysis and UI)
- `eth`: `src, dst, type`
- `ipv4`/`ipv6`: `src, dst, ttl, proto_, version, fragmented?`; ipv4 also `id, df, mf, checksumOk`
- `tcp`: `srcPort, dstPort, seq, ack, relSeq, relAck, flags, flagNames[], window, payloadLen, payloadOffset, stream, dir, options{mss,wscale,sackOk,ts}, analysis[]`
- `udp`: `srcPort, dstPort, payloadLen, payloadOffset, stream, dir`
- `arp`: `opcode, senderMac, senderIp, targetMac, targetIp`
- `icmp`/`icmpv6`: `type, code, id?, seq?, origSrc?, origDst?, origSrcPort?, origDstPort?`
- `dns`: `id, isResponse, opcode, rcode, rcodeName, flags{aa,tc,rd,ra}, queries:[{name,type,typeName,cls}], answers:[{name,type,typeName,ttl,data}] (data = string rendering: IP, target name, txt...), authorities:[], additionals:[]`
- `dhcp`: `op, msgType, msgTypeName, xid, clientMac, clientIp, yourIp, serverIp, hostname?, requestedIp?, serverId?, options:[{code,name,value}]`
- `http`: `isRequest, method?, uri?, version, host?, status?, statusText?, headers:[[name,value]], contentType?, contentLength?, userAgent?, bodyOffset, bodyLength, authorization?, cookies?` ; full URL as `url` when host known.
- `tls`: `records:[{type,typeName,version,length,handshakeType?}], version (negotiated/hello), sni?, alpn?:[], ja3?, ja3Hash?, ja3s?, ja3sHash?, cipher?, cipherName?, certs?:[{subject, issuer, notBefore, notAfter, sans:[], serial, sha1, sha256, selfSigned}]`, `isClientHello`, `isServerHello`.
- `ssh`: `banner?, software?, kex? (algorithm lists), hassh?, hasshServer?`
- `ftp`/`smtp`/`pop`/`imap`/`telnet`/`irc`: `isRequest, command?, args?, code?, message?, lines:[]`
- `ntp`: `mode, modeName, stratum, version, refId, txTime`
- `nbns`/`mdns`/`llmnr` may reuse the dns dissector (same proto id 'dns' with `l.label` set to 'MDNS' etc.).
- `smb`/`smb2`: `command, commandName, isResponse, status?, tree?, filename?, user?, domain?, ntlm?`
- `data`: `payload` (Uint8Array)

## Filter language (src/analysis/filter.js)
Wireshark-like subset. Field paths: `<proto>.<prop>` resolved against layers (e.g. `ip.addr`, `ip.src`, `tcp.port`, `tcp.srcport`, `tcp.flags.syn`, `tcp.stream`, `udp.port`, `dns.qry.name`, `dns.resp.addr`, `http.host`, `http.request.method`, `http.response.code`, `tls.handshake.sni`, `tls.ja3`, `frame.len`, `frame.number`, `frame.time_relative`, `eth.addr`, `arp.opcode`, `icmp.type`). Bare `<proto>` = protocol present. Operators `== != < <= >= > contains matches`, `&&/and`, `||/or`, `!/not`, parentheses, `in {a b c}`. `ip` matches ipv4 or ipv6. Strings quoted or bare; IPv4 CIDR supported for `ip.addr == 10.0.0.0/8`.

## Style
- Plain JS, 2-space indent, semicolons, single quotes. No dependencies at runtime.
- Prefer small pure functions; keep dissectors self-contained.
- Tests: build packets with `tools/pktbuild.mjs`; assert on layer properties and `packet.info` text.
- Do not edit files outside your assignment unless told; `app/index.js` and `analysis/index.js` are shared and pre-wired.
