# 🔎 PacketLens

**A full packet analyzer that runs entirely in your browser.** Open a `.pcap` or `.pcapng`
capture and PacketLens dissects the protocols, follows TCP streams, carves transferred files,
recovers exposed credentials, and flags likely threats (kinda Wireshark-style)

> All parsing happens client-side in a Web Worker.
> There is no backend. You can even save the app as a single HTML file and open it offline.

## Why

Sharing a packet capture with an online analyzer means handing your network's internal
IPs, hostnames, tokens, sometimes plaintext passwords to someone else's server. PacketLens does
the same forensic work without that trade-off. It is also a compact, readable reference
implementation of how packet dissection actually works.

## Features

- **Deep protocol dissection** — Ethernet, VLAN, PPP/PPPoE, MPLS, Linux cooked capture, ARP,
  IPv4/IPv6 (with extension headers), ICMP/ICMPv6, TCP (with relative sequence numbers, stream
  tracking, retransmission/out-of-order/zero-window analysis), UDP, GRE, and application protocols:
  DNS/mDNS/LLMNR, DHCP/DHCPv6, HTTP, TLS, SSH, FTP, SMTP/POP3/IMAP, Telnet, IRC, SMB1/2, NTP, NetBIOS.
- **Wireshark-style display filters** — `tcp.port == 443 && ip.addr == 10.0.0.0/8`,
  `http.request.method == GET`, `dns.qry.name contains "evil"`, `tcp.flags.syn && !tcp.flags.ack`,
  with live validation and autocomplete.
- **Follow stream** — reassemble and read any TCP or UDP conversation in ASCII, hex, or raw, with
  client and server bytes color-coded; save the payload.
- **File carving** — extract files transferred over HTTP (and SMB reads / email), with SHA-256,
  magic-byte type detection, and a one-click download. Executables are flagged.
- **Credential recovery** — surfaces secrets exposed over HTTP Basic/Bearer/NTLM, FTP, POP/IMAP,
  SMTP AUTH, Telnet, and SMB NTLMSSP.
- **Threat detection** — ARP spoofing, port scans and host sweeps, DNS tunneling/exfiltration,
  rogue DHCP, cleartext credentials, executable downloads, self-signed/expired certificates, and
  known scanning tools by User-Agent.
- **Fingerprints** — JA3/JA3S (TLS) and HASSH (SSH) for client/server identification.
- **Conversations & protocol hierarchy** — endpoint and conversation tables, protocol breakdown.
- **Export** — save the current (optionally filtered) packet set back to a `.pcap`.

## Run it

No build step needed for development:

```bash
npm install        # only dev dependency is esbuild (for the single-file build)
npm run serve      # http://localhost:8088
```

Then open the URL and drop a capture in, or click **Load sample** for a synthetic demo capture
that exercises most detections.

### Single-file build

```bash
npm run build      # -> dist/index.html  (self-contained: HTML + JS + worker inlined)
```

`dist/index.html` has no external dependencies. Host it on any static server, or open it directly
from disk.

## Tests

```bash
npm test           # node:test; dissectors, analysis, and filters
```

Fixtures are generated in-memory by `tools/pktbuild.mjs` — a small packet builder that emits real
Ethernet/IP/TCP/UDP frames with correct checksums, plus helpers for full TCP sessions and DNS
messages.

## Architecture

```
src/core/        reader (pcap/pcapng), dissection pipeline, registry, packet model, bytes, hashes
src/dissectors/  link/network/transport dissectors  (app/ = application layer)
src/analysis/    stream reassembly, conversations, file extraction, IOC/threat engine, display filter
src/ui/          the browser UI (vanilla DOM) + the Web Worker that does the heavy lifting
tools/           packet builder, dev server
```

Dissectors register themselves against dispatch tables (link type, ethertype, IP protocol, TCP/UDP
port) and chain to the next layer. See `CLAUDE.md` for the full dissector contract.

## Caveats

Detections are heuristic and meant to speed up triage, not to replace an IDS. TLS 1.3 and any
encrypted payload are only analyzed as far as the handshake allows. Reassembly is capped per stream
to keep memory bounded on very large captures.

## License

MIT.
