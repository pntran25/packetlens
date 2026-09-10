// Builds a synthetic but realistic demo capture in-browser, exercising many
// protocols and several of PacketLens's detections. Returns a pcap Uint8Array.
import * as B from '../tools/pktbuild.mjs';
import { concat } from '../src/core/bytes.js';
const { str } = B;

function be16(v) { return [(v >> 8) & 0xff, v & 0xff]; }

// A minimal TLS ClientHello with SNI = the given host and a couple cipher suites.
function tlsClientHello(host) {
  const sni = str(host);
  const serverNameList = new Uint8Array([0, ...be16(sni.length), ...sni]); // type host_name(0) + len + name
  const sniExt = new Uint8Array([0, 0, ...be16(serverNameList.length + 2), ...be16(serverNameList.length), ...serverNameList]);
  const alpn = new Uint8Array([0, 16, 0, 0x0e, 0, 0x0c, 2, 0x68, 0x32, 8, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]); // h2, http/1.1
  const groups = new Uint8Array([0, 10, 0, 4, 0, 2, 0, 0x1d]); // supported_groups x25519
  const exts = concat([sniExt, alpn, groups]);
  const ciphers = new Uint8Array([0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f, 0xc0, 0x2b]);
  const body = concat([
    new Uint8Array([3, 3]),           // client version TLS1.2
    new Uint8Array(32),               // random
    new Uint8Array([0]),              // session id len
    new Uint8Array(be16(ciphers.length)), ciphers,
    new Uint8Array([1, 0]),           // compression
    new Uint8Array(be16(exts.length)), exts,
  ]);
  const hs = concat([new Uint8Array([1, 0, ...be16(body.length).slice(0, 1) === 0 ? [0] : [0]]), body]); // placeholder, fix below
  // Handshake header: type(1)=1, length(3)
  const hsHeader = new Uint8Array([1, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]);
  const handshake = concat([hsHeader, body]);
  // TLS record: type 22, version 0301, length
  const rec = concat([new Uint8Array([22, 3, 1, ...be16(handshake.length)]), handshake]);
  return rec;
}

function png1x1() {
  // 1x1 transparent PNG.
  return B.hexBytes('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8cfc0f01f0005000180ff9b6f2a0000000049454e44ae426082');
}

export function buildSample() {
  const recs = [];
  let t = 1725580800; // 2024-09-06
  const add = (data) => { recs.push({ ts: t, data }); t += 0.0007 + Math.random() * 0.002; };
  const client = '192.168.1.105', gw = '192.168.1.1', dns = '192.168.1.1';
  const web = '93.184.216.34', evil = '45.33.32.156', ftp = '192.168.1.50';
  const cMac = '08:00:27:12:34:56', gwMac = '52:54:00:aa:bb:cc', evilMac = 'de:ad:be:ef:00:01';

  // 1) ARP: who-has gateway, reply, then a spoofed reply from attacker (conflict).
  add(B.eth({ src: cMac, type: 0x0806, payload: B.arp({ op: 1, senderMac: cMac, senderIp: client, targetIp: gw }) }));
  add(B.eth({ src: gwMac, dst: cMac, type: 0x0806, payload: B.arp({ op: 2, senderMac: gwMac, senderIp: gw, targetMac: cMac, targetIp: client }) }));
  add(B.eth({ src: evilMac, dst: cMac, type: 0x0806, payload: B.arp({ op: 2, senderMac: evilMac, senderIp: gw, targetMac: cMac, targetIp: client }) })); // SPOOF

  // 2) DNS query + response for example.com
  const q = B.dnsMessage({ id: 0x1a2b, flags: 0x0100, questions: [{ name: 'example.com', type: 1 }] });
  add(B.udpFrame({ src: client, dst: dns, sport: 51000, dport: 53, srcMac: cMac, dstMac: gwMac, payload: q }));
  const r = B.dnsMessage({ id: 0x1a2b, flags: 0x8180, questions: [{ name: 'example.com', type: 1 }], answers: [{ name: 'example.com', type: 1, data: web, ttl: 3600 }] });
  add(B.udpFrame({ src: dns, dst: client, sport: 53, dport: 51000, srcMac: gwMac, dstMac: cMac, payload: r }));

  // 3) Suspicious DNS: long high-entropy label (looks like tunneling/exfil)
  const exfil = 'a8f3k29dhqp1z0xm4v7bqw9e2rt6yu3i.tunnel.evil-c2.top';
  const qx = B.dnsMessage({ id: 0x2c2c, flags: 0x0100, questions: [{ name: exfil, type: 16 }] });
  add(B.udpFrame({ src: client, dst: dns, sport: 51001, dport: 53, srcMac: cMac, dstMac: gwMac, payload: qx }));

  // 4) HTTP GET returning a PNG (file extraction) + a Basic-Auth request (creds)
  const png = png1x1();
  const httpResp = concat([str(`HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: ${png.length}\r\nServer: ECS\r\n\r\n`), png]);
  recs.push(...B.tcpSession({ client, server: web, sport: 80, cport: 49200, t0: t, clientMac: cMac, serverMac: gwMac,
    exchanges: [['c', 'GET /logo.png HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n'], ['s', httpResp]] }));
  t = recs[recs.length - 1].ts + 0.01;
  recs.push(...B.tcpSession({ client, server: web, sport: 80, cport: 49201, t0: t, clientMac: cMac, serverMac: gwMac,
    exchanges: [['c', 'GET /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\nUser-Agent: sqlmap/1.7\r\n\r\n'], ['s', 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="admin"\r\nContent-Length: 0\r\n\r\n']] }));
  t = recs[recs.length - 1].ts + 0.01;

  // 5) FTP cleartext login
  recs.push(...B.tcpSession({ client, server: ftp, sport: 21, cport: 49300, t0: t, clientMac: cMac, serverMac: gwMac,
    exchanges: [['s', '220 ProFTPD Server ready\r\n'], ['c', 'USER alice\r\n'], ['s', '331 Password required for alice\r\n'], ['c', 'PASS S3cr3tP@ss\r\n'], ['s', '230 User alice logged in\r\n'], ['c', 'QUIT\r\n'], ['s', '221 Goodbye\r\n']] }));
  t = recs[recs.length - 1].ts + 0.01;

  // 6) TLS ClientHello to a C2-ish host
  recs.push(...B.tcpSession({ client, server: evil, sport: 443, cport: 49400, t0: t, clientMac: cMac, serverMac: gwMac,
    exchanges: [['c', tlsClientHello('cdn.evil-c2.top')]], teardown: false }));
  t = recs[recs.length - 1].ts + 0.05;

  // 7) Port scan: client SYNs many ports on a target, mostly no reply
  const target = '192.168.1.77';
  for (const port of [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9000, 27017]) {
    add(B.tcpFrame({ src: client, dst: target, sport: 40000 + port, dport: port, srcMac: cMac, dstMac: gwMac, seq: 1000, flags: 0x02 }));
  }
  // A couple of open ports answer SYN-ACK
  add(B.tcpFrame({ src: target, dst: client, sport: 22, dport: 40022, srcMac: gwMac, dstMac: cMac, seq: 9000, ack: 1001, flags: 0x12 }));
  add(B.tcpFrame({ src: target, dst: client, sport: 445, dport: 40445, srcMac: gwMac, dstMac: cMac, seq: 9000, ack: 1001, flags: 0x12 }));

  // 8) ICMP echo (ping) + oversized ICMP (possible tunnel)
  add(B.icmpFrame({ src: client, dst: gw, id: 0x1234, seq: 1, srcMac: cMac, dstMac: gwMac }));
  add(B.icmpFrame({ src: gw, dst: client, type: 0, id: 0x1234, seq: 1, srcMac: gwMac, dstMac: cMac }));
  add(B.icmpFrame({ src: client, dst: evil, id: 0x9999, seq: 1, srcMac: cMac, dstMac: gwMac, payload: str('X'.repeat(220)) }));

  // 9) DHCP request/ack (adds a lease + hostname)
  // (kept simple — a raw DISCOVER/OFFER pair would need option crafting; skipped for brevity)

  recs.sort((a, b) => a.ts - b.ts);
  return B.writePcap(recs, 1);
}
