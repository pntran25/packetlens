// Threat / indicator summary built from dissection state, conversations and
// extracted artifacts. Produces domains, URLs, user-agents, file hashes, TLS
// findings, and a prioritized alert list.

const SUSPICIOUS_TLDS = ['top', 'xyz', 'tk', 'ru', 'su', 'cc', 'gq', 'ml'];
const TOOL_UA = /sqlmap|nikto|nmap|masscan|curl|wget|python-requests|go-http-client|libwww-perl|hydra|wpscan|dirbuster|gobuster|metasploit|havij|zgrab|nuclei/i;
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function labelEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

function isDgaLike(domain) {
  const labels = domain.split('.').filter(Boolean);
  if (labels.length < 2) return false;
  // Consider the longest non-TLD label.
  const cand = labels.slice(0, -1).sort((a, b) => b.length - a.length)[0] || '';
  if (cand.length < 10) return false;
  const digits = (cand.match(/\d/g) || []).length;
  const ent = labelEntropy(cand);
  return ent > 3.6 || digits / cand.length > 0.35;
}

function suspiciousTld(domain) {
  const tld = domain.split('.').pop()?.toLowerCase();
  return tld && SUSPICIOUS_TLDS.includes(tld) ? tld : null;
}

export function collectIocs(packets, state, conversations, extraction) {
  const captureEnd = packets.reduce((m, p) => (p && p.ts > m ? p.ts : m), 0);

  // ---- credentials (dedup) ----
  const rawCreds = Array.isArray(state?.ext?.credentials) ? state.ext.credentials : [];
  const seenCred = new Set();
  const credentials = [];
  for (const c of rawCreds) {
    const key = `${c.proto}|${c.kind}|${c.user}|${c.secret}`;
    if (seenCred.has(key)) continue;
    seenCred.add(key);
    credentials.push(c);
  }

  // ---- domains ----
  const domainMap = new Map();
  const addDomain = (name, source, pkt) => {
    if (!name) return;
    const n = String(name).toLowerCase().replace(/\.$/, '');
    if (!n || !n.includes('.')) return;
    let d = domainMap.get(n);
    if (!d) { d = { name: n, sources: new Set(), count: 0, packets: [], suspicious: false, reasons: [] }; domainMap.set(n, d); }
    d.sources.add(source); d.count++;
    if (pkt != null && d.packets.length < 50) d.packets.push(pkt);
  };

  // ---- urls / user-agents / tls, gathered by one packet walk ----
  const urls = [];
  const uaMap = new Map();
  const tlsSelfSigned = [];
  const tlsExpired = [];
  const ja3Map = new Map();
  const icmpTunnelPkts = [];
  const cleartextProtos = new Set();

  for (const p of packets) {
    if (!p) continue;
    const dns = p.layer('dns');
    if (dns && Array.isArray(dns.queries)) for (const q of dns.queries) addDomain(q.name, 'dns', p.index);

    const tls = p.layer('tls');
    if (tls) {
      if (tls.sni) addDomain(tls.sni, 'tls-sni', p.index);
      const j = tls.ja3Hash || tls.ja3;
      if (j && tls.isClientHello !== false && (tls.ja3Hash || tls.isClientHello)) {
        let jr = ja3Map.get(j);
        if (!jr) { jr = { hash: j, count: 0, destinations: new Set(), packets: [] }; ja3Map.set(j, jr); }
        jr.count++;
        if (p.dst) jr.destinations.add(p.dst);
        if (jr.packets.length < 50) jr.packets.push(p.index);
      }
      if (Array.isArray(tls.certs)) {
        for (const cert of tls.certs) {
          if (cert.selfSigned) tlsSelfSigned.push({ subject: cert.subject, issuer: cert.issuer, host: p.dst, packet: p.index, sha256: cert.sha256 });
          const na = cert.notAfter ? Date.parse(cert.notAfter) / 1000 : NaN;
          if (Number.isFinite(na) && captureEnd && na < captureEnd) tlsExpired.push({ subject: cert.subject, notAfter: cert.notAfter, host: p.dst, packet: p.index });
        }
      }
    }

    const http = p.layer('http');
    if (http) {
      if (http.host) addDomain(http.host, 'http-host', p.index);
      if (http.isRequest) {
        const url = http.url || (http.host ? `http://${http.host}${http.uri || ''}` : http.uri) || '';
        urls.push({ method: http.method || '', url, host: http.host || null, uri: http.uri || null, packet: p.index, statusCode: null, isExecutableDownload: false });
      }
      const ua = http.userAgent;
      if (ua) {
        let u = uaMap.get(ua);
        if (!u) { u = { ua, count: 0, tool: TOOL_UA.test(ua) || !!http.uaFlag, packets: [] }; uaMap.set(ua, u); }
        u.count++;
        if (http.uaFlag) u.tool = true;
        if (u.packets.length < 50) u.packets.push(p.index);
      }
      if (http.authorization) cleartextProtos.add('http-auth');
    }

    // Cleartext protocol usage.
    const top = p.top;
    if (top && ['ftp', 'telnet', 'pop', 'imap', 'smtp', 'http', 'irc'].includes(top.proto)) cleartextProtos.add(top.proto);

    const icmp = p.layer('icmp');
    if (icmp && icmp.hint === 'large-icmp-payload') icmpTunnelPkts.push(p.index);
  }

  // Flag suspicious domains.
  for (const d of domainMap.values()) {
    const tld = suspiciousTld(d.name);
    if (tld) { d.suspicious = true; d.reasons.push(`suspicious TLD .${tld}`); }
    if (isDgaLike(d.name)) { d.suspicious = true; d.reasons.push('high-entropy / DGA-like label'); }
    d.sources = [...d.sources];
  }
  const domains = [...domainMap.values()];
  const suspiciousDomains = domains.filter((d) => d.suspicious);
  const dnsExfil = Array.isArray(state?.ext?.dns?.suspicious) ? state.ext.dns.suspicious : [];

  // ---- file hashes / exec downloads (from extraction) ----
  const files = extraction?.files || [];
  const fileHashes = files.map((f) => ({
    filename: f.filename, sha256: f.sha256, fileType: f.fileType, size: f.size,
    executable: f.executable, note: f.executable ? 'executable' : (f.script ? 'script' : null),
    host: f.host, uri: f.uri, packet: f.packet, stream: f.stream,
  }));
  // Attach status/exec flag onto matching URLs.
  for (const f of files) {
    if (!f.uri) continue;
    for (const u of urls) {
      if (u.uri === f.uri) { u.statusCode = f.statusCode ?? u.statusCode; if (f.executable) u.isExecutableDownload = true; }
    }
  }

  const ja3 = [...ja3Map.values()].map((j) => ({ hash: j.hash, count: j.count, destinations: [...j.destinations], packets: j.packets, widespread: j.destinations.size > 5 }));
  const tlsFindings = { selfSigned: tlsSelfSigned, expired: tlsExpired, ja3 };
  const userAgents = [...uaMap.values()];

  // ---- alerts ----
  const alerts = [];
  const push = (severity, category, title, detail, pkts = [], hosts = []) =>
    alerts.push({ severity, category, title, detail, packets: pkts, hosts });

  // Credentials.
  const plainCreds = credentials.filter((c) => c.kind !== 'ntlm');
  const ntlmCreds = credentials.filter((c) => c.kind === 'ntlm');
  for (const c of plainCreds) {
    push('high', 'credential', `Plaintext ${c.proto.toUpperCase()} credentials`,
      `User "${c.user || '(unknown)'}" over ${c.proto} from ${c.src} to ${c.dst}`,
      [c.packet], [c.src, c.dst].filter(Boolean));
  }
  if (ntlmCreds.length) {
    push('medium', 'credential', `NTLM authentication captured (${ntlmCreds.length})`,
      ntlmCreds.map((c) => `${c.domain ? c.domain + '\\' : ''}${c.user}`).join(', '),
      ntlmCreds.map((c) => c.packet), [...new Set(ntlmCreds.flatMap((c) => [c.src, c.dst]))].filter(Boolean));
  }

  // ARP spoofing.
  const conflicts = state?.ext?.arp?.conflicts || [];
  for (const cf of conflicts) {
    push('high', 'arp-spoof', `ARP spoofing: ${cf.ip} claimed by multiple MACs`,
      `${cf.ip} was ${cf.macs[0]} then ${cf.macs[1]}`, [cf.packet], [cf.ip]);
  }

  // Rogue DHCP (multiple servers).
  const dhcpServers = new Map();
  for (const p of packets) {
    if (!p) continue;
    const dh = p.layer('dhcp');
    if (!dh) continue;
    const mt = (dh.msgTypeName || '').toLowerCase();
    if (mt === 'offer' || mt === 'ack' || dh.serverId) {
      const sid = dh.serverId || dh.serverIp || p.src;
      if (sid && sid !== '0.0.0.0') { if (!dhcpServers.has(sid)) dhcpServers.set(sid, []); dhcpServers.get(sid).push(p.index); }
    }
  }
  if (dhcpServers.size > 1) {
    push('medium', 'rogue-dhcp', `Multiple DHCP servers (${dhcpServers.size})`,
      `Servers: ${[...dhcpServers.keys()].join(', ')}`,
      [...dhcpServers.values()].flat(), [...dhcpServers.keys()]);
  }

  // Executable download over HTTP.
  for (const f of files) {
    if (f.source === 'http' && f.direction === 'download' && f.executable) {
      push('high', 'malware', `Executable downloaded over HTTP: ${f.filename}`,
        `${f.fileType.toUpperCase()} (${f.size} bytes) from ${f.host || '?'}${f.uri || ''}, sha256 ${f.sha256 || '(too large)'}`,
        f.packet != null ? [f.packet] : [], [f.host].filter(Boolean));
    }
  }

  // DNS tunneling / exfil.
  if (dnsExfil.length) {
    push('high', 'dns-exfil', `DNS tunneling / exfiltration suspected (${dnsExfil.length})`,
      'Anomalous DNS queries flagged by the DNS dissector',
      dnsExfil.map((e) => e.packet).filter((x) => x != null), []);
  }
  for (const d of suspiciousDomains) {
    if (d.reasons.some((r) => r.includes('DGA'))) {
      push('medium', 'suspicious-domain', `Suspicious domain: ${d.name}`,
        d.reasons.join('; '), d.packets, []);
    }
  }

  // TLS findings.
  for (const c of tlsSelfSigned) {
    push('low', 'tls', `Self-signed certificate: ${c.subject || '(unknown)'}`,
      `Issuer ${c.issuer || '(self)'}${c.host ? ' on ' + c.host : ''}`, [c.packet], [c.host].filter(Boolean));
  }
  for (const c of tlsExpired) {
    push('medium', 'tls', `Expired certificate: ${c.subject || '(unknown)'}`,
      `notAfter ${c.notAfter}`, [c.packet], [c.host].filter(Boolean));
  }

  // Port scan / host sweep from TCP flows.
  const scanMap = new Map();
  for (const s of state?.tcp?.list || []) {
    if (!s.synSeen) continue;
    const src = s.a?.ip;
    if (!src) continue;
    let r = scanMap.get(src);
    if (!r) { r = { ports: new Set(), dsts: new Set(), syns: 0, synacks: 0, packets: [] }; scanMap.set(src, r); }
    r.ports.add(s.b?.port); r.dsts.add(s.b?.ip); r.syns++;
    if (s.synAckSeen) r.synacks++;
    for (const idx of (s.packets || []).slice(0, 2)) if (r.packets.length < 200) r.packets.push(idx);
  }
  for (const [src, r] of scanMap) {
    const completedRatio = r.syns ? r.synacks / r.syns : 1;
    if (r.ports.size > 20 && completedRatio < 0.3) {
      push('high', 'port-scan', `Port scan from ${src}`,
        `${r.ports.size} distinct destination ports, ${r.synacks}/${r.syns} handshakes completed`,
        r.packets, [src]);
    } else if (r.dsts.size > 20 && completedRatio < 0.3) {
      push('high', 'host-sweep', `Host sweep from ${src}`,
        `${r.dsts.size} distinct destination hosts, ${r.synacks}/${r.syns} handshakes completed`,
        r.packets, [src]);
    }
  }

  // ICMP tunneling.
  if (icmpTunnelPkts.length) {
    push('medium', 'icmp-tunnel', `Large / unusual ICMP payloads (${icmpTunnelPkts.length})`,
      'Oversized ICMP echo payloads may indicate tunneling or exfiltration',
      icmpTunnelPkts.slice(0, 100), []);
  }

  // Cleartext protocols in use.
  if (cleartextProtos.size) {
    push('info', 'cleartext', `Cleartext protocols in use`,
      `Observed: ${[...cleartextProtos].join(', ')}`, [], []);
  }

  // Known-bad user agents.
  for (const u of userAgents) {
    if (u.tool) push('medium', 'tool-ua', `Tool-like User-Agent: ${u.ua}`,
      `Seen ${u.count}x`, u.packets, []);
  }

  alerts.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]));

  const counts = {
    alerts: alerts.length,
    high: alerts.filter((a) => a.severity === 'high').length,
    medium: alerts.filter((a) => a.severity === 'medium').length,
    low: alerts.filter((a) => a.severity === 'low').length,
    info: alerts.filter((a) => a.severity === 'info').length,
    credentials: credentials.length,
    domains: domains.length,
    suspiciousDomains: suspiciousDomains.length,
    urls: urls.length,
    userAgents: userAgents.length,
    files: files.length,
  };

  return { credentials, domains, suspiciousDomains, dnsExfil, urls, userAgents, fileHashes, tlsFindings, alerts, counts };
}
