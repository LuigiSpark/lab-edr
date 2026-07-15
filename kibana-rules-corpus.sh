#!/usr/bin/env bash
# kibana-rules-corpus.sh — Zeek/Elastic Agent detection rules for this lab, deployed by debian_script.sh during provisioning.
# Lab IPs: 10.10.1.1 = Debian (Elastic stack), 10.10.1.10 = Windows (victim), 10.10.10.10 = Kali (attacker).
# Rules are named TLS-1..4, HTTP-1..5, DNS-1..6, TCP-1..3, FILE-1..2, EDR-1 (TCP-4 exists in Kibana but disabled, not in this script).

KIBANA="http://10.10.1.1:5601"
AUTH="elastic:vagrant"

echo "[kibana-rules] Waiting for Kibana..."
for i in $(seq 1 30); do
  STATUS=$(curl -s -u "$AUTH" "$KIBANA/api/status" 2>/dev/null | grep -o '"overall"' | head -1)
  if [ -n "$STATUS" ]; then echo "[kibana-rules] Kibana ready."; break; fi
  echo "  [$i/30] waiting..."
  sleep 10
done

echo "[kibana-rules] Creating rules..."

# ════════════════════════════════════════════════════════════════════
# TLS — zeek.ssl
# ════════════════════════════════════════════════════════════════════

# TLS-1 - Obsolete TLS version (1.0 / 1.1 / 1.2)

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] TLS version 1.2 used",
    "description": "Detects TLS 1.2 connections on port 443 - modern clients prefer 1.3",
    "rule_id": "zeek-tls-obsolete-version",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.ssl\" and source.ip: \"10.10.1.10\" and tls.version: (\"1.0\" or \"1.1\" or \"1.2\") and destination.port: 443",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 40,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m"
  }' -o /dev/null && echo "[kibana-rules] TLS-1 created: obsolete TLS version"

# TLS-2 — TLS connection using a self-signed certificate.

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Self-signed TLS certificate",
    "description": "TLS connection from Windows toward a server with a self-signed certificate. Only detectable in TLS 1.2 — TLS 1.3 encrypts the certificate during the handshake.",
    "rule_id": "zeek-self-signed-cert",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.ssl\" and zeek.ssl.validation.status: \"self signed certificate\" and not destination.ip: \"10.10.1.1\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 71,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "TLS", "C2", "T1573"]
  }' -o /dev/null && echo "[kibana-rules] TLS-2 created: self-signed cert"

# TLS-3 — TLS connection with no SNI (raw IP, no domain).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] SNI absent",
    "description": "TLS connection from Windows with no Server Name Indication. No legitimate browser connects to a raw IP without SNI. Works in TLS 1.2 and TLS 1.3.",
    "rule_id": "zeek-no-sni",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.ssl\" and not zeek.ssl.server.name: * and source.ip: \"10.10.1.10\"",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 50,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "TLS", "SNI", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] TLS-3 created: SNI absent"

# TLS-4 — JA4+JA4S fingerprint for known Sliver C2 (source: ja4db.com).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] JA4+JA4S fingerprint - Sliver C2",
    "description": "TLS ClientHello (JA4) and ServerHello (JA4S) both match the Sliver C2 default Go TLS stack. Hash validated on ja4db.com / FoxIO ja4plus-mapping.csv (9 July 2026).",
    "rule_id": "zeek-tls4-ja4-ja4s-sliver",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.ssl\" and source.ip: \"10.10.1.10\" and zeek.ssl.ja4: \"t13d190900_9dc949149365_97f8aa674fd9\" and zeek.ssl.ja4s: \"t130200_1301_a56c5b993250\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 73,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "TLS", "JA4", "C2", "T1573"]
  }' -o /dev/null && echo "[kibana-rules] TLS-4 created: JA4+JA4S Sliver"

# ════════════════════════════════════════════════════════════════════
# HTTP — zeek.http
# ════════════════════════════════════════════════════════════════════

# HTTP-1 — HTTP request with no Host header.

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] HTTP without HostName",
    "description": "The field Host: example.com is missing in the HTTP header. Required by RFC 7230 — any modern client sends it. Absence indicates a custom or primitive HTTP client, typical of C2 tooling.",
    "rule_id": "zeek-no-host-header",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.http\" and source.ip: \"10.10.1.10\" and not url.domain: *",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 65,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "HTTP", "C2", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] HTTP-1 created: HTTP no Host header"

# HTTP-2 — User-Agent that is not a real browser.

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] HTTP User-Agent non-browser",
    "description": "HTTP request from Windows with a User-Agent that does not contain a modern browser token (Chrome/, Edg/, Firefox/, Safari/) nor a known Windows update agent string. Catches unconfigured C2 default UAs (Meterpreter reverse_http default is IE6-on-XP) and bare HTTP clients.",
    "rule_id": "zeek-http-nonbrowser-ua",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.http\" and source.ip: \"10.10.1.10\" and user_agent.original: * and not user_agent.original: (*Chrome/* or *Edg/* or *Firefox/* or *Safari/* or *Windows-Update-Agent* or *Microsoft-Delivery-Optimization*)",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 55,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "HTTP", "C2", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] HTTP-2 created: User-Agent non-browser"

# HTTP-2-bis — known C2 User-Agent exact-match blacklist (source: SigmaHQ proxy_ua_frameworks.yml).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Known signatures of C2 User Agent.",
    "description": "Exact-match blacklist of known default C2 User-Agent strings (Metasploit, Cobalt Strike, Havoc)",
    "rule_id": "zeek-http-blacklist-user-agent",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.http\" and source.ip: \"10.10.1.10\" and user_agent.original: (\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; InfoPath.2)\" or \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\" or \"Mozilla/4.0 (compatible; Metasploit RSPEC)\" or \"Mozilla/5.0\" or \"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MAAU)\" or \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36\")",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 75,
    "enabled": true,
    "interval": "5m",
    "from": "now-6m",
    "tags": ["Zeek", "User Agent", "C2", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] HTTP-2-bis created: C2 User-Agent blacklist"

# HTTP-3 — 3+ big HTTP POST bodies to the same destination (Threshold).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Threshold — POST HTTP large body (exfiltration by chunking)",
    "description": "HTTP POST with body over 100KB to same destination in 5 min. Detects chunked exfiltration over cleartext HTTP.",
    "rule_id": "zeek-threshold-http-post-exfil",
    "type": "threshold",
    "language": "kuery",
    "query": "event.dataset: \"zeek.http\" AND source.ip: \"10.10.1.10\" AND http.request.method: \"POST\" AND http.request.body.bytes > 100000",
    "threshold": {
      "field": ["destination.ip"],
      "value": 3
    },
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 60,
    "enabled": true,
    "interval": "5m",
    "from": "now-6m",
    "tags": ["Zeek", "HTTP", "Exfiltration", "T1041"]
  }' -o /dev/null && echo "[kibana-rules] HTTP-3 created: threshold POST large body"

# HTTP-4 (P3) — a single HTTP CONNECT to an external IP is enough to flag tunneling or proxy discovery.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] HTTP CONNECT to external IP (tunneling / proxy discovery)",
    "description": "Single HTTP CONNECT to external IP. Two scenarios: (1) proxy-aware implant discovering egress path — one CONNECT is enough to detect the probe. (2) active tunnel (Chisel, Ligolo-ng) — also a single CONNECT, followed by an opaque TCP stream. No threshold needed: in a lab with no configured proxy, any CONNECT to an external IP is anomalous.",
    "rule_id": "zeek-http-connect-external",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.http\" and source.ip: \"10.10.1.10\" and http.request.method: \"CONNECT\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 73,
    "enabled": true,
    "interval": "1m",
    "from": "now-2m",
    "tags": ["Zeek", "HTTP", "Tunnel", "T1572", "T1090"]
  }' -o /dev/null && echo "[kibana-rules] HTTP-4 created: HTTP CONNECT external IP"

# HTTP-5 (P1) — a TLS connection with no SNI followed by a large data transfer (EQL sequence).
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] EQL — Exfiltration HTTPS toward raw IP (no-SNI + volume)",
    "description": "TLS connection to raw IP (no SNI) followed by at least 1MB outbound on the same socket",
    "rule_id": "zeek-eql-https-exfil-nosni",
    "type": "eql",
    "language": "eql",
    "query": "sequence by source.ip, destination.ip, destination.port with maxspan=5m\n  [any where event.dataset == \"zeek.ssl\" and zeek.ssl.server.name == null and source.ip == \"10.10.1.10\"]\n  [any where event.dataset == \"zeek.connection\" and source.bytes > 1000000 and source.ip == \"10.10.1.10\"]",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 80,
    "enabled": true,
    "interval": "5m",
    "from": "now-6m",
    "tags": ["Zeek", "EQL", "Exfiltration", "T1041", "T1573"]
  }' -o /dev/null && echo "[kibana-rules] HTTP-5 created: EQL HTTPS exfil no-SNI"

# ════════════════════════════════════════════════════════════════════
# DNS — zeek.dns
# ════════════════════════════════════════════════════════════════════

# DNS-1 — DNS TXT query from a Windows workstation.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] DNS TXT request",
    "description": "DNS TXT query from a Windows workstation. Normal workstations never query TXT records — that is a mail server responsibility. Tools like dnscat2 use DNS TXT to tunnel C2 traffic over port 53.",
    "rule_id": "zeek-dns-txt",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.dns\" and source.ip: \"10.10.1.10\" and dns.question.type: \"TXT\"",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 50,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "DNS", "C2", "T1071", "T1048"]
  }' -o /dev/null && echo "[kibana-rules] DNS-1 created: DNS TXT"

# DNS-2 — DNS query sent to a resolver that is not the official one.

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] DNS direct resolution",
    "description": "Alert if a DNS resolution is made directly by the victim instead of using the configured resolver.",
    "rule_id": "zeek-dns-direct-resolution",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.dns\" and source.ip: \"10.10.1.10\" and not destination.ip: \"10.10.1.1\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 65,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m"
  }' -o /dev/null && echo "[kibana-rules] DNS-2 created: DNS direct resolution"

# DNS-3 — 20+ NXDOMAIN answers in 5 minutes (DGA malware, Threshold).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Threshold — DNS NXDOMAIN burst T1568",
    "description": "The malware generates a lot of DNS requests to find the domain name used by its master.",
    "rule_id": "zeek-threshold-dns-nxdomain",
    "type": "threshold",
    "language": "kuery",
    "query": "event.dataset: \"zeek.dns\" AND source.ip: \"10.10.1.10\" AND zeek.dns.rcode_name: \"NXDOMAIN\"",
    "threshold": {
      "field": ["source.ip"],
      "value": 20
    },
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 60,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "DNS", "T1568", "NXDOMAIN"]
  }' -o /dev/null && echo "[kibana-rules] DNS-3 created: threshold DNS NXDOMAIN burst"

# DNS-4 — one very long DNS subdomain name (EQL).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] DNS long subdomain (exfiltration)",
    "description": "DNS query name > 50 chars from Windows. Exfiltration tools encode data in subdomain names regardless of record type. Covers DNS-1 blind spot on A/AAAA/CNAME records.",
    "rule_id": "zeek-dns-long-subdomain",
    "type": "eql",
    "language": "eql",
    "query": "any where event.dataset == \"zeek.dns\" and source.ip == \"10.10.1.10\" and length(dns.question.name) > 50",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 55,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "DNS", "Exfiltration", "T1071", "T1048"]
  }' -o /dev/null && echo "[kibana-rules] DNS-4 created: DNS long subdomain"

# DNS-5 — many different subdomains under the same domain (Threshold + cardinality).
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Threshold — DNS important number of subdomain associated with a domain.",
    "description": "To encode traffic in subdomain implies numerous subdomain register under a domaine name — T1071",
    "rule_id": "zeek-threshold-dns-subdomain-cardinality",
    "type": "threshold",
    "language": "kuery",
    "query": "event.dataset: \"zeek.dns\" AND source.ip: \"10.10.1.10\" AND dns.question.registered_domain: *",
    "threshold": {
      "field": ["source.ip"],
      "value": 15
    },
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 60,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "DNS", "T1071", "subdomain"]
  }' -o /dev/null && echo "[kibana-rules] DNS-5 created: threshold DNS subdomain cardinality"

# DNS-6 — same subdomain queried 10+ times with TTL=0 answers (Threshold, heartbeat/beaconing).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Threshold — DNS TTL=0 heartbeat (same subdomain)",
    "description": "Same DNS name queried 10+ times with TTL=0 answers from the same source. TTL=0 forces cache bypass — required by C2 implants (Sliver, DNScale) so every heartbeat traverses the full resolution path. Low FP: legitimate TTL=0 (CDN failover) never repeats the same hostname this many times in minutes.",
    "rule_id": "zeek-threshold-dns-ttl-zero",
    "type": "threshold",
    "language": "kuery",
    "query": "event.dataset: \"zeek.dns\" AND source.ip: \"10.10.1.10\" AND dns.answers.ttl: 0",
    "threshold": {
      "field": ["source.ip", "dns.question.name"],
      "value": 10
    },
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 55,
    "enabled": true,
    "interval": "1m",
    "from": "now-6m",
    "tags": ["Zeek", "DNS", "T1071", "TTL", "Heartbeat"]
  }' -o /dev/null && echo "[kibana-rules] DNS-6 created: threshold DNS TTL=0 heartbeat"

# ════════════════════════════════════════════════════════════════════
# TCP / Transport — zeek.connection
# ════════════════════════════════════════════════════════════════════

# TCP-1 — TCP connection using a non-standard port.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Connection through a non-standard port",
    "description": "TCP connection from Windows to a port outside the whitelist. Reverse shells and C2 frameworks use custom ports to bypass firewall rules.",
    "rule_id": "zeek-nonstandard-port",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.connection\" and source.ip: \"10.10.1.10\" and network.transport: \"tcp\" and not destination.port: (53 or 80 or 123 or 443 or 445 or 3389 or 5601 or 8080 or 8220 or 9200)",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 47,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "C2", "T1571"]
  }' -o /dev/null && echo "[kibana-rules] TCP-1 created: non-standard port"

# TCP-2 — connection to a Tor port (9001 / 9030 / 9050).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] TOR connection",
    "description": "Detect if a connection to a tor server node (9001, 9030) or to a tor client (9050).",
    "rule_id": "zeek-tcp-tor-port",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.connection\" and source.ip: \"10.10.1.10\" and network.transport: \"tcp\" and destination.port: (9001 or 9030 or 9050)",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 75,
    "enabled": true,
    "interval": "1m",
    "from": "now-2m"
  }' -o /dev/null && echo "[kibana-rules] TCP-2 created: TOR connection"

# TCP-3 — connection to a lateral movement port (SMB / WinRM / RDP).

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Agent] EQL - Lateral movement ports (unsigned process)",
    "description": "Detect lateral movement from non-legitimate process on ports 445, 135, 3389, 5985, 5986. Correlates process start (unsigned, non-system) to outbound network event via process.entity_id.",
    "rule_id": "agent-eql-lateral-movement-ports",
    "type": "eql",
    "language": "eql",
    "query": "sequence by process.entity_id with maxspan=1m\n  [process where host.os.type == \"windows\" and event.type == \"start\"\n   and process.pid != 4\n   and not user.id in (\"S-1-5-19\", \"S-1-5-20\")\n   and not (process.code_signature.trusted == true\n            and startsWith(process.code_signature.subject_name, \"Microsoft\"))]\n  [network where host.os.type == \"windows\"\n   and destination.port in (445, 135, 3389, 5985, 5986)\n   and process.pid != 4]",
    "index": ["logs-endpoint.events.process-*", "logs-endpoint.events.network-*"],
    "severity": "high",
    "risk_score": 70,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Agent", "EQL", "LateralMovement", "T1021"]
  }' -o /dev/null && echo "[kibana-rules] TCP-3 created: EQL lateral movement ports"

# FILE-1 (T1105) — a PE executable download detected over HTTP by magic bytes.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] PE executable download over HTTP",
    "description": "PE32 file (application/x-dosexec) downloaded by Windows over cleartext HTTP. Zeek identifies from magic bytes. Indicates stage-2 payload delivery (T1105). Blind on HTTPS.",
    "rule_id": "zeek-pe-download-http",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.files\" and zeek.files.mime_type: \"application/x-dosexec\" and zeek.files.id.orig_h: \"10.10.1.10\" and zeek.files.source: \"HTTP\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 80,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "T1105", "Payload", "PE"]
  }' -o /dev/null && echo "[kibana-rules] T1105 created: PE download over HTTP"

# FILE-2 (E4) — a direct SMTP connection from a Windows endpoint
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] SMTP from endpoint (T1071.003)",
    "description": "Direct SMTP connection from a Windows endpoint. Normal workstations route mail through Exchange. Indicates email-based exfiltration or C2.",
    "rule_id": "zeek-smtp-from-endpoint",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.smtp\" and source.ip: \"10.10.1.10\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 70,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "SMTP", "Exfiltration", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] FILE-2 created: SMTP from endpoint"

# EDR-1 — LOLBins open a network connection.

curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Agent] EQL - LOLBin outbound network connection",
    "description": "A Windows LOLBin (curl, certutil, mshta, regsvr32...) started and opened an outbound network connection within 2 minutes. Correlates process.entity_id across Elastic Defend process and network events. Near-zero FP on non-admin workstations.",
    "rule_id": "community-lolbin-outbound-network",
    "type": "eql",
    "language": "eql",
    "query": "sequence by host.id, process.entity_id with maxspan=2m\n  [process where host.os.type == \"windows\" and event.type == \"start\"\n   and process.name : (\"powershell.exe\",\"pwsh.exe\",\"cmd.exe\",\"wscript.exe\",\"cscript.exe\",\"mshta.exe\",\"rundll32.exe\",\"regsvr32.exe\",\"cmstp.exe\",\"certutil.exe\",\"bitsadmin.exe\",\"curl.exe\",\"xwizard.exe\")]\n  [network where host.os.type == \"windows\"\n   and event.action : \"connection_attempted\"\n   and destination.ip != \"127.0.0.1\"]",
    "index": ["logs-endpoint.events.process-*", "logs-endpoint.events.network-*"],
    "severity": "high",
    "risk_score": 73,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Agent", "EQL", "LOLBin", "T1059"]
  }' -o /dev/null && echo "[kibana-rules] EDR-1 created: LOLBin outbound network"

echo "[kibana-rules] Done."
