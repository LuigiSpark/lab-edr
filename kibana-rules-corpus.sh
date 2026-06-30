#!/usr/bin/env bash
# ── kibana-rules-corpus.sh ────────────────────────────────────────────────
# All Zeek detection rules for this lab — 12 rules across 5 datasets.
# Called by debian_script.sh during provisioning.
#
# Lab IPs:
#   10.10.1.1   = Debian (Elastic stack — exclude from most rules)
#   10.10.1.10  = Windows (victim — source of suspicious traffic)
#   10.10.10.10 = Kali (attacker)
#
# JA4 hashes calibrated on this lab (29 June 2026):
#   t12i1807h1_4b22cbed5bed_2dae41c691ec = curl OpenSSL (Linux, TLS 1.2)
#   t13i2011h1_2b729b4bf6f3_36bf25f296df = Windows Schannel (TLS 1.3)
#
# Corpus reference: ai/corpus-regles-detection-reseau.md
# ─────────────────────────────────────────────────────────────────────────

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
# CATEGORY A — TLS layer (zeek.ssl)
# ════════════════════════════════════════════════════════════════════

# A1 — Self-signed TLS certificate (MITRE T1573)
# An attacker spinning up a C2 server generates a self-signed cert with openssl in seconds.
# Excluded: 10.10.1.1 (Elastic stack uses self-signed certs internally).
# IMPORTANT: only detectable in TLS 1.2 — TLS 1.3 encrypts the certificate in the handshake.
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
  }' -o /dev/null && echo "[kibana-rules] A1 created: self-signed cert"

# A2 — TLS connection without SNI (MITRE T1071)
# Every legitimate browser sends SNI in the TLS ClientHello.
# A malware connecting directly to an IP (no DNS lookup) has no hostname to put in SNI.
# Works in TLS 1.2 AND TLS 1.3 — SNI is always sent in plaintext before encryption starts.
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
    "query": "event.dataset: \"zeek.ssl\" and not tls.server_name: * and source.ip: \"10.10.1.10\"",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 50,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "TLS", "SNI", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] A2 created: SNI absent"

# A3 — JA4 fingerprint of known tool (MITRE T1071)
# JA4 hashes the TLS ClientHello: protocol, version, ciphers, extensions, ALPN.
# Unlike JA3, JA4 sorts extensions before hashing — resistant to randomization attacks.
# These two hashes match Windows Schannel (curl.exe) and curl OpenSSL used in this lab.
# Suricata ET Open covers known hashes on port 443 only; Zeek covers all ports.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] JA4 fingerprint — non-browser tool",
    "description": "JA4 fingerprint matching Windows Schannel (curl.exe) or curl OpenSSL — not a browser. JA4 is resistant to cipher-order randomization (unlike JA3). Hashes calibrated on this lab.",
    "rule_id": "zeek-ja4-tool",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.ssl\" AND source.ip: \"10.10.1.10\" AND zeek.ssl.ja4: (\"t13i2011h1_2b729b4bf6f3_36bf25f296df\" OR \"t12i1807h1_4b22cbed5bed_2dae41c691ec\")",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 80,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "JA4", "Fingerprint", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] A3 created: JA4 fingerprint"

# A5 — TLS obsolete version (1.0 or 1.1) (MITRE T1573)
# TLS 1.0 and 1.1 were deprecated by RFC 8996 (March 2021).
# All modern clients (Windows 11, Chrome, Edge) have them disabled.
# A malware compiled against an old OpenSSL or using a minimal custom TLS stack
# may negotiate TLS 1.0/1.1. Presence from a Windows 11 host is anomalous.
# Note: unlikely to trigger in this lab — serves as baseline signal documentation.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] TLS obsolete version (1.0 or 1.1)",
    "description": "TLS 1.0 and 1.1 are deprecated by RFC 8996 (2021). A Windows 11 host negotiating these versions indicates a legacy-compiled implant or custom TLS stack.",
    "rule_id": "zeek-tls-legacy",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.ssl\" AND source.ip: \"10.10.1.10\" AND tls.version: (\"1.0\" OR \"1.1\")",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 40,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "TLS", "T1573"]
  }' -o /dev/null && echo "[kibana-rules] A5 created: TLS legacy version"

# ════════════════════════════════════════════════════════════════════
# CATEGORY B — HTTP layer (zeek.http)
# ════════════════════════════════════════════════════════════════════

# B1 — HTTP request without Host header (MITRE T1071)
# HTTP/1.1 mandates the Host header (RFC 7230). Every browser and HTTP library sends it.
# A raw-socket C2 or primitive reverse shell using HTTP/1.0 may omit it.
# Near-zero false positives — any framework omitting it is either broken or custom-built.
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
    "query": "event.dataset: \"zeek.http\" AND source.ip: \"10.10.1.10\" AND NOT zeek.http.host: *",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 65,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "HTTP", "C2", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] B1 created: HTTP no Host header"

# B2 — HTTP User-Agent non-browser (MITRE T1071)
# Metasploit meterpreter/reverse_http uses "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
# by default — IE6 on Windows XP, in 2026. Cobalt Strike default: MSIE 9.0 on Windows 7.
# The whitelist covers browsers and legitimate Windows/Elastic agents.
# ECS field: user_agent.original (NOT zeek.http.user_agent which is not indexed).
# Limit: configured C2 (Malleable C2, Sliver HTTP profile) can spoof a Chrome UA.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] HTTP User-Agent non-browser",
    "description": "HTTP request from Windows with a User-Agent that is not a browser. Metasploit default: MSIE 6.0 on Windows XP. Cobalt Strike default: MSIE 9.0. FP: curl, PowerShell, enterprise agents.",
    "rule_id": "zeek-useragent",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.http\" AND source.ip: \"10.10.1.10\" AND user_agent.original: * AND NOT user_agent.original: (*Mozilla* OR *Chrome* OR *Edge* OR *Windows-Update-Agent* OR *Microsoft-Delivery-Optimization* OR *Elastic*)",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 55,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "HTTP", "C2", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] B2 created: User-Agent non-browser"

# B3 — HTTP POST with large body (MITRE T1048.003)
# Legitimate HTTP POSTs from endpoints rarely exceed 100 KB.
# File exfiltration or secrets encoded in base64 can easily exceed this threshold.
# Only detectable in cleartext HTTP — HTTPS body is encrypted and invisible to Zeek.
# New field: zeek.http.request_body_len = size in bytes of the HTTP request body.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] HTTP POST large body (potential exfiltration)",
    "description": "HTTP POST with body > 100 KB from Windows. Legitimate endpoints rarely send that volume. Possible file or secret exfiltration. Only detectable on cleartext HTTP — HTTPS body is encrypted.",
    "rule_id": "zeek-http-post-large",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.http\" AND source.ip: \"10.10.1.10\" AND http.request.method: \"POST\" AND zeek.http.request_body_len > 100000",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 60,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "HTTP", "Exfiltration", "T1048"]
  }' -o /dev/null && echo "[kibana-rules] B3 created: HTTP POST large body"

# ════════════════════════════════════════════════════════════════════
# CATEGORY C — DNS layer (zeek.dns)
# ════════════════════════════════════════════════════════════════════

# C1 — DNS TXT query from endpoint (MITRE T1071.004, T1048.003)
# TXT records carry arbitrary text — used by mail servers for SPF/DKIM/DMARC.
# A Windows workstation never makes TXT queries in normal usage (mail server job).
# Tools like dnscat2 encode C2 commands in DNS TXT responses, tunneling over port 53
# which passes through most firewalls that block 80/443.
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
    "query": "event.dataset: \"zeek.dns\" AND source.ip: \"10.10.1.10\" AND dns.question.type: \"TXT\"",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 50,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "DNS", "C2", "T1071", "T1048"]
  }' -o /dev/null && echo "[kibana-rules] C1 created: DNS TXT"

# C2 — NXDomain burst — DGA indicator (MITRE T1568.002)
# DGA malware generates hundreds of candidate domain names algorithmically and queries them
# until one resolves. Conficker (2008): up to 250 candidates/day.
# A legitimate user never produces 20+ NXDOMAINs in 5 minutes.
# Threshold rule — fires when the same source IP hits 20 NXDOMAINs in 5 minutes.
# Note: only visible to Zeek if DNS goes through eth2 (toward Kali), not to local resolver.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] NXDomain burst — DGA indicator",
    "description": "More than 20 NXDOMAIN DNS responses from Windows in 5 minutes. Characteristic of Domain Generation Algorithm (DGA) malware probing for active C2 domains.",
    "rule_id": "zeek-nxdomain-burst",
    "type": "threshold",
    "language": "kuery",
    "query": "event.dataset: \"zeek.dns\" AND source.ip: \"10.10.1.10\" AND zeek.dns.rcode_name: \"NXDOMAIN\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 60,
    "enabled": true,
    "interval": "5m",
    "from": "now-6m",
    "threshold": {
      "field": ["source.ip"],
      "value": 20,
      "cardinality": []
    },
    "tags": ["Zeek", "DNS", "DGA", "T1568"]
  }' -o /dev/null && echo "[kibana-rules] C2 created: NXDomain burst"

# C3 — DNS query to unauthorized resolver (MITRE T1071.004)
# In enterprise environments, all DNS must go through the internal resolver (10.10.1.1).
# An attacker using DNS tunneling configures the implant to query their own DNS server
# directly — bypassing the internal resolver and its blocklist.
# Note: does not catch DNS over HTTPS (DoH) which uses port 443, invisible in zeek.dns.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] DNS to unauthorized resolver",
    "description": "DNS query from Windows to an IP other than the internal resolver (10.10.1.1). Indicates DNS tunneling or C2 using an attacker-controlled DNS server. Does not detect DoH (port 443).",
    "rule_id": "zeek-dns-unauth-resolver",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.dns\" AND source.ip: \"10.10.1.10\" AND NOT destination.ip: \"10.10.1.1\"",
    "index": ["filebeat-*"],
    "severity": "medium",
    "risk_score": 45,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "DNS", "C2", "T1071"]
  }' -o /dev/null && echo "[kibana-rules] C3 created: DNS unauthorized resolver"

# ════════════════════════════════════════════════════════════════════
# CATEGORY D — Transport layer (zeek.connection)
# ════════════════════════════════════════════════════════════════════

# D1 — Non-standard TCP port (MITRE T1571)
# Reverse shells and C2 frameworks use custom ports (e.g. 4444, 9001) to bypass firewall rules.
# Whitelist: DNS(53), HTTP(80), NTP(123), HTTPS(443), SMB(445),
#            RDP(3389), Kibana(5601), proxy(8080), Fleet(8220), Elasticsearch(9200).
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
  }' -o /dev/null && echo "[kibana-rules] D1 created: non-standard port"

# D2 — Lateral movement ports from Windows (MITRE T1021)
# SMB (445), DCOM endpoint mapper (135), WinRM (5985/5986), RDP (3389).
# These are the four dominant lateral movement vectors in Windows environments.
# Windows should never initiate SMB or WinRM toward Kali (10.10.10.x).
# Excludes 10.10.1.1 (internal server — SMB/RDP to it may be legitimate).
# Gap vs CrowdStrike: Falcon additionally correlates the process that opened the socket.
curl -s -u "$AUTH" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  "$KIBANA/api/detection_engine/rules" \
  -X POST \
  -d '{
    "name": "[Zeek] Lateral movement ports from Windows",
    "description": "Windows initiating connection on SMB (445), DCOM (135), WinRM (5985/5986) or RDP (3389) toward an unexpected host. Typical post-compromise pivot attempt.",
    "rule_id": "zeek-lateral-movement",
    "type": "query",
    "language": "kuery",
    "query": "event.dataset: \"zeek.connection\" AND source.ip: \"10.10.1.10\" AND destination.port: (445 OR 135 OR 5985 OR 5986 OR 3389) AND NOT destination.ip: \"10.10.1.1\"",
    "index": ["filebeat-*"],
    "severity": "high",
    "risk_score": 75,
    "enabled": true,
    "interval": "1m",
    "from": "now-5m",
    "tags": ["Zeek", "LateralMovement", "T1021"]
  }' -o /dev/null && echo "[kibana-rules] D2 created: lateral movement ports"

echo "[kibana-rules] All 12 rules created."
