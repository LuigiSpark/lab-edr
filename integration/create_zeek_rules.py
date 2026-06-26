"""
create_zeek_rules.py
====================
Creates three Elastic Security detection rules based on Zeek conn.log data.
These rules fire on network behavior visible from Zeek even when
endpoint events (Elastic Defend process/network) are not flowing.

Run from debian: python3 create_zeek_rules.py
"""

import urllib.request
import urllib.error
import json
import base64

KIBANA_URL = "http://10.10.1.1:5601"
ES_USER    = "elastic"
ES_PASS    = "vagrant"

# Zeek conn.log lands in filebeat-* via the zeek.connection fileset
ZEEK_INDEX = "filebeat-*"

# Windows VM source IP — origin of all suspicious outbound connections
WINDOWS_IP = "10.10.1.10"

# Attacker network — any destination in this subnet is suspicious from Windows
ATTACKER_SUBNET = "10.10.10.0/24"

# Minimum duration (nanoseconds) to qualify as a persistent C2 connection.
# 30 seconds = 30_000_000_000 ns. Filters out legitimate short connections.
MIN_DURATION_NS = 30_000_000_000

# Ports considered normal for Windows outbound traffic in this lab.
# Connections to anything else are suspicious.
ALLOWED_PORTS = [80, 443, 53, 8080, 8220, 5601, 9200]


def kb_post(path: str, body: dict) -> dict:
    """POST to Kibana API, return parsed JSON response."""
    creds   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {creds}",
        # kbn-xsrf is required by Kibana for all mutating requests
        "kbn-xsrf":      "true",
    }
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{KIBANA_URL}{path}", data=data, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  HTTP {e.code}: {body[:300]}")
        return {}


# ── Rule definitions ────────────────────────────────────────────────────────────

RULES = [
    {
        # Rule 1 — Port 4444 outbound from Windows
        # Port 4444 is the default port for Metasploit, netcat, and many reverse shells.
        # Any outbound TCP connection from Windows to port 4444 is highly suspicious.
        "name":        "[Zeek] Outbound TCP to port 4444 (reverse shell)",
        "description": "Detects a TCP connection from Windows (10.10.1.10) to port 4444. "
                       "Port 4444 is the default for Metasploit and netcat reverse shells.",
        "severity":    "high",
        "risk_score":  73,
        "type":        "query",
        "language":    "kuery",
        "query": (
            f'event.dataset: "zeek.connection" '
            f'AND source.ip: "{WINDOWS_IP}" '
            f'AND destination.port: 4444 '
            f'AND network.transport: "tcp"'
        ),
        "index":    [ZEEK_INDEX],
        "interval": "1m",
        "from":     "now-2m",
        "tags":     ["zeek", "reverse-shell", "T1059", "lab"],
    },
    {
        # Rule 2 — Long TCP connection from Windows to attacker subnet
        # A reverse shell stays connected for minutes or hours.
        # Any TCP connection from Windows to 10.10.10.0/24 lasting more than 30 seconds
        # is a strong indicator of C2 activity.
        # event.duration is stored in nanoseconds in Zeek ECS mapping.
        "name":        "[Zeek] Long TCP connection from Windows to attacker subnet",
        "description": "Detects persistent TCP connections (>30s) from the Windows VM "
                       "to the attacker network (10.10.10.0/24). Characteristic of C2 channels.",
        "severity":    "high",
        "risk_score":  73,
        "type":        "query",
        "language":    "kuery",
        "query": (
            f'event.dataset: "zeek.connection" '
            f'AND source.ip: "{WINDOWS_IP}" '
            f'AND destination.ip: "10.10.10.0/24" '
            f'AND event.duration > {MIN_DURATION_NS} '
            f'AND network.transport: "tcp"'
        ),
        "index":    [ZEEK_INDEX],
        "interval": "1m",
        "from":     "now-2m",
        "tags":     ["zeek", "c2", "T1095", "lab"],
    },
    {
        # Rule 3 — TCP connection from Windows to non-standard port
        # Legitimate Windows traffic uses a small set of well-known ports.
        # A connection to any other port (not 80, 443, 53, 8080, 8220, 5601, 9200)
        # warrants investigation in this lab environment.
        "name":        "[Zeek] Windows outbound TCP to non-standard port",
        "description": "Detects outbound TCP from Windows to a port not in the known-good list "
                       f"({', '.join(str(p) for p in ALLOWED_PORTS)}). "
                       "Covers port-obfuscated reverse shells and non-standard C2.",
        "severity":    "medium",
        "risk_score":  47,
        "type":        "query",
        "language":    "kuery",
        "query": (
            f'event.dataset: "zeek.connection" '
            f'AND source.ip: "{WINDOWS_IP}" '
            f'AND network.transport: "tcp" '
            f'AND NOT destination.port: '
            f'({" OR ".join(str(p) for p in ALLOWED_PORTS)})'
        ),
        "index":    [ZEEK_INDEX],
        "interval": "1m",
        "from":     "now-2m",
        "tags":     ["zeek", "non-standard-port", "T1571", "lab"],
    },
]


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    for rule in RULES:
        print(f"Creating: {rule['name']}")

        # Build the minimal rule payload expected by the Kibana Detection Engine API
        payload = {
            "name":          rule["name"],
            "description":   rule["description"],
            "risk_score":    rule["risk_score"],
            "severity":      rule["severity"],
            "type":          rule["type"],
            "language":      rule["language"],
            "query":         rule["query"],
            "index":         rule["index"],
            "interval":      rule["interval"],
            "from":          rule["from"],
            "enabled":       True,
            "tags":          rule["tags"],
            # threat field maps to MITRE ATT&CK — left empty for simplicity
            "threat":        [],
        }

        result = kb_post("/api/detection_engine/rules", payload)

        if result.get("id"):
            print(f"  OK  id={result['id']}")
        else:
            print(f"  FAILED: {result}")

    print("\nDone.")


if __name__ == "__main__":
    main()
