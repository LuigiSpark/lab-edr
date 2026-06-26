"""
collect_alerts.py
=================
Watches C:\\lab\\submissions\\ for new files.
When a new file appears:
  1. Records the start time (UTC)
  2. Executes the file
  3. Waits OBSERVATION_WINDOW_SECONDS for defenses to react
  4. Queries Elasticsearch for alerts generated during that window
  5. Writes a JSON report to C:\\lab\\results\\<filename>_logs.json

Elasticsearch is queried on http://10.10.1.1:9200
(Debian VM, windows_net NIC — accessible from Windows on 10.10.1.0/24).

No third-party libraries required - only Python stdlib.
"""

import os
import sys
import json
import time
import base64
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


# ── Logging ─────────────────────────────────────────────────────────────────────
# All output goes to both stdout (for interactive use) and the log file (always).
# The log file uses append mode so history is preserved across restarts.

LOG_FILE = Path(r"C:\lab\collect_alerts.log")

class _Tee:
    """Writes to multiple file-like objects at once."""
    def __init__(self, *targets):
        self._targets = targets
    def write(self, msg):
        for t in self._targets:
            t.write(msg)
            t.flush()
    def flush(self):
        for t in self._targets:
            t.flush()

_log_handle = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
sys.stdout   = _Tee(sys.__stdout__, _log_handle)
sys.stderr   = _Tee(sys.__stderr__, _log_handle)


# ── Configuration ──────────────────────────────────────────────────────────────

SUBMISSIONS_DIR = Path(r"C:\lab\submissions")
RESULTS_DIR     = Path(r"C:\lab\results")

# Persistent list of already-processed filenames.
# Survives restarts: on startup, files in this list are skipped even if they
# are still sitting in submissions/.
PROCESSED_FILE  = Path(r"C:\lab\processed.txt")

ES_URL  = "http://10.10.1.1:9200"
ES_USER = "elastic"
ES_PASS = "vagrant"

# How long (seconds) to observe after execution before collecting alerts.
# 90s gives Elastic rules and Suricata time to generate and index their alerts.
OBSERVATION_WINDOW_SECONDS = 90

# How often (seconds) the watch loop checks for new files.
POLL_INTERVAL_SECONDS = 2

# Suricata stores severity as an integer. Map to human-readable labels.
# Convention: 1 = high, 2 = medium, 3 = low (lower number = more critical).
SURICATA_SEVERITY_MAP = {1: "high", 2: "medium", 3: "low"}

# Used to sort alerts: higher number = higher priority in the report.
SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "unknown": 0}

# Elasticsearch index names.
# Wildcards are used so the script keeps working if indices roll over.
INDEX_ELASTIC_ALERTS = ".internal.alerts-security.alerts-*"
INDEX_FILEBEAT       = ".ds-filebeat-*"


# ── Elasticsearch helper ────────────────────────────────────────────────────────

def es_search(index: str, body: dict) -> dict:
    """
    Sends a POST /_search request to Elasticsearch and returns the parsed JSON.

    Uses HTTP Basic Auth. No SSL - the lab runs without TLS on ES.
    On network error, prints a message and returns an empty result
    so the rest of the script can continue gracefully.
    """
    url = f"{ES_URL}/{index}/_search"

    # Encode credentials as Base64 for the Authorization header.
    credentials = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}",
    }

    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read())
    except urllib.error.URLError as e:
        print(f"  [ERROR] Cannot reach Elasticsearch at {ES_URL}: {e}")
        # Return a sentinel that callers can detect to flag the report as incomplete.
        return {"hits": {"hits": []}, "_es_error": str(e)}


# ── Alert collectors ────────────────────────────────────────────────────────────

def get_elastic_alerts(t_start: str, t_end: str) -> list:
    """
    Fetches Elastic Security alerts generated between t_start and t_end.

    These alerts are produced by detection rules (Elastic Defend rules,
    Zeek-based rules, EQL rules...) and stored in the .internal.alerts-* index.

    Each returned dict has: timestamp, source, rule, severity, reason.
    """
    body = {
        "size": 100,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "range": {
                "@timestamp": {"gte": t_start, "lte": t_end}
            }
        }
    }

    result = es_search(INDEX_ELASTIC_ALERTS, body)
    if "_es_error" in result:
        return [], result["_es_error"]

    alerts = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        alerts.append({
            "timestamp": src.get("@timestamp", ""),
            "source":    "elastic_security",
            # kibana.alert.rule.name is stored as a flat dotted key in _source
            "rule":      src.get("kibana.alert.rule.name", "unknown"),
            "severity":  src.get("kibana.alert.severity", "unknown"),
            # reason is a human-readable sentence generated by Elastic
            # e.g. "process cmd.exe, parent conhost.exe, created medium alert..."
            "reason":    src.get("kibana.alert.reason", ""),
        })

    return alerts, None


def get_suricata_alerts(t_start: str, t_end: str) -> list:
    """
    Fetches Suricata IDS alerts from the Filebeat index.

    Suricata writes events to /var/log/suricata/eve.json.
    Filebeat ships them to Elasticsearch, mapping fields to ECS format.
    We filter on suricata.eve.event_type = "alert" to exclude stats and flows
    (which make up the vast majority of records in the index).

    Each returned dict has: timestamp, source, rule, severity, reason.
    """
    body = {
        "size": 100,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"term":  {"suricata.eve.event_type": "alert"}},
                    {"range": {"@timestamp": {"gte": t_start, "lte": t_end}}}
                ]
            }
        }
    }

    result = es_search(INDEX_FILEBEAT, body)
    if "_es_error" in result:
        return [], result["_es_error"]

    alerts = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        # event.severity is an integer in Suricata's ECS mapping (1=high, 3=low)
        raw_severity = src.get("event", {}).get("severity", 3)
        alerts.append({
            "timestamp": src.get("@timestamp", ""),
            "source":    "suricata",
            # rule.name contains the full Suricata signature name
            "rule":      src.get("rule", {}).get("name", "unknown"),
            "severity":  SURICATA_SEVERITY_MAP.get(raw_severity, "unknown"),
            # rule.category contains the Suricata category (e.g. "Potentially Bad Traffic")
            "reason":    src.get("rule", {}).get("category", ""),
        })

    return alerts, None


# ── Report builder ──────────────────────────────────────────────────────────────

def build_report(filename: str, t_start: str, t_end: str,
                 elastic_alerts: list, suricata_alerts: list,
                 es_error: str | None = None) -> dict:
    """
    Merges alerts from both sources and sorts them by severity (highest first).

    The final structure is:
    {
      "payload":     "bypass_xor_v3.ps1",
      "t_start":     "2026-06-25T11:00:00Z",
      "t_end":       "2026-06-25T11:01:30Z",
      "alert_count": 2,
      "alerts": [
        { "timestamp": ..., "source": "elastic_security", "rule": ...,
          "severity": "medium", "reason": "..." },
        ...
      ]
    }
    """
    all_alerts = elastic_alerts + suricata_alerts

    # Sort by severity descending: high (3) → medium (2) → low (1) → unknown (0)
    all_alerts.sort(
        key=lambda a: SEVERITY_ORDER.get(a["severity"], 0),
        reverse=True
    )

    report = {
        "payload":     filename,
        "t_start":     t_start,
        "t_end":       t_end,
        "alert_count": len(all_alerts),
        "alerts":      all_alerts,
    }
    # Surface Elasticsearch connectivity errors so that a report with 0 alerts
    # is distinguishable from a report where the query itself failed.
    if es_error:
        report["es_error"] = es_error
    return report


# ── Payload executor ────────────────────────────────────────────────────────────

def execute_payload(filepath: Path) -> subprocess.Popen:
    """
    Launches the payload without waiting for it to exit.
    Returns the Popen handle so the caller can terminate the process
    after the observation window.

    We use Popen (not run/call) because payloads like reverse shells
    never terminate on their own - waiting for them would block the script.

    Execution is adapted to the file extension:
      .ps1  → PowerShell with execution policy bypass
      .bat  → cmd.exe /c
      other → run directly (covers .exe and anything else)
    """
    ext = filepath.suffix.lower()

    if ext == ".ps1":
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(filepath)]
    elif ext in (".bat", ".cmd"):
        cmd = ["cmd.exe", "/c", str(filepath)]
    elif ext in (".doc", ".docx", ".xls", ".xlsx", ".pdf", ".js", ".vbs", ".hta"):
        # Non-executable file types: open with the default Windows application
        # (requires Office for .doc, browser for .html, etc.)
        cmd = ["cmd.exe", "/c", "start", "", str(filepath)]
    else:
        # .exe, .dll (via rundll32), or unknown — run directly
        cmd = [str(filepath)]

    print(f"  [RUN] {filepath.name}")
    try:
        return subprocess.Popen(cmd)
    except OSError as e:
        # WinError 193 = the file is not a valid Win32 application
        # (corrupted PE, wrong architecture, or not a binary at all).
        # We return None so the main loop can skip this file gracefully.
        print(f"  [SKIP] Cannot launch {filepath.name}: {e}")
        return None


# ── Persistence helpers ─────────────────────────────────────────────────────────

def _save_processed(names: set) -> None:
    """Writes the set of processed filenames to PROCESSED_FILE (one per line)."""
    PROCESSED_FILE.write_text("\n".join(sorted(names)), encoding="utf-8")


# ── Main loop ───────────────────────────────────────────────────────────────────

def main():
    # Create the two directories if they do not exist yet.
    SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("[*] collect_alerts.py started")
    print(f"[*] Watching : {SUBMISSIONS_DIR}")
    print(f"[*] Results  : {RESULTS_DIR}")
    print(f"[*] ES       : {ES_URL}")
    print(f"[*] Window   : {OBSERVATION_WINDOW_SECONDS}s")

    # Load the persistent list of already-processed files.
    # This allows the script to survive restarts without re-executing old samples.
    if PROCESSED_FILE.exists():
        seen = set(
            l for l in PROCESSED_FILE.read_text(encoding="utf-8").splitlines() if l
        )
    else:
        seen = set()

    pending = set(os.listdir(SUBMISSIONS_DIR)) - seen
    print(f"[*] Processed: {len(seen)} file(s) already done")
    print(f"[*] Pending  : {len(pending)} file(s) to run")
    print()

    # Session counters — reset to zero each time the script starts.
    # session_total grows as new files appear (including files added mid-run).
    # session_done  counts files processed (or skipped) since startup.
    session_done  = 0
    session_total = len(pending)

    while True:
        current   = set(os.listdir(SUBMISSIONS_DIR))
        new_files = current - seen

        # If new files arrived since last poll, grow the denominator.
        added = len(new_files) - max(0, session_total - session_done)
        if added > 0:
            session_total += added

        for filename in sorted(new_files):  # sorted for deterministic order
            filepath = SUBMISSIONS_DIR / filename
            session_done += 1
            print(f"[{session_done}/{session_total}] {filename}")

            # --- Step 1: record start time ---
            t_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            print(f"  t_start = {t_start}")

            # --- Step 2: execute the payload ---
            proc = execute_payload(filepath)

            if proc is None:
                # Execution failed (invalid PE, wrong arch, etc.) — mark as done
                # so the script does not retry it on the next restart.
                seen.add(filename)
                _save_processed(seen)
                continue

            # --- Step 3: wait for defenses to react ---
            elapsed = 0
            while elapsed < OBSERVATION_WINDOW_SECONDS:
                chunk = min(10, OBSERVATION_WINDOW_SECONDS - elapsed)
                time.sleep(chunk)
                elapsed += chunk
                remaining = OBSERVATION_WINDOW_SECONDS - elapsed
                if remaining > 0:
                    print(f"  [{elapsed:3}s / {OBSERVATION_WINDOW_SECONDS}s] waiting...")

            # Terminate the payload process if it is still running.
            # A reverse shell or persistent implant would otherwise keep running
            # and pollute the next payload's observation window.
            if proc.poll() is None:
                proc.terminate()
                print("  [KILL] payload process terminated")

            # --- Step 4: record end time ---
            t_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            print(f"  t_end   = {t_end}")

            # --- Step 5: query Elasticsearch ---
            print("  querying Elastic Security...")
            elastic_alerts, err_elastic  = get_elastic_alerts(t_start, t_end)

            print("  querying Suricata...")
            suricata_alerts, err_suricata = get_suricata_alerts(t_start, t_end)

            es_error = err_elastic or err_suricata
            total = len(elastic_alerts) + len(suricata_alerts)
            print(f"  {len(elastic_alerts)} elastic + {len(suricata_alerts)} suricata = {total} alert(s)")
            if es_error:
                print(f"  [WARNING] ES unreachable — report marked incomplete")

            # --- Step 6: build and write report ---
            report = build_report(filename, t_start, t_end,
                                  elastic_alerts, suricata_alerts, es_error)

            stem        = Path(filename).stem           # e.g. "bypass_xor_v3"
            output_path = RESULTS_DIR / f"{stem}_logs.json"

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"  => {output_path.name}")
            print()

            # Mark file as processed so a restart does not re-execute it.
            seen.add(filename)
            _save_processed(seen)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
