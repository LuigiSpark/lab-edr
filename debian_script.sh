# Enable IP routing between the two internal networks (Windows <-> Kali).
echo "net.ipv4.ip_forward = 1" | tee -a /etc/sysctl.conf
sysctl -p
iptables -A FORWARD -i eth1 -o eth2 -j ACCEPT
iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT

# NAT Windows traffic to internet via Debian.
# Without this, packets from 10.10.1.10 have no return address on the internet.
# The FORWARD chain already allows all traffic — only MASQUERADE is missing.
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# ── Suricata ──────────────────────────────────────────────────────────────
# Network IDS: inspects every packet that passes through this VM (NFQUEUE mode).
# Acts as a middleman between Kali and Windows — sees all traffic.

echo "deb http://deb.debian.org/debian bookworm-backports main" > \
    /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install -t bookworm-backports suricata suricata-update jq -y

systemctl stop suricata 2>/dev/null || true
systemctl disable suricata

# Set Suricata to "accept" mode: it inspects packets but does NOT drop them.
# fail-open: if Suricata crashes, traffic keeps flowing instead of being blocked.
sed -i 's/#  mode: accept/  mode: accept/' /etc/suricata/suricata.yaml
sed -i '/  mode: accept/a\  fail-open: yes' /etc/suricata/suricata.yaml

suricata-update enable-source et/open   # enable Emerging Threats ruleset
suricata-update                         # download detection rules

# Start Suricata in background (NFQUEUE mode: inspect without blocking).
# Snapshot is taken after this — no need for systemd persistence.
suricata -c /etc/suricata/suricata.yaml -q 0 -D

# Send all forwarded packets to Suricata (queue 0).
# --queue-bypass: if Suricata crashes, packets pass through instead of being dropped.
iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

# ── Elasticsearch ─────────────────────────────────────────────────────────
# The database that stores everything: Zeek logs, Suricata alerts, Windows events.
# Kibana reads from Elasticsearch to display dashboards and detection alerts.

echo "vm.max_map_count=300000" | tee -a /etc/sysctl.conf
sysctl -p

apt install gpg curl -y
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
apt-get install apt-transport-https -y
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" \
  | tee /etc/apt/sources.list.d/elastic-9.x.list
apt-get update && apt-get install elasticsearch -y

tee /etc/elasticsearch/elasticsearch.yml << 'EOF'
cluster.name: edr-lab
node.name: central
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 10.10.1.1
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.enrollment.enabled: false  # disable the interactive setup wizard
xpack.security.http.ssl.enabled: false    # plain HTTP — lab network is isolated, no need for TLS
xpack.security.transport.ssl.enabled: false
EOF

# Définit le mot de passe admin avant le premier démarrage
echo "vagrant" | /usr/share/elasticsearch/bin/elasticsearch-keystore add --stdin bootstrap.password
systemctl start elasticsearch.service

# Attend qu'Elasticsearch soit prêt (code 401 = sécurité active = prêt)
echo "Waiting for Elasticsearch..."
for i in $(seq 1 30); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://10.10.1.1:9200" 2>/dev/null)
  [ "$status" = "401" ] || [ "$status" = "200" ] && break
  sleep 1
done
sleep 2

# Crée le mot de passe du compte interne utilisé par Kibana
curl -s -X POST "http://10.10.1.1:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" -u elastic:vagrant \
  -d '{"password": "vagrant"}'

# ── Kibana ────────────────────────────────────────────────────────────────
# The web UI on port 5601. Used to view events, write detection rules, and see alerts.

apt-get update && apt-get install kibana -y

tee /etc/kibana/kibana.yml << 'EOF'
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://10.10.1.1:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "vagrant"
xpack.encryptedSavedObjects.encryptionKey: "lab_key_32_chars_minimum_xxxxxxxx"
EOF

systemctl start kibana.service

# ── Règles de détection ───────────────────────────────────────────────────
# Installe et active les ~1700 règles prebuilt Elastic Security

echo "Waiting for Kibana..."
for i in $(seq 1 60); do
  level=$(curl -s "http://localhost:5601/api/status" -u elastic:vagrant 2>/dev/null \
    | jq -r '.status.overall.level' 2>/dev/null)
  [ "$level" = "available" ] && { echo "Kibana ready."; break; }
  echo "  [$i/60] ${level:-unreachable}..."
  sleep 3
done

curl -s -X PUT "http://localhost:5601/api/detection_engine/rules/prepackaged" \
  -H "kbn-xsrf: true" -u elastic:vagrant \
  | jq '{rules_installed, rules_updated}'

# Active les règles désactivées par lot de 100 (limite de l'API)
ITER=1
while true; do
  IDS=$(curl -s "http://localhost:5601/api/detection_engine/rules/_find?per_page=100&filter=alert.attributes.enabled:false" \
    -u elastic:vagrant | jq -c '[.data[].id]')
  COUNT=$(echo "$IDS" | jq 'length')
  [ "$COUNT" -eq 0 ] && break
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://localhost:5601/api/detection_engine/rules/_bulk_action" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" -u elastic:vagrant \
    -d "{\"action\": \"enable\", \"ids\": ${IDS}}")
  echo "  Batch ${ITER}: ${COUNT} rules — HTTP ${STATUS}"
  ITER=$((ITER + 1))
done

# ── Fleet Server ──────────────────────────────────────────────────────────
# Fleet manages remote agents (Windows): it pushes configs and updates to them.
# The Windows VM enrolls here to get its monitoring policy.

# Le paquet apt n'inclut pas Fleet Server — le tarball contient la version complète
curl -sL "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.2-linux-x86_64.tar.gz" \
  | tar xz -C /tmp/

# Initialise Fleet dans Kibana (crée les index internes nécessaires)
curl -s -X POST "http://localhost:5601/api/fleet/setup" \
  -H "kbn-xsrf: true" -u elastic:vagrant > /dev/null

# Jeton qui permet à Fleet Server de s'authentifier auprès d'Elasticsearch
SERVICE_TOKEN=$(curl -s -X POST "http://localhost:5601/api/fleet/service_tokens" \
  -H "kbn-xsrf: true" -u elastic:vagrant | jq -r '.value')
[ -z "$SERVICE_TOKEN" ] || [ "$SERVICE_TOKEN" = "null" ] && { echo "ERROR: fleet service token empty"; exit 1; }

# Politique dédiée à Fleet Server (séparée des endpoints Windows)
FLEET_POLICY_ID=$(curl -s -X POST "http://localhost:5601/api/fleet/agent_policies" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" -u elastic:vagrant \
  -d '{"name":"Fleet Server","namespace":"default","has_fleet_server":true}' \
  | jq -r '.item.id')
[ -z "$FLEET_POLICY_ID" ] || [ "$FLEET_POLICY_ID" = "null" ] && { echo "ERROR: fleet policy id empty"; exit 1; }

# Installe Fleet Server sur cette machine
# --fleet-server-es-insecure : autorise HTTP (pas de TLS) vers Elasticsearch
/tmp/elastic-agent-9.4.2-linux-x86_64/elastic-agent install \
  --fleet-server-es=http://10.10.1.1:9200 \
  --fleet-server-service-token="$SERVICE_TOKEN" \
  --fleet-server-policy="$FLEET_POLICY_ID" \
  --fleet-server-port=8220 \
  --fleet-server-es-insecure \
  --non-interactive

# Attend que Fleet Server réponde sur le port 8220
echo "Waiting for Fleet Server..."
FLEET_READY=0
for i in $(seq 1 30); do
  [ "$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:8220/api/status")" = "200" ] \
    && FLEET_READY=1 && break
  sleep 3
done
[ "$FLEET_READY" -eq 0 ] && { echo "ERROR: Fleet Server not ready after 90s"; exit 1; }

# Attend que le module endpoint soit disponible dans le catalogue Fleet (race condition au démarrage)
ENDPOINT_VERSION=""
for i in $(seq 1 12); do
  ENDPOINT_VERSION=$(curl -s "http://localhost:5601/api/fleet/epm/packages/endpoint" \
    -u elastic:vagrant | jq -r '.item.version // empty')
  [ -n "$ENDPOINT_VERSION" ] && break
  sleep 5
done
[ -z "$ENDPOINT_VERSION" ] || [ "$ENDPOINT_VERSION" = "null" ] && { echo "ERROR: endpoint package version empty"; exit 1; }

# Installe la version récupérée (idempotent — sans erreur si déjà installé)
curl -s -X POST "http://localhost:5601/api/fleet/epm/packages/endpoint/$ENDPOINT_VERSION" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -u elastic:vagrant -d '{"force":true}' > /dev/null

# Politique pour les agents Windows
WINDOWS_POLICY_ID=$(curl -s -X POST "http://localhost:5601/api/fleet/agent_policies" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" -u elastic:vagrant \
  -d '{"name":"Windows Endpoints","namespace":"default"}' \
  | jq -r '.item.id')
[ -z "$WINDOWS_POLICY_ID" ] || [ "$WINDOWS_POLICY_ID" = "null" ] && { echo "ERROR: windows policy id empty"; exit 1; }

# Attache Elastic Defend à la politique Windows
# Sans "inputs" : Fleet génère automatiquement la bonne configuration
curl -s -X POST "http://localhost:5601/api/fleet/package_policies" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" -u elastic:vagrant \
  -d "{
    \"name\": \"endpoint-lab\",
    \"policy_id\": \"$WINDOWS_POLICY_ID\",
    \"package\": {\"name\": \"endpoint\", \"version\": \"$ENDPOINT_VERSION\"}
  }" > /dev/null

# Crée le jeton d'enrôlement que Windows utilisera pour rejoindre Fleet
curl -s -X POST "http://localhost:5601/api/fleet/enrollment_api_keys" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" -u elastic:vagrant \
  -d "{\"policy_id\": \"$WINDOWS_POLICY_ID\"}" > /dev/null

# Fleet crée par défaut un output vers localhost:9200, inaccessible depuis Windows
# On corrige l'adresse vers l'IP réelle d'Elasticsearch
curl -s -X PUT "http://localhost:5601/api/fleet/outputs/fleet-default-output" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" -u elastic:vagrant \
  -d '{"name":"default","type":"elasticsearch","hosts":["http://10.10.1.1:9200"],"is_default":true,"is_default_monitoring":true}' \
  > /dev/null

# ── Filebeat / Suricata ───────────────────────────────────────────────────
# Filebeat reads Suricata's EVE JSON log and ships the alerts to Elasticsearch.
# Without this, Suricata alerts stay in a local file and Kibana never sees them.

apt-get install filebeat -y
filebeat modules enable suricata

tee /etc/filebeat/modules.d/suricata.yml << 'EOF'
- module: suricata
  eve:
    enabled: true
    var.paths:
      - /var/log/suricata/eve.json
EOF

tee /etc/filebeat/filebeat.yml << 'EOF'
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

output.elasticsearch:
  hosts: ["http://10.10.1.1:9200"]
  username: "elastic"
  password: "vagrant"
EOF

filebeat setup --index-management
systemctl enable filebeat
systemctl start filebeat

# ── Packetbeat ────────────────────────────────────────────────────────────
# Captures and decodes network protocols (DNS, HTTP, TLS, ICMP) directly from the wire.
# Feeds the Elastic ML jobs for behavioral anomaly detection (beaconing, rare destinations).

apt-get install libpcap0.8 packetbeat -y

tee /etc/packetbeat/packetbeat.yml << 'EOF'
# Capture sur toutes les interfaces (Windows + Kali + NAT)
packetbeat.interfaces.type: af_packet
packetbeat.interfaces.device: any

packetbeat.protocols:
- type: icmp
  enabled: true
- type: dns
  ports: [53]
- type: http
  ports: [80, 8080]
- type: tls
  ports: [443, 8443]

setup.kibana:
  host: "localhost:5601"
  username: "elastic"
  password: "vagrant"

output.elasticsearch:
  hosts: ["http://10.10.1.1:9200"]
  username: "elastic"
  password: "vagrant"
EOF

packetbeat setup           # charge les dashboards Kibana et les index templates
systemctl enable packetbeat
systemctl start packetbeat

# ── minGW-w64 ────────────────────────────────────────────────────────────
# Cross-compiler: lets you build Windows .exe files from Linux.
# Used to compile C payloads for the Windows VM without needing a Windows build environment.

sudo apt-get install mingw-w64 -y

# ── Elastic trial (Enterprise — 30 days) ────────────────────────────────
# Unlocks ML anomaly detection jobs, entity analytics, and advanced security features.
# Safe to run multiple times: if already activated, Elasticsearch returns trial_already_activated.
echo "[trial] Attente Elasticsearch..."
for i in $(seq 1 30); do
  STATUS=$(curl -s -u elastic:vagrant http://10.10.1.1:9200/_cluster/health 2>/dev/null | grep -o '"status":"[^"]*"' | head -1)
  if echo "$STATUS" | grep -qE "green|yellow"; then
    break
  fi
  sleep 10
done

RESULT=$(curl -s -X POST "http://elastic:vagrant@10.10.1.1:9200/_license/start_trial?acknowledge=true")
echo "[trial] $RESULT"

# ── ML Jobs — network anomaly detection ──────────────────────────────────
# 3 unsupervised ML jobs that learn what "normal" TLS traffic looks like,
# then alert when something unusual appears (new IP, unusual fingerprint, beaconing pattern).
# Safe to run multiple times: if already created, Elasticsearch returns resource_already_exists_exception.

echo "[ml] Attente Elasticsearch ready..."
for i in $(seq 1 30); do
  STATUS=$(curl -s --max-time 5 -u elastic:vagrant http://10.10.1.1:9200/_cluster/health 2>/dev/null | grep -o '"status":"[^"]*"' | head -1)
  if echo "$STATUS" | grep -qE "green|yellow"; then
    break
  fi
  sleep 10
done

# Job 1: alert when Windows connects to an IP it has never connected to before.
curl -s -u elastic:vagrant -X PUT http://10.10.1.1:9200/_ml/anomaly_detectors/lab-tls-rare-destination \
  -H Content-Type:application/json \
  -d '{"description":"Connexion TLS vers destination inhabituelle","analysis_config":{"bucket_span":"1h","detectors":[{"function":"rare","by_field_name":"destination.ip","over_field_name":"source.ip"}],"influencers":["source.ip","destination.ip"]},"data_description":{"time_field":"@timestamp"},"model_plot_config":{"enabled":false}}' \
  -o /dev/null

# Job 2: alert when TLS connections to the same IP are unusually frequent (C2 beaconing pattern).
curl -s -u elastic:vagrant -X PUT http://10.10.1.1:9200/_ml/anomaly_detectors/lab-tls-beacon \
  -H Content-Type:application/json \
  -d '{"description":"Beacon pattern - connexions TLS trop frequentes vers meme destination","analysis_config":{"bucket_span":"5m","detectors":[{"function":"high_count","over_field_name":"destination.ip"}],"influencers":["source.ip","destination.ip"]},"data_description":{"time_field":"@timestamp"}}' \
  -o /dev/null

# Job 3: alert when a TLS fingerprint (JA3) appears that has never been seen before.
# A new tool making TLS connections will have a different fingerprint than a browser.
curl -s -u elastic:vagrant -X PUT http://10.10.1.1:9200/_ml/anomaly_detectors/lab-tls-rare-ja3 \
  -H Content-Type:application/json \
  -d '{"description":"Fingerprint JA3 inhabituel - client TLS non-navigateur","analysis_config":{"bucket_span":"1h","detectors":[{"function":"rare","by_field_name":"tls.client.ja3"}],"influencers":["source.ip","tls.client.ja3"]},"data_description":{"time_field":"@timestamp"}}' \
  -o /dev/null

# Datafeeds sur Packetbeat TLS
for JOB in lab-tls-rare-destination lab-tls-beacon lab-tls-rare-ja3; do
  curl -s -u elastic:vagrant -X PUT http://10.10.1.1:9200/_ml/datafeeds/datafeed-${JOB} \
    -H Content-Type:application/json \
    -d "{\"job_id\":\"${JOB}\",\"indices\":[\".ds-packetbeat-9.4.2-*\"],\"query\":{\"term\":{\"network.protocol\":\"tls\"}},\"frequency\":\"1m\",\"scroll_size\":500}" \
    -o /dev/null
  curl -s -u elastic:vagrant -X POST http://10.10.1.1:9200/_ml/anomaly_detectors/${JOB}/_open -o /dev/null
  curl -s -u elastic:vagrant -X POST http://10.10.1.1:9200/_ml/datafeeds/datafeed-${JOB}/_start \
    -H Content-Type:application/json \
    -d '{"start":"now-30d"}' \
    -o /dev/null
  echo "[ml] $JOB started"
done

# ── Zeek 8.0 ─────────────────────────────────────────────────────────────────
# Analyseur réseau passif — produit ssl.log (ja3, ja3s, validation_status, ja4)
# Installé depuis OBS Debian 12 (openSUSE Build Service)
# Logs dans /opt/zeek/spool/zeek/ → symlink /opt/zeek/logs/current

echo "[zeek] Ajout repo OBS Debian 12..."
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
  | tee /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
  | gpg --dearmor | tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null
apt-get update -q
apt-get install -y zeek-8.0

echo "[zeek] Configuration interface eth2 (attacker network)..."
sed -i 's/^interface=.*/interface=eth2/' /opt/zeek/etc/node.cfg

echo "[zeek] Activation JSON logs, checksum fix, validation_status, JA3/JA4..."
tee -a /opt/zeek/share/zeek/site/local.zeek << 'ZEEKEOF'

# JSON output pour Filebeat
@load policy/tuning/json-logs.zeek
# Ignorer les checksums NIC offloading (VMs VirtualBox)
redef ignore_checksums = T;
# Certificate validation → champ zeek.ssl.validation.status
@load policy/protocols/ssl/validate-certs.zeek
# Charger les packages installés (JA3, JA4)
@load packages
ZEEKEOF

echo "[zeek] Installation packages JA3 + JA4..."
/opt/zeek/bin/zkg install zeek/salesforce/ja3 --force
/opt/zeek/bin/zkg install zeek/foxio/ja4 --force

echo "[zeek] Déploiement..."
/opt/zeek/bin/zeekctl deploy

echo "[zeek] Symlink logs/current → spool/zeek..."
ln -sfn /opt/zeek/spool/zeek /opt/zeek/logs/current

echo "[zeek] Status :"
/opt/zeek/bin/zeekctl status

# ── Filebeat module Zeek → Elasticsearch ─────────────────────────────────────
echo "[filebeat-zeek] Activation module zeek..."
filebeat modules enable zeek

tee /etc/filebeat/modules.d/zeek.yml << 'FBEOF'
- module: zeek
  connection:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/conn.log"]
  dns:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/dns.log"]
  http:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/http.log"]
  ssl:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/ssl.log"]
  x509:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/x509.log"]
  files:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/files.log"]
  weird:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/weird.log"]
FBEOF

systemctl restart filebeat
echo "[filebeat-zeek] Module zeek activé et Filebeat redémarré"

# ── Kibana detection rules (Zeek) ────────────────────────────────────────
# All 12 rules are defined in kibana-rules-corpus.sh (same directory).
# Corpus reference: ai/corpus-regles-detection-reseau.md
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$SCRIPT_DIR/kibana-rules-corpus.sh"
