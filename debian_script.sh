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
# IDS réseau : inspecte chaque paquet qui passe par la VM (mode NFQUEUE)

echo "deb http://deb.debian.org/debian bookworm-backports main" > \
    /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install -t bookworm-backports suricata suricata-update jq -y

systemctl stop suricata 2>/dev/null || true
systemctl disable suricata

# Mode "accept" : Suricata inspecte sans bloquer — "fail-open" laisse passer si crash
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
# Base de données qui stocke tous les événements du lab

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
xpack.security.enrollment.enabled: false  # désactive l'assistant de configuration
xpack.security.http.ssl.enabled: false    # HTTP simple — réseau de lab isolé
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
# Interface web pour visualiser les événements et gérer les alertes

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
# Fleet gère les agents à distance : déploiement, configuration, mises à jour

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
# Envoie les alertes réseau Suricata vers Elasticsearch

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
# Capture et analyse les protocoles réseau (DNS, HTTP, TLS, ICMP)

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
# Pour compiler les binaires Windows depuis Linux (cross-compilation)

sudo apt-get install mingw-w64 -y

# ── Elastic trial (Enterprise — 30 jours) ────────────────────────────────
# Active ML jobs, anomaly detection, entity analytics
# Idempotent : si déjà activé, Elasticsearch retourne trial_already_activated
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

# ── ML Jobs réseau (Elastic Enterprise trial) ─────────────────────────────
# 3 jobs anomaly detection sur données Packetbeat TLS
# Idempotents : si déjà créés, ES retourne resource_already_exists_exception

echo "[ml] Attente Elasticsearch ready..."
for i in $(seq 1 30); do
  STATUS=$(curl -s --max-time 5 -u elastic:vagrant http://10.10.1.1:9200/_cluster/health 2>/dev/null | grep -o '"status":"[^"]*"' | head -1)
  if echo "$STATUS" | grep -qE "green|yellow"; then
    break
  fi
  sleep 10
done

# Job 1 : destination inhabituelle (rare IP)
curl -s -u elastic:vagrant -X PUT http://10.10.1.1:9200/_ml/anomaly_detectors/lab-tls-rare-destination \
  -H Content-Type:application/json \
  -d '{"description":"Connexion TLS vers destination inhabituelle","analysis_config":{"bucket_span":"1h","detectors":[{"function":"rare","by_field_name":"destination.ip","over_field_name":"source.ip"}],"influencers":["source.ip","destination.ip"]},"data_description":{"time_field":"@timestamp"},"model_plot_config":{"enabled":false}}' \
  -o /dev/null

# Job 2 : beacon pattern (high count)
curl -s -u elastic:vagrant -X PUT http://10.10.1.1:9200/_ml/anomaly_detectors/lab-tls-beacon \
  -H Content-Type:application/json \
  -d '{"description":"Beacon pattern - connexions TLS trop frequentes vers meme destination","analysis_config":{"bucket_span":"5m","detectors":[{"function":"high_count","over_field_name":"destination.ip"}],"influencers":["source.ip","destination.ip"]},"data_description":{"time_field":"@timestamp"}}' \
  -o /dev/null

# Job 3 : JA3 inhabituel
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

# ── Règles Kibana Zeek ─────────────────────────────────────────────────────────
# 3 règles KQL dans Elastic Security : cert auto-signé, SNI absent, JA3 curl
# Attendre Kibana disponible
echo "[kibana-rules] Attente Kibana..."
for i in $(seq 1 30); do
  STATUS=$(curl -s -u elastic:vagrant http://10.10.1.1:5601/api/status 2>/dev/null | grep -o '"overall"' | head -1)
  if [ -n "$STATUS" ]; then break; fi
  sleep 10
done

curl -s -u elastic:vagrant \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  "http://10.10.1.1:5601/api/detection_engine/rules" -X POST \
  -d '{"name":"[Zeek] Certificat auto-signé détecté","description":"Zeek détecte validation_status=self signed certificate — indicateur de C2 avec cert généré localement.","rule_id":"zeek-self-signed-cert","type":"query","language":"kuery","query":"event.dataset: \"zeek.ssl\" and zeek.ssl.validation.status: \"self signed certificate\"","index":["filebeat-*"],"severity":"high","risk_score":73,"enabled":true,"interval":"1m","from":"now-5m","max_signals":100,"tags":["Zeek","TLS","C2","Evasion"]}' \
  -o /dev/null && echo "[kibana-rules] Règle 1 créée"

curl -s -u elastic:vagrant \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  "http://10.10.1.1:5601/api/detection_engine/rules" -X POST \
  -d '{"name":"[Zeek] TLS sans SNI sur port 443","description":"Connexion HTTPS sans Server Name Indication — malware se connecte par IP directe.","rule_id":"zeek-no-sni","type":"query","language":"kuery","query":"event.dataset: \"zeek.ssl\" and not tls.server_name: * and destination.port: 443","index":["filebeat-*"],"severity":"medium","risk_score":47,"enabled":true,"interval":"1m","from":"now-5m","max_signals":100,"tags":["Zeek","TLS","SNI","Evasion"]}' \
  -o /dev/null && echo "[kibana-rules] Règle 2 créée"

curl -s -u elastic:vagrant \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  "http://10.10.1.1:5601/api/detection_engine/rules" -X POST \
  -d '{"name":"[Zeek] JA3 curl/outil détecté sur port 443","description":"JA3 hash correspondant à curl OpenSSL standard — pas un navigateur web.","rule_id":"zeek-ja3-curl","type":"query","language":"kuery","query":"event.dataset: \"zeek.ssl\" and tls.client.ja3: (\"78f0dc5ac5b19daf131a133cfdee9691\" or \"5723c02ba862f61e9215c3e669c1c0d8\")","index":["filebeat-*"],"severity":"medium","risk_score":47,"enabled":true,"interval":"1m","from":"now-5m","max_signals":100,"tags":["Zeek","JA3","Fingerprint","Evasion"]}' \
  -o /dev/null && echo "[kibana-rules] Règle 3 créée"

