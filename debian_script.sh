# ── Réseau ────────────────────────────────────────────────────────────────
# Active le routage IP et autorise le trafic entre les deux interfaces réseau

echo "net.ipv4.ip_forward = 1" | tee -a /etc/sysctl.conf
sysctl -p
iptables -A FORWARD -i eth1 -o eth2 -j ACCEPT
iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT

# ── Suricata ──────────────────────────────────────────────────────────────
# IDS réseau : inspecte chaque paquet qui passe par la VM (mode NFQUEUE)

echo "deb http://deb.debian.org/debian bookworm-backports main" > \
    /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install -t bookworm-backports suricata suricata-update jq -y

systemctl stop suricata
systemctl disable suricata

# Mode "accept" : Suricata inspecte sans bloquer — "fail-open" laisse passer si crash
sed -i 's/#  mode: accept/  mode: accept/' /etc/suricata/suricata.yaml
sed -i '/  mode: accept/a\  fail-open: yes' /etc/suricata/suricata.yaml

suricata-update                                       # télécharge les règles de détection
suricata -c /etc/suricata/suricata.yaml -q 0 -D       # démarre en arrière-plan
iptables -I FORWARD -j NFQUEUE --queue-num 0          # redirige le trafic vers Suricata

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

# Installe le module Elastic Defend et récupère sa version exacte
ENDPOINT_VERSION=$(curl -s -X POST "http://localhost:5601/api/fleet/epm/packages/endpoint" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -u elastic:vagrant -d '{"force":true}' | jq -r '.items[0].version // .item.version')
[ -z "$ENDPOINT_VERSION" ] || [ "$ENDPOINT_VERSION" = "null" ] && { echo "ERROR: endpoint package version empty"; exit 1; }

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
