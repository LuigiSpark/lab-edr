# Network 

echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

sudo iptables -A FORWARD -i eth1 -o eth2 -j ACCEPT
sudo iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT

# Suricata

echo "deb http://deb.debian.org/debian bookworm-backports main" > \
    /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install -t bookworm-backports suricata suricata-update jq -y

systemctl stop suricata
systemctl disable suricata

sed -i 's/#  mode: accept/  mode: accept/' /etc/suricata/suricata.yaml
sed -i '/  mode: accept/a\  fail-open: yes' /etc/suricata/suricata.yaml

sudo suricata -c /etc/suricata/suricata.yaml -q 0 -D

iptables -I FORWARD -j NFQUEUE --queue-num 0

# Elastic Search

echo "vm.max_map_count=300000" | sudo tee -a "/etc/sysctl.conf"
sudo sysctl -p

sudo apt install gpg -y
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

sudo apt-get install apt-transport-https -y 
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
sudo apt-get update && sudo apt-get install elasticsearch -y

sudo tee /etc/elasticsearch/elasticsearch.yml << 'EOF'
# Identity
cluster.name: edr-lab
node.name: central

# Paths
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Network — listen on windows_net interface only
network.host: 10.10.1.1
http.port: 9200

# Single-node — no cluster discovery needed
discovery.type: single-node

# Security
# Authentication is active — credentials required for all requests
xpack.security.enabled: true
# Disable the auto-configuration wizard (enrollment token)
xpack.security.enrollment.enabled: false
# HTTP over plain text — lab is on isolated internal network
xpack.security.http.ssl.enabled: false
# No inter-node encryption — single-node has no inter-node communication
xpack.security.transport.ssl.enabled: false
EOF

echo "vagrant" | /usr/share/elasticsearch/bin/elasticsearch-keystore add --stdin bootstrap.password

sudo systemctl start elasticsearch.service

sudo apt install curl -y

echo "Waiting for Elasticsearch security to initialize..."
for i in $(seq 1 30); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://10.10.1.1:9200" 2>/dev/null)
  if [ "$status" = "401" ] || [ "$status" = "200" ]; then
    break
  fi
  sleep 1
done
sleep 2

curl -s -X POST "http://10.10.1.1:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -u elastic:vagrant \
  -d '{"password": "vagrant"}'


# Kibana

sudo apt-get update && sudo apt-get install kibana -y
sudo tee /etc/kibana/kibana.yml << 'EOF'
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://10.10.1.1:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "vagrant"
EOF
#Disable fleet, note that : xpack.fleet.enabled: false exits but is not advised.
sudo tee -a /etc/kibana/kibana.yml << 'EOF'
xpack.encryptedSavedObjects.encryptionKey: "lab_key_32_chars_minimum_xxxxxxxx"
EOF
sudo systemctl start kibana.service

# Detection rules

echo "Waiting for Kibana to be fully available..."
for i in $(seq 1 60); do
  level=$(curl -s "http://localhost:5601/api/status" \
    -u elastic:vagrant 2>/dev/null | jq -r '.status.overall.level' 2>/dev/null)
  if [ "$level" = "available" ]; then
    echo "Kibana is available."
    break
  fi
  echo "  [$i/60] level=${level:-unreachable}, retrying..."
  sleep 3
done

echo "Installing prepackaged detection rules..."
curl -s -X PUT "http://localhost:5601/api/detection_engine/rules/prepackaged" \
  -H "kbn-xsrf: true" \
  -u elastic:vagrant \
  | jq '{rules_installed, rules_updated}'

echo "Enabling all detection rules..."
ITER=1
while true; do
  IDS=$(curl -s "http://localhost:5601/api/detection_engine/rules/_find?per_page=100&filter=alert.attributes.enabled:false" \
    -u elastic:vagrant | jq -c '[.data[].id]')
  COUNT=$(echo "$IDS" | jq 'length')
  [ "$COUNT" -eq 0 ] && break
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://localhost:5601/api/detection_engine/rules/_bulk_action" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -u elastic:vagrant \
    -d "{\"action\": \"enable\", \"ids\": ${IDS}}")
  echo "  Batch ${ITER}: ${COUNT} rules — HTTP ${STATUS}"
  ITER=$((ITER + 1))
done

# Suricata integration with Elastic via Filebeat

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
output.elasticsearch:
  hosts: ["http://10.10.1.1:9200"]
  username: "elastic"
  password: "vagrant"
EOF

filebeat setup --index-management
systemctl enable filebeat
systemctl start filebeat