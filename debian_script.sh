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

curl -s -X POST "http://10.10.1.1:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -u elastic:vagrant \
  -d '{"password": "vagrant"}'