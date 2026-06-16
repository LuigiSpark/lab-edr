# Configure network.
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

sudo iptables -A FORWARD -i eth1 -o eth2 -j ACCEPT
sudo iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT

sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent
#Configure suricata.
echo "deb http://deb.debian.org/debian bookworm-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install -t bookworm-backports suricata suricata-update jq -y

systemctl stop suricata
systemctl disable suricata

iptables -I FORWARD -j NFQUEUE --queue-num 0
iptables-save | sudo tee -a /etc/iptables/rules.v4

sed -i 's/#  mode: accept/  mode: accept/' /etc/suricata/suricata.yaml
sed -i '/  mode: accept/a\  fail-open: yes' /etc/suricata/suricata.yaml

sudo suricata-update
sudo suricata -c /etc/suricata/suricata.yaml -q 0 -D
