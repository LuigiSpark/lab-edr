#!/usr/bin/env bash
# Route traffic to Windows network through Debian (10.10.10.1).
ip route add 10.10.1.0/24 via 10.10.10.1 || true

# apt-get update needs this directory to exist — it may be missing on a fresh Vagrant box.
mkdir -p /var/lib/apt/lists/partial

# Refresh package list before installing anything.
apt-get update -y

# gnupg is required by the Metasploit install script to verify package signatures.
# smbclient : transfert de fichiers vers Windows sans limite de taille (évite les bugs WinRM).
# inotify-tools : surveillance de répertoire sans polling (watcher watch_and_transfer.sh).
apt-get install -y gnupg curl git smbclient inotify-tools

# Install Metasploit (msfvenom + msfconsole). Takes ~5 min, ~400 MB.
# Tested on Kali VM 2026-06-26: msfvenom generated a valid PE32+ 64-bit exe.
curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
  -o /tmp/msfinstall
chmod 755 /tmp/msfinstall
/tmp/msfinstall

# Dismiss the one-time setup prompt so msfvenom works non-interactively later.
echo "no" | msfvenom --help > /dev/null 2>&1 || true

# ── Outils de transfert malware → Windows ────────────────────────────────
# Les scripts sont copiés par Vagrant (provision "file") vers /tmp/ avant ce script.

# send-malware.sh : transfère un fichier vers C:\lab\submissions\ via SMB C$
install -m 755 /tmp/send-malware.sh /usr/local/bin/send-malware.sh

# watch_and_transfer.sh : watcher inotify qui appelle send-malware.sh automatiquement
mkdir -p /home/vagrant/lab
install -m 755 /tmp/watch_and_transfer.sh /home/vagrant/lab/watch_and_transfer.sh
chown vagrant:vagrant /home/vagrant/lab /home/vagrant/lab/watch_and_transfer.sh

# Crée le répertoire surveillé dès le provisioning
mkdir -p /tmp/malware
chown vagrant:vagrant /tmp/malware
