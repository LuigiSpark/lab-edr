#!/usr/bin/env bash
# Route traffic to Windows network through Debian (10.10.10.1).
ip route add 10.10.1.0/24 via 10.10.10.1 || true

# apt-get update needs this directory to exist — it may be missing on a fresh Vagrant box.
mkdir -p /var/lib/apt/lists/partial

# Refresh package list before installing anything.
apt-get update -y

# gnupg is required by the Metasploit install script to verify package signatures.
apt-get install -y gnupg curl

# Install Metasploit (msfvenom + msfconsole). Takes ~5 min, ~400 MB.
# Tested on Kali VM 2026-06-26: msfvenom generated a valid PE32+ 64-bit exe.
curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
  -o /tmp/msfinstall
chmod 755 /tmp/msfinstall
/tmp/msfinstall

# Dismiss the one-time setup prompt so msfvenom works non-interactively later.
echo "no" | msfvenom --help > /dev/null 2>&1 || true
