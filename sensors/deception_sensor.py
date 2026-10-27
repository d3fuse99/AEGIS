import socket
import threading
import urllib.parse
from core.event_bus import bus

def handle_ssh(client_sock, ip):
    try:
        client_sock.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        client_sock.settimeout(10.0)
        client_sock.recv(1024)
        client_sock.sendall(b"login as: ")
        user = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
        client_sock.sendall(f"{user}@target-srv password: ".encode("utf-8"))
        pwd = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
        client_sock.sendall(b"\r\nAccess denied.\r\n")
        return f"SSH Login -> User: '{user}' | Pass: '{pwd}'", 10
    except Exception:
        return "SSH Connection Dropped", 4

def handle_ftp(client_sock, ip):
    try:
        client_sock.sendall(b"220 (vsFTPd 3.0.3)\r\n")
        client_sock.settimeout(10.0)
        data = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
        user = data.replace("USER", "").strip()
        client_sock.sendall(b"331 Please specify the password.\r\n")
        data_pass = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
        pwd = data_pass.replace("PASS", "").strip()
        client_sock.sendall(b"530 Login incorrect.\r\n")
        return f"FTP Login -> User: '{user}' | Pass: '{pwd}'", 10
    except Exception:
        return "FTP Connection Dropped", 4

def handle_http(client_sock, ip):
    try:
        client_sock.settimeout(8.0)
        data = client_sock.recv(4096).decode("utf-8", errors="ignore")
        if not data:
            return "Empty HTTP Probe", 2
        first_line = data.split("\r\n")[0]
        if "POST" in first_line:
            parts = data.split("\r\n\r\n", 1)
            body = urllib.parse.unquote_plus(parts[1]).strip() if len(parts) > 1 else ""
            resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nConnection: close\r\n\r\nUnauthorized"
            client_sock.sendall(resp.encode())
            return f"HTTP POST -> {first_line} | Body: {body}", 10
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<h2>Management Console</h2><form method='POST'><input name='user'/><input name='pass'/></form>"
        client_sock.sendall(resp.encode())
        return f"HTTP Recon -> {first_line}", 5
    except Exception:
        return "HTTP Connection Dropped", 2

def handle_generic(client_sock, ip, service):
    try:
        client_sock.settimeout(8.0)
        raw = client_sock.recv(1024)
        payload = raw.decode("utf-8", errors="ignore").strip() if raw else "Port Probe"
        return f"{service} Probe -> {payload}", 5
    except Exception:
        return f"{service} Dropped", 2

def listener_worker(port, service):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(64)
    except Exception:
        return

    while True:
        try:
            client, addr = srv.accept()
            ip = addr[0]
            if service == "SSH":
                payload, pts = handle_ssh(client, ip)
            elif service == "FTP":
                payload, pts = handle_ftp(client, ip)
            elif service == "HTTP":
                payload, pts = handle_http(client, ip)
            else:
                payload, pts = handle_generic(client, ip, service)

            client.close()
            bus.publish("HONEYPOT_ATTACK", {
                "ip": ip,
                "port": port,
                "service": service,
                "payload": payload,
                "points": pts
            })
        except Exception:
            pass

def start_deception_sensor(config):
    if not config["sensors"]["deception"].get("enabled", True):
        return
    ports_map = config["sensors"]["deception"].get("ports", {})
    for port_str, service in ports_map.items():
        t = threading.Thread(target=listener_worker, args=(int(port_str), service), daemon=True)
        t.start()