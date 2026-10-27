import os
import sys
import json
import time
import queue
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from core.database import (
    get_recent_events, is_process_whitelisted, add_process_whitelist,
    is_usb_whitelisted, add_usb_whitelist, remove_usb_whitelist,
    get_blocked_ips, is_auth_configured, setup_auth, verify_auth
)
from core.event_bus import bus
from mitigation.process_killer import kill_process_tree
from mitigation.firewall_blocker import block_remote_ip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class AegisDashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.serve_file(os.path.join(BASE_DIR, "index.html"), "text/html")
        elif path == "/app.js":
            self.serve_file(os.path.join(BASE_DIR, "app.js"), "application/javascript")
        elif path == "/api/events":
            self.handle_sse()
        elif path == "/api/recent_events":
            self.send_json(get_recent_events(50))
        elif path == "/api/blocked_ips":
            self.send_json(get_blocked_ips())
        elif path == "/api/auth/status":
            self.send_json({"configured": is_auth_configured()})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if path == "/api/process/kill":
            pid = payload.get("pid")
            if pid:
                success = kill_process_tree(int(pid))
                self.send_json({"status": "success" if success else "failed"})
            else:
                self.send_json({"status": "error", "message": "Missing PID"}, 400)

        elif path == "/api/process/whitelist":
            name = payload.get("name")
            if name:
                add_process_whitelist(name)
                self.send_json({"status": "success"})
            else:
                self.send_json({"status": "error"}, 400)

        elif path == "/api/usb/whitelist/add":
            serial = payload.get("serial")
            if serial:
                add_usb_whitelist(serial)
                self.send_json({"status": "success"})
            else:
                self.send_json({"status": "error"}, 400)

        elif path == "/api/usb/whitelist/remove":
            serial = payload.get("serial")
            if serial:
                remove_usb_whitelist(serial)
                self.send_json({"status": "success"})
            else:
                self.send_json({"status": "error"}, 400)

        elif path == "/api/firewall/block":
            ip = payload.get("ip")
            if ip:
                ok = block_remote_ip(ip, "Manual Operator Action")
                self.send_json({"status": "success" if ok else "failed"})
            else:
                self.send_json({"status": "error"}, 400)

        elif path == "/api/auth/setup":
            pwd = payload.get("password")
            if pwd and len(pwd) >= 4:
                ok = setup_auth(pwd)
                self.send_json({"status": "success" if ok else "failed"})
            else:
                self.send_json({"status": "error", "message": "Password too short"}, 400)

        elif path == "/api/auth/verify":
            pwd = payload.get("password")
            valid = verify_auth(pwd) if pwd else False
            self.send_json({"valid": valid})

        else:
            self.send_response(404)
            self.end_headers()

    def handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = bus.register_sse_client()
        try:
            self.wfile.write(b"data: {\"status\": \"connected\"}\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = q.get(timeout=15.0)
                    msg = f"data: {json.dumps(event)}\n\n".encode("utf-8")
                    self.wfile.write(msg)
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            bus.unregister_sse_client(q)

    def serve_file(self, filepath, content_type):
        if not os.path.exists(filepath):
            self.send_response(404)
            self.end_headers()
            return
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_response(500)
            self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

def start_dashboard_server(host="127.0.0.1", port=8080):
    server = ThreadingHTTPServer((host, port), AegisDashboardHandler)
    server.serve_forever()