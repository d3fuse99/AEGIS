import os
import sys
import json
import time
import queue
import psutil
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from core.database import (
    get_recent_events, is_process_whitelisted, add_process_whitelist,
    is_usb_whitelisted, add_usb_whitelist, remove_usb_whitelist,
    get_blocked_ips, is_auth_configured, setup_auth, verify_auth
)
from core.event_bus import bus
from core.engine import get_global_engine
from mitigation.process_killer import kill_process_tree
from mitigation.firewall_blocker import block_remote_ip, is_admin
from sensors.net_sensor import perform_lan_sweep
from sensors.usb_sensor import scan_usb_registry, is_temporarily_unlocked, set_temporary_unlock
from sensors.deception_sensor import get_active_bound_ports

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

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
        elif path == "/api/snapshot":
            self.handle_snapshot()
        elif path == "/api/export_dump":
            self.handle_export_dump()
        elif path == "/api/recent_events":
            self.send_json(get_recent_events(100))
        elif path == "/api/blocked_ips":
            self.send_json(get_blocked_ips())
        elif path == "/api/usb_list":
            self.send_json(self.get_usb_list())
        elif path == "/api/auth/status":
            self.send_json({
                "configured": is_auth_configured(),
                "unlocked": is_temporarily_unlocked()
            })
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
                self.send_json({"status": "error"}, 400)

        elif path == "/api/process/whitelist":
            name = payload.get("name")
            if name:
                add_process_whitelist(name)
                self.send_json({"status": "success"})
            else:
                self.send_json({"status": "error"}, 400)

        elif path == "/api/lan/scan":
            results = perform_lan_sweep()
            self.send_json(results)

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

        elif path == "/api/usb/unlock":
            duration = int(payload.get("duration", 120))
            pwd = payload.get("password", "")
            if not is_auth_configured() or verify_auth(pwd):
                set_temporary_unlock(duration)
                bus.publish("SYSTEM_ALERT", {"message": f"Hardware ports unlocked for {duration}s"})
                self.send_json({"status": "success", "seconds": duration})
            else:
                self.send_json({"status": "denied"}, 403)

        elif path == "/api/firewall/block":
            ip = payload.get("ip")
            if ip:
                ok = block_remote_ip(ip, "Manual Analyst Block")
                self.send_json({"status": "success" if ok else "failed"})
            else:
                self.send_json({"status": "error"}, 400)

        elif path == "/api/auth/setup":
            pwd = payload.get("password")
            if pwd and len(pwd) >= 4:
                ok = setup_auth(pwd)
                self.send_json({"status": "success" if ok else "failed"})
            else:
                self.send_json({"status": "error"}, 400)

        else:
            self.send_response(404)
            self.end_headers()

    def handle_snapshot(self):
        engine = get_global_engine()
        scores = engine.get_process_scores_snapshot() if engine else {}

        active_sockets = {}
        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.pid and c.status == "ESTABLISHED" and c.raddr:
                    active_sockets[c.pid] = f"{c.raddr.ip}:{c.raddr.port}"
        except Exception:
            pass

        procs = []
        for p in psutil.process_iter(attrs=["pid", "name", "exe", "cpu_percent"]):
            try:
                exe = p.info.get("exe") or ""
                p_name = p.info.get("name") or "Unknown"
                if p_name.lower() in ("idle", "system", "registry"):
                    continue
                pid = p.info["pid"]
                procs.append({
                    "pid": pid,
                    "name": p_name,
                    "exe": exe,
                    "cpu": p.info.get("cpu_percent") or 0.0,
                    "score": scores.get(pid, 0),
                    "remote_socket": active_sockets.get(pid, None)
                })
            except Exception:
                continue

        procs = sorted(procs, key=lambda x: (x["score"], x["cpu"]), reverse=True)[:60]

        quarantine_dir = Path(os.path.join(ROOT_DIR, "EDR_Quarantine"))
        quarantine_count = len(list(quarantine_dir.glob("*.vir"))) if quarantine_dir.exists() else 0

        data = {
            "daemon_pid": os.getpid(),
            "is_admin": is_admin(),
            "quarantine_count": quarantine_count,
            "processes": procs,
            "blocked_count": len(get_blocked_ips()),
            "bound_honeypot_ports": get_active_bound_ports()
        }
        self.send_json(data)

    def handle_export_dump(self):
        try:
            records = get_recent_events(500)
            payload = json.dumps(records, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=aegis_forensic_dump.json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def get_usb_list(self):
        devices = scan_usb_registry()
        for d in devices:
            d["is_whitelisted"] = is_usb_whitelisted(d["serial"])
        return devices

    def handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = bus.register_sse_client()
        try:
            self.wfile.write(b"data: {\"type\": \"SYSTEM_INIT\", \"data\": {\"status\": \"ONLINE\"}}\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = q.get(timeout=10.0)
                    msg = f"data: {json.dumps(event)}\n\n".encode("utf-8")
                    self.wfile.write(msg)
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
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