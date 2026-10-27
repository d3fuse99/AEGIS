import socket
import ipaddress
import threading
import time
import subprocess
import platform
import re
from concurrent.futures import ThreadPoolExecutor
import psutil
from core.event_bus import bus

socket.setdefaulttimeout(1.5)
_GEO_CACHE = {}

def is_valid_remote(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False

def check_dnsbl(ip, dnsbl_list):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return []
    except Exception:
        return []

    listed = []
    rev_ip = ".".join(reversed(ip.split(".")))
    for bl in dnsbl_list:
        try:
            query = rev_ip + "." + bl
            res = socket.gethostbyname(query)
            if res and res != "127.0.0.2":
                listed.append(bl)
        except Exception:
            pass
    return listed

def evaluate_socket_threat(ip, proc_path, dnsbl_list):
    score = 0
    factors = []
    path_lower = (proc_path or "").lower()
    if any(p in path_lower for p in ["appdata", "temp", "tmp", "downloads"]):
        score += 35
        factors.append("Process running from Temp/Untrusted folder")
    bl_hits = check_dnsbl(ip, dnsbl_list)
    if bl_hits:
        score += 45
        factors.append("Listed in DNSBL: " + ", ".join(bl_hits))
    return score, factors

def run_socket_loop(config):
    cfg = config["sensors"]["net"]
    interval = cfg.get("refresh_interval_sec", 5)
    dnsbl = cfg.get("dnsbl_list", [])

    while True:
        try:
            conns = psutil.net_connections(kind="tcp")
            for c in conns:
                if c.raddr and c.status == "ESTABLISHED":
                    r_ip = c.raddr.ip
                    if is_valid_remote(r_ip):
                        proc_path = ""
                        p_name = "Unknown"
                        if c.pid:
                            try:
                                p = psutil.Process(c.pid)
                                proc_path = p.exe()
                                p_name = p.name()
                            except Exception:
                                pass

                        score, factors = evaluate_socket_threat(r_ip, proc_path, dnsbl)
                        if score >= 60:
                            bus.publish("NET_THREAT", {
                                "remote_ip": r_ip,
                                "remote_port": c.raddr.port,
                                "pid": c.pid,
                                "process": p_name,
                                "score": score,
                                "factors": factors
                            })
        except Exception:
            pass
        time.sleep(interval)

def ping_node(ip):
    sys_type = platform.system().lower()
    cmd = ['ping', '-n', '1', '-w', '150', ip] if sys_type == "windows" else ['ping', '-c', '1', '-W', '1', ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False

def get_arp_table():
    mapping = {}
    sys_type = platform.system().lower()
    try:
        cmd = ["arp", "-a"] if sys_type == "windows" else ["arp", "-n"]
        out = subprocess.check_output(cmd).decode("cp866" if sys_type == "windows" else "utf-8", errors="ignore")
        for line in out.splitlines():
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+.*?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
            if m:
                mapping[m.group(1)] = m.group(2).replace('-', ':').upper()
    except Exception:
        pass
    return mapping

def perform_lan_sweep():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()

    if local_ip == '127.0.0.1':
        return []

    prefix = ".".join(local_ip.split(".")[:-1]) + "."
    active_ips = []

    def probe(i):
        ip = f"{prefix}{i}"
        if ping_node(ip):
            active_ips.append(ip)

    with ThreadPoolExecutor(max_workers=50) as pool:
        pool.map(probe, range(1, 255))

    arp = get_arp_table()
    results = []
    for ip in active_ips:
        mac = arp.get(ip, "00:00:00:00:00:00")
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = "Unknown Host"
        results.append({"ip": ip, "mac": mac, "name": name})
    return results

def start_net_sensor(config):
    if not config["sensors"]["net"].get("enabled", True):
        return
    t = threading.Thread(target=run_socket_loop, args=(config,), daemon=True)
    t.start()