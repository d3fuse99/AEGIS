import os
import time
import math
import random
import threading
import psutil
from core.event_bus import bus

file_states = {}

def calculate_shannon_entropy(path):
    try:
        if not os.path.exists(path):
            return 0.0
        with open(path, "rb") as f:
            data = f.read(2048)
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception:
        return 0.0

def recreate_decoy(path):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        words = ["invoice", "financial", "secret", "private", "backup", "credentials", "database"]
        content = "\n".join(" ".join(random.choices(words, k=5)) for _ in range(25))
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass

def get_decoy_paths(decoy_names):
    home = os.path.expanduser("~")
    dirs = [
        os.path.join(home, "Documents", "AegisDecoys"),
        os.path.join(home, "Desktop", "AegisDecoys")
    ]
    if os.name == "nt":
        dirs.append(r"C:\ProgramData\Aegis\Decoys")
    paths = []
    for d in dirs:
        for name in decoy_names:
            paths.append(os.path.join(d, name))
    return paths

def find_responsible_process(target_path):
    target_lower = target_path.lower()
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            procs.append(p)
        except Exception:
            pass
    procs.sort(key=lambda x: x.info.get("create_time", 0), reverse=True)

    for p in procs:
        try:
            for f in p.open_files():
                if target_lower in f.path.lower():
                    return p
        except Exception:
            pass

    for p in procs:
        try:
            exe = p.info.get("exe")
            if exe and target_lower in exe.lower():
                return p
        except Exception:
            pass
    return None

def run_canary_loop(config):
    cfg = config["sensors"]["canary"]
    interval = cfg.get("interval_sec", 0.05)
    threshold = cfg.get("entropy_threshold", 7.2)
    decoy_paths = get_decoy_paths(cfg.get("decoys", []))

    for p in decoy_paths:
        if not os.path.exists(p):
            recreate_decoy(p)
        file_states[p] = {
            "mtime": os.path.getmtime(p) if os.path.exists(p) else 0.0,
            "size": os.path.getsize(p) if os.path.exists(p) else 0,
            "exists": os.path.exists(p)
        }

    while True:
        time.sleep(interval)
        for path in decoy_paths:
            exists = os.path.exists(path)
            prev = file_states.get(path)
            if not prev:
                continue

            triggered = False
            event_type = ""
            if prev["exists"] and not exists:
                triggered = True
                event_type = "DELETION"
            elif exists:
                try:
                    mtime = os.path.getmtime(path)
                    size = os.path.getsize(path)
                    if not prev["exists"]:
                        triggered = True
                        event_type = "CREATION"
                    elif mtime != prev["mtime"] or size != prev["size"]:
                        triggered = True
                        event_type = "MODIFICATION"
                except Exception:
                    pass

            if triggered:
                entropy = calculate_shannon_entropy(path)
                proc = find_responsible_process(path)
                pid = proc.pid if proc else 0
                p_name = proc.name() if proc else "Unknown"
                exe = ""
                try:
                    exe = proc.exe() if proc else ""
                except Exception:
                    pass

                if entropy >= threshold or event_type == "DELETION":
                    bus.publish("CANARY_BREACH", {
                        "decoy": os.path.basename(path),
                        "path": path,
                        "event_type": event_type,
                        "entropy": entropy,
                        "pid": pid,
                        "name": p_name,
                        "exe": exe
                    })

                recreate_decoy(path)
                file_states[path] = {
                    "mtime": os.path.getmtime(path) if os.path.exists(path) else 0.0,
                    "size": os.path.getsize(path) if os.path.exists(path) else 0,
                    "exists": os.path.exists(path)
                }

def start_canary_sensor(config):
    if not config["sensors"]["canary"].get("enabled", True):
        return
    t = threading.Thread(target=run_canary_loop, args=(config,), daemon=True)
    t.start()