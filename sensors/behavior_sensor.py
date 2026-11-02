import os
import re
import sys
import time
import hashlib
import threading
import psutil
from core.event_bus import bus

_HASH_CACHE = {}
_PROCESS_TRIGGERED_HEURISTICS = {}
_LOCK = threading.Lock()

KNOWN_NETWORK_APPS = {
    "firefox.exe", "chrome.exe", "msedge.exe", "opera.exe", "brave.exe",
    "steam.exe", "steamwebhelper.exe", "discord.exe", "telegram.exe", "spotify.exe",
    "code.exe", "msedgewebview2.exe", "searchhost.exe", "startmenuexperiencehost.exe"
}

def is_trusted_directory(exe_path):
    if not exe_path:
        return False
    path_lower = exe_path.lower()
    win_dir = os.environ.get("SystemRoot", "c:\\windows").lower()
    if path_lower.startswith(win_dir):
        return True
    trusted_keywords = [
        ":\\program files\\", ":\\program files (x86)\\",
        "\\steam\\", "\\steamlibrary\\", "\\programs\\microsoft vs code\\",
        "/usr/", "/bin/", "/sbin/"
    ]
    return any(k in path_lower for k in trusted_keywords)

def get_registry_autorun_paths():
    paths = {}
    if sys.platform != "win32":
        return paths
    try:
        import winreg
        targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        ]
        for hive, subkey in targets:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        name, val, _ = winreg.EnumValue(key, i)
                        paths[str(val).strip('\"').lower()] = name
            except Exception:
                continue
    except Exception:
        pass
    return paths

def get_file_hash(file_path):
    try:
        if not file_path or not os.path.isfile(file_path):
            return None
        st = os.stat(file_path)
        if st.st_size > 26214400:
            return None
        cache_key = (file_path, st.st_mtime)
        if cache_key in _HASH_CACHE:
            return _HASH_CACHE[cache_key]
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        _HASH_CACHE[cache_key] = digest
        return digest
    except Exception:
        return None

def scan_process_memory(proc):
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class MBI(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", wintypes.LPVOID),
                ("AllocationBase", wintypes.LPVOID),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)
            ]

        handle = ctypes.windll.kernel32.OpenProcess(0x0010 | 0x0400, False, proc.pid)
        if not handle:
            return False

        sigs = [b"mimikatz", b"beacon.dll", b"metasploit", b"powersploit", b"lsass dump"]
        mbi = MBI()
        addr = 0
        found = False

        while addr < 0x7FFFFFFF:
            res = ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not res:
                break
            if mbi.State == 0x1000 and mbi.Protect in (0x40, 0x04):
                scan_len = min(mbi.RegionSize, 65536)
                buf = ctypes.create_string_buffer(scan_len)
                bytes_read = ctypes.c_size_t()
                if ctypes.windll.kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, scan_len, ctypes.byref(bytes_read)):
                    raw_data = buf.raw[:bytes_read.value].lower()
                    if any(s in raw_data for s in sigs):
                        found = True
                        break
            addr += mbi.RegionSize
        ctypes.windll.kernel32.CloseHandle(handle)
        return found
    except Exception:
        return False

def check_process(proc, autorun_paths, config):
    try:
        pid = proc.pid
        name = proc.name().lower()
        my_pid = os.getpid()
        if pid in {0, 1, 4, my_pid} or name in config["safelist"]:
            return

        with _LOCK:
            if pid not in _PROCESS_TRIGGERED_HEURISTICS:
                _PROCESS_TRIGGERED_HEURISTICS[pid] = set()
            triggered = _PROCESS_TRIGGERED_HEURISTICS[pid]

        exe = ""
        try:
            exe = proc.exe().lower()
        except Exception:
            pass

        def fire_heuristic(heuristic_name, pts):
            if heuristic_name not in triggered:
                with _LOCK:
                    triggered.add(heuristic_name)
                bus.publish("PROCESS_SUSPICIOUS", {
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "points": pts,
                    "heuristic": heuristic_name
                })

        if exe:
            temp_dirs = ["\\temp\\", "/tmp/", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\"]
            if any(d in exe for d in temp_dirs):
                fire_heuristic("TEMP_DIR_EXEC_PATH", config["points_temp_dir"])

            evasion = [r"\.exe\.exe$", r"\.pdf\.exe$", r"\.xlsx\.exe$", r"\\recycler\\", r"\\\$recycle\.bin\\"]
            if any(re.search(pat, exe) for pat in evasion):
                fire_heuristic("EVASION_PATH_PATTERN", config["points_suspicious_path"])

            f_hash = get_file_hash(exe)
            if f_hash and f_hash in config["known_bad_hashes"]:
                fire_heuristic("KNOWN_MALICIOUS_HASH", config["points_known_bad_hash"])

            if not is_trusted_directory(exe):
                for path_entry in autorun_paths:
                    if exe in path_entry:
                        fire_heuristic("REGISTRY_PERSISTENCE", config["points_registry_persistence"])
                        break

        try:
            parent = proc.parent()
            if parent:
                p_name = parent.name().lower()
                bad_parents = ["chrome.exe", "msword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
                bad_children = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "certutil.exe"]
                if p_name in bad_parents and name in bad_children:
                    fire_heuristic("SUSPICIOUS_PARENT_CHILD", config["points_suspicious_parent"])
        except Exception:
            pass

        try:
            cmd = " ".join([arg.lower() for arg in proc.cmdline()])
            if cmd:
                if any(x in cmd for x in ["vssadmin delete shadows", "bcdedit /set recoveryenabled no", "wbadmin delete catalog"]):
                    fire_heuristic("RANSOMWARE_INHIBIT_RECOVERY", config["points_ransomware_behavior"])
                if name in ["certutil.exe", "bitsadmin.exe", "mshta.exe"] and ("http://" in cmd or "https://" in cmd):
                    fire_heuristic("SUSPICIOUS_LOLBIN_EXECUTION", config["points_suspicious_parent"])
        except Exception:
            pass

        if scan_process_memory(proc):
            fire_heuristic("MALICIOUS_MEMORY_SIGNATURE", config["points_memory_signature"])

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

def run_behavior_loop(config):
    cfg = config["sensors"]["behavior"]
    interval = cfg.get("interval_sec", 1.5)
    while True:
        autorun_paths = get_registry_autorun_paths()
        active_pids = set()
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            try:
                active_pids.add(proc.info["pid"])
                check_process(proc, autorun_paths, cfg)
            except Exception:
                pass
        
        with _LOCK:
            stale_pids = [p for p in _PROCESS_TRIGGERED_HEURISTICS if p not in active_pids]
            for p in stale_pids:
                del _PROCESS_TRIGGERED_HEURISTICS[p]
                
        time.sleep(interval)

def start_behavior_sensor(config):
    if not config["sensors"]["behavior"].get("enabled", True):
        return
    t = threading.Thread(target=run_behavior_loop, args=(config,), daemon=True)
    t.start()