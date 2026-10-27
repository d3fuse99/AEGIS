import os
import sys
import time
import datetime
import threading
import subprocess
from core.database import is_usb_whitelisted, log_event
from core.event_bus import bus

UNLOCK_UNTIL_TIMESTAMP = 0.0

def set_temporary_unlock(duration_seconds):
    global UNLOCK_UNTIL_TIMESTAMP
    UNLOCK_UNTIL_TIMESTAMP = time.time() + duration_seconds

def is_temporarily_unlocked():
    global UNLOCK_UNTIL_TIMESTAMP
    return time.time() < UNLOCK_UNTIL_TIMESTAMP

def parse_first_connected(serial):
    if sys.platform != "win32":
        return "Unknown"
    log_path = r"C:\Windows\INF\setupapi.dev.log"
    if not os.path.exists(log_path):
        return "Unknown"
    try:
        earliest_time = None
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            curr_time = None
            for line in f:
                if line.startswith(">>>  ["):
                    curr_time = None
                elif line.startswith("<<<  [Section end"):
                    parts = line.split()
                    if len(parts) >= 5:
                        curr_time = parts[3].replace("/", "-") + " " + parts[4].split(".")[0]
                if serial in line and curr_time:
                    if not earliest_time:
                        earliest_time = curr_time
        return earliest_time or "Unknown"
    except Exception:
        return "Unknown"

def scan_usb_registry():
    devices = []
    if sys.platform != "win32":
        return devices
    try:
        import winreg
        for base_key_str, is_usbstor in [(r"SYSTEM\CurrentControlSet\Enum\USBSTOR", True), (r"SYSTEM\CurrentControlSet\Enum\USB", False)]:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key_str, 0, winreg.KEY_READ) as main_key:
                    num_sub, _, _ = winreg.QueryInfoKey(main_key)
                    for i in range(num_sub):
                        dev_class = winreg.EnumKey(main_key, i)
                        class_path = base_key_str + "\\" + dev_class
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, class_path, 0, winreg.KEY_READ) as class_key:
                            num_ser, _, _ = winreg.QueryInfoKey(class_key)
                            for j in range(num_ser):
                                ser_name = winreg.EnumKey(class_key, j)
                                ser_path = class_path + "\\" + ser_name
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ser_path, 0, winreg.KEY_READ) as ser_key:
                                    _, _, filetime = winreg.QueryInfoKey(ser_key)
                                    ts_str = "Unknown"
                                    if filetime > 0:
                                        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
                                        ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")

                                    dev_name = "Unknown USB Device"
                                    for vname in ["FriendlyName", "DeviceDesc"]:
                                        try:
                                            val, _ = winreg.QueryValueEx(ser_key, vname)
                                            if val:
                                                dev_name = val.split(";")[-1].strip()
                                                break
                                        except Exception:
                                            pass
                                    devices.append({
                                        "serial": ser_name,
                                        "name": dev_name,
                                        "last_connected": ts_str,
                                        "is_usbstor": is_usbstor,
                                        "first_connected": parse_first_connected(ser_name)
                                    })
            except Exception:
                pass
    except Exception:
        pass
    return devices

def disable_pnp_hardware(serial):
    if sys.platform != "win32":
        return False
    escaped = serial.replace("'", "''")
    cmd = f"Get-PnpDevice | Where-Object {{ $_.InstanceId -like '*{escaped}*' }} | Disable-PnpDevice -Confirm:$false"
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True, timeout=10)
        return res.returncode == 0
    except Exception:
        return False

def run_usb_loop(config):
    cfg = config["sensors"]["usb"]
    interval = cfg.get("interval_sec", 2.0)
    mitigation_active = cfg.get("mitigation_enabled", True)
    known_serials = set()

    for d in scan_usb_registry():
        known_serials.add(d["serial"])

    while True:
        time.sleep(interval)
        try:
            current_devs = scan_usb_registry()
            for dev in current_devs:
                serial = dev["serial"]
                if serial not in known_serials:
                    known_serials.add(serial)
                    trusted = is_usb_whitelisted(serial)
                    unlocked = is_temporarily_unlocked()

                    bus.publish("USB_EVENT", {
                        "serial": serial,
                        "name": dev["name"],
                        "trusted": trusted,
                        "unlocked": unlocked
                    })

                    if not trusted:
                        log_event("HARDWARE", "CRITICAL", "UNAUTHORIZED_USB_ATTACHED", f"Unapproved USB insertion: {dev['name']} ({serial})", dev)
                        if mitigation_active and not unlocked:
                            disable_pnp_hardware(serial)
                            log_event("MITIGATION", "ACTION", "USB_PNP_DISABLED", f"Disabled unauthorized device node {serial}")
        except Exception:
            pass

def start_usb_sensor(config):
    if not config["sensors"]["usb"].get("enabled", True):
        return
    t = threading.Thread(target=run_usb_loop, args=(config,), daemon=True)
    t.start()