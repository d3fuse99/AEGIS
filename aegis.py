import os
import sys
import json
import time
import ctypes
import threading
import webbrowser
from core.database import init_db
from core.engine import CorrelationEngine
from sensors.behavior_sensor import start_behavior_sensor
from sensors.canary_sensor import start_canary_sensor
from sensors.deception_sensor import start_deception_sensor
from sensors.net_sensor import start_net_sensor
from sensors.usb_sensor import start_usb_sensor
from dashboard.server import start_dashboard_server

CONFIG_FILE = "config.json"

def check_admin():
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

def load_config():
    if not os.path.exists(CONFIG_FILE):
        sys.exit(1)
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def print_banner(is_elevated, host, port):
    cyan = "\033[96m"
    green = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    bold = "\033[1m"
    reset = "\033[0m"

    if sys.platform == "win32":
        try:
            k32 = ctypes.windll.kernel32
            handle = k32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            k32.GetConsoleMode(handle, ctypes.byref(mode))
            k32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

    print(f"\033[H\033[2J{cyan}{bold}")
    print("    ___    ______ _____ ____ _____")
    print("   /   |  / ____// ___//  _// ___/")
    print("  / /| | / __/  / / __ / /  \\__ \\ ")
    print(" / ___ |/ /___ / /_/ // /  ___/ / ")
    print("/_/  |_/_____/ \\____/___/ /____/  ")
    print(f"{reset}")
    print(f"{bold} [ AEGIS // ADVANCED MODULAR HOST XDR PLATFORM ]{reset}\n")
    
    priv_str = f"{green}ELEVATED (ADMIN){reset}" if is_elevated else f"{red}LIMITED (USER){reset}"
    print(f" [*] System Privilege Level : {priv_str}")
    print(f" [*] Telemetry Engine       : {green}ONLINE{reset}")
    print(f" [*] Local Operations Port  : {yellow}http://{host}:{port}{reset}")
    print(f" [*] Quarantine Subsystem   : {green}ARMED{reset}")
    print(f" [*] Peripheral Firewall    : {green}ACTIVE{reset}\n")
    if not is_elevated:
        print(f"{yellow} [!] Warning: Running with standard rights. Kernel mitigations and PnP hardware drops will be restricted.{reset}\n")

def main():
    is_elevated = check_admin()
    config = load_config()

    init_db()

    srv_cfg = config.get("server", {})
    host = srv_cfg.get("host", "127.0.0.1")
    port = srv_cfg.get("port", 8080)

    print_banner(is_elevated, host, port)

    engine = CorrelationEngine(config)
    engine.start()

    start_behavior_sensor(config)
    start_canary_sensor(config)
    start_deception_sensor(config)
    start_net_sensor(config)
    start_usb_sensor(config)

    srv_thread = threading.Thread(target=start_dashboard_server, args=(host, port), daemon=True)
    srv_thread.start()

    time.sleep(0.5)
    webbrowser.open(f"http://{host}:{port}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
        print("\n\033[93m[*] AEGIS core successfully disarmed.\033[0m")
        sys.exit(0)

if __name__ == "__main__":
    main()