import os
import sys
import json
import time
import ctypes
import threading
import webbrowser
from core.database import init_db
from core.engine import CorrelationEngine, set_global_engine
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

def request_elevation():
    if sys.platform == "win32":
        try:
            script_path = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}" {params}', None, 1)
            if ret > 32:
                sys.exit(0)
        except Exception:
            pass

def load_config():
    if not os.path.exists(CONFIG_FILE):
        sys.exit(1)
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    if not check_admin():
        request_elevation()

    is_elevated = check_admin()
    config = load_config()

    init_db()

    srv_cfg = config.get("server", {})
    host = srv_cfg.get("host", "127.0.0.1")
    port = srv_cfg.get("port", 8080)

    engine = CorrelationEngine(config)
    set_global_engine(engine)
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
        sys.exit(0)

if __name__ == "__main__":
    main()