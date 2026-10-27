import os
import sys
import ctypes
import subprocess
import ipaddress
from core.database import record_blocked_ip, is_ip_blocked

def is_admin():
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

def block_remote_ip(ip, reason="Automated IPS Mitigation", score=100):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
    except ValueError:
        return False

    if is_ip_blocked(ip):
        return True

    if not is_admin():
        return False

    success = False
    try:
        if sys.platform == "win32":
            rule_name = f"AEGIS-Block-{ip}"
            ps_cmd = (
                f'$ErrorActionPreference = "Stop"; '
                f'if (-not (Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue)) {{ '
                f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress "{ip}" | Out-Null }}'
            )
            res = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], capture_output=True, text=True)
            success = (res.returncode == 0)
        else:
            check_cmd = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
            if check_cmd.returncode != 0:
                res = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
                success = (res.returncode == 0)
            else:
                success = True
    except Exception:
        success = False

    if success:
        record_blocked_ip(ip, reason, score)

    return success