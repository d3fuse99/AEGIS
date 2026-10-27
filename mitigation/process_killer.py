import os
import sys
import psutil
from mitigation.quarantine import isolate_file

def clean_registry_autorun(exe_path):
    if sys.platform != "win32" or not exe_path:
        return
    try:
        import winreg
        exe_lower = exe_path.lower()
        targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        ]
        for hive, subkey in targets:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    names_to_del = []
                    for i in range(count):
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        if exe_lower in str(val_data).lower():
                            names_to_del.append(val_name)
                    for vname in names_to_del:
                        winreg.DeleteValue(key, vname)
            except Exception:
                continue
    except Exception:
        pass

def kill_process_tree(pid, exe_hint=""):
    try:
        if not psutil.pid_exists(pid):
            if exe_hint and os.path.isfile(exe_hint):
                isolate_file(exe_hint)
                clean_registry_autorun(exe_hint)
                try:
                    os.remove(exe_hint)
                except Exception:
                    pass
                return True
            return False

        target_proc = psutil.Process(pid)
        exe_path = exe_hint
        try:
            exe_path = target_proc.exe() or exe_hint
        except Exception:
            pass

        try:
            target_proc.suspend()
        except Exception:
            pass

        children = []
        try:
            children = target_proc.children(recursive=True)
        except Exception:
            pass

        all_procs = children + [target_proc]

        for p in all_procs:
            try:
                p.suspend()
            except Exception:
                pass

        if exe_path and os.path.isfile(exe_path):
            isolate_file(exe_path)
            clean_registry_autorun(exe_path)

        for p in all_procs:
            try:
                p.kill()
            except Exception:
                pass

        if exe_path and os.path.isfile(exe_path):
            try:
                os.remove(exe_path)
            except Exception:
                pass

        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    except Exception:
        return False