import os
import time
from pathlib import Path

DEFAULT_QUARANTINE_DIR = "EDR_Quarantine"
DEFAULT_XOR_KEY = 0x5A
DEFAULT_MAX_QUOTA_BYTES = 104857600

def enforce_quota(quarantine_path, max_bytes=DEFAULT_MAX_QUOTA_BYTES):
    try:
        p = Path(quarantine_path)
        if not p.exists():
            return
        files = sorted(list(p.glob("*.vir")), key=lambda x: x.stat().st_mtime)
        total_size = sum(f.stat().st_size for f in files)
        while total_size > max_bytes and files:
            oldest = files.pop(0)
            total_size -= oldest.stat().st_size
            oldest.unlink(missing_ok=True)
    except Exception:
        pass

def xor_transform(src_path, dest_path, key=DEFAULT_XOR_KEY):
    with open(src_path, "rb") as fin:
        data = bytearray(fin.read())
    for i in range(len(data)):
        data[i] ^= key
    with open(dest_path, "wb") as fout:
        fout.write(data)

def isolate_file(file_path, quarantine_dir=DEFAULT_QUARANTINE_DIR, key=DEFAULT_XOR_KEY):
    try:
        if not file_path or not os.path.isfile(file_path):
            return None
        q_dir = Path(quarantine_dir)
        q_dir.mkdir(parents=True, exist_ok=True)
        enforce_quota(q_dir)
        
        src = Path(file_path)
        dest_name = f"{src.stem}_{int(time.time())}.vir"
        dest_path = q_dir / dest_name
        xor_transform(src, dest_path, key)
        return str(dest_path)
    except Exception:
        return None