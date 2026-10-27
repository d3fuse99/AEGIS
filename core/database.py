import sqlite3
import os
import json
import hashlib
import time

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aegis.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            severity TEXT,
            event_type TEXT,
            description TEXT,
            payload TEXT
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS trusted_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proc_name TEXT UNIQUE,
            added_at TEXT
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS trusted_usb (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_hash TEXT UNIQUE,
            added_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS trusted_macs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT UNIQUE,
            added_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            reason TEXT,
            score INTEGER,
            blocked_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS auth_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT,
            salt TEXT
        )
    """)

    conn.commit()
    conn.close()

def log_event(source, severity, event_type, description, payload=None):
    conn = get_connection()
    c = conn.cursor()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    payload_str = json.dumps(payload) if payload else "{}"
    c.execute(
        "INSERT INTO security_events (timestamp, source, severity, event_type, description, payload) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, source, severity, event_type, description, payload_str)
    )
    conn.commit()
    conn.close()

def get_recent_events(limit=50):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def is_process_whitelisted(proc_name):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM trusted_processes WHERE LOWER(proc_name) = LOWER(?)", (proc_name,))
    res = c.fetchone() is not None
    conn.close()
    return res

def add_process_whitelist(proc_name):
    conn = get_connection()
    c = conn.cursor()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("INSERT OR IGNORE INTO trusted_processes (proc_name, added_at) VALUES (?, ?)", (proc_name.lower(), ts))
        conn.commit()
    finally:
        conn.close()

def is_usb_whitelisted(serial, salt="aegis_secure_salt"):
    s_hash = hashlib.sha256((serial + salt).encode("utf-8")).hexdigest()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM trusted_usb WHERE serial_hash = ? OR serial_hash = ?", (s_hash, serial))
    res = c.fetchone() is not None
    conn.close()
    return res

def add_usb_whitelist(serial, salt="aegis_secure_salt"):
    s_hash = hashlib.sha256((serial + salt).encode("utf-8")).hexdigest()
    conn = get_connection()
    c = conn.cursor()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("INSERT OR IGNORE INTO trusted_usb (serial_hash, added_at) VALUES (?, ?)", (s_hash, ts))
        conn.commit()
    finally:
        conn.close()

def remove_usb_whitelist(serial, salt="aegis_secure_salt"):
    s_hash = hashlib.sha256((serial + salt).encode("utf-8")).hexdigest()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM trusted_usb WHERE serial_hash = ? OR serial_hash = ?", (s_hash, serial))
        conn.commit()
    finally:
        conn.close()

def is_mac_trusted(mac):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM trusted_macs WHERE UPPER(mac) = UPPER(?)", (mac,))
    res = c.fetchone() is not None
    conn.close()
    return res

def add_mac_trusted(mac):
    conn = get_connection()
    c = conn.cursor()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("INSERT OR IGNORE INTO trusted_macs (mac, added_at) VALUES (?, ?)", (mac.upper(), ts))
        conn.commit()
    finally:
        conn.close()

def is_ip_blocked(ip):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
    res = c.fetchone() is not None
    conn.close()
    return res

def record_blocked_ip(ip, reason, score):
    conn = get_connection()
    c = conn.cursor()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("INSERT OR REPLACE INTO blocked_ips (ip, reason, score, blocked_at) VALUES (?, ?, ?, ?)", (ip, reason, score, ts))
        conn.commit()
    finally:
        conn.close()

def get_blocked_ips():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def is_auth_configured():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM auth_credentials LIMIT 1")
    res = c.fetchone() is not None
    conn.close()
    return res

def setup_auth(password):
    import secrets
    salt = secrets.token_hex(16)
    p_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM auth_credentials")
        c.execute("INSERT INTO auth_credentials (password_hash, salt) VALUES (?, ?)", (p_hash, salt))
        conn.commit()
        return True
    finally:
        conn.close()

def verify_auth(password):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM auth_credentials LIMIT 1")
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    p_hash = hashlib.sha256((password + row["salt"]).encode("utf-8")).hexdigest()
    return p_hash == row["password_hash"]