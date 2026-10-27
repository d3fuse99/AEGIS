import time
import threading
from core.event_bus import bus
from core.database import log_event, is_process_whitelisted
from mitigation.process_killer import kill_process_tree
from mitigation.firewall_blocker import block_remote_ip

class CorrelationEngine:
    def __init__(self, config):
        self.config = config
        self.process_scores = {}
        self.ip_scores = {}
        self.lock = threading.Lock()
        self.threshold = config["threat_engine"]["global_threshold"]
        self.decay_rate = config["threat_engine"]["decay_rate"]
        self.decay_interval = config["threat_engine"]["decay_interval_sec"]
        self.running = False
        
        bus.subscribe("PROCESS_SUSPICIOUS", self._on_process_suspicious)
        bus.subscribe("CANARY_BREACH", self._on_canary_breach)
        bus.subscribe("HONEYPOT_ATTACK", self._on_honeypot_attack)
        bus.subscribe("NET_THREAT", self._on_net_threat)

    def start(self):
        self.running = True
        t = threading.Thread(target=self._decay_loop, daemon=True)
        t.start()

    def stop(self):
        self.running = False

    def _decay_loop(self):
        while self.running:
            time.sleep(self.decay_interval)
            with self.lock:
                dead_pids = []
                for pid, meta in self.process_scores.items():
                    if meta["score"] > 0:
                        meta["score"] = max(0, meta["score"] - self.decay_rate)
                    if meta["score"] == 0 and time.time() - meta.get("updated", 0) > 10:
                        dead_pids.append(pid)
                for pid in dead_pids:
                    del self.process_scores[pid]

    def _on_process_suspicious(self, event_type, data):
        pid = data.get("pid")
        proc_name = data.get("name", "Unknown")
        points = data.get("points", 0)
        heuristic = data.get("heuristic", "GENERIC_HEURISTIC")
        
        if is_process_whitelisted(proc_name):
            return

        with self.lock:
            if pid not in self.process_scores:
                self.process_scores[pid] = {
                    "name": proc_name,
                    "score": 0,
                    "heuristics": set(),
                    "updated": time.time(),
                    "exe": data.get("exe", "")
                }
            self.process_scores[pid]["score"] += points
            self.process_scores[pid]["heuristics"].add(heuristic)
            self.process_scores[pid]["updated"] = time.time()
            total = self.process_scores[pid]["score"]

        log_event("BEHAVIOR", "WARNING" if total < self.threshold else "CRITICAL", heuristic, f"Process {proc_name} (PID: {pid}) accumulated score {total}", data)

        if total >= self.threshold:
            self._mitigate_process(pid, proc_name, total, list(self.process_scores[pid]["heuristics"]), data.get("exe", ""))

    def _on_canary_breach(self, event_type, data):
        pid = data.get("pid", 0)
        proc_name = data.get("name", "Unknown")
        entropy = data.get("entropy", 0.0)
        decoy = data.get("decoy", "Unknown")
        
        if pid > 0 and is_process_whitelisted(proc_name):
            return

        log_event("CANARY", "CRITICAL", "RANSOMWARE_TRIGGERED", f"Canary {decoy} modified with entropy {entropy} by PID {pid}", data)
        
        if pid > 0:
            self._mitigate_process(pid, proc_name, 100, ["HIGH_ENTROPY_CANARY_ALTERATION"], data.get("exe", ""))

    def _on_honeypot_attack(self, event_type, data):
        ip = data.get("ip")
        points = data.get("points", 0)
        service = data.get("service", "TCP")
        payload = data.get("payload", "")

        with self.lock:
            self.ip_scores[ip] = self.ip_scores.get(ip, 0) + points
            total_ip_score = self.ip_scores[ip]

        log_event("DECEPTION", "WARNING" if total_ip_score < 10 else "CRITICAL", "HONEYPOT_INTRUSION", f"Attacker {ip} triggered {service} trap: {payload}", data)

        if total_ip_score >= self.config["sensors"]["deception"]["threat_limit"]:
            block_remote_ip(ip, f"Exceeded Honeypot Threshold on {service}")

    def _on_net_threat(self, event_type, data):
        pid = data.get("pid")
        ip = data.get("remote_ip")
        score = data.get("score", 0)
        if pid and score >= 60:
            with self.lock:
                if pid in self.process_scores:
                    self.process_scores[pid]["score"] += 30
                    self.process_scores[pid]["heuristics"].add("EXTERNAL_MALICIOUS_C2_SOCKET")

    def _mitigate_process(self, pid, name, score, heuristics, exe=""):
        success = kill_process_tree(pid, exe)
        severity = "ACTION" if success else "ERROR"
        log_event("MITIGATION", severity, "PROCESS_TERMINATED", f"Process {name} (PID: {pid}) neutralized. Score: {score}", {"heuristics": heuristics, "exe": exe})
        with self.lock:
            if pid in self.process_scores:
                del self.process_scores[pid]
        bus.publish("MITIGATION_EXECUTED", {"pid": pid, "name": name, "score": score, "action": "TERMINATED_AND_QUARANTINED"})