"""
Aegis AV - Application Firewall & Intrusion Detection
A lightweight user-space firewall that tracks egress connections per process,
applies block rules, and detects intrusion / brute-force patterns
(SSH/RDP burst attempts, anomalous port scans, C2 callbacks).
"""

import os
import time
import socket
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("Aegis.Firewall")


# Suspicious country IP first-octets (very rough geo heuristic without GeoIP DB).
# This is intentionally lightweight; production builds should use MaxMind GeoLite2.
TOR_EXIT_HINTS = {
    "171.25.193.", "62.102.148.", "193.11.114.",
}


class FirewallEngine:
    """
    User-space firewall.
    Maintains:
      - block_rules : list of dicts {type, value, reason, created_at}
        types: 'host', 'ip', 'port', 'process'
      - intrusion_events : recent anomaly events
      - app_traffic : per-process accumulated counts
    """

    def __init__(self, database):
        self.db = database
        self.active = False

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

        self.block_rules = []           # in-memory ruleset
        self.intrusion_events = deque(maxlen=200)
        self.app_traffic = defaultdict(lambda: {"connections": 0, "last_seen": 0})

        # Connection 4-tuples we've already counted (pid:lport:rip:rport).
        # Prevents re-counting the same long-lived socket on every 4-s poll.
        self._known_connections = {}     # key -> first_seen_ts

        # Brute-force trackers (key: target identifier, value: deque of timestamps)
        # Each timestamp = a NEW connection observation, not a re-poll of the same socket.
        self._burst_tracker = defaultdict(lambda: deque(maxlen=50))

        # Per-event-kind throttle so toasts/notifications don't spam
        self._last_alert_ts = defaultdict(float)  # key -> last fired ts

        # Callbacks
        self.on_block = None
        self.on_intrusion = None

        # Seed reasonable defaults
        self.block_rules.append({
            "type": "port", "value": 4444,
            "reason": "Metasploit default reverse-shell port",
            "created_at": datetime.now().isoformat(),
        })
        self.block_rules.append({
            "type": "port", "value": 31337,
            "reason": "Back-Orifice port", "created_at": datetime.now().isoformat(),
        })

    # ── Lifecycle ─────────────────────────────────────────────────────
    def start(self):
        if not HAS_PSUTIL:
            logger.warning("psutil missing – firewall disabled")
            return False
        if self.active:
            return True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.active = True
        logger.info("Firewall engine started")
        return True

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.active = False

    # ── Rules ─────────────────────────────────────────────────────────
    def add_rule(self, rule_type: str, value, reason: str = ""):
        rule_type = rule_type.lower()
        if rule_type not in {"host", "ip", "port", "process"}:
            raise ValueError("Invalid rule type")

        with self._lock:
            # Dedupe
            for r in self.block_rules:
                if r["type"] == rule_type and str(r["value"]) == str(value):
                    return r
            rule = {
                "type": rule_type,
                "value": value if rule_type != "port" else int(value),
                "reason": reason or "Manually added",
                "created_at": datetime.now().isoformat(),
            }
            self.block_rules.append(rule)
            return rule

    def remove_rule(self, rule_type: str, value):
        with self._lock:
            before = len(self.block_rules)
            self.block_rules = [
                r for r in self.block_rules
                if not (r["type"] == rule_type and str(r["value"]) == str(value))
            ]
            return before != len(self.block_rules)

    def list_rules(self):
        with self._lock:
            return list(self.block_rules)

    # ── Snapshot of live activity ────────────────────────────────────
    def list_active_connections(self, limit=200):
        if not HAS_PSUTIL:
            return []
        results = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                try:
                    if not conn.raddr:
                        continue
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except Exception:
                            pass
                    results.append({
                        "pid": conn.pid,
                        "process": proc_name,
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "status": conn.status,
                        "blocked": self._is_blocked(conn.raddr.ip, conn.raddr.port, proc_name),
                    })
                except Exception:
                    continue
        except Exception:
            return []
        return results[:limit]

    def get_status(self):
        return {
            "active": self.active,
            "rules_count": len(self.block_rules),
            "intrusion_events": len(self.intrusion_events),
            "tracked_processes": len(self.app_traffic),
        }

    def list_intrusion_events(self):
        return list(self.intrusion_events)

    # ── Internal logic ────────────────────────────────────────────────
    def _is_blocked(self, remote_ip: str, remote_port: int, process: str = ""):
        with self._lock:
            for rule in self.block_rules:
                if rule["type"] == "ip" and rule["value"] == remote_ip:
                    return True
                if rule["type"] == "port" and int(rule["value"]) == int(remote_port):
                    return True
                if rule["type"] == "host" and remote_ip.endswith(rule["value"]):
                    return True
                if rule["type"] == "process" and process and rule["value"].lower() == process.lower():
                    return True
        return False

    def _loop(self):
        """Background poller that scans connections for intrusion patterns."""
        while not self._stop_event.is_set():
            try:
                self._scan_once()
            except Exception as e:
                logger.debug("Firewall loop tick failed: %s", e)
            self._stop_event.wait(4)

    def _scan_once(self):
        if not HAS_PSUTIL:
            return

        connections = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return

        now = time.time()
        listening_ports = set()
        established_per_remote_new = defaultdict(int)  # only count NEW sockets
        current_keys = set()

        for conn in connections:
            try:
                if conn.status == "LISTEN" and conn.laddr:
                    listening_ports.add(conn.laddr.port)

                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0

                proc_name = ""
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        proc_name = ""

                # Per-connection dedupe key – this socket counted as ONE event
                conn_key = f"{conn.pid}:{local_port}:{remote_ip}:{remote_port}"
                current_keys.add(conn_key)
                is_new_connection = conn_key not in self._known_connections
                if is_new_connection:
                    self._known_connections[conn_key] = now

                # Per-process traffic counter (re-tick is fine – it's a meter)
                self.app_traffic[proc_name or f"pid-{conn.pid}"]["connections"] += 1
                self.app_traffic[proc_name or f"pid-{conn.pid}"]["last_seen"] = now

                # ── Skip non-actionable re-polls of already-seen sockets ──
                if not is_new_connection:
                    continue

                established_per_remote_new[remote_ip] += 1

                # Suspicious Tor exit (only fire once per (proc, ip))
                if any(remote_ip.startswith(prefix) for prefix in TOR_EXIT_HINTS):
                    self._record_intrusion(
                        kind="tor_exit",
                        details=f"{proc_name or 'unknown'} → {remote_ip}:{remote_port} (known Tor exit prefix)",
                        severity="medium",
                        throttle_key=f"tor:{proc_name}:{remote_ip}",
                        throttle_sec=300,
                    )

                # Block rule applies?
                if self._is_blocked(remote_ip, remote_port, proc_name):
                    self._record_intrusion(
                        kind="block_hit",
                        details=f"BLOCKED {proc_name or 'pid-' + str(conn.pid)} → {remote_ip}:{remote_port}",
                        severity="high",
                        throttle_key=f"block:{proc_name}:{remote_ip}:{remote_port}",
                        throttle_sec=60,
                    )
                    if self.on_block:
                        try:
                            self.on_block({
                                "process": proc_name,
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "pid": conn.pid,
                            })
                        except Exception:
                            pass

                # ── Beacon burst tracker (NEW connections only) ──
                # 20 new connection attempts from the same process to the same
                # host within 90 s = unusual. Browsers do open many sockets, but
                # rarely 20 fresh ones to a single host in that window.
                key = f"{proc_name}::{remote_ip}"
                bucket = self._burst_tracker[key]
                bucket.append(now)
                # Garbage-collect old timestamps from this bucket
                while bucket and now - bucket[0] > 90:
                    bucket.popleft()
                if len(bucket) >= 20:
                    self._record_intrusion(
                        kind="beacon_burst",
                        details=f"Possible C2 beacon: {proc_name or 'unknown'} → {remote_ip} "
                                f"({len(bucket)} new sockets in 90 s)",
                        severity="high",
                        throttle_key=f"beacon:{proc_name}:{remote_ip}",
                        throttle_sec=300,
                    )
                    bucket.clear()

            except Exception:
                continue

        # Port-scan detector – one host hitting many local ports
        # (only counts NEW sockets observed this tick)
        for remote, hits in established_per_remote_new.items():
            if hits >= 12:
                self._record_intrusion(
                    kind="port_scan",
                    details=f"{hits} new sessions opened to {remote} in one tick",
                    severity="medium",
                    throttle_key=f"scan:{remote}",
                    throttle_sec=120,
                )

        # Anomalous listening port
        for port in listening_ports:
            if port in {4444, 5555, 31337, 12345, 1337}:
                self._record_intrusion(
                    kind="suspicious_listener",
                    details=f"A service is listening on port {port}",
                    severity="critical",
                    throttle_key=f"listen:{port}",
                    throttle_sec=600,
                )

        # ── House-keeping: forget closed connection keys & stale buckets ──
        stale = set(self._known_connections.keys()) - current_keys
        for k in stale:
            self._known_connections.pop(k, None)
        # Bound memory of burst tracker
        if len(self._burst_tracker) > 500:
            now2 = time.time()
            for k in list(self._burst_tracker.keys()):
                b = self._burst_tracker[k]
                if not b or now2 - b[-1] > 300:
                    del self._burst_tracker[k]

    def _record_intrusion(
        self,
        kind: str,
        details: str,
        severity: str = "medium",
        throttle_key: str = None,
        throttle_sec: int = 60,
    ):
        # Throttle identical alerts – we never want to spam the UI with the
        # same finding within `throttle_sec` seconds.
        now = time.time()
        tkey = throttle_key or f"{kind}:{details}"
        if now - self._last_alert_ts.get(tkey, 0.0) < throttle_sec:
            return
        self._last_alert_ts[tkey] = now

        event = {
            "kind": kind,
            "details": details,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        }
        self.intrusion_events.append(event)
        try:
            self.db.add_realtime_event(
                event_type="intrusion",
                details=f"[{severity.upper()}] {kind} – {details}",
                action_taken="alert",
            )
        except Exception:
            pass
        if self.on_intrusion:
            try:
                self.on_intrusion(event)
            except Exception:
                pass
