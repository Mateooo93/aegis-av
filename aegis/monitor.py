"""
Aegis AV - Real-Time Monitoring
File system monitoring, process monitoring, and network connection monitoring.
"""

import os
import time
import threading
import logging
import socket
from datetime import datetime
from collections import defaultdict

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

from aegis.config import (
    EXECUTABLE_EXTENSIONS, SUSPICIOUS_PATHS, Config, logger
)

logger = logging.getLogger("Aegis.Monitor")


# ── File System Monitor ───────────────────────────────────────────

class FileEventHandler(FileSystemEventHandler):
    """Handles file system events for real-time scanning."""

    def __init__(self, scan_callback, on_event_callback=None):
        super().__init__()
        self.scan_callback = scan_callback
        self.on_event = on_event_callback
        self._recently_scanned = {}
        self._cooldown = 2  # seconds

    def _should_scan(self, path):
        """Check if file should be scanned (cooldown + extension check)."""
        lower_path = path.lower()
        # Skip system, dev, temp build folders that change very frequently
        ignored_patterns = ["appdata", ".git", ".gemini", "node_modules", ".vscode", ".idea", "venv", "__pycache__"]
        if any(pat in lower_path for pat in ignored_patterns):
            return False

        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in EXECUTABLE_EXTENSIONS:
            return False

        # Cooldown to avoid scanning the same file repeatedly
        now = time.time()
        last_scan = self._recently_scanned.get(path, 0)
        if now - last_scan < self._cooldown:
            return False

        self._recently_scanned[path] = now

        # Clean old entries
        if len(self._recently_scanned) > 1000:
            cutoff = now - 60
            self._recently_scanned = {
                k: v for k, v in self._recently_scanned.items()
                if v > cutoff
            }

        return True

    def on_created(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            logger.debug("New file detected: %s", event.src_path)
            if self.on_event:
                self.on_event("file_created", event.src_path)
            # Delay briefly to allow file write to complete
            threading.Timer(1.0, self.scan_callback, args=[event.src_path]).start()

    def on_modified(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            logger.debug("File modified: %s", event.src_path)
            if self.on_event:
                self.on_event("file_modified", event.src_path)
            threading.Timer(1.0, self.scan_callback, args=[event.src_path]).start()

    def on_moved(self, event):
        if not event.is_directory and self._should_scan(event.dest_path):
            logger.debug("File moved: %s -> %s", event.src_path, event.dest_path)
            if self.on_event:
                self.on_event("file_moved", event.dest_path)
            threading.Timer(1.0, self.scan_callback, args=[event.dest_path]).start()


class RealtimeProtection:
    """Real-time file system monitoring with automatic scanning."""

    def __init__(self, scanner, database, config):
        self.scanner = scanner
        self.db = database
        self.config = config
        self.active = False
        self.observer = None
        self.events_count = 0
        self.threats_blocked = 0
        self.on_threat = None  # Callback: (file_path, detections) -> None
        self.on_event = None   # Callback: (event_type, details) -> None
        self._lock = threading.Lock()

    def start(self):
        """Start real-time file monitoring."""
        if not HAS_WATCHDOG:
            logger.error("watchdog not installed - real-time protection unavailable")
            return False

        if self.active:
            return True

        try:
            self.observer = Observer()
            handler = FileEventHandler(
                scan_callback=self._on_file_event,
                on_event_callback=self._on_fs_event
            )

            # Monitor configured paths
            paths = self.config.get("realtime_paths", [os.path.expanduser("~")])
            for path in paths:
                if os.path.exists(path):
                    self.observer.schedule(handler, path, recursive=True)
                    logger.info("Monitoring: %s", path)

            self.observer.start()
            self.active = True
            logger.info("Real-time protection started")
            return True

        except Exception as e:
            logger.error("Failed to start real-time protection: %s", e)
            return False

    def stop(self):
        """Stop real-time monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
        self.active = False
        logger.info("Real-time protection stopped")

    def _on_fs_event(self, event_type, file_path):
        """Track file system events."""
        with self._lock:
            self.events_count += 1
        if self.on_event:
            self.on_event(event_type, file_path)

    def _on_file_event(self, file_path):
        """Scan a file triggered by file system event."""
        try:
            if not os.path.exists(file_path):
                return

            detections = self.scanner.scan_single_file(file_path)
            if detections:
                with self._lock:
                    self.threats_blocked += 1

                logger.warning("Real-time: Threat detected in %s", file_path)

                # Record event
                self.db.add_realtime_event(
                    event_type="threat_detected",
                    file_path=file_path,
                    details="; ".join(d.threat_name for d in detections),
                    action_taken="blocked" if self.config.get("auto_quarantine") else "detected"
                )

                if self.on_threat:
                    self.on_threat(file_path, detections)

        except Exception as e:
            logger.debug("Real-time scan error for %s: %s", file_path, e)


# ── Process Monitor ───────────────────────────────────────────────

class ProcessMonitor:
    """Monitors running processes for suspicious activity."""

    # Known suspicious process names
    SUSPICIOUS_PROCESSES = {
        "mimikatz", "lazagne", "procdump", "pwdump",
        "wce", "fgdump", "gsecdump", "cachedump",
        "meterpreter", "cobaltstrike", "beacon",
        "netcat", "nc", "ncat",
        "keylogger", "ratclient",
    }

    def __init__(self, database):
        self.db = database
        self.active = False
        self._thread = None
        self._stop_event = threading.Event()
        self.suspicious_processes = []
        self.on_suspicious = None  # Callback: (process_info) -> None
        self._known_pids = set()

    def start(self):
        """Start process monitoring."""
        if not HAS_PSUTIL:
            logger.error("psutil not installed - process monitoring unavailable")
            return False

        if self.active:
            return True

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.active = True
        logger.info("Process monitor started")
        return True

    def stop(self):
        """Stop process monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.active = False
        logger.info("Process monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self._check_processes()
            except Exception as e:
                logger.debug("Process monitor error: %s", e)
            self._stop_event.wait(5)  # Check every 5 seconds

    def _check_processes(self):
        """Check all running processes for suspicious activity."""
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
            try:
                pid = proc.info["pid"]
                if pid in self._known_pids:
                    continue

                name = (proc.info["name"] or "").lower()
                exe = proc.info["exe"] or ""
                cmdline = " ".join(proc.info.get("cmdline") or [])

                suspicious = False
                reason = ""

                # Check against known suspicious process names
                for sus_name in self.SUSPICIOUS_PROCESSES:
                    if sus_name in name:
                        suspicious = True
                        reason = f"Known suspicious tool: {sus_name}"
                        break

                # Check for suspicious command line patterns
                if not suspicious and cmdline:
                    cmdline_lower = cmdline.lower()
                    if "powershell" in cmdline_lower and "-enc" in cmdline_lower:
                        suspicious = True
                        reason = "Encoded PowerShell execution"
                    elif "cmd /c" in cmdline_lower and "http" in cmdline_lower:
                        suspicious = True
                        reason = "CMD with network activity"
                    elif "certutil" in cmdline_lower and "-urlcache" in cmdline_lower:
                        suspicious = True
                        reason = "Certutil download attempt"
                    elif "bitsadmin" in cmdline_lower and "/transfer" in cmdline_lower:
                        suspicious = True
                        reason = "BITSAdmin file transfer"

                # Check for processes running from temp directories
                if not suspicious and exe:
                    exe_lower = exe.lower()
                    temp_dirs = [
                        os.path.expandvars(r"%TEMP%").lower(),
                        os.path.expandvars(r"%LOCALAPPDATA%\Temp").lower(),
                        r"c:\windows\temp",
                    ]
                    for temp_dir in temp_dirs:
                        if exe_lower.startswith(temp_dir):
                            suspicious = True
                            reason = f"Executable running from temp directory"
                            break

                self._known_pids.add(pid)

                if suspicious:
                    proc_info = {
                        "pid": pid,
                        "name": proc.info["name"],
                        "exe": exe,
                        "cmdline": cmdline,
                        "reason": reason,
                        "timestamp": datetime.now().isoformat(),
                    }
                    self.suspicious_processes.append(proc_info)

                    # Keep list manageable
                    if len(self.suspicious_processes) > 100:
                        self.suspicious_processes = self.suspicious_processes[-100:]

                    self.db.add_realtime_event(
                        event_type="suspicious_process",
                        process_name=proc.info["name"],
                        details=f"PID: {pid}, Reason: {reason}, CMD: {cmdline[:200]}",
                        action_taken="alert"
                    )

                    if self.on_suspicious:
                        self.on_suspicious(proc_info)

                    logger.warning("Suspicious process: PID=%d Name=%s Reason=%s",
                                   pid, proc.info["name"], reason)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Clean up dead PIDs periodically
        if len(self._known_pids) > 5000:
            active_pids = {p.pid for p in psutil.process_iter(["pid"])}
            self._known_pids &= active_pids

    def get_all_processes(self):
        """Get list of all running processes."""
        if not HAS_PSUTIL:
            return []

        processes = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent",
                                          "memory_percent", "username", "status"]):
            try:
                processes.append({
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "exe": proc.info["exe"] or "",
                    "cpu": proc.info.get("cpu_percent", 0),
                    "memory": proc.info.get("memory_percent", 0),
                    "user": proc.info.get("username", ""),
                    "status": proc.info.get("status", ""),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes

    def kill_process(self, pid):
        """Kill a process by PID."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            logger.info("Killed process: PID=%d", pid)
            return True
        except Exception as e:
            logger.error("Failed to kill PID %d: %s", pid, e)
            # Try force kill
            try:
                proc = psutil.Process(pid)
                proc.kill()
                return True
            except Exception:
                return False


# ── Network Monitor ───────────────────────────────────────────────

class NetworkMonitor:
    """Monitors network connections for suspicious activity."""

    # Known suspicious ports
    SUSPICIOUS_PORTS = {
        4444,   # Metasploit default
        5555,   # Common backdoor
        1337,   # Common hacker port
        31337,  # Back Orifice
        12345,  # NetBus
        27374,  # SubSeven
        6666, 6667, 6668, 6669,  # IRC (C2)
        8443,   # Alternative HTTPS (C2)
        9001, 9030,  # Tor
        3389,   # RDP (if unexpected)
    }

    # Known malicious IPs/ranges (sample - in production this would be a large list)
    SUSPICIOUS_IP_RANGES = []

    def __init__(self, database):
        self.db = database
        self.active = False
        self._thread = None
        self._stop_event = threading.Event()
        self.suspicious_connections = []
        self.on_suspicious = None  # Callback: (connection_info) -> None
        self._seen_connections = set()
        self.connection_history = []

    def start(self):
        """Start network monitoring."""
        if not HAS_PSUTIL:
            logger.error("psutil not installed - network monitoring unavailable")
            return False

        if self.active:
            return True

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.active = True
        logger.info("Network monitor started")
        return True

    def stop(self):
        """Stop network monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.active = False
        logger.info("Network monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self._check_connections()
            except Exception as e:
                logger.debug("Network monitor error: %s", e)
            self._stop_event.wait(10)  # Check every 10 seconds

    def _check_connections(self):
        """Check active network connections."""
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            try:
                if conn.status != "ESTABLISHED":
                    continue

                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0
                pid = conn.pid

                # Create connection key to avoid duplicates
                conn_key = f"{pid}:{remote_ip}:{remote_port}"
                if conn_key in self._seen_connections:
                    continue
                self._seen_connections.add(conn_key)

                # Check for suspicious connections
                suspicious = False
                reason = ""

                # Check suspicious remote ports
                if remote_port in self.SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Connection to suspicious port {remote_port}"

                # Check suspicious local listening ports
                if local_port in self.SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Listening on suspicious port {local_port}"

                # Get process name
                proc_name = ""
                try:
                    if pid:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                conn_info = {
                    "pid": pid,
                    "process": proc_name,
                    "local": f"{conn.laddr.ip}:{local_port}" if conn.laddr else "",
                    "remote": f"{remote_ip}:{remote_port}",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status,
                    "suspicious": suspicious,
                    "reason": reason,
                    "timestamp": datetime.now().isoformat(),
                }

                self.connection_history.append(conn_info)
                if len(self.connection_history) > 500:
                    self.connection_history = self.connection_history[-500:]

                if suspicious:
                    self.suspicious_connections.append(conn_info)
                    if len(self.suspicious_connections) > 100:
                        self.suspicious_connections = self.suspicious_connections[-100:]

                    self.db.add_realtime_event(
                        event_type="suspicious_connection",
                        process_name=proc_name,
                        details=f"PID: {pid}, Remote: {remote_ip}:{remote_port}, "
                                f"Reason: {reason}",
                        action_taken="alert"
                    )

                    if self.on_suspicious:
                        self.on_suspicious(conn_info)

                    logger.warning("Suspicious connection: %s -> %s:%d (%s)",
                                   proc_name, remote_ip, remote_port, reason)

            except Exception:
                pass

        # Clean up old connection keys
        if len(self._seen_connections) > 5000:
            self._seen_connections.clear()

    def get_active_connections(self):
        """Get all active network connections."""
        if not HAS_PSUTIL:
            return []

        connections = []
        for conn in psutil.net_connections(kind="inet"):
            try:
                proc_name = ""
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                connections.append({
                    "pid": conn.pid,
                    "process": proc_name,
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                    "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                })
            except Exception:
                pass
        return connections

    def get_network_stats(self):
        """Get network I/O statistics."""
        if not HAS_PSUTIL:
            return {}
        try:
            io = psutil.net_io_counters()
            return {
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
            }
        except Exception:
            return {}
