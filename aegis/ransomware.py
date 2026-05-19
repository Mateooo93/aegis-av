"""
Aegis AV - Ransomware Shield
Protects user-selected folders from unauthorized mass-modification
characteristic of ransomware. Watches file create/modify/rename events
inside protected folders and surfaces a high-severity alert when
suspicious entropy or rapid mass-rewrites are detected.
"""

import os
import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

logger = logging.getLogger("Aegis.Ransomware")


# Common file extensions ransomware appends to encrypted files
KNOWN_RANSOM_EXTENSIONS = {
    ".crypted", ".locked", ".encrypted", ".enc", ".cry", ".crypt",
    ".rcrypted", ".pay", ".payforunlock", ".readme", ".ransom",
    ".wcry", ".wncry", ".djvu", ".stop", ".rdp", ".phobos",
    ".lockbit", ".babuk", ".conti", ".sodinokibi", ".revil",
    ".darkside", ".blackcat", ".clop", ".hive", ".alphvm",
}

KNOWN_RANSOM_NOTE_KEYWORDS = (
    "your files have been encrypted",
    "pay the ransom",
    "send bitcoin",
    "decryption key",
    "all your files are encrypted",
)


class RansomwareShield:
    """Behavior-based ransomware detection on protected folders."""

    DEFAULT_PROTECTED = [
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "Pictures"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
    ]

    # Rolling window thresholds (per minute)
    RAPID_MODIFY_THRESHOLD = 25     # >25 modifies in a minute = suspicious
    RAPID_RENAME_THRESHOLD = 15     # >15 renames with new ext in a minute = critical

    def __init__(self, database, config):
        self.db = database
        self.config = config
        self.active = False
        self.observer = None
        self.protected_folders = list(self.DEFAULT_PROTECTED)
        self.events = deque(maxlen=200)
        self.last_alert_time = 0

        # Behaviour trackers
        self._lock = threading.Lock()
        self._modify_history = deque(maxlen=500)
        self._rename_history = deque(maxlen=500)

        # Callbacks
        self.on_attack = None  # Callback(event_payload)

    def start(self):
        if not HAS_WATCHDOG:
            logger.warning("watchdog missing – ransomware shield disabled")
            return False
        if self.active:
            return True

        handler = _RansomwareHandler(self)
        try:
            self.observer = Observer()
            for folder in self.protected_folders:
                if os.path.isdir(folder):
                    self.observer.schedule(handler, folder, recursive=True)
                    logger.info("Ransomware shield watching: %s", folder)
            self.observer.start()
            self.active = True
            return True
        except Exception as e:
            logger.error("Ransomware shield failed: %s", e)
            return False

    def stop(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=3)
            except Exception:
                pass
        self.observer = None
        self.active = False

    # ── Protected folders config ──────────────────────────────────────
    def add_folder(self, folder: str):
        folder = os.path.normpath(folder)
        if folder not in self.protected_folders and os.path.isdir(folder):
            self.protected_folders.append(folder)
            # Restart observer to pick up new path
            if self.active:
                self.stop()
                self.start()
            return True
        return False

    def remove_folder(self, folder: str):
        folder = os.path.normpath(folder)
        if folder in self.protected_folders:
            self.protected_folders.remove(folder)
            if self.active:
                self.stop()
                self.start()
            return True
        return False

    def get_status(self):
        return {
            "active": self.active,
            "protected_folders": list(self.protected_folders),
            "events_logged": len(self.events),
        }

    def get_events(self, limit=50):
        return list(self.events)[-limit:][::-1]

    # ── Internals ────────────────────────────────────────────────────
    def _record_event(self, kind: str, path: str, severity: str = "medium",
                      details: str = ""):
        event = {
            "kind": kind,
            "path": path,
            "severity": severity,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        }
        self.events.append(event)
        try:
            self.db.add_realtime_event(
                event_type="ransomware",
                file_path=path,
                details=f"[{severity.upper()}] {kind} – {details}",
                action_taken="alert",
            )
        except Exception:
            pass
        if self.on_attack:
            try:
                self.on_attack(event)
            except Exception:
                pass

    def _check_behaviour(self):
        """Look at recent modification rate – throttle alerts."""
        now = time.time()
        with self._lock:
            modify_rate = sum(1 for t in self._modify_history if now - t < 60)
            rename_rate = sum(1 for t in self._rename_history if now - t < 60)

        # Throttle: don't alert more than once per 20 s
        if now - self.last_alert_time < 20:
            return

        if modify_rate >= self.RAPID_MODIFY_THRESHOLD:
            self.last_alert_time = now
            self._record_event(
                kind="mass_modify",
                path="(multiple)",
                severity="high",
                details=f"{modify_rate} file modifications in last 60 s",
            )
        if rename_rate >= self.RAPID_RENAME_THRESHOLD:
            self.last_alert_time = now
            self._record_event(
                kind="mass_rename",
                path="(multiple)",
                severity="critical",
                details=f"{rename_rate} suspicious renames detected in 60 s",
            )

    def _on_modify(self, path: str):
        with self._lock:
            self._modify_history.append(time.time())
        ext = os.path.splitext(path)[1].lower()
        if ext in KNOWN_RANSOM_EXTENSIONS:
            self._record_event(
                kind="known_ransom_ext",
                path=path,
                severity="critical",
                details=f"File now has known ransomware extension: {ext}",
            )
        self._check_behaviour()

    def _on_rename(self, src: str, dest: str):
        with self._lock:
            self._rename_history.append(time.time())
        new_ext = os.path.splitext(dest)[1].lower()
        if new_ext in KNOWN_RANSOM_EXTENSIONS:
            self._record_event(
                kind="suspicious_rename",
                path=dest,
                severity="critical",
                details=f"{src} → {dest} (ransom extension {new_ext})",
            )
        self._check_behaviour()

    def _on_create(self, path: str):
        # Ransomware often drops a "README_DECRYPT.txt" style note
        name = os.path.basename(path).lower()
        if "decrypt" in name or "readme" in name or "ransom" in name:
            try:
                if os.path.isfile(path) and os.path.getsize(path) < 50 * 1024:
                    with open(path, "rb") as f:
                        sample = f.read(4096).decode("utf-8", errors="ignore").lower()
                    if any(kw in sample for kw in KNOWN_RANSOM_NOTE_KEYWORDS):
                        self._record_event(
                            kind="ransom_note",
                            path=path,
                            severity="critical",
                            details="Suspected ransom note dropped in protected folder",
                        )
            except Exception:
                pass


class _RansomwareHandler(FileSystemEventHandler if HAS_WATCHDOG else object):
    def __init__(self, shield: RansomwareShield):
        if HAS_WATCHDOG:
            super().__init__()
        self.shield = shield

    def on_modified(self, event):
        if not event.is_directory:
            self.shield._on_modify(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.shield._on_create(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.shield._on_rename(event.src_path, getattr(event, "dest_path", event.src_path))
