"""
Aegis AV - Web Shield Module
Provides URL reputation checks, phishing detection, malicious download alerts,
and a browser-download inspector. Watches the user's Downloads folder for
new files and auto-scans them, surfacing toast-grade alerts upstream.
"""

import os
import re
import time
import json
import threading
import logging
from datetime import datetime
from urllib.parse import urlparse

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

logger = logging.getLogger("Aegis.WebShield")


# Curated lists of well-known phishing / malware indicator hosts.
# Production builds can pull these from a remote feed (PhishTank, URLhaus, etc.)
KNOWN_PHISHING_KEYWORDS = [
    "secure-login", "verify-account", "account-suspended", "update-billing",
    "confirm-identity", "wallet-recovery", "metamask-helpdesk",
    "apple-id-locked", "paypal-resolution", "netflix-billing",
    "bank-of-america-secure", "microsoft-verify", "google-recovery",
    "irs-refund", "office365-security",
]

# Suspicious TLDs commonly abused by phishing campaigns
SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".click", ".xyz", ".top", ".gq", ".tk", ".ml",
    ".cf", ".cn", ".info", ".cam", ".rest", ".bar",
}

# Hardcoded sample blocklist (cleared, modifiable at runtime)
DEFAULT_BLOCKLIST = {
    "evil-update.cn",
    "free-robux-generator.xyz",
    "support-microsoft-verify.top",
    "binance-claim-airdrop.click",
    "secure-paypal-resolution.cf",
    "office365-mailbox-verify.bar",
    "apple-id-locked-recovery.info",
    "netflix-billing-update.gq",
}


class WebShield:
    """
    Web Shield - URL reputation, phishing detector, and download inspector.
    Designed to plug into the realtime monitor pipeline.
    """

    def __init__(self, scanner, database, config):
        self.scanner = scanner
        self.db = database
        self.config = config

        self.active = False
        self.observer = None
        self.on_event = None        # Callback(payload) for live UI alerts
        self.on_download_threat = None  # Callback(file_path, detections)

        # Runtime mutable URL blocklist
        self._blocklist_lock = threading.Lock()
        self._blocklist = set(DEFAULT_BLOCKLIST)

        # Counters surfaced to dashboards
        self.urls_checked = 0
        self.urls_blocked = 0
        self.downloads_scanned = 0
        self.downloads_blocked = 0

        # Cooldown to avoid duplicate scanning
        self._recent_files = {}
        self._recent_cooldown_sec = 4

    # ── URL Reputation ────────────────────────────────────────────────
    def check_url(self, url: str) -> dict:
        """Return reputation verdict for a given URL."""
        self.urls_checked += 1
        result = {
            "url": url,
            "verdict": "safe",
            "reasons": [],
            "score": 0,
        }

        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            host = (parsed.hostname or "").lower()
        except Exception:
            return result

        if not host:
            return result

        # Blocklist match
        with self._blocklist_lock:
            if host in self._blocklist:
                result["verdict"] = "blocked"
                result["reasons"].append("Host present on Aegis blocklist")
                result["score"] += 100

        # Phishing keyword match
        host_no_dot = host.replace(".", "-")
        for kw in KNOWN_PHISHING_KEYWORDS:
            if kw in host_no_dot or kw in url.lower():
                result["reasons"].append(f"Phishing pattern: '{kw}'")
                result["score"] += 35

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                result["reasons"].append(f"Suspicious TLD: {tld}")
                result["score"] += 15
                break

        # Heuristic: too many dashes/digits in hostname
        if host.count("-") >= 4:
            result["reasons"].append("Excessive hyphens in hostname")
            result["score"] += 10
        if sum(c.isdigit() for c in host) >= 6:
            result["reasons"].append("Numerically dense hostname")
            result["score"] += 10

        # Final verdict
        if result["verdict"] != "blocked":
            if result["score"] >= 50:
                result["verdict"] = "malicious"
            elif result["score"] >= 25:
                result["verdict"] = "suspicious"

        if result["verdict"] in ("blocked", "malicious"):
            self.urls_blocked += 1
            try:
                self.db.add_realtime_event(
                    event_type="web_block",
                    details=f"URL {result['verdict']}: {url} | {'; '.join(result['reasons'])}",
                    action_taken="blocked",
                )
            except Exception:
                pass

        return result

    def add_to_blocklist(self, host: str):
        with self._blocklist_lock:
            self._blocklist.add(host.lower().strip())

    def remove_from_blocklist(self, host: str):
        with self._blocklist_lock:
            self._blocklist.discard(host.lower().strip())

    def get_blocklist(self):
        with self._blocklist_lock:
            return sorted(self._blocklist)

    # ── Download Inspector ────────────────────────────────────────────
    def start(self):
        """Monitor the user's Downloads folder for new files."""
        if not HAS_WATCHDOG:
            logger.warning("watchdog missing – web shield download inspector disabled")
            return False
        if self.active:
            return True

        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        if not os.path.isdir(downloads):
            logger.warning("Downloads folder not found: %s", downloads)
            return False

        handler = _DownloadHandler(self)
        try:
            self.observer = Observer()
            self.observer.schedule(handler, downloads, recursive=False)
            self.observer.start()
            self.active = True
            logger.info("Web Shield active – watching downloads at %s", downloads)
            return True
        except Exception as e:
            logger.error("Web Shield failed to start: %s", e)
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

    def _maybe_scan_download(self, file_path: str):
        """Scan a downloaded file and surface a toast-style alert."""
        now = time.time()
        last = self._recent_files.get(file_path, 0)
        if now - last < self._recent_cooldown_sec:
            return
        self._recent_files[file_path] = now

        # Wait briefly for the file write to complete
        time.sleep(0.8)

        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return

        try:
            self.downloads_scanned += 1
            detections = self.scanner.scan_single_file(file_path) or []

            verdict = "clean"
            if detections:
                verdict = "malicious"
                self.downloads_blocked += 1

            payload = {
                "type": "download_alert",
                "verdict": verdict,
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "detections": [d.threat_name for d in detections],
                "timestamp": datetime.now().isoformat(),
            }

            try:
                self.db.add_realtime_event(
                    event_type="download_scan",
                    file_path=file_path,
                    details=(f"Download verdict: {verdict} | "
                             f"{', '.join(d.threat_name for d in detections) if detections else 'clean'}"),
                    action_taken=verdict,
                )
            except Exception:
                pass

            if self.on_event:
                try:
                    self.on_event(payload)
                except Exception:
                    pass

            if detections and self.on_download_threat:
                try:
                    self.on_download_threat(file_path, detections)
                except Exception:
                    pass

        except Exception as e:
            logger.debug("Download scan failed for %s: %s", file_path, e)

    def get_status(self):
        return {
            "active": self.active,
            "urls_checked": self.urls_checked,
            "urls_blocked": self.urls_blocked,
            "downloads_scanned": self.downloads_scanned,
            "downloads_blocked": self.downloads_blocked,
            "blocklist_size": len(self._blocklist),
        }


class _DownloadHandler(FileSystemEventHandler if HAS_WATCHDOG else object):
    """Internal watcher delegating to WebShield."""

    def __init__(self, shield: WebShield):
        if HAS_WATCHDOG:
            super().__init__()
        self.shield = shield

    def on_created(self, event):
        if not event.is_directory:
            threading.Thread(
                target=self.shield._maybe_scan_download,
                args=(event.src_path,),
                daemon=True,
            ).start()

    def on_moved(self, event):
        dest = getattr(event, "dest_path", None)
        if dest and not event.is_directory:
            threading.Thread(
                target=self.shield._maybe_scan_download,
                args=(dest,),
                daemon=True,
            ).start()
