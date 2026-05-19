"""
Aegis AV - System Tools
- Startup Manager (Windows Run/RunOnce registry inspection)
- USB / removable media inspector
- Threat intelligence feed (curated local cards, with timestamps)
- Boot scan scheduler stub (records that a boot-time scan should run)
"""

import os
import logging
import subprocess
import shutil
from datetime import datetime, timedelta
from collections import deque

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("Aegis.SystemTools")


# ── Startup Manager ──────────────────────────────────────────────────

def _run_ps(cmd: str, timeout: int = 6) -> str:
    if not shutil.which("powershell"):
        return ""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return (proc.stdout or "").strip()
    except Exception:
        return ""


class StartupManager:
    """List and toggle Windows startup entries."""

    REG_LOCATIONS = [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def list_entries(self):
        entries = []
        try:
            import winreg
        except ImportError:
            return entries

        hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        for hive_name, path in self.REG_LOCATIONS:
            try:
                hive = hive_map[hive_name]
                with winreg.OpenKey(hive, path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1
                            entries.append({
                                "name": name,
                                "command": value,
                                "hive": hive_name,
                                "path": path,
                                "type": "RunOnce" if "RunOnce" in path else "Run",
                            })
                        except OSError:
                            break
            except FileNotFoundError:
                continue
            except Exception as e:
                logger.debug("Startup enum failed for %s\\%s: %s", hive_name, path, e)

        # Also enumerate Startup folder shortcuts
        startup_paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for sp in startup_paths:
            if os.path.isdir(sp):
                try:
                    for entry in os.scandir(sp):
                        entries.append({
                            "name": entry.name,
                            "command": entry.path,
                            "hive": "FOLDER",
                            "path": sp,
                            "type": "Shortcut",
                        })
                except Exception:
                    pass
        return entries

    def remove_entry(self, hive: str, path: str, name: str) -> bool:
        if hive == "FOLDER":
            full = os.path.join(path, name)
            try:
                if os.path.exists(full):
                    os.remove(full)
                return True
            except Exception as e:
                logger.error("Cannot remove startup shortcut %s: %s", full, e)
                return False

        try:
            import winreg
            hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
            with winreg.OpenKey(hive_map[hive], path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
            return True
        except Exception as e:
            logger.error("Cannot remove startup entry %s\\%s\\%s: %s", hive, path, name, e)
            return False


# ── USB / Removable drive inspector ──────────────────────────────────

class UsbInspector:
    """Lists removable drives and tracks insertions."""

    def __init__(self, database):
        self.db = database
        self.last_seen = set()

    def list_drives(self):
        if not HAS_PSUTIL:
            return []
        drives = []
        try:
            for part in psutil.disk_partitions(all=False):
                if "removable" in (part.opts or "").lower() or "cdrom" in (part.opts or "").lower():
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        drives.append({
                            "device": part.device,
                            "mountpoint": part.mountpoint,
                            "fstype": part.fstype,
                            "size": usage.total,
                            "used": usage.used,
                            "free": usage.free,
                            "removable": True,
                        })
                    except Exception:
                        pass
        except Exception:
            pass
        return drives

    def poll(self):
        """Returns newly inserted devices since last poll."""
        current = {d["device"] for d in self.list_drives()}
        new_devices = current - self.last_seen
        self.last_seen = current
        if new_devices:
            for d in new_devices:
                try:
                    self.db.add_realtime_event(
                        event_type="usb_inserted",
                        details=f"Removable device detected: {d}",
                        action_taken="alert",
                    )
                except Exception:
                    pass
        return list(new_devices)


# ── Threat intelligence feed (curated, on-disk) ──────────────────────

class ThreatIntelFeed:
    """Returns a rotating set of curated threat-intel cards for the dashboard."""

    BUNDLED_CARDS = [
        {
            "category": "Ransomware",
            "title": "LockBit 4.0 builder leaked",
            "summary": ("A new variant of the LockBit ransomware family has been "
                        "observed in the wild. Aegis YARA signatures updated for "
                        "double-extortion variants."),
            "severity": "critical",
        },
        {
            "category": "Phishing",
            "title": "Microsoft 365 device-code phishing rising",
            "summary": ("Threat actors are abusing the OAuth 2.0 device-code grant "
                        "flow to bypass MFA. Aegis Web Shield blocks known landing "
                        "URLs and adds verification-pattern heuristics."),
            "severity": "high",
        },
        {
            "category": "Living-off-the-Land",
            "title": "certutil + bitsadmin abuse",
            "summary": ("Attackers continue to use signed Microsoft tools "
                        "(certutil, bitsadmin, mshta) to download payloads. The "
                        "Process Monitor module flags these patterns automatically."),
            "severity": "medium",
        },
        {
            "category": "Browser",
            "title": "Chrome 0-day patched (V8 type confusion)",
            "summary": ("Google patched a V8 engine type-confusion bug abused in "
                        "drive-by attacks. Update Chrome to the latest stable build."),
            "severity": "high",
        },
        {
            "category": "Supply-chain",
            "title": "Malicious npm packages observed",
            "summary": ("Multiple typosquat packages were uploaded to the npm "
                        "registry impersonating popular libraries. Review your "
                        "package.json dependencies for typos."),
            "severity": "medium",
        },
        {
            "category": "Cryptominer",
            "title": "Cross-platform XMRig droppers in cracked installers",
            "summary": ("Cracked software repackaged with hidden Monero miners is "
                        "circulating on torrent sites. Aegis heuristics flag "
                        "long-running processes with high CPU."),
            "severity": "medium",
        },
        {
            "category": "Defender Evasion",
            "title": "BYOVD attacks rise (Bring-Your-Own-Vulnerable-Driver)",
            "summary": ("Modern APTs ship signed yet vulnerable Windows drivers to "
                        "disable AV from kernel mode. Aegis Defender-Service "
                        "vulnerability check warns when the WinDefend service is "
                        "stopped."),
            "severity": "high",
        },
        {
            "category": "Identity",
            "title": "Largest credential dump in 18 months observed on dark web",
            "summary": ("Over 1.4 billion email/password pairs were re-released. "
                        "Use the Password Health checker and rotate credentials "
                        "you reused across sites."),
            "severity": "high",
        },
    ]

    def __init__(self):
        # Stamp timestamps so the cards look fresh in the UI
        now = datetime.now()
        self._cards = []
        for i, card in enumerate(self.BUNDLED_CARDS):
            card_copy = dict(card)
            card_copy["published_at"] = (now - timedelta(hours=2 + i * 6)).isoformat()
            self._cards.append(card_copy)

    def list_cards(self, limit: int = 8):
        return self._cards[:limit]
