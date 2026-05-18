"""
Aegis AV - Configuration Management
Handles all application settings, paths, and user preferences.
"""

import os
import json
import logging
from datetime import datetime

# ── Application Paths ──────────────────────────────────────────────
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(APP_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "aegis.db")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
RULES_DIR = os.path.join(APP_DIR, "rules")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
LOG_DIR = os.path.join(DATA_DIR, "logs")
HASH_DB_PATH = os.path.join(DATA_DIR, "known_hashes.json")

# Create directories
for _d in [DATA_DIR, QUARANTINE_DIR, LOG_DIR]:
    os.makedirs(_d, exist_ok=True)

# ── Logging Setup ──────────────────────────────────────────────────
LOG_FILE = os.path.join(LOG_DIR, f"aegis_{datetime.now().strftime('%Y%m%d')}.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Aegis")

# ── File Extensions ────────────────────────────────────────────────
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".scr", ".pif", ".msi", ".jar", ".com", ".cpl", ".hta",
    ".inf", ".reg", ".rgs", ".sct", ".shb", ".shs", ".wsc", ".wsf"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"
}

DOCUMENT_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".rtf", ".odt", ".ods", ".odp"
}

ALL_SCANNABLE = EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS | DOCUMENT_EXTENSIONS

# ── Suspicious Indicators ─────────────────────────────────────────
SUSPICIOUS_APIS = {
    # Process injection
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    # Privilege escalation
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
    # Anti-debugging
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugString",
    # Keylogging
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    # Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
    # Network
    "InternetOpen", "InternetConnect", "HttpSendRequest", "URLDownloadToFile",
    "WinHttpOpen", "WinHttpConnect",
    # Registry
    "RegCreateKeyEx", "RegSetValueEx", "RegDeleteKey",
    # File system
    "FindFirstFile", "FindNextFile", "GetTempPath", "MoveFileEx",
    # Shell
    "ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcess",
    "CreateProcessAsUser",
    # Service
    "CreateService", "StartService", "ControlService",
    # Screen capture
    "BitBlt", "GetDC", "CreateCompatibleDC",
}

SUSPICIOUS_STRINGS = [
    # Network indicators
    b"http://", b"https://", b"ftp://",
    b"cmd.exe", b"powershell", b"wscript", b"cscript",
    b"HKEY_LOCAL_MACHINE", b"HKEY_CURRENT_USER",
    b"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    b"schtasks", b"at.exe", b"net.exe",
    b"taskkill", b"tasklist",
    b"reg add", b"reg delete",
    b"netsh firewall", b"netsh advfirewall",
    b"bcdedit", b"vssadmin",
    b"wmic", b"shadowcopy",
    b"bitcoin", b"wallet", b"ransom",
    b"encrypt", b"decrypt",
    b"password", b"credential",
    b"keylog", b"screenshot",
    b"backdoor", b"rootkit",
    b"YOUR FILES HAVE BEEN",
    b"pay the ransom",
    b"send bitcoin",
]

SUSPICIOUS_PATHS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
    r"C:\Windows\Temp",
    r"C:\ProgramData",
]

# ── Default Configuration ─────────────────────────────────────────
DEFAULT_CONFIG = {
    "scan_extensions": list(ALL_SCANNABLE),
    "skip_dirs": [
        r"C:\Windows\WinSxS",
        r"C:\Windows\Installer",
        r"C:\Windows\servicing",
        r"C:\$Recycle.Bin",
    ],
    "max_file_size_mb": 500,
    "realtime_protection": False,
    "realtime_paths": [os.path.expanduser("~")],
    "virustotal_api_key": "",
    "scan_archives": True,
    "heuristic_sensitivity": "medium",  # low, medium, high
    "auto_quarantine": False,
    "scheduled_scan_enabled": False,
    "scheduled_scan_time": "02:00",
    "scheduled_scan_type": "quick",
    "theme": "dark",
    "notifications_enabled": True,
    "excluded_paths": [],
    "excluded_hashes": [],
    "deep_scan_enabled": True,
    "scan_memory": True,
    "update_definitions_auto": True,
    "performance_mode": False,
}


class Config:
    """Application configuration manager with persistent storage."""

    def __init__(self):
        self.settings = DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        """Load configuration from disk."""
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r") as f:
                    saved = json.load(f)
                self.settings.update(saved)
                logger.info("Configuration loaded from %s", CONFIG_PATH)
            except Exception as e:
                logger.warning("Failed to load config: %s", e)

    def save(self):
        """Save configuration to disk."""
        try:
            with open(CONFIG_PATH, "w") as f:
                json.dump(self.settings, f, indent=2)
            logger.info("Configuration saved to %s", CONFIG_PATH)
        except Exception as e:
            logger.error("Failed to save config: %s", e)

    def get(self, key, default=None):
        """Get a configuration value."""
        return self.settings.get(key, default)

    def set(self, key, value):
        """Set a configuration value and persist."""
        self.settings[key] = value
        self.save()

    def reset(self):
        """Reset to default configuration."""
        self.settings = DEFAULT_CONFIG.copy()
        self.save()
        logger.info("Configuration reset to defaults")
