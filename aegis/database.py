"""
Aegis AV - Database Management
SQLite database for scan history, threats, quarantine records, and known malware hashes.
"""

import sqlite3
import os
import json
import threading
from datetime import datetime
from aegis.config import DB_PATH, logger


class ThreatDatabase:
    """Thread-safe SQLite database for all Aegis AV data."""

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._init_db()

    def _get_conn(self):
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA cache_size = -100000")  # Allocate 100MB RAM Cache
        return self._local.conn

    def _init_db(self):
        """Initialize database schema."""
        with self._init_lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target_path TEXT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    files_scanned INTEGER DEFAULT 0,
                    threats_found INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running',
                    details TEXT
                );

                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    file_path TEXT NOT NULL,
                    threat_name TEXT NOT NULL,
                    threat_type TEXT,
                    severity TEXT DEFAULT 'medium',
                    detection_engine TEXT,
                    action_taken TEXT DEFAULT 'detected',
                    detected_at TEXT NOT NULL,
                    file_hash TEXT,
                    file_size INTEGER,
                    details TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(id)
                );

                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    threat_name TEXT,
                    quarantined_at TEXT NOT NULL,
                    file_hash TEXT,
                    file_size INTEGER,
                    restored INTEGER DEFAULT 0,
                    deleted INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS malware_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_sha256 TEXT UNIQUE NOT NULL,
                    hash_md5 TEXT,
                    threat_name TEXT NOT NULL,
                    severity TEXT DEFAULT 'high',
                    source TEXT DEFAULT 'local',
                    added_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT,
                    file_hash TEXT,
                    added_at TEXT NOT NULL,
                    reason TEXT
                );

                CREATE TABLE IF NOT EXISTS realtime_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    file_path TEXT,
                    process_name TEXT,
                    details TEXT,
                    timestamp TEXT NOT NULL,
                    action_taken TEXT
                );

                CREATE TABLE IF NOT EXISTS scanned_files_cache (
                    file_path TEXT PRIMARY KEY,
                    mtime REAL NOT NULL,
                    file_size INTEGER NOT NULL,
                    was_threat INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_threats_scan_id ON threats(scan_id);
                CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
                CREATE INDEX IF NOT EXISTS idx_malware_sha256 ON malware_hashes(hash_sha256);
                CREATE INDEX IF NOT EXISTS idx_whitelist_hash ON whitelist(file_hash);
                CREATE INDEX IF NOT EXISTS idx_quarantine_original ON quarantine(original_path);
            """)
            conn.commit()
            
            # Reset any orphaned 'running' scans from previous sessions to 'cancelled'
            cursor.execute("UPDATE scan_history SET status = 'cancelled' WHERE status = 'running'")
            
            # Clean up any pre-existing duplicate whitelist rules that got inserted from duplicate clicks
            cursor.execute("""
                DELETE FROM whitelist 
                WHERE id NOT IN (
                    SELECT MIN(id) 
                    FROM whitelist 
                    GROUP BY COALESCE(file_path, ''), COALESCE(file_hash, '')
                )
            """)
            conn.commit()
            
            logger.info("Database initialized at %s", self.db_path)

    # ── Scan History ───────────────────────────────────────────────

    def start_scan(self, scan_type, target_path=""):
        """Record start of a new scan. Returns scan ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            "INSERT INTO scan_history (scan_type, target_path, start_time, status) VALUES (?, ?, ?, ?)",
            (scan_type, target_path, datetime.now().isoformat(), "running")
        )
        conn.commit()
        return cursor.lastrowid

    def update_scan(self, scan_id, files_scanned=None, threats_found=None, status=None):
        """Update scan progress."""
        conn = self._get_conn()
        updates = []
        params = []
        if files_scanned is not None:
            updates.append("files_scanned = ?")
            params.append(files_scanned)
        if threats_found is not None:
            updates.append("threats_found = ?")
            params.append(threats_found)
        if status is not None:
            updates.append("status = ?")
            params.append(status)
            if status in ("completed", "cancelled", "error"):
                updates.append("end_time = ?")
                params.append(datetime.now().isoformat())
        if updates:
            params.append(scan_id)
            conn.execute(
                f"UPDATE scan_history SET {', '.join(updates)} WHERE id = ?",
                params
            )
            conn.commit()

    def get_scan_history(self, limit=50):
        """Get recent scan history."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY start_time DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id):
        """Get a specific scan record."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None

    # ── Threats ────────────────────────────────────────────────────

    def add_threat(self, scan_id, file_path, threat_name, threat_type="malware",
                   severity="medium", detection_engine="", action_taken="detected",
                   file_hash="", file_size=0, details=""):
        """Record a detected threat."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO threats
               (scan_id, file_path, threat_name, threat_type, severity,
                detection_engine, action_taken, detected_at, file_hash, file_size, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, file_path, threat_name, threat_type, severity,
             detection_engine, action_taken, datetime.now().isoformat(),
             file_hash, file_size, details)
        )
        conn.commit()
        return cursor.lastrowid

    def get_threats(self, scan_id=None, limit=100):
        """Get threats, optionally filtered by scan ID."""
        conn = self._get_conn()
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM threats WHERE scan_id = ? ORDER BY detected_at DESC LIMIT ?",
                (scan_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_threat_stats(self):
        """Get threat statistics."""
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        by_severity = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as count FROM threats GROUP BY severity"
        ).fetchall():
            by_severity[row["severity"]] = row["count"]
        by_engine = {}
        for row in conn.execute(
            "SELECT detection_engine, COUNT(*) as count FROM threats GROUP BY detection_engine"
        ).fetchall():
            by_engine[row["detection_engine"]] = row["count"]
        return {
            "total": total,
            "by_severity": by_severity,
            "by_engine": by_engine,
        }

    # ── Quarantine ─────────────────────────────────────────────────

    def add_quarantine(self, original_path, quarantine_path, threat_name="",
                       file_hash="", file_size=0):
        """Record a quarantined file."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO quarantine
               (original_path, quarantine_path, threat_name, quarantined_at,
                file_hash, file_size)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (original_path, quarantine_path, threat_name,
             datetime.now().isoformat(), file_hash, file_size)
        )
        conn.commit()
        return cursor.lastrowid

    def get_quarantined(self):
        """Get all quarantined files (not restored or deleted)."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM quarantine WHERE restored = 0 AND deleted = 0 ORDER BY quarantined_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_restored(self, quarantine_id):
        """Mark a quarantined file as restored."""
        conn = self._get_conn()
        conn.execute("UPDATE quarantine SET restored = 1 WHERE id = ?", (quarantine_id,))
        conn.commit()

    def mark_deleted(self, quarantine_id):
        """Mark a quarantined file as permanently deleted."""
        conn = self._get_conn()
        conn.execute("UPDATE quarantine SET deleted = 1 WHERE id = ?", (quarantine_id,))
        conn.commit()

    # ── Malware Hashes ─────────────────────────────────────────────

    def add_malware_hash(self, sha256, threat_name, md5="", severity="high", source="local"):
        """Add a known malware hash."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO malware_hashes
                   (hash_sha256, hash_md5, threat_name, severity, source, added_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (sha256, md5, threat_name, severity, source, datetime.now().isoformat())
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass

    def check_hash(self, sha256):
        """Check if a hash is in the malware database. Returns threat info or None."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM malware_hashes WHERE hash_sha256 = ?", (sha256,)
        ).fetchone()
        return dict(row) if row else None

    def get_hash_count(self):
        """Get total number of known malware hashes."""
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM malware_hashes").fetchone()[0]

    # ── Whitelist ──────────────────────────────────────────────────

    def add_whitelist(self, file_path="", file_hash="", reason=""):
        """Add a file to the whitelist, avoiding duplicates."""
        conn = self._get_conn()
        
        if file_path:
            # Check if this exact path is already whitelisted
            row = conn.execute(
                "SELECT id FROM whitelist WHERE file_path = ?", (file_path,)
            ).fetchone()
            if row:
                # Update existing rule reason and timestamp
                conn.execute(
                    "UPDATE whitelist SET added_at = ?, reason = ? WHERE id = ?",
                    (datetime.now().isoformat(), reason, row["id"])
                )
                conn.commit()
                return
                
        if file_hash:
            # Check if this exact hash is already whitelisted
            row = conn.execute(
                "SELECT id FROM whitelist WHERE file_hash = ?", (file_hash,)
            ).fetchone()
            if row:
                # Update existing rule reason and timestamp
                conn.execute(
                    "UPDATE whitelist SET added_at = ?, reason = ? WHERE id = ?",
                    (datetime.now().isoformat(), reason, row["id"])
                )
                conn.commit()
                return

        # Insert new rule if no duplicate exists
        conn.execute(
            "INSERT INTO whitelist (file_path, file_hash, added_at, reason) VALUES (?, ?, ?, ?)",
            (file_path, file_hash, datetime.now().isoformat(), reason)
        )
        conn.commit()

    def is_whitelisted(self, file_path="", file_hash=""):
        """Check if a file is whitelisted (or resides in a whitelisted directory)."""
        conn = self._get_conn()
        if file_hash:
            row = conn.execute(
                "SELECT * FROM whitelist WHERE file_hash = ?", (file_hash,)
            ).fetchone()
            if row:
                return True
        if file_path:
            # Exact match check
            row = conn.execute(
                "SELECT * FROM whitelist WHERE file_path = ?", (file_path,)
            ).fetchone()
            if row:
                return True
                
            # Folder boundary prefix check
            normalized_file_path = os.path.normpath(file_path).lower()
            all_whitelisted = conn.execute(
                "SELECT file_path FROM whitelist WHERE file_path IS NOT NULL AND file_path != ''"
            ).fetchall()
            for r in all_whitelisted:
                w_path = os.path.normpath(r["file_path"]).lower()
                if w_path == normalized_file_path:
                    return True
                if normalized_file_path.startswith(w_path + os.sep):
                    return True
        return False

    def get_whitelist(self):
        """Get all whitelisted items."""
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM whitelist ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]

    def remove_whitelist(self, whitelist_id):
        """Remove an item from the whitelist."""
        conn = self._get_conn()
        conn.execute("DELETE FROM whitelist WHERE id = ?", (whitelist_id,))
        conn.commit()

    # ── Real-time Events ──────────────────────────────────────────

    def add_realtime_event(self, event_type, file_path="", process_name="",
                           details="", action_taken=""):
        """Record a real-time monitoring event."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO realtime_events
               (event_type, file_path, process_name, details, timestamp, action_taken)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (event_type, file_path, process_name, details,
             datetime.now().isoformat(), action_taken)
        )
        conn.commit()

    def get_recent_events(self, limit=100):
        """Get recent real-time events."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM realtime_events ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Statistics ─────────────────────────────────────────────────

    def get_dashboard_stats(self):
        """Get statistics for the dashboard."""
        conn = self._get_conn()
        total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        total_threats = conn.execute("SELECT COUNT(*) FROM threats WHERE action_taken = 'detected'").fetchone()[0]
        quarantined = conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE restored = 0 AND deleted = 0"
        ).fetchone()[0]
        total_files_scanned = conn.execute(
            "SELECT COALESCE(SUM(files_scanned), 0) FROM scan_history"
        ).fetchone()[0]
        last_scan = conn.execute(
            "SELECT * FROM scan_history ORDER BY start_time DESC LIMIT 1"
        ).fetchone()
        recent_threats = conn.execute(
            "SELECT * FROM threats WHERE action_taken = 'detected' ORDER BY detected_at DESC LIMIT 5"
        ).fetchall()

        return {
            "total_scans": total_scans,
            "total_threats": total_threats,
            "quarantined": quarantined,
            "total_files_scanned": total_files_scanned,
            "last_scan": dict(last_scan) if last_scan else None,
            "recent_threats": [dict(r) for r in recent_threats],
            "hash_db_size": self.get_hash_count(),
        }

    def check_scan_cache(self, file_path, current_mtime, current_size):
        """Check if file matches cached entry. Returns was_threat (1 or 0) if hit, else None."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT mtime, file_size, was_threat FROM scanned_files_cache WHERE file_path = ?",
                (file_path,)
            )
            row = cursor.fetchone()
            if row:
                cached_mtime, cached_size, was_threat = row[0], row[1], row[2]
                if abs(cached_mtime - current_mtime) < 0.001 and cached_size == current_size:
                    return was_threat
        except Exception:
            pass
        return None

    def update_scan_cache(self, file_path, mtime, file_size, was_threat):
        """Insert or replace cache entry for a scanned file."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO scanned_files_cache (file_path, mtime, file_size, was_threat) VALUES (?, ?, ?, ?)",
                (file_path, mtime, file_size, 1 if was_threat else 0)
            )
            conn.commit()
        except Exception:
            pass

    def close(self):
        """Close the database connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
