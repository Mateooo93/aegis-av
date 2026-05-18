"""
Aegis AV - File Scanner
Orchestrates multi-engine file scanning with progress tracking,
scan types (quick, full, custom), and threat handling.
"""

import os
import time
import threading
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from aegis.config import Config, EXECUTABLE_EXTENSIONS, ALL_SCANNABLE
from aegis.engines import ScanEngine, compute_hashes, DetectionResult

logger = logging.getLogger("Aegis.Scanner")


class ScanJob:
    """Represents a scan operation with progress tracking."""

    def __init__(self, scan_type, target_path, database, config, scan_engine):
        self.scan_type = scan_type
        self.target_path = target_path
        self.db = database
        self.config = config
        self.engine = scan_engine

        # State
        self.scan_id = None
        self.running = False
        self.cancelled = False
        self.paused = False
        self.completed = False

        # Progress
        self.total_files = 0
        self.scanned_files = 0
        self.threats_found = 0
        self.current_file = ""
        self.start_time = None
        self.end_time = None
        self.detections = []
        self.errors = []
        self.skipped = 0

        # Callbacks
        self.on_progress = None  # (scan_job) -> None
        self.on_threat = None    # (scan_job, file_path, detections) -> None
        self.on_complete = None  # (scan_job) -> None
        self.on_error = None     # (scan_job, error) -> None

        # Thread
        self._thread = None
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._last_gui_update = 0

    @property
    def progress(self):
        """Progress percentage 0-100."""
        if self.total_files == 0:
            return 0
        return min(100, int((self.scanned_files / self.total_files) * 100))

    @property
    def elapsed_time(self):
        """Elapsed time in seconds."""
        if not self.start_time:
            return 0
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def scan_rate(self):
        """Files scanned per second."""
        elapsed = self.elapsed_time
        if elapsed == 0:
            return 0
        return self.scanned_files / elapsed

    @property
    def eta_seconds(self):
        """Estimated time remaining in seconds."""
        rate = self.scan_rate
        if rate == 0:
            return 0
        remaining = self.total_files - self.scanned_files
        return remaining / rate

    def start(self):
        """Start the scan in a background thread."""
        if self.running:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def cancel(self):
        """Cancel the scan."""
        self.cancelled = True
        self._pause_event.set()

    def pause(self):
        """Pause the scan."""
        self.paused = True
        self._pause_event.clear()

    def resume(self):
        """Resume the scan."""
        self.paused = False
        self._pause_event.set()

    def _run(self):
        """Main scan execution."""
        self.running = True
        self.start_time = time.time()
        self.scan_id = self.db.start_scan(self.scan_type, self.target_path)

        logger.info("Starting %s scan on: %s (ID: %d)",
                     self.scan_type, self.target_path, self.scan_id)

        try:
            # Est baseline totals to make progress bar responsive from second 1
            if self.scan_type == "quick":
                self.total_files = 1000
            elif self.scan_type == "full":
                self.total_files = 25000
            else:
                self.total_files = 500

            skip_dirs = set(d.lower() for d in self.config.get("skip_dirs", []))
            excluded = set(p.lower() for p in self.config.get("excluded_paths", []))
            max_size = self.config.get("max_file_size_mb", 500) * 1024 * 1024

            if self.scan_type == "quick":
                scan_paths = self._get_quick_scan_paths()
                extensions = EXECUTABLE_EXTENSIONS
            elif self.scan_type == "full":
                scan_paths = self._get_full_scan_paths()
                extensions = ALL_SCANNABLE if self.config.get("deep_scan_enabled") else EXECUTABLE_EXTENSIONS
            elif self.scan_type == "custom":
                scan_paths = [self.target_path]
                extensions = ALL_SCANNABLE
            else:
                scan_paths = [self.target_path]
                extensions = ALL_SCANNABLE

            # Walk and scan on the fly
            for scan_path in scan_paths:
                if self.cancelled:
                    break

                if not os.path.exists(scan_path):
                    continue

                if os.path.isfile(scan_path):
                    self._process_single_file(scan_path)
                    continue

                for root, dirs, filenames in os.walk(scan_path, topdown=True):
                    if self.cancelled:
                        break

                    # Skip excluded directories
                    root_lower = root.lower()
                    dirs[:] = [d for d in dirs
                               if os.path.join(root_lower, d.lower()) not in skip_dirs
                               and os.path.join(root_lower, d.lower()) not in excluded
                               and not d.startswith("$")]

                    for fname in filenames:
                        if self.cancelled:
                            break

                        fpath = os.path.join(root, fname)
                        ext = os.path.splitext(fname)[1].lower()

                        if ext not in extensions:
                            continue

                        if fpath.lower() in excluded:
                            continue

                        try:
                            fsize = os.path.getsize(fpath)
                            if fsize > max_size or fsize == 0:
                                continue
                        except Exception:
                            continue

                        # Process this file on-the-fly!
                        self._process_single_file(fpath)

            # Phase 3: Finalize
            if self.cancelled:
                status = "cancelled"
            else:
                status = "completed"
                self.completed = True
                # Set total_files to scanned_files so progress reaches 100% on success!
                self.total_files = self.scanned_files

            self.end_time = time.time()
            self.db.update_scan(
                self.scan_id,
                files_scanned=self.scanned_files,
                threats_found=self.threats_found,
                status=status
            )

            logger.info("Scan %s: %d files scanned, %d threats found (%.1f seconds)",
                         status, self.scanned_files, self.threats_found, self.elapsed_time)

        except Exception as e:
            logger.error("Scan error: %s", e)
            self.end_time = time.time()
            self.db.update_scan(self.scan_id, status="error")
            if self.on_error:
                self.on_error(self, str(e))

        finally:
            self.running = False
            if self.on_complete:
                self.on_complete(self)

    def _process_single_file(self, file_path):
        """Processes, scans, and updates DB/progress for a single file on-the-fly."""
        # Handle pause state
        self._pause_event.wait()

        # Check path whitelist first to bypass scannable cycle entirely
        if self.db.is_whitelisted(file_path=file_path):
            return

        self.current_file = file_path
        self.scanned_files += 1

        # Keep total_files scaling up if baseline was too small
        if self.scanned_files > self.total_files:
            self.total_files = self.scanned_files + 100

        try:
            # Fetch current metadata for cache validation
            try:
                mtime = os.path.getmtime(file_path)
                fsize = os.path.getsize(file_path)
            except Exception:
                mtime = 0
                fsize = 0

            # Query Incremental Scan Cache
            cached_was_threat = self.db.check_scan_cache(file_path, mtime, fsize)
            if cached_was_threat is not None:
                # If cached entry exists and file is unchanged, skip re-flagging or re-scanning!
                if cached_was_threat == 1:
                    logger.debug("Cache hit: skipping unchanged threat file: %s", file_path)
                return

            # Cache miss or file changed: scan file!
            detections = self.engine.scan_file(file_path)
            
            # Store outcome in cache for future scans
            was_threat = bool(detections)
            self.db.update_scan_cache(file_path, mtime, fsize, was_threat)

            if detections:
                # Record to database
                hashes = compute_hashes(file_path)
                file_hash = hashes["sha256"] if hashes else ""
                
                # Check whitelist again with hash
                if self.db.is_whitelisted(file_path=file_path, file_hash=file_hash):
                    logger.info("Skipping whitelisted threat file: %s", file_path)
                    return

                self.threats_found += 1
                self.detections.extend(
                    [(file_path, d) for d in detections]
                )
                file_size = 0
                try:
                    file_size = os.path.getsize(file_path)
                except Exception:
                    pass

                # Use the highest severity detection
                severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                best = max(detections, key=lambda d: severity_order.get(d.severity, 0))

                all_details = "; ".join(
                    f"[{d.engine}] {d.details}" for d in detections if d.details
                )

                self.db.add_threat(
                    scan_id=self.scan_id,
                    file_path=file_path,
                    threat_name=best.threat_name,
                    threat_type=best.threat_type,
                    severity=best.severity,
                    detection_engine=", ".join(d.engine for d in detections),
                    file_hash=file_hash,
                    file_size=file_size,
                    details=all_details
                )

                if self.on_threat:
                    self.on_threat(self, file_path, detections)

                logger.warning("THREAT: %s in %s (%s)",
                               best.threat_name, file_path, best.severity)

        except PermissionError:
            self.skipped += 1
        except Exception as e:
            self.errors.append((file_path, str(e)))
            logger.debug("Scan error for %s: %s", file_path, e)

        # Throttle GUI progress updates to at most once every 150ms to prevent main thread rendering lag
        now = time.time()
        if now - self._last_gui_update > 0.15 or detections:
            self._last_gui_update = now
            if self.on_progress:
                self.on_progress(self)

    def _get_quick_scan_paths(self):
        """Get paths for quick scan (commonly infected locations)."""
        user_home = os.path.expanduser("~")
        paths = [
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Documents"),
            os.path.join(user_home, "AppData", "Local", "Temp"),
            os.path.join(user_home, "AppData", "Roaming"),
            os.path.join(user_home, "AppData", "Local"),
            os.path.expandvars(r"%PROGRAMDATA%"),
            os.path.expandvars(r"%WINDIR%\Temp"),
            os.path.expandvars(
                r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
            ),
        ]
        return [p for p in paths if os.path.exists(p)]

    def _get_full_scan_paths(self):
        """Get paths for full system scan."""
        paths = []
        # Scan all fixed drives
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                paths.append(drive)
        return paths


class FileScanner:
    """High-level scanner interface for the GUI."""

    def __init__(self, database, config):
        self.db = database
        self.config = config
        self.engine = ScanEngine(
            database,
            sensitivity=config.get("heuristic_sensitivity", "medium"),
            config=config
        )
        self.current_scan = None

    def quick_scan(self, callbacks=None):
        """Start a quick scan of common locations."""
        return self._start_scan("quick", "", callbacks)

    def full_scan(self, callbacks=None):
        """Start a full system scan."""
        return self._start_scan("full", "", callbacks)

    def custom_scan(self, path, callbacks=None):
        """Start a custom scan of a specific path."""
        return self._start_scan("custom", path, callbacks)

    def _start_scan(self, scan_type, target_path, callbacks=None):
        """Create and start a scan job."""
        if self.current_scan and self.current_scan.running:
            self.current_scan.cancel()
            time.sleep(0.5)

        job = ScanJob(scan_type, target_path, self.db, self.config, self.engine)

        if callbacks:
            job.on_progress = callbacks.get("on_progress")
            job.on_threat = callbacks.get("on_threat")
            job.on_complete = callbacks.get("on_complete")
            job.on_error = callbacks.get("on_error")

        self.current_scan = job
        job.start()
        return job

    def scan_single_file(self, file_path):
        """Synchronously scan a single file. Returns list of DetectionResults."""
        return self.engine.scan_file(file_path)

    def cancel_scan(self):
        """Cancel the current scan."""
        if self.current_scan and self.current_scan.running:
            self.current_scan.cancel()

    def get_engine_status(self):
        """Get status of all detection engines."""
        return self.engine.get_engine_status()
