"""
Aegis AV - Scheduler
A tiny in-process scheduler that fires registered scans at user-defined times
(daily / weekly / on boot). No external cron dependency.
"""

import time
import logging
import threading
from datetime import datetime, timedelta

logger = logging.getLogger("Aegis.Scheduler")


class Scheduler:
    """
    In-process timer-based job runner. Persists schedules through the
    Config object so they survive restarts.
    """

    def __init__(self, config, scanner):
        self.config = config
        self.scanner = scanner
        self._thread = None
        self._stop_event = threading.Event()
        self.active = False
        self.last_runs = {}  # id -> ISO timestamp

    def start(self):
        if self.active:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.active = True
        logger.info("Scheduler started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.active = False

    # ── Schedules API ─────────────────────────────────────────────────
    def list_schedules(self):
        return list(self.config.get("scan_schedules", []) or [])

    def add_schedule(self, schedule_type: str, scan_type: str, time_str: str,
                     day_of_week: int = -1, target_path: str = ""):
        """
        schedule_type: 'daily' | 'weekly' | 'on_boot'
        scan_type: 'quick' | 'full' | 'custom'
        time_str: 'HH:MM' (ignored for on_boot)
        day_of_week: 0=Mon..6=Sun (only for weekly)
        """
        schedules = self.list_schedules()
        new_id = max([s.get("id", 0) for s in schedules], default=0) + 1
        rec = {
            "id": new_id,
            "schedule_type": schedule_type,
            "scan_type": scan_type,
            "time": time_str,
            "day_of_week": day_of_week,
            "target_path": target_path,
            "enabled": True,
            "created_at": datetime.now().isoformat(),
        }
        schedules.append(rec)
        self.config.set("scan_schedules", schedules)
        return rec

    def remove_schedule(self, schedule_id: int):
        schedules = self.list_schedules()
        new_schedules = [s for s in schedules if s.get("id") != schedule_id]
        self.config.set("scan_schedules", new_schedules)
        return len(new_schedules) != len(schedules)

    def toggle_schedule(self, schedule_id: int, enabled: bool):
        schedules = self.list_schedules()
        for s in schedules:
            if s.get("id") == schedule_id:
                s["enabled"] = bool(enabled)
        self.config.set("scan_schedules", schedules)

    # ── Internal loop ─────────────────────────────────────────────────
    def _loop(self):
        # Fire on_boot schedules once shortly after startup
        boot_fired = False
        boot_at = time.time()

        while not self._stop_event.is_set():
            try:
                now = datetime.now()
                schedules = self.list_schedules()

                for sched in schedules:
                    if not sched.get("enabled", True):
                        continue

                    sid = sched.get("id")
                    last = self.last_runs.get(sid)
                    last_dt = None
                    if last:
                        try:
                            last_dt = datetime.fromisoformat(last)
                        except Exception:
                            last_dt = None

                    if sched.get("schedule_type") == "on_boot" and not boot_fired and time.time() - boot_at > 30:
                        # Fire once on startup
                        self._fire(sched)
                        boot_fired = True
                        continue

                    if sched.get("schedule_type") in {"daily", "weekly"}:
                        target_time = sched.get("time", "02:00")
                        try:
                            target_h, target_m = [int(x) for x in target_time.split(":")]
                        except Exception:
                            continue

                        is_due = (now.hour == target_h and now.minute == target_m)
                        if sched["schedule_type"] == "weekly":
                            dow = int(sched.get("day_of_week", -1))
                            if dow < 0:
                                continue
                            if now.weekday() != dow:
                                continue

                        if is_due:
                            if not last_dt or (now - last_dt).total_seconds() > 60:
                                self._fire(sched)

            except Exception as e:
                logger.debug("Scheduler tick failed: %s", e)

            self._stop_event.wait(20)  # check every 20 s

    def _fire(self, sched: dict):
        scan_type = sched.get("scan_type", "quick")
        target = sched.get("target_path", "")
        sid = sched.get("id")

        if self.scanner.current_scan and self.scanner.current_scan.running:
            logger.info("Scheduler skipping #%s – a scan is already running", sid)
            return

        logger.info("Scheduler firing scan #%s (%s)", sid, scan_type)
        self.last_runs[sid] = datetime.now().isoformat()
        try:
            if scan_type == "full":
                self.scanner.full_scan()
            elif scan_type == "custom" and target:
                self.scanner.custom_scan(target)
            else:
                self.scanner.quick_scan()
        except Exception as e:
            logger.error("Scheduler fire failed: %s", e)
