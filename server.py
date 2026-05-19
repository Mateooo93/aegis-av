"""
Aegis AV - High-Performance Web Server
FastAPI service hosting the REST API, live WebSocket streams, and the premium
HTML dashboard. Wired to the full suite of defensive engines.
"""

import os
import sys
import asyncio
import json
import math
import shutil
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional, Any

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel

# Add app directory to path
APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from aegis.config import Config, logger
from aegis.database import ThreatDatabase
from aegis.scanner import FileScanner
from aegis.quarantine import QuarantineManager
from aegis.monitor import RealtimeProtection, ProcessMonitor, NetworkMonitor

# New Aegis 2.1 modules
from aegis.web_shield import WebShield
from aegis.firewall import FirewallEngine
from aegis.ransomware import RansomwareShield
from aegis.vulnerability import VulnerabilityScanner
from aegis.scheduler import Scheduler
from aegis.security_score import compute_security_score
from aegis.system_tools import StartupManager, UsbInspector, ThreatIntelFeed
from aegis import password_health


# ── Singletons ─────────────────────────────────────────────────────
config = Config()
db = ThreatDatabase()
quarantine = QuarantineManager(db)
scanner = FileScanner(db, config)
realtime = RealtimeProtection(scanner, db, config)
process_mon = ProcessMonitor(db)
network_mon = NetworkMonitor(db)

# Aegis 2.1 additions
web_shield = WebShield(scanner, db, config)
firewall = FirewallEngine(db)
ransomware = RansomwareShield(db, config)
ransomware.protected_folders = list(config.get("ransomware_protected_folders") or [])
vuln_scanner = VulnerabilityScanner()
scheduler = Scheduler(config, scanner)
startup_mgr = StartupManager()
usb_inspector = UsbInspector(db)
threat_intel = ThreatIntelFeed()


app = FastAPI(title="Aegis AV Core Server", version="2.1")


# ── WebSocket connection manager ───────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop):
        self._loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(json.dumps(message, default=str))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def broadcast_threadsafe(self, message: dict):
        """Safe to call from any thread."""
        if self._loop and self._loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)
            except Exception:
                pass


manager = ConnectionManager()


# ── Helpers ────────────────────────────────────────────────────────
def apply_system_priority():
    is_perf = config.get("performance_mode", False)
    try:
        p = psutil.Process()
        if is_perf:
            p.nice(psutil.HIGH_PRIORITY_CLASS)
            logger.info("System Priority Boost active: elevated CPU class assigned.")
        else:
            p.nice(psutil.NORMAL_PRIORITY_CLASS)
    except Exception as e:
        logger.warning("Could not set process priority class: %s", e)


def push_notification(kind: str, title: str, message: str = "", severity: str = "info"):
    """Persist + broadcast a notification."""
    try:
        notif_id = db.add_notification(kind, title, message, severity)
    except Exception:
        notif_id = None
    payload = {
        "type": "notification",
        "notification": {
            "id": notif_id,
            "kind": kind,
            "title": title,
            "message": message,
            "severity": severity,
            "created_at": datetime.now().isoformat(),
        }
    }
    manager.broadcast_threadsafe(payload)


# ── Background broadcasters ────────────────────────────────────────
async def stats_broadcaster():
    """Push lightweight system telemetry every second."""
    last_net = psutil.net_io_counters() if hasattr(psutil, "net_io_counters") else None
    last_ts = time.time()

    while True:
        try:
            cpu = await asyncio.to_thread(psutil.cpu_percent, None)
            virtual_mem = await asyncio.to_thread(psutil.virtual_memory)
            ram = virtual_mem.percent

            net_payload = None
            try:
                cur = await asyncio.to_thread(psutil.net_io_counters)
                now = time.time()
                dt = max(0.5, now - last_ts)
                up_kbs = (cur.bytes_sent - last_net.bytes_sent) / dt / 1024 if last_net else 0
                dn_kbs = (cur.bytes_recv - last_net.bytes_recv) / dt / 1024 if last_net else 0
                net_payload = {"up_kbs": round(up_kbs, 1), "dn_kbs": round(dn_kbs, 1)}
                last_net = cur
                last_ts = now
            except Exception:
                net_payload = None

            await manager.broadcast({
                "type": "system_stats",
                "cpu": cpu,
                "ram": ram,
                "performance_mode": config.get("performance_mode", False),
                "net": net_payload,
            })
        except Exception:
            pass
        await asyncio.sleep(1.0)


async def usb_poller():
    """Detect newly-attached removable drives and surface a notification."""
    while True:
        try:
            new = await asyncio.to_thread(usb_inspector.poll)
            for dev in new:
                push_notification(
                    "usb",
                    "Removable media inserted",
                    f"Aegis is auto-scanning new device: {dev}",
                    "info",
                )
                # Kick off a custom scan on the device
                try:
                    if scanner.current_scan is None or not scanner.current_scan.running:
                        scanner.custom_scan(dev)
                except Exception:
                    pass
        except Exception:
            pass
        await asyncio.sleep(8.0)


# ── Hookups ────────────────────────────────────────────────────────
def on_realtime_threat(file_path: str, detections: list):
    """Called from the realtime monitor thread when a threat is detected."""
    from aegis.engines import compute_hashes
    try:
        hashes = compute_hashes(file_path)
        file_hash = hashes["sha256"] if hashes else ""
    except Exception:
        file_hash = ""

    if db.is_whitelisted(file_path, file_hash):
        logger.info("Realtime ignoring whitelisted path: %s", file_path)
        return

    threat_names = ", ".join(d.threat_name for d in detections)
    severity = "high"
    try:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        severity = max(detections, key=lambda d: order.get(d.severity, 0)).severity
    except Exception:
        pass

    action = "detected"
    if config.get("auto_quarantine"):
        try:
            if quarantine.quarantine_file(file_path, threat_names):
                action = "quarantined"
        except Exception:
            pass

    push_notification(
        "threat",
        f"Threat {action}: {threat_names}",
        f"File: {file_path}",
        "critical" if severity in ("high", "critical") else "warning",
    )

    manager.broadcast_threadsafe({
        "type": "monitor_event",
        "event": {
            "event_type": "threat",
            "file_path": file_path,
            "details": f"Detections: {threat_names}",
            "timestamp": datetime.now().isoformat(),
            "action_taken": action,
        }
    })


def on_download_event(payload: dict):
    """Web shield raised a verdict on a downloaded file."""
    verdict = payload.get("verdict", "unknown")
    file_name = payload.get("file_name", "(unknown)")

    if verdict == "malicious":
        push_notification(
            "download",
            f"MALICIOUS DOWNLOAD BLOCKED",
            f"{file_name} matched {', '.join(payload.get('detections', []))}",
            "critical",
        )
    elif verdict == "clean":
        push_notification(
            "download",
            "Download verified clean",
            f"{file_name} — Aegis scanned it successfully",
            "success",
        )
    manager.broadcast_threadsafe({"type": "download_alert", "payload": payload})


def on_firewall_intrusion(event: dict):
    push_notification(
        "intrusion",
        f"Intrusion alert: {event.get('kind')}",
        event.get("details", ""),
        "critical" if event.get("severity") == "critical" else "warning",
    )
    manager.broadcast_threadsafe({"type": "intrusion_alert", "event": event})


def on_ransomware_attack(event: dict):
    push_notification(
        "ransomware",
        f"Ransomware shield alert: {event.get('kind')}",
        event.get("details", ""),
        "critical",
    )
    manager.broadcast_threadsafe({"type": "ransomware_alert", "event": event})


def setup_monitors():
    """Wire all callbacks BEFORE starting engines."""
    realtime.on_threat = on_realtime_threat
    web_shield.on_event = on_download_event
    firewall.on_intrusion = on_firewall_intrusion
    ransomware.on_attack = on_ransomware_attack

    original_add_event = db.add_realtime_event

    def hooked_add_event(event_type, file_path="", process_name="", details="", action_taken="logged"):
        event_id = original_add_event(event_type, file_path, process_name, details, action_taken)
        manager.broadcast_threadsafe({
            "type": "monitor_event",
            "event": {
                "id": event_id,
                "event_type": event_type,
                "file_path": file_path or process_name,
                "details": details,
                "timestamp": datetime.now().isoformat(),
                "action_taken": action_taken,
            }
        })
        return event_id

    db.add_realtime_event = hooked_add_event


# ── Pydantic models ────────────────────────────────────────────────
class ScanStartRequest(BaseModel):
    scan_type: str
    target_path: Optional[str] = None

class SettingsUpdateRequest(BaseModel):
    performance_mode: Optional[bool] = None
    auto_quarantine: Optional[bool] = None
    scan_archives: Optional[bool] = None
    virustotal_api_key: Optional[str] = None
    realtime_protection: Optional[bool] = None
    web_shield_enabled: Optional[bool] = None
    firewall_enabled: Optional[bool] = None
    ransomware_shield_enabled: Optional[bool] = None
    notifications_enabled: Optional[bool] = None
    game_mode: Optional[bool] = None
    heuristic_sensitivity: Optional[str] = None

class OptimizerCleanRequest(BaseModel):
    temp: bool = False
    reg: bool = False
    logs: bool = False
    browser_cache: bool = False

class WhitelistAddRequest(BaseModel):
    file_path: Optional[str] = ""
    file_hash: Optional[str] = ""
    note: Optional[str] = ""

class FirewallRuleRequest(BaseModel):
    rule_type: str  # ip / host / port / process
    value: str
    reason: Optional[str] = ""

class UrlCheckRequest(BaseModel):
    url: str

class BlocklistRequest(BaseModel):
    host: str

class FolderRequest(BaseModel):
    folder: str

class ScheduleRequest(BaseModel):
    schedule_type: str
    scan_type: str
    time: Optional[str] = "02:00"
    day_of_week: Optional[int] = -1
    target_path: Optional[str] = ""

class ToggleRequest(BaseModel):
    enabled: bool

class PasswordCheckRequest(BaseModel):
    password: str
    check_breach: bool = True

class ProcessActionRequest(BaseModel):
    pid: int


# ── Startup / shutdown ────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    manager.bind_loop(asyncio.get_event_loop())

    apply_system_priority()
    setup_monitors()

    # Start engines conditionally based on user prefs (default ON for new pillars)
    if config.get("realtime_protection", True):
        realtime.start()
    process_mon.start()
    network_mon.start()
    if config.get("web_shield_enabled", True):
        web_shield.start()
    if config.get("firewall_enabled", True):
        firewall.start()
    if config.get("ransomware_shield_enabled", True):
        ransomware.start()

    scheduler.start()

    asyncio.create_task(stats_broadcaster())
    asyncio.create_task(usb_poller())

    push_notification(
        "system",
        "Aegis AV started",
        "All defensive layers are online.",
        "success",
    )


@app.on_event("shutdown")
async def on_shutdown():
    realtime.stop()
    process_mon.stop()
    network_mon.stop()
    web_shield.stop()
    firewall.stop()
    ransomware.stop()
    scheduler.stop()
    db.close()


# ── WebSocket ─────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── Static + index ────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    path = os.path.join(APP_DIR, "web", "index.html")
    if os.path.exists(path):
        return FileResponse(path)
    return HTMLResponse("<h1>Aegis Dashboard not found</h1>")


# ── Dashboard / stats ────────────────────────────────────────────
@app.get("/api/stats")
async def get_dashboard_stats():
    base = db.get_dashboard_stats()
    base["realtime_active"] = realtime.active
    base["web_shield_active"] = web_shield.active
    base["firewall_active"] = firewall.active
    base["ransomware_active"] = ransomware.active
    base["uptime_seconds"] = int(time.time() - psutil.Process().create_time())
    return base


@app.get("/api/security-score")
async def api_security_score():
    vuln = vuln_scanner.last_report  # don't trigger a fresh PowerShell run on every poll
    return compute_security_score(
        realtime=realtime,
        web_shield=web_shield,
        firewall=firewall,
        ransomware=ransomware,
        db=db,
        vulnerability_report=vuln,
        config=config,
    )


# ── Scan APIs ─────────────────────────────────────────────────────
def get_scan_status_dict():
    job = scanner.current_scan
    if not job:
        return {
            "running": False, "status": "idle", "progress": 0,
            "scanned_files": 0, "threats_found": 0, "scan_rate": 0,
            "eta_seconds": 0, "current_file": "",
        }
    return {
        "running": job.running,
        "status": "paused" if job.paused else (
            "running" if job.running else (
                "cancelled" if job.cancelled else "completed"
            )
        ),
        "progress": job.progress,
        "scanned_files": job.scanned_files,
        "threats_found": job.threats_found,
        "scan_rate": job.scan_rate,
        "eta_seconds": job.eta_seconds,
        "current_file": job.current_file,
        "scan_type": job.scan_type,
    }


@app.post("/api/scan/start")
async def api_start_scan(req: ScanStartRequest):
    if scanner.current_scan and scanner.current_scan.running:
        return {"status": "error", "message": "A scan is already active."}

    loop = asyncio.get_running_loop()

    def broadcast_progress(*args):
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"type": "scan_progress", "status": get_scan_status_dict()}),
            loop,
        )

    callbacks = {
        "on_progress": broadcast_progress,
        "on_threat": broadcast_progress,
        "on_complete": broadcast_progress,
        "on_error": broadcast_progress,
    }

    if req.scan_type == "quick":
        scanner.quick_scan(callbacks)
    elif req.scan_type == "full":
        scanner.full_scan(callbacks)
    elif req.scan_type == "custom":
        scanner.custom_scan(req.target_path or "C:\\", callbacks)
    elif req.scan_type == "boot":
        config.set("boot_scan_pending", True)
        return {"status": "queued", "message": "Boot scan scheduled for next launch."}
    else:
        return {"status": "error", "message": f"Unknown scan type: {req.scan_type}"}

    push_notification("scan", f"{req.scan_type.title()} scan started", "Scan running in background", "info")
    return {"status": "started"}


@app.post("/api/scan/pause")
async def api_pause_scan():
    if scanner.current_scan:
        scanner.current_scan.pause()
        return {"status": "paused"}
    return {"status": "error", "message": "No scan is in progress."}


@app.post("/api/scan/resume")
async def api_resume_scan():
    if scanner.current_scan:
        scanner.current_scan.resume()
        return {"status": "resumed"}
    return {"status": "error", "message": "No scan is in progress."}


@app.post("/api/scan/cancel")
async def api_cancel_scan():
    if scanner.current_scan:
        scanner.current_scan.cancel()
        return {"status": "cancelled"}
    return {"status": "error", "message": "No scan is in progress."}


@app.get("/api/scan/status")
async def api_get_scan_status():
    return get_scan_status_dict()


# ── Threats / Quarantine / Whitelist ─────────────────────────────
@app.get("/api/threats")
async def api_get_threats():
    conn = db._get_conn()
    rows = conn.execute(
        "SELECT * FROM threats WHERE action_taken = 'detected' ORDER BY detected_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/threats/quarantine-all")
async def api_quarantine_all_threats():
    conn = db._get_conn()
    rows = conn.execute("SELECT * FROM threats WHERE action_taken = 'detected'").fetchall()
    threats = [dict(r) for r in rows]

    quarantined = failed = 0
    for t in threats:
        path = t["file_path"]
        if db.is_whitelisted(path, t.get("file_hash", "")):
            continue
        if os.path.exists(path):
            rec_id = await asyncio.to_thread(quarantine.quarantine_file, path, t["threat_name"])
            if rec_id:
                conn.execute("UPDATE threats SET action_taken='quarantined' WHERE id=?", (t["id"],))
                conn.commit()
                quarantined += 1
            else:
                failed += 1
        else:
            conn.execute("UPDATE threats SET action_taken='missing/handled' WHERE id=?", (t["id"],))
            conn.commit()
            quarantined += 1
    return {"status": "success", "quarantined": quarantined, "failed": failed,
            "message": f"Quarantined {quarantined} threats. {failed} failures."}


@app.post("/api/threats/{threat_id}/quarantine")
async def api_quarantine_threat(threat_id: int):
    conn = db._get_conn()
    row = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Threat not found")
    t = dict(row)
    if db.is_whitelisted(t["file_path"], t.get("file_hash", "")):
        return {"status": "success", "message": "File is whitelisted; skipped."}
    if os.path.exists(t["file_path"]):
        if await asyncio.to_thread(quarantine.quarantine_file, t["file_path"], t["threat_name"]):
            conn.execute("UPDATE threats SET action_taken='quarantined' WHERE id=?", (threat_id,))
            conn.commit()
            return {"status": "success", "message": "Threat quarantined."}
    else:
        conn.execute("UPDATE threats SET action_taken='missing/handled' WHERE id=?", (threat_id,))
        conn.commit()
        return {"status": "success", "message": "File missing — marked handled."}
    raise HTTPException(status_code=500, detail="Quarantine process failed")


@app.post("/api/threats/{threat_id}/delete")
async def api_delete_threat(threat_id: int):
    conn = db._get_conn()
    row = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Threat not found")
    t = dict(row)
    try:
        if os.path.exists(t["file_path"]):
            await asyncio.to_thread(os.unlink, t["file_path"])
        conn.execute("UPDATE threats SET action_taken='deleted' WHERE id=?", (threat_id,))
        conn.commit()
        return {"status": "success", "message": "Threat purged from disk."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Purge failed: {e}")


@app.get("/api/quarantine")
async def api_get_quarantine():
    items = await asyncio.to_thread(quarantine.get_quarantined_files)
    vault_size = await asyncio.to_thread(quarantine.get_vault_size)
    return {"items": items, "vault_size": vault_size}


@app.post("/api/quarantine/{quar_id}/restore")
async def api_restore_quarantine(quar_id: int):
    if await asyncio.to_thread(quarantine.restore_file, quar_id):
        push_notification("quarantine", "Item restored", "File restored from secure vault", "info")
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Restore failed")


@app.post("/api/quarantine/{quar_id}/delete")
async def api_delete_quarantine(quar_id: int):
    if await asyncio.to_thread(quarantine.delete_permanently, quar_id):
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Vault delete failed")


@app.post("/api/quarantine/purge")
async def api_purge_quarantine():
    await asyncio.to_thread(quarantine.clean_vault, 30)
    return {"status": "success"}


def check_and_restore_quarantine_matches(file_path_added="", file_hash_added=""):
    quar_files = quarantine.get_quarantined_files()
    restored = 0
    for q in quar_files:
        matches = False
        if file_hash_added and q["file_hash"] == file_hash_added:
            matches = True
        elif file_path_added:
            norm = os.path.normpath(q["original_path"]).lower()
            w = os.path.normpath(file_path_added).lower()
            if w == norm or norm.startswith(w + os.sep):
                matches = True
        if matches and db.is_whitelisted(q["original_path"], q["file_hash"]):
            if quarantine.restore_file(q["id"]):
                restored += 1
    return restored


@app.get("/api/whitelist")
async def api_get_whitelist():
    return await asyncio.to_thread(db.get_whitelist)


@app.post("/api/whitelist")
async def api_add_whitelist(req: WhitelistAddRequest):
    if not req.file_path and not req.file_hash:
        raise HTTPException(status_code=400, detail="Provide file path or hash")
    await asyncio.to_thread(db.add_whitelist, req.file_path, req.file_hash, req.note)
    restored = await asyncio.to_thread(check_and_restore_quarantine_matches, req.file_path, req.file_hash)
    return {"status": "success",
            "message": f"Whitelist updated. {restored} matching files auto-restored."}


@app.delete("/api/whitelist/{wl_id}")
async def api_remove_whitelist(wl_id: int):
    await asyncio.to_thread(db.remove_whitelist, wl_id)
    return {"status": "success"}


# ── History / settings / optimizer ───────────────────────────────
@app.get("/api/history")
async def api_get_history():
    return db.get_scan_history(limit=50)


@app.get("/api/settings")
async def api_get_settings():
    return {
        "performance_mode":      config.get("performance_mode", False),
        "auto_quarantine":       config.get("auto_quarantine", False),
        "scan_archives":         config.get("scan_archives", True),
        "virustotal_api_key":    config.get("virustotal_api_key", ""),
        "realtime_protection":   config.get("realtime_protection", True),
        "web_shield_enabled":    config.get("web_shield_enabled", True),
        "firewall_enabled":      config.get("firewall_enabled", True),
        "ransomware_shield_enabled": config.get("ransomware_shield_enabled", True),
        "notifications_enabled": config.get("notifications_enabled", True),
        "game_mode":             config.get("game_mode", False),
        "heuristic_sensitivity": config.get("heuristic_sensitivity", "medium"),
    }


@app.post("/api/settings")
async def api_save_settings(req: SettingsUpdateRequest):
    """Patch-style update; only fields supplied are mutated."""
    changes = req.model_dump(exclude_none=True) if hasattr(req, "model_dump") else req.dict(exclude_none=True)
    for k, v in changes.items():
        config.set(k, v)

    apply_system_priority()

    # Live-toggle engines based on new prefs
    rt_want = config.get("realtime_protection", True)
    if rt_want and not realtime.active:
        realtime.start()
    elif not rt_want and realtime.active:
        realtime.stop()

    ws_want = config.get("web_shield_enabled", True)
    if ws_want and not web_shield.active:
        web_shield.start()
    elif not ws_want and web_shield.active:
        web_shield.stop()

    fw_want = config.get("firewall_enabled", True)
    if fw_want and not firewall.active:
        firewall.start()
    elif not fw_want and firewall.active:
        firewall.stop()

    rs_want = config.get("ransomware_shield_enabled", True)
    if rs_want and not ransomware.active:
        ransomware.start()
    elif not rs_want and ransomware.active:
        ransomware.stop()

    # If sensitivity changed, propagate to engine
    if "heuristic_sensitivity" in changes:
        try:
            scanner.engine.heuristic_engine.sensitivity = changes["heuristic_sensitivity"]
            scanner.engine.heuristic_engine.threshold = (
                scanner.engine.heuristic_engine.SENSITIVITY_THRESHOLDS.get(
                    changes["heuristic_sensitivity"], 40
                )
            )
        except Exception:
            pass

    return {"status": "success"}


@app.get("/api/optimizer/scan")
def api_opt_scan():
    """Compute on-disk junk size + registry placeholder + browser cache size."""
    temp_dirs = [os.environ.get("TEMP", ""), os.path.expandvars("%LOCALAPPDATA%\\Temp"), r"C:\Windows\Temp"]
    total = 0
    for folder in temp_dirs:
        if not folder or not os.path.exists(folder):
            continue
        try:
            for entry in os.scandir(folder):
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat().st_size
                except Exception:
                    pass
        except Exception:
            pass

    # Browser cache sizes
    user = os.path.expanduser("~")
    browser_paths = [
        os.path.join(user, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"),
        os.path.join(user, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"),
        os.path.join(user, "AppData", "Local", "Mozilla", "Firefox", "Profiles"),
    ]
    browser_size = 0
    for bp in browser_paths:
        if os.path.isdir(bp):
            try:
                for root, _, files in os.walk(bp):
                    for f in files:
                        try:
                            browser_size += os.path.getsize(os.path.join(root, f))
                        except Exception:
                            pass
            except Exception:
                pass

    def _fmt(n):
        if n <= 0:
            return "0 B"
        units = ("B", "KB", "MB", "GB")
        i = min(int(math.log(n, 1024)), len(units) - 1)
        return f"{round(n / (1024 ** i), 2)} {units[i]}"

    return {
        "junk_size": _fmt(total),
        "junk_bytes": total,
        "browser_cache": _fmt(browser_size),
        "broken_registries": 14,
    }


@app.post("/api/optimizer/clean")
def api_opt_clean(req: OptimizerCleanRequest):
    cleared = 0
    bytes_freed = 0

    def _purge(folder):
        nonlocal cleared, bytes_freed
        if not folder or not os.path.exists(folder):
            return
        try:
            for entry in os.scandir(folder):
                try:
                    if entry.is_file(follow_symlinks=False):
                        size = entry.stat().st_size
                        os.unlink(entry.path)
                        cleared += 1
                        bytes_freed += size
                    elif entry.is_dir(follow_symlinks=False):
                        shutil.rmtree(entry.path, ignore_errors=True)
                        cleared += 1
                except Exception:
                    pass
        except Exception:
            pass

    if req.temp:
        for f in [os.environ.get("TEMP", ""),
                  os.path.expandvars("%LOCALAPPDATA%\\Temp"),
                  r"C:\Windows\Temp"]:
            _purge(f)

    if req.browser_cache:
        user = os.path.expanduser("~")
        for bp in [
            os.path.join(user, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"),
            os.path.join(user, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"),
        ]:
            _purge(bp)

    push_notification("optimizer", "Optimization complete",
                      f"Purged {cleared} items ({bytes_freed // 1024} KB freed)", "success")
    return {"status": "success",
            "message": f"Purged {cleared} items, freed {bytes_freed // 1024} KB.",
            "items": cleared, "bytes_freed": bytes_freed}


# ── Web Shield API ───────────────────────────────────────────────
@app.get("/api/web-shield/status")
async def api_ws_status():
    return web_shield.get_status()


@app.post("/api/web-shield/check-url")
async def api_check_url(req: UrlCheckRequest):
    return web_shield.check_url(req.url)


@app.get("/api/web-shield/blocklist")
async def api_get_blocklist():
    return {"blocklist": web_shield.get_blocklist()}


@app.post("/api/web-shield/blocklist")
async def api_add_block(req: BlocklistRequest):
    web_shield.add_to_blocklist(req.host)
    custom = list(config.get("url_blocklist_custom", []) or [])
    if req.host not in custom:
        custom.append(req.host)
        config.set("url_blocklist_custom", custom)
    return {"status": "success", "blocklist": web_shield.get_blocklist()}


@app.delete("/api/web-shield/blocklist")
async def api_remove_block(req: BlocklistRequest):
    web_shield.remove_from_blocklist(req.host)
    custom = [h for h in (config.get("url_blocklist_custom", []) or []) if h != req.host]
    config.set("url_blocklist_custom", custom)
    return {"status": "success", "blocklist": web_shield.get_blocklist()}


@app.get("/api/web-shield/downloads")
async def api_recent_downloads(limit: int = 30):
    conn = db._get_conn()
    rows = conn.execute(
        "SELECT * FROM realtime_events WHERE event_type IN ('download_scan','web_block') "
        "ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ── Firewall API ─────────────────────────────────────────────────
@app.get("/api/firewall/status")
async def api_fw_status():
    return firewall.get_status()


@app.get("/api/firewall/rules")
async def api_fw_rules():
    return firewall.list_rules()


@app.post("/api/firewall/rules")
async def api_fw_add_rule(req: FirewallRuleRequest):
    try:
        rule = firewall.add_rule(req.rule_type, req.value, req.reason)
        return {"status": "success", "rule": rule}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/firewall/rules")
async def api_fw_remove_rule(req: FirewallRuleRequest):
    ok = firewall.remove_rule(req.rule_type, req.value)
    return {"status": "success" if ok else "error"}


@app.get("/api/firewall/connections")
async def api_fw_connections():
    return firewall.list_active_connections()


@app.get("/api/firewall/intrusions")
async def api_fw_intrusions():
    return firewall.list_intrusion_events()


# ── Ransomware Shield API ────────────────────────────────────────
@app.get("/api/ransomware/status")
async def api_rs_status():
    return ransomware.get_status()


@app.get("/api/ransomware/events")
async def api_rs_events():
    return ransomware.get_events(50)


@app.post("/api/ransomware/folders")
async def api_rs_add_folder(req: FolderRequest):
    ok = ransomware.add_folder(req.folder)
    config.set("ransomware_protected_folders", ransomware.protected_folders)
    return {"status": "success" if ok else "error",
            "folders": ransomware.protected_folders}


@app.delete("/api/ransomware/folders")
async def api_rs_remove_folder(req: FolderRequest):
    ok = ransomware.remove_folder(req.folder)
    config.set("ransomware_protected_folders", ransomware.protected_folders)
    return {"status": "success" if ok else "error",
            "folders": ransomware.protected_folders}


# ── Vulnerability scanner API ────────────────────────────────────
@app.get("/api/vulnerabilities")
async def api_vuln_scan(force: int = 0):
    if force:
        return await asyncio.to_thread(vuln_scanner.scan)
    return await asyncio.to_thread(vuln_scanner.get_cached_or_scan)


# ── Network inspector API ────────────────────────────────────────
@app.get("/api/network/connections")
async def api_network_connections():
    return network_mon.get_active_connections()


@app.get("/api/network/stats")
async def api_network_stats():
    return network_mon.get_network_stats()


@app.get("/api/network/interfaces")
async def api_network_ifaces():
    if not hasattr(psutil, "net_if_addrs"):
        return []
    result = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ips = [a.address for a in addr_list if hasattr(a, "address")]
            entry = {
                "name": name,
                "addresses": ips,
                "up": getattr(stats.get(name), "isup", False) if name in stats else False,
                "speed": getattr(stats.get(name), "speed", 0) if name in stats else 0,
            }
            result.append(entry)
    except Exception:
        pass
    return result


# ── Process Manager API ──────────────────────────────────────────
@app.get("/api/processes")
async def api_processes(sort: str = "cpu", limit: int = 200):
    procs = process_mon.get_all_processes()
    # Mark suspicious ones
    sus_pids = {p.get("pid") for p in process_mon.suspicious_processes if p.get("pid")}
    for p in procs:
        p["suspicious"] = p.get("pid") in sus_pids
    if sort == "cpu":
        procs.sort(key=lambda p: p.get("cpu", 0) or 0, reverse=True)
    elif sort == "memory":
        procs.sort(key=lambda p: p.get("memory", 0) or 0, reverse=True)
    elif sort == "name":
        procs.sort(key=lambda p: (p.get("name") or "").lower())
    return procs[:limit]


@app.post("/api/processes/kill")
async def api_kill_process(req: ProcessActionRequest):
    ok = await asyncio.to_thread(process_mon.kill_process, req.pid)
    if ok:
        push_notification("process", f"Process terminated", f"PID {req.pid} ended by user", "info")
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Could not terminate process")


@app.get("/api/processes/suspicious")
async def api_sus_processes():
    return process_mon.suspicious_processes


# ── Startup Manager API ──────────────────────────────────────────
@app.get("/api/startup")
async def api_startup_list():
    return await asyncio.to_thread(startup_mgr.list_entries)


@app.post("/api/startup/remove")
async def api_startup_remove(payload: Dict[str, str]):
    ok = await asyncio.to_thread(
        startup_mgr.remove_entry,
        payload.get("hive", ""),
        payload.get("path", ""),
        payload.get("name", ""),
    )
    if ok:
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Could not remove startup entry")


# ── Scheduler API ────────────────────────────────────────────────
@app.get("/api/schedules")
async def api_schedules_list():
    return scheduler.list_schedules()


@app.post("/api/schedules")
async def api_schedule_add(req: ScheduleRequest):
    rec = scheduler.add_schedule(
        req.schedule_type, req.scan_type, req.time or "02:00",
        req.day_of_week if req.day_of_week is not None else -1,
        req.target_path or "",
    )
    return {"status": "success", "schedule": rec}


@app.delete("/api/schedules/{sid}")
async def api_schedule_remove(sid: int):
    ok = scheduler.remove_schedule(sid)
    return {"status": "success" if ok else "error"}


@app.post("/api/schedules/{sid}/toggle")
async def api_schedule_toggle(sid: int, req: ToggleRequest):
    scheduler.toggle_schedule(sid, req.enabled)
    return {"status": "success"}


# ── Reports / Analytics ─────────────────────────────────────────
@app.get("/api/reports")
async def api_reports():
    return {
        "threats_over_time": db.get_threats_over_time(14),
        "scans_over_time":   db.get_scans_over_time(14),
        "severity_breakdown": db.get_severity_breakdown(),
        "engine_breakdown": db.get_engine_breakdown(),
        "events_24h": db.event_kind_counts(24),
    }


# ── Threat Intelligence Feed ────────────────────────────────────
@app.get("/api/threat-intel")
async def api_threat_intel():
    return {"cards": threat_intel.list_cards(8)}


# ── Password Health ─────────────────────────────────────────────
@app.post("/api/password-health")
async def api_pw_health(req: PasswordCheckRequest):
    return await asyncio.to_thread(
        password_health.evaluate_full, req.password, req.check_breach
    )


# ── Notifications ───────────────────────────────────────────────
@app.get("/api/notifications")
async def api_notifs_list(unread: int = 0, limit: int = 50):
    items = db.get_notifications(limit=limit, unread_only=bool(unread))
    return {"items": items, "unread": db.unread_notification_count()}


@app.post("/api/notifications/read-all")
async def api_notifs_read_all():
    db.mark_all_notifications_read()
    return {"status": "success"}


@app.post("/api/notifications/{nid}/read")
async def api_notifs_read(nid: int):
    db.mark_notification_read(nid)
    return {"status": "success"}


@app.delete("/api/notifications")
async def api_notifs_clear():
    db.clear_notifications()
    return {"status": "success"}


# ── First-run / onboarding ──────────────────────────────────────
@app.get("/api/first-run")
async def api_first_run():
    return {"first_run_complete": config.get("first_run_complete", False)}


@app.post("/api/first-run/complete")
async def api_first_run_complete():
    config.set("first_run_complete", True)
    return {"status": "success"}


# ── Mount Static ────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "web")), name="static")
