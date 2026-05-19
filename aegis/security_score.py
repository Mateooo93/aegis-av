"""
Aegis AV - Security Score
Aggregates the state of every defensive layer into a single 0-100 metric
with a per-pillar breakdown, grade letter and ordered recommendation list.
"""

from datetime import datetime


# Weight for each pillar (sum should be 100)
WEIGHTS = {
    "realtime":    20,   # File-system real-time monitor
    "web_shield":  10,   # Download/URL protection
    "firewall":    15,   # Egress firewall + intrusion
    "ransomware":  15,   # Ransomware shield
    "scanner":     15,   # Recent full scan + no active threats
    "vuln":        15,   # System vulnerability findings
    "updates":     10,   # Up-to-date AV definitions
}


def _grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 90: return "A"
    if score >= 85: return "A-"
    if score >= 80: return "B+"
    if score >= 75: return "B"
    if score >= 70: return "B-"
    if score >= 65: return "C+"
    if score >= 60: return "C"
    if score >= 50: return "C-"
    if score >= 40: return "D"
    return "F"


def compute_security_score(*, realtime, web_shield, firewall, ransomware, db,
                            vulnerability_report=None, config=None) -> dict:
    """
    Each pillar returns a per-pillar weighted score & recommendations.
    Result schema:
        {
            score: 0-100,
            grade: 'A+'..'F',
            verdict: 'protected' | 'attention' | 'at_risk' | 'critical',
            pillars: [ {id, name, score, max, status, message} ],
            recommendations: [str],
            generated_at: iso,
        }
    """
    pillars = []
    recommendations = []

    # 1. Realtime protection pillar
    rt_active = bool(getattr(realtime, "active", False))
    rt_score = WEIGHTS["realtime"] if rt_active else 0
    pillars.append({
        "id": "realtime",
        "name": "Real-time Defense",
        "score": rt_score,
        "max": WEIGHTS["realtime"],
        "status": "good" if rt_active else "bad",
        "message": "Filesystem monitoring is active" if rt_active else "Realtime monitor is OFF",
    })
    if not rt_active:
        recommendations.append("Enable real-time protection from the Dashboard.")

    # 2. Web shield pillar
    ws_active = bool(getattr(web_shield, "active", False))
    ws_score = WEIGHTS["web_shield"] if ws_active else int(WEIGHTS["web_shield"] * 0.3)
    pillars.append({
        "id": "web_shield",
        "name": "Web & Download Shield",
        "score": ws_score,
        "max": WEIGHTS["web_shield"],
        "status": "good" if ws_active else "warn",
        "message": "Download inspection live" if ws_active else "Download inspector offline",
    })
    if not ws_active:
        recommendations.append("Enable the Web Shield to inspect new downloads automatically.")

    # 3. Firewall pillar
    fw_active = bool(getattr(firewall, "active", False))
    fw_intrusions = len(getattr(firewall, "intrusion_events", []) or [])
    fw_score = WEIGHTS["firewall"] if fw_active else 0
    if fw_active and fw_intrusions > 5:
        fw_score = max(0, fw_score - 5)
    pillars.append({
        "id": "firewall",
        "name": "Firewall & Intrusion Detection",
        "score": fw_score,
        "max": WEIGHTS["firewall"],
        "status": "good" if fw_active and fw_intrusions == 0 else ("warn" if fw_active else "bad"),
        "message": (
            f"{fw_intrusions} recent intrusion alert(s)" if fw_active and fw_intrusions
            else "Active – no intrusion alerts" if fw_active
            else "Firewall engine offline"
        ),
    })
    if not fw_active:
        recommendations.append("Activate the Aegis Firewall to monitor outbound connections.")

    # 4. Ransomware shield pillar
    rs_active = bool(getattr(ransomware, "active", False))
    rs_score = WEIGHTS["ransomware"] if rs_active else 0
    pillars.append({
        "id": "ransomware",
        "name": "Ransomware Shield",
        "score": rs_score,
        "max": WEIGHTS["ransomware"],
        "status": "good" if rs_active else "bad",
        "message": (
            f"Watching {len(getattr(ransomware, 'protected_folders', []) or [])} folder(s)"
            if rs_active else "Ransomware shield disabled"
        ),
    })
    if not rs_active:
        recommendations.append("Turn on the Ransomware Shield to protect Documents & Pictures.")

    # 5. Scanner pillar – penalize for unresolved threats / stale scans
    scanner_score = WEIGHTS["scanner"]
    threats_open = 0
    last_scan_age_days = 999
    try:
        stats = db.get_dashboard_stats()
        threats_open = int(stats.get("total_threats", 0))
        last = stats.get("last_scan")
        if last and last.get("start_time"):
            try:
                start = datetime.fromisoformat(last["start_time"])
                last_scan_age_days = max(0, (datetime.now() - start).days)
            except Exception:
                pass
    except Exception:
        pass

    if threats_open > 0:
        scanner_score = max(0, scanner_score - min(scanner_score, threats_open * 3))
        recommendations.append(
            f"Resolve {threats_open} unhandled threat(s) in the Threats tab."
        )

    if last_scan_age_days > 7:
        scanner_score = max(0, scanner_score - 5)
        recommendations.append("Run a Quick Scan – last scan was over a week ago.")

    pillars.append({
        "id": "scanner",
        "name": "Threat Posture",
        "score": scanner_score,
        "max": WEIGHTS["scanner"],
        "status": "good" if threats_open == 0 and last_scan_age_days <= 7 else "warn",
        "message": (
            "All scans current – no open threats"
            if threats_open == 0 and last_scan_age_days <= 7
            else f"{threats_open} open threat(s), last scan {last_scan_age_days} d ago"
        ),
    })

    # 6. Vulnerability pillar
    vuln_score = WEIGHTS["vuln"]
    vuln_status = "good"
    vuln_message = "No system vulnerability data yet – run scan"
    if vulnerability_report and vulnerability_report.get("counts"):
        counts = vulnerability_report["counts"]
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        med = counts.get("medium", 0)
        vuln_score = max(0, vuln_score - (crit * 5 + high * 3 + med * 1))
        if crit > 0:
            vuln_status = "bad"
            vuln_message = f"{crit} critical vulnerability finding(s)"
            recommendations.append(f"Fix the {crit} critical issue(s) in System Vulnerabilities.")
        elif high > 0:
            vuln_status = "warn"
            vuln_message = f"{high} high-severity finding(s)"
            recommendations.append(f"Resolve the {high} high-severity issue(s) in System Vulnerabilities.")
        else:
            vuln_message = "No critical vulnerability findings"
    pillars.append({
        "id": "vuln",
        "name": "System Vulnerabilities",
        "score": vuln_score,
        "max": WEIGHTS["vuln"],
        "status": vuln_status,
        "message": vuln_message,
    })

    # 7. Auto-quarantine / definitions update
    auto_q = bool(config and config.get("auto_quarantine"))
    upd_score = WEIGHTS["updates"] if auto_q else int(WEIGHTS["updates"] * 0.5)
    pillars.append({
        "id": "updates",
        "name": "Auto-Quarantine Policy",
        "score": upd_score,
        "max": WEIGHTS["updates"],
        "status": "good" if auto_q else "warn",
        "message": "Auto-quarantine active" if auto_q else "Auto-quarantine disabled",
    })
    if not auto_q:
        recommendations.append("Enable Auto-Quarantine in Settings to neutralise threats instantly.")

    # Aggregate
    total = sum(p["score"] for p in pillars)
    max_total = sum(p["max"] for p in pillars)
    score_pct = int(round(100 * total / max_total)) if max_total else 0

    if score_pct >= 85:
        verdict = "protected"
    elif score_pct >= 70:
        verdict = "attention"
    elif score_pct >= 50:
        verdict = "at_risk"
    else:
        verdict = "critical"

    return {
        "score": score_pct,
        "grade": _grade(score_pct),
        "verdict": verdict,
        "pillars": pillars,
        "recommendations": recommendations[:8],
        "generated_at": datetime.now().isoformat(),
    }
