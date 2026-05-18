"""
Aegis AV - Main Application Window
Modern dark-themed GUI with sidebar navigation.
"""

import customtkinter as ctk
import threading
import os
import sys
import time
from datetime import datetime

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis.config import Config, logger
from aegis.database import ThreatDatabase
from aegis.scanner import FileScanner
from aegis.quarantine import QuarantineManager
from aegis.monitor import RealtimeProtection, ProcessMonitor, NetworkMonitor

# ── Theme Colors ───────────────────────────────────────────────────
COLORS = {
    "bg_dark": "#0d1117",
    "bg_surface": "#161b22",
    "bg_card": "#1c2333",
    "bg_hover": "#252d3a",
    "bg_input": "#0d1117",
    "accent": "#00d4aa",
    "accent_hover": "#00e6b8",
    "accent_dim": "#004d3d",
    "danger": "#f85149",
    "danger_dim": "#5c1a1a",
    "warning": "#d29922",
    "warning_dim": "#4b3a0f",
    "info": "#58a6ff",
    "success": "#3fb950",
    "text": "#e6edf3",
    "text_secondary": "#8b949e",
    "text_dim": "#484f58",
    "border": "#30363d",
    "sidebar": "#0d1117",
    "sidebar_active": "#1c2333",
}


class AegisApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # ── Core Systems ───────────────────────────────────────────
        self.config = Config()
        self.db = ThreatDatabase()
        self.scanner = FileScanner(self.db, self.config)
        self.quarantine = QuarantineManager(self.db)
        self.realtime = RealtimeProtection(self.scanner, self.db, self.config)
        self.process_monitor = ProcessMonitor(self.db)
        self.network_monitor = NetworkMonitor(self.db)
        
        # ── Extreme Performance Mode ──────────────────────────────
        self.apply_performance_mode()

        # ── Window Setup ───────────────────────────────────────────
        self.title("Aegis AV - Security Suite")
        self.geometry("1200x750")
        self.minsize(1000, 650)
        self.configure(fg_color=COLORS["bg_dark"])

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        # Set icon if available
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            self.iconbitmap(icon_path)

        # ── Layout ─────────────────────────────────────────────────
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._create_sidebar()
        self._content_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_dark"], corner_radius=0)
        self._content_frame.grid(row=0, column=1, sticky="nsew")
        self._content_frame.grid_columnconfigure(0, weight=1)
        self._content_frame.grid_rowconfigure(0, weight=1)

        self._pages = {}
        self._current_page = None
        self._create_pages()
        self._show_page("dashboard")

        # ── Auto-start Monitors ────────────────────────────────────
        if self.config.get("realtime_protection"):
            self.after(1000, self._start_realtime)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _create_sidebar(self):
        """Create the sidebar navigation."""
        sidebar = ctk.CTkFrame(self, width=220, fg_color=COLORS["sidebar"], corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.pack_propagate(False)

        # 1. Bottom status frame (pack first with side="bottom" so it anchors at the very bottom)
        status_frame = ctk.CTkFrame(sidebar, fg_color=COLORS["bg_card"], corner_radius=10)
        status_frame.pack(side="bottom", fill="x", padx=12, pady=12)

        self._status_indicator = ctk.CTkLabel(
            status_frame, text="● Protected",
            font=("Segoe UI", 12, "bold"), text_color=COLORS["success"]
        )
        self._status_indicator.pack(padx=15, pady=(10, 2), anchor="w")

        self._status_detail = ctk.CTkLabel(
            status_frame, text="All systems active",
            font=("Segoe UI", 10), text_color=COLORS["text_dim"]
        )
        self._status_detail.pack(padx=15, pady=(0, 10), anchor="w")

        # 2. Top widgets (packed with side="top")
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.pack(side="top", fill="x", padx=20, pady=(25, 5))

        ctk.CTkLabel(logo_frame, text="🛡️", font=("Segoe UI Emoji", 28)).pack(side="left")
        ctk.CTkLabel(logo_frame, text="AEGIS", font=("Segoe UI", 22, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=(8, 0))

        ctk.CTkLabel(sidebar, text="Security Suite v1.0",
                     font=("Segoe UI", 11), text_color=COLORS["text_dim"]
                     ).pack(side="top", anchor="w", padx=28, pady=(0, 20))

        # Separator
        sep = ctk.CTkFrame(sidebar, height=1, fg_color=COLORS["border"])
        sep.pack(side="top", fill="x", padx=15, pady=(0, 15))

        # Nav buttons
        self._nav_buttons = {}
        nav_items = [
            ("dashboard", "🏠  Dashboard"),
            ("scanner", "🔍  Scanner"),
            ("protection", "🔒  Protection"),
            ("quarantine", "📦  Quarantine"),
            ("threats", "⚠️  Threats Log"),
            ("history", "📋  History"),
            ("optimizer", "⚡  Optimizer"),
            ("settings", "⚙️  Settings"),
        ]

        for key, label in nav_items:
            btn = ctk.CTkButton(
                sidebar, text=label, font=("Segoe UI", 14),
                fg_color="transparent", text_color=COLORS["text_secondary"],
                hover_color=COLORS["bg_hover"], anchor="w",
                height=42, corner_radius=8,
                command=lambda k=key: self._show_page(k)
            )
            btn.pack(side="top", fill="x", padx=10, pady=2)
            self._nav_buttons[key] = btn

    def _create_pages(self):
        """Create all page views."""
        from gui.views import (DashboardView, ScannerView, ProtectionView,
                               QuarantineView, HistoryView, SettingsView, OptimizerView)
        from gui.views.threats import ThreatsView

        pages = {
            "dashboard": DashboardView,
            "scanner": ScannerView,
            "protection": ProtectionView,
            "quarantine": QuarantineView,
            "threats": ThreatsView,
            "history": HistoryView,
            "optimizer": OptimizerView,
            "settings": SettingsView,
        }

        for key, ViewClass in pages.items():
            page = ViewClass(self._content_frame, app=self)
            page.grid(row=0, column=0, sticky="nsew")
            self._pages[key] = page

    def _show_page(self, page_key):
        """Show a specific page."""
        if page_key == self._current_page:
            return

        # Update nav button states
        for key, btn in self._nav_buttons.items():
            if key == page_key:
                btn.configure(fg_color=COLORS["sidebar_active"],
                              text_color=COLORS["accent"])
            else:
                btn.configure(fg_color="transparent",
                              text_color=COLORS["text_secondary"])

        # Show page
        page = self._pages.get(page_key)
        if page:
            # 1. Raise the page instantly in 0ms (UI responds immediately with zero freeze!)
            page.tkraise()
            self._current_page = page_key
            
            # 2. Defer heavy widget rendering/data loading by 10ms to prevent blocking the click animation
            if hasattr(page, "on_show"):
                self.after(10, page.on_show)

    def _start_realtime(self):
        """Start real-time protection."""
        self.realtime.on_threat = self._on_realtime_threat
        self.realtime.start()
        self.process_monitor.start()
        self.network_monitor.start()
        self._update_status()

    def _on_realtime_threat(self, file_path, detections):
        """Handle real-time threat detection."""
        threat_names = ", ".join(d.threat_name for d in detections)
        logger.warning("Real-time threat: %s in %s", threat_names, file_path)
        # Auto-quarantine if enabled
        if self.config.get("auto_quarantine"):
            self.quarantine.quarantine_file(file_path, threat_names)

    def _update_status(self):
        """Update the sidebar status indicator."""
        if self.realtime.active:
            self._status_indicator.configure(text="● Protected", text_color=COLORS["success"])
            self._status_detail.configure(text="Real-time protection active")
        else:
            self._status_indicator.configure(text="● Monitoring Off", text_color=COLORS["warning"])
            self._status_detail.configure(text="Enable real-time protection")

    def apply_performance_mode(self):
        """Configure high-priority system resource allocation if Extreme Performance Mode is active."""
        is_perf = self.config.get("performance_mode", False)
        import psutil
        try:
            p = psutil.Process()
            # Windows process priority classes
            if is_perf:
                p.nice(psutil.HIGH_PRIORITY_CLASS)
                logger.info("⚡ Extreme Performance Mode ENABLED: High-priority CPU scheduler class allocated.")
            else:
                p.nice(psutil.NORMAL_PRIORITY_CLASS)
                logger.info("Standard Performance Mode: Normal priority CPU scheduling active.")
        except Exception as e:
            logger.warning("Could not set process priority class: %s", e)

    def _on_close(self):
        """Clean up and close."""
        logger.info("Shutting down Aegis AV...")
        self.realtime.stop()
        self.process_monitor.stop()
        self.network_monitor.stop()
        self.db.close()
        self.destroy()
