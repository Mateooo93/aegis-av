"""
Aegis AV - Dashboard View
Provides system health overview, quick stats cards, and action shortcuts.
"""

import customtkinter as ctk
from datetime import datetime
from gui.app import COLORS

class DashboardView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # ── Header ────────────────────────────────────────────────
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.grid(row=0, column=0, padx=30, pady=(25, 10), sticky="ew")
        
        self.title = ctk.CTkLabel(
            self.header, text="System Dashboard",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        self.time_label = ctk.CTkLabel(
            self.header, text="",
            font=("Segoe UI", 12), text_color=COLORS["text_secondary"]
        )
        self.time_label.pack(side="right", pady=(10, 0))
        self.update_time()
        
        # ── Status Banner ─────────────────────────────────────────
        self.status_banner = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12, height=140)
        self.status_banner.grid(row=1, column=0, padx=30, pady=15, sticky="ew")
        self.status_banner.grid_propagate(False)
        self.status_banner.grid_columnconfigure(0, weight=1)
        self.status_banner.grid_rowconfigure(0, weight=1)
        
        self.banner_layout = ctk.CTkFrame(self.status_banner, fg_color="transparent")
        self.banner_layout.pack(fill="both", expand=True, padx=25, pady=20)
        
        self.status_icon = ctk.CTkLabel(self.banner_layout, text="🛡️", font=("Segoe UI Emoji", 48))
        self.status_icon.pack(side="left")
        
        self.status_text_frame = ctk.CTkFrame(self.banner_layout, fg_color="transparent")
        self.status_text_frame.pack(side="left", padx=20, fill="both")
        
        self.status_title = ctk.CTkLabel(
            self.status_text_frame, text="Your PC is Protected",
            font=("Segoe UI", 20, "bold"), text_color=COLORS["accent"],
            anchor="w"
        )
        self.status_title.pack(anchor="w")
        
        self.status_desc = ctk.CTkLabel(
            self.status_text_frame, text="All engines active. Real-time protection is safeguarding your system.",
            font=("Segoe UI", 13), text_color=COLORS["text_secondary"],
            anchor="w"
        )
        self.status_desc.pack(anchor="w", pady=(2, 0))
        
        self.scan_btn = ctk.CTkButton(
            self.banner_layout, text="Quick Scan",
            font=("Segoe UI", 13, "bold"), fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"], text_color=COLORS["bg_dark"],
            height=38, width=120, corner_radius=8,
            command=lambda: self.app._show_page("scanner")
        )
        self.scan_btn.pack(side="right")
        
        # ── Stats Grid ────────────────────────────────────────────
        self.stats_container = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_container.grid(row=2, column=0, padx=30, pady=10, sticky="nsew")
        self.stats_container.grid_columnconfigure((0, 1, 2), weight=1)
        self.stats_container.grid_rowconfigure(1, weight=1)
        
        # Stat Card helper
        self.cards = {}
        self._create_stat_card("scanned", "Files Scanned", "0", "Total files evaluated", 0, COLORS["info"])
        self._create_stat_card("threats", "Threats Blocked", "0", "Malicious files isolated", 1, COLORS["danger"])
        self._create_stat_card("quarantined", "Quarantined", "0", "Files currently vault-secured", 2, COLORS["warning"])
        
        # ── Bottom Section (Recent Threats & Threat Map/Logs) ─────
        self.bottom_container = ctk.CTkFrame(self, fg_color="transparent")
        self.bottom_container.grid(row=3, column=0, padx=30, pady=(15, 30), sticky="ew")
        self.bottom_container.grid_columnconfigure(0, weight=3)
        self.bottom_container.grid_columnconfigure(1, weight=2)
        
        # Left Panel - Recent Threats
        self.threat_panel = ctk.CTkFrame(self.bottom_container, fg_color=COLORS["bg_card"], corner_radius=12, height=220)
        self.threat_panel.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        self.threat_panel.grid_propagate(False)
        
        ctk.CTkLabel(
            self.threat_panel, text="⚠️ Recent Threat Detections",
            font=("Segoe UI", 14, "bold"), text_color=COLORS["text"]
        ).pack(anchor="w", padx=20, pady=(15, 10))
        
        self.threat_list = ctk.CTkScrollableFrame(self.threat_panel, fg_color="transparent")
        self.threat_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Right Panel - Shield Details
        self.shield_panel = ctk.CTkFrame(self.bottom_container, fg_color=COLORS["bg_card"], corner_radius=12, height=220)
        self.shield_panel.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        self.shield_panel.grid_propagate(False)
        
        ctk.CTkLabel(
            self.shield_panel, text="🛡️ Engines Status",
            font=("Segoe UI", 14, "bold"), text_color=COLORS["text"]
        ).pack(anchor="w", padx=20, pady=(15, 10))
        
        self.engine_list = ctk.CTkFrame(self.shield_panel, fg_color="transparent")
        self.engine_list.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        self._create_engine_indicators()

    def _create_stat_card(self, key, title, val, desc, col, color):
        card = ctk.CTkFrame(self.stats_container, fg_color=COLORS["bg_card"], corner_radius=12, height=110)
        card.grid(row=0, column=col, padx=5 if col == 1 else 0, sticky="ew")
        card.grid_propagate(False)
        
        lbl_title = ctk.CTkLabel(card, text=title, font=("Segoe UI", 12), text_color=COLORS["text_secondary"])
        lbl_title.pack(anchor="w", padx=20, pady=(15, 0))
        
        lbl_val = ctk.CTkLabel(card, text=val, font=("Segoe UI", 28, "bold"), text_color=color)
        lbl_val.pack(anchor="w", padx=20, pady=(2, 0))
        
        lbl_desc = ctk.CTkLabel(card, text=desc, font=("Segoe UI", 10), text_color=COLORS["text_dim"])
        lbl_desc.pack(anchor="w", padx=20, pady=(2, 10))
        
        self.cards[key] = (lbl_val, card)

    def _create_engine_indicators(self):
        self.engine_lbls = {}
        engines = [
            ("Signature scanner", "Loaded", COLORS["success"]),
            ("YARA heuristic rule sets", "Active", COLORS["success"]),
            ("Static PE analyzer", "Active", COLORS["success"]),
            ("Real-time watchdog", "Running", COLORS["success"]),
            ("VirusTotal Cloud protection", "Checking...", COLORS["text_secondary"]),
        ]
        for name, status, color in engines:
            row = ctk.CTkFrame(self.engine_list, fg_color="transparent", height=28)
            row.pack(fill="x", pady=1)
            
            ctk.CTkLabel(row, text=name, font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(side="left")
            lbl_status = ctk.CTkLabel(row, text=status, font=("Segoe UI", 11, "bold"), text_color=color)
            lbl_status.pack(side="right")
            
            self.engine_lbls[name] = lbl_status

    def update_time(self):
        now = datetime.now().strftime("%A, %b %d, %Y  %I:%M %p")
        self.time_label.configure(text=now)
        self.after(60000, self.update_time)

    def on_show(self):
        """Called when this view gains focus."""
        stats = self.db.get_dashboard_stats()
        
        # Update cards
        self.cards["scanned"][0].configure(text=f"{stats['total_files_scanned']:,}")
        self.cards["threats"][0].configure(text=str(stats["total_threats"]))
        self.cards["quarantined"][0].configure(text=str(stats["quarantined"]))
        
        # Update VirusTotal indicator status dynamically
        vt_key = self.app.config.get("virustotal_api_key", "").strip()
        if vt_key:
            self.engine_lbls["VirusTotal Cloud protection"].configure(text="Active", text_color=COLORS["success"])
        else:
            self.engine_lbls["VirusTotal Cloud protection"].configure(text="Inactive", text_color=COLORS["text_secondary"])
        
        # Update real-time protective status visual indicators
        if self.app.realtime.active:
            self.status_title.configure(text="Your PC is Protected", text_color=COLORS["accent"])
            self.status_desc.configure(text="All engines active. Real-time protection is safeguarding your system.")
            self.status_icon.configure(text="🛡️")
        else:
            self.status_title.configure(text="Protection is Disabled", text_color=COLORS["warning"])
            self.status_desc.configure(text="Your PC might be vulnerable. Enable real-time protection immediately.")
            self.status_icon.configure(text="⚠️")
            
        # Load recent threats
        for widget in self.threat_list.winfo_children():
            widget.destroy()
            
        recent = stats["recent_threats"]
        if not recent:
            ctk.CTkLabel(
                self.threat_list, text="No threats detected recently. Your system is safe.",
                font=("Segoe UI", 12, "italic"), text_color=COLORS["text_secondary"]
            ).pack(anchor="w", padx=20, pady=20)
        else:
            for threat in recent:
                row = ctk.CTkFrame(self.threat_list, fg_color=COLORS["bg_dark"], corner_radius=6, height=45)
                row.pack(fill="x", pady=4, padx=5)
                row.pack_propagate(False)
                
                # Severity dot or label
                sev_color = COLORS["danger"] if threat["severity"] in ("high", "critical") else COLORS["warning"]
                ctk.CTkLabel(
                    row, text="●", text_color=sev_color, font=("Segoe UI", 16)
                ).pack(side="left", padx=(15, 5))
                
                # Name & path
                name_frame = ctk.CTkFrame(row, fg_color="transparent")
                name_frame.pack(side="left", padx=5, fill="y", expand=True)
                
                ctk.CTkLabel(
                    name_frame, text=threat["threat_name"], font=("Segoe UI", 12, "bold"),
                    text_color=COLORS["text"], anchor="w"
                ).pack(anchor="w", pady=(4, 0))
                
                path_truncated = threat["file_path"]
                if len(path_truncated) > 60:
                    path_truncated = "..." + path_truncated[-57:]
                ctk.CTkLabel(
                    name_frame, text=path_truncated, font=("Segoe UI", 10),
                    text_color=COLORS["text_secondary"], anchor="w"
                ).pack(anchor="w")
                
                # Action badge
                action = threat.get("action_taken", "Detected").upper()
                badge_color = COLORS["success"] if action == "QUARANTINED" or action == "BLOCKED" else COLORS["info"]
                
                ctk.CTkLabel(
                    row, text=action, font=("Segoe UI", 9, "bold"),
                    text_color=COLORS["bg_dark"], fg_color=badge_color,
                    corner_radius=4, width=80, height=20
                ).pack(side="right", padx=15, pady=12)
