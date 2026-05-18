"""
Aegis AV - Protection View
Enables or disables real-time scanners (Watchdog, Process, Network Monitor).
"""

import customtkinter as ctk
import time
from gui.app import COLORS

class ProtectionView(ctk.CTkFrame):
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
            self.header, text="Real-Time Protection Shield",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        # ── Toggle Controls ───────────────────────────────────────
        self.controls = ctk.CTkFrame(self, fg_color="transparent")
        self.controls.grid(row=1, column=0, padx=30, pady=10, sticky="ew")
        self.controls.grid_columnconfigure((0, 1, 2), weight=1)
        
        self.sw_fs = self._create_toggle_card(
            "File Watchdog Shield", "Actively scans newly created, modified, or downloaded files in monitored user space paths.",
            0, self.toggle_fs
        )
        self.sw_proc = self._create_toggle_card(
            "Behavior Process Shield", "Monitors executing system processes for suspicious actions, shellcode injection, or credential harvesting.",
            1, self.toggle_proc
        )
        self.sw_net = self._create_toggle_card(
            "Network Activity Shield", "Watches established internet sockets for connections targeting malicious commands or unauthorized backdoor ports.",
            2, self.toggle_net
        )
        
        # ── Details Layout ────────────────────────────────────────
        self.details_container = ctk.CTkFrame(self, fg_color="transparent")
        self.details_container.grid(row=2, column=0, padx=30, pady=(15, 30), sticky="nsew")
        self.details_container.grid_columnconfigure(0, weight=1)
        self.details_container.grid_rowconfigure(0, weight=1)
        
        # Monitor logs panel
        self.log_panel = ctk.CTkFrame(self.details_container, fg_color=COLORS["bg_card"], corner_radius=12)
        self.log_panel.grid(row=0, column=0, sticky="nsew")
        self.log_panel.grid_columnconfigure(0, weight=1)
        self.log_panel.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(
            self.log_panel, text="🛡️ Live Real-time Monitor Events",
            font=("Segoe UI", 14, "bold"), text_color=COLORS["text"]
        ).grid(row=0, column=0, padx=20, pady=(15, 10), sticky="w")
        
        self.event_list = ctk.CTkScrollableFrame(self.log_panel, fg_color=COLORS["bg_dark"])
        self.event_list.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

    def _create_toggle_card(self, title, desc, col, command):
        card = ctk.CTkFrame(self.controls, fg_color=COLORS["bg_card"], corner_radius=12, height=125)
        card.grid(row=0, column=col, padx=8 if col == 1 else 0, sticky="ew")
        card.grid_propagate(False)
        
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=15, pady=(12, 0))
        
        lbl_title = ctk.CTkLabel(top, text=title, font=("Segoe UI", 13, "bold"), text_color=COLORS["text"])
        lbl_title.pack(side="left")
        
        sw = ctk.CTkSwitch(
            top, text="", width=40, height=20,
            switch_width=36, switch_height=18,
            button_color=COLORS["text_secondary"],
            button_hover_color=COLORS["text"],
            progress_color=COLORS["accent"],
            fg_color=COLORS["bg_dark"],
            command=command
        )
        sw.pack(side="right")
        
        lbl_desc = ctk.CTkLabel(
            card, text=desc, font=("Segoe UI", 11),
            text_color=COLORS["text_secondary"], wraplength=235, justify="left"
        )
        lbl_desc.pack(anchor="w", padx=15, pady=(5, 10))
        
        return sw

    def toggle_fs(self):
        if self.sw_fs.get():
            self.app.realtime.start()
            self.app.config.set("realtime_protection", True)
        else:
            self.app.realtime.stop()
            self.app.config.set("realtime_protection", False)
        self.app._update_status()
        self.on_show()

    def toggle_proc(self):
        if self.sw_proc.get():
            self.app.process_monitor.start()
        else:
            self.app.process_monitor.stop()
        self.on_show()

    def toggle_net(self):
        if self.sw_net.get():
            self.app.network_monitor.start()
        else:
            self.app.network_monitor.stop()
        self.on_show()

    def on_show(self):
        # Sync switches
        if self.app.realtime.active:
            self.sw_fs.select()
        else:
            self.sw_fs.deselect()
            
        if self.app.process_monitor.active:
            self.sw_proc.select()
        else:
            self.sw_proc.deselect()
            
        if self.app.network_monitor.active:
            self.sw_net.select()
        else:
            self.sw_net.deselect()
            
        # Load logs
        for widget in self.event_list.winfo_children():
            widget.destroy()
            
        events = self.db.get_recent_events(limit=40)
        if not events:
            ctk.CTkLabel(
                self.event_list, text="No events registered. Protection shields are listening...",
                font=("Segoe UI", 12, "italic"), text_color=COLORS["text_secondary"]
            ).pack(anchor="w", padx=20, pady=20)
        else:
            for ev in events:
                row = ctk.CTkFrame(self.event_list, fg_color=COLORS["bg_dark"], corner_radius=6, height=45)
                row.pack(fill="x", pady=3, padx=5)
                row.pack_propagate(False)
                
                # Icon mapping
                icon = "📁"
                col = COLORS["info"]
                if "process" in ev["event_type"]:
                    icon = "⚡"
                    col = COLORS["warning"]
                elif "connection" in ev["event_type"]:
                    icon = "🌐"
                    col = COLORS["info"]
                elif "threat" in ev["event_type"]:
                    icon = "⚠️"
                    col = COLORS["danger"]
                    
                ctk.CTkLabel(
                    row, text=icon, font=("Segoe UI Emoji", 14)
                ).pack(side="left", padx=(15, 5))
                
                # Details
                details = ctk.CTkFrame(row, fg_color="transparent")
                details.pack(side="left", padx=5, fill="y", expand=True)
                
                # Timestamp parsing
                t_str = ev["timestamp"]
                try:
                    t_parsed = datetime.fromisoformat(t_str).strftime("%H:%M:%S")
                except Exception:
                    t_parsed = t_str
                    
                ctk.CTkLabel(
                    details, text=f"[{t_parsed}] {ev['event_type'].upper().replace('_', ' ')}",
                    font=("Segoe UI", 11, "bold"), text_color=col, anchor="w"
                ).pack(anchor="w", pady=(3, 0))
                
                trunc = ev["details"] or ev["file_path"] or ev["process_name"] or ""
                if len(trunc) > 75:
                    trunc = trunc[:72] + "..."
                ctk.CTkLabel(
                    details, text=trunc, font=("Segoe UI", 10),
                    text_color=COLORS["text_secondary"], anchor="w"
                ).pack(anchor="w")
                
                # Action label
                act = ev.get("action_taken", "")
                if act:
                    ctk.CTkLabel(
                        row, text=act.upper(), font=("Segoe UI", 9, "bold"),
                        text_color=COLORS["text"], fg_color=COLORS["bg_hover"],
                        corner_radius=4, width=70, height=20
                    ).pack(side="right", padx=15, pady=12)
