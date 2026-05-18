"""
Aegis AV - History View
Displays scan histories, past records, files analyzed, and detailed logs.
Optimized to dynamically self-refresh while scans are running, and allow clicking active scans to jump to progress view.
"""

import customtkinter as ctk
from datetime import datetime
from gui.app import COLORS

class HistoryView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self._refresh_timer = None
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # ── Header ────────────────────────────────────────────────
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.grid(row=0, column=0, padx=30, pady=(25, 10), sticky="ew")
        
        self.title = ctk.CTkLabel(
            self.header, text="Detection Logs & Scan History",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        # ── Container ─────────────────────────────────────────────
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=1, column=0, padx=30, pady=(15, 30), sticky="nsew")
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)
        
        self.panel = ctk.CTkFrame(self.container, fg_color=COLORS["bg_card"], corner_radius=12)
        self.panel.grid(row=0, column=0, sticky="nsew")
        self.panel.grid_columnconfigure(0, weight=1)
        self.panel.grid_rowconfigure(1, weight=1)
        
        # Table Header
        self.th = ctk.CTkFrame(self.panel, fg_color="transparent", height=30)
        self.th.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="ew")
        self.th.pack_propagate(False)
        
        ctk.CTkLabel(self.th, text="Scan Scope", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=120, anchor="w").pack(side="left", padx=(15, 5))
        ctk.CTkLabel(self.th, text="Triggered Date / Time", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], anchor="w").pack(side="left", padx=10, fill="x", expand=True)
        ctk.CTkLabel(self.th, text="Duration", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=90, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(self.th, text="Files Evaluated", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(self.th, text="Findings", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=100, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(self.th, text="Execution Status", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=110, anchor="center").pack(side="right", padx=15)
        
        self.table_scroll = ctk.CTkScrollableFrame(self.panel, fg_color=COLORS["bg_dark"])
        self.table_scroll.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

    def on_show(self):
        # Cancel any scheduled auto-refreshes first to prevent overlap
        if self._refresh_timer is not None:
            try:
                self.after_cancel(self._refresh_timer)
            except Exception:
                pass
            self._refresh_timer = None
            
        # Reload scans list
        for widget in self.table_scroll.winfo_children():
            widget.destroy()
            
        history = self.db.get_scan_history(limit=50)
        has_running_scan = False
        
        if not history:
            ctk.CTkLabel(
                self.table_scroll, text="No scan histories found. Perform a scan to build logs.",
                font=("Segoe UI", 12, "italic"), text_color=COLORS["text_secondary"]
            ).pack(anchor="center", pady=30)
        else:
            for scan in history:
                is_running = (scan["status"].lower() == "running")
                if is_running:
                    has_running_scan = True
                    
                # Use a hoverable highlighted card if active to invite clicking
                bg_color = COLORS["bg_hover"] if is_running else COLORS["bg_dark"]
                
                row = ctk.CTkFrame(self.table_scroll, fg_color=bg_color, corner_radius=6, height=45)
                row.pack(fill="x", pady=3, padx=5)
                row.pack_propagate(False)
                
                # Scan type
                ctk.CTkLabel(
                    row, text=f"{scan['scan_type'].upper()} SCAN", font=("Segoe UI", 11, "bold"),
                    text_color=COLORS["accent"], width=120, anchor="w"
                ).pack(side="left", padx=(15, 5))
                
                # Timestamp
                t_str = scan["start_time"]
                try:
                    t_parsed = datetime.fromisoformat(t_str).strftime("%b %d, %Y  %I:%M %p")
                except Exception:
                    t_parsed = t_str
                    
                ctk.CTkLabel(
                    row, text=t_parsed, font=("Segoe UI", 11),
                    text_color=COLORS["text_secondary"], anchor="w"
                ).pack(side="left", padx=10, fill="x", expand=True)
                
                # Duration
                dur_text = "--"
                if scan["end_time"]:
                    try:
                        t1 = datetime.fromisoformat(scan["start_time"])
                        t2 = datetime.fromisoformat(scan["end_time"])
                        diff = int((t2 - t1).total_seconds())
                        m = diff // 60
                        s = diff % 60
                        dur_text = f"{m}m {s}s" if m > 0 else f"{s}s"
                    except Exception:
                        pass
                elif is_running:
                    dur_text = "In Progress"
                    
                ctk.CTkLabel(
                    row, text=dur_text, font=("Segoe UI", 11),
                    text_color=COLORS["text_secondary"], width=90, anchor="w"
                ).pack(side="left", padx=10)
                
                # Files scanned
                ctk.CTkLabel(
                    row, text=f"{scan['files_scanned']:,}", font=("Segoe UI", 11),
                    text_color=COLORS["text_secondary"], width=110, anchor="w"
                ).pack(side="left", padx=10)
                
                # Threats
                threats = scan["threats_found"]
                th_color = COLORS["danger"] if threats > 0 else COLORS["success"]
                th_txt = f"⚠️ {threats} Threat(s)" if threats > 0 else "Clean"
                
                ctk.CTkLabel(
                    row, text=th_txt, font=("Segoe UI", 11, "bold"),
                    text_color=th_color, width=100, anchor="w"
                ).pack(side="left", padx=10)
                
                # Status
                st = scan["status"].upper()
                st_color = COLORS["success"] if st == "COMPLETED" else (COLORS["warning"] if st == "RUNNING" else COLORS["danger"])
                
                status_lbl = ctk.CTkLabel(
                    row, text=st, font=("Segoe UI", 9, "bold"),
                    text_color=COLORS["bg_dark"], fg_color=st_color,
                    corner_radius=4, width=90, height=20
                )
                status_lbl.pack(side="right", padx=15, pady=12)
                
                # Make the row fully clickable to view live progress if it's active
                if is_running:
                    # Visual feedback to indicate clickability
                    row.configure(cursor="hand2")
                    for child in row.winfo_children():
                        child.configure(cursor="hand2")
                        
                    def go_to_active_scan(event):
                        self.app._show_page("scanner")
                        
                    row.bind("<Button-1>", go_to_active_scan)
                    for child in row.winfo_children():
                        child.bind("<Button-1>", go_to_active_scan)
                        
        # If there are any active scans running, auto-refresh every 3 seconds
        if has_running_scan and self.winfo_exists():
            self._refresh_timer = self.after(3000, self.on_show)
