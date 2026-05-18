"""
Aegis AV - Threats View
Displays a master log of all detected threat alerts, with one-click actions to Quarantine or permanently Delete files.
"""

import customtkinter as ctk
import os
from datetime import datetime
from gui.app import COLORS

class ThreatsView(ctk.CTkFrame):
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
            self.header, text="Threat Alert Registry",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        # ── Summary Cards ─────────────────────────────────────────
        self.summary = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12, height=75)
        self.summary.grid(row=1, column=0, padx=30, pady=10, sticky="ew")
        self.summary.grid_propagate(False)
        
        self.sum_lbl = ctk.CTkLabel(
            self.summary, text="Active Threat Alerts: 0  |  Unresolved Detections",
            font=("Segoe UI", 13, "bold"), text_color=COLORS["text_secondary"]
        )
        self.sum_lbl.pack(side="left", padx=25, pady=22)
        
        # ── Table Layout ──────────────────────────────────────────
        self.threat_container = ctk.CTkFrame(self, fg_color="transparent")
        self.threat_container.grid(row=2, column=0, padx=30, pady=(15, 30), sticky="nsew")
        self.threat_container.grid_columnconfigure(0, weight=1)
        self.threat_container.grid_rowconfigure(0, weight=1)
        
        self.threat_panel = ctk.CTkFrame(self.threat_container, fg_color=COLORS["bg_card"], corner_radius=12)
        self.threat_panel.grid(row=0, column=0, sticky="nsew")
        self.threat_panel.grid_columnconfigure(0, weight=1)
        self.threat_panel.grid_rowconfigure(1, weight=1)
        
        # Table Header
        self.th = ctk.CTkFrame(self.threat_panel, fg_color="transparent", height=30)
        self.th.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="ew")
        self.th.pack_propagate(False)
        
        ctk.CTkLabel(self.th, text="Threat Identifier", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=150, anchor="w").pack(side="left", padx=(15, 5))
        ctk.CTkLabel(self.th, text="Flagged Path Location", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], anchor="w").pack(side="left", padx=10, fill="x", expand=True)
        ctk.CTkLabel(self.th, text="Risk Level", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=90, anchor="center").pack(side="left", padx=10)
        ctk.CTkLabel(self.th, text="Actions", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=150, anchor="center").pack(side="right", padx=15)
        
        self.table_scroll = ctk.CTkScrollableFrame(self.threat_panel, fg_color=COLORS["bg_dark"])
        self.table_scroll.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

    def quarantine_threat(self, threat):
        # Quarantine file
        original_path = threat["file_path"]
        threat_name = threat["threat_name"]
        
        if os.path.exists(original_path):
            if self.app.quarantine.quarantine_file(original_path, threat_name):
                # Update threat action status in db
                conn = self.db._get_conn()
                conn.execute(
                    "UPDATE threats SET action_taken = 'quarantined' WHERE id = ?",
                    (threat["id"],)
                )
                conn.commit()
        else:
            # File already missing
            conn = self.db._get_conn()
            conn.execute(
                "UPDATE threats SET action_taken = 'missing/handled' WHERE id = ?",
                (threat["id"],)
            )
            conn.commit()
            
        self.on_show()

    def delete_threat(self, threat):
        original_path = threat["file_path"]
        try:
            if os.path.exists(original_path):
                os.unlink(original_path)
            conn = self.db._get_conn()
            conn.execute(
                "UPDATE threats SET action_taken = 'deleted' WHERE id = ?",
                (threat["id"],)
            )
            conn.commit()
        except Exception:
            pass
            
        self.on_show()

    def on_show(self):
        # Retrieve threats from database
        conn = self.db._get_conn()
        threats = conn.execute(
            "SELECT * FROM threats WHERE action_taken = 'detected' ORDER BY detected_at DESC"
        ).fetchall()
        threats = [dict(t) for t in threats]
        
        self.sum_lbl.configure(text=f"Active Unresolved Threats: {len(threats)}")
        
        # Clear table
        for widget in self.table_scroll.winfo_children():
            widget.destroy()
            
        if not threats:
            ctk.CTkLabel(
                self.table_scroll, text="🟢 System Clean: No unresolved threats registered.",
                font=("Segoe UI", 12, "italic"), text_color=COLORS["success"]
            ).pack(anchor="w", padx=20, pady=20)
        else:
            for item in threats:
                row = ctk.CTkFrame(self.table_scroll, fg_color=COLORS["bg_dark"], corner_radius=6, height=50)
                row.pack(fill="x", pady=3, padx=5)
                row.pack_propagate(False)
                
                # Threat name
                ctk.CTkLabel(
                    row, text=item["threat_name"], font=("Segoe UI", 12, "bold"),
                    text_color=COLORS["danger"], width=150, anchor="w"
                ).pack(side="left", padx=(15, 5))
                
                # Location (Truncated)
                loc_trunc = item["file_path"]
                if len(loc_trunc) > 50:
                    loc_trunc = "..." + loc_trunc[-47:]
                ctk.CTkLabel(
                    row, text=loc_trunc, font=("Segoe UI", 11),
                    text_color=COLORS["text_secondary"], anchor="w"
                ).pack(side="left", padx=10, fill="x", expand=True)
                
                # Severity Tag
                sev = item["severity"].upper()
                sev_color = COLORS["danger"] if sev in ("HIGH", "CRITICAL") else COLORS["warning"]
                
                sev_frame = ctk.CTkFrame(row, fg_color=COLORS["bg_card"], height=24, corner_radius=4)
                sev_frame.pack(side="left", padx=10, pady=13)
                sev_lbl = ctk.CTkLabel(
                    sev_frame, text=sev, font=("Segoe UI", 9, "bold"),
                    text_color=sev_color
                )
                sev_lbl.pack(padx=8, pady=2)
                
                # Actions buttons
                act_frame = ctk.CTkFrame(row, fg_color="transparent")
                act_frame.pack(side="right", padx=15, fill="y")
                
                # Check if file still exists on disk
                file_exists = os.path.exists(item["file_path"])
                
                if file_exists:
                    btn_quar = ctk.CTkButton(
                        act_frame, text="Quarantine", font=("Segoe UI", 11, "bold"),
                        fg_color=COLORS["accent_dim"], hover_color=COLORS["accent"],
                        text_color=COLORS["text"], width=75, height=28, corner_radius=4,
                        command=lambda t=item: self.quarantine_threat(t)
                    )
                    btn_quar.pack(side="left", padx=(0, 5), pady=11)
                    
                    btn_del = ctk.CTkButton(
                        act_frame, text="Delete", font=("Segoe UI", 11, "bold"),
                        fg_color=COLORS["danger_dim"], hover_color=COLORS["danger"],
                        text_color=COLORS["text"], width=60, height=28, corner_radius=4,
                        command=lambda t=item: self.delete_threat(t)
                    )
                    btn_del.pack(side="left", pady=11)
                else:
                    ctk.CTkLabel(
                        act_frame, text="Already Removed", font=("Segoe UI", 11, "italic"),
                        text_color=COLORS["text_dim"]
                    ).pack(side="right", padx=10, pady=15)
