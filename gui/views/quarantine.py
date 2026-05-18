"""
Aegis AV - Quarantine View
Displays secure quarantined files list, with buttons to restore or permanently delete files.
"""

import customtkinter as ctk
import os
from datetime import datetime
from gui.app import COLORS

class QuarantineView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.quarantine = app.quarantine
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # ── Header ────────────────────────────────────────────────
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.grid(row=0, column=0, padx=30, pady=(25, 10), sticky="ew")
        
        self.title = ctk.CTkLabel(
            self.header, text="Quarantine Secure Vault",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        # ── Summary Info ──────────────────────────────────────────
        self.summary = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12, height=75)
        self.summary.grid(row=1, column=0, padx=30, pady=10, sticky="ew")
        self.summary.grid_propagate(False)
        
        self.sum_lbl = ctk.CTkLabel(
            self.summary, text="Vault Size: 0 Bytes  |  Total Items: 0",
            font=("Segoe UI", 13, "bold"), text_color=COLORS["text_secondary"]
        )
        self.sum_lbl.pack(side="left", padx=25, pady=22)
        
        self.clean_btn = ctk.CTkButton(
            self.summary, text="Purge Old Files",
            font=("Segoe UI", 12, "bold"), fg_color=COLORS["danger_dim"],
            hover_color=COLORS["danger"], text_color=COLORS["text"],
            height=32, width=120, corner_radius=6,
            command=self.purge_vault
        )
        self.clean_btn.pack(side="right", padx=20, pady=20)
        
        # ── Table Layout ──────────────────────────────────────────
        self.vault_container = ctk.CTkFrame(self, fg_color="transparent")
        self.vault_container.grid(row=2, column=0, padx=30, pady=(15, 30), sticky="nsew")
        self.vault_container.grid_columnconfigure(0, weight=1)
        self.vault_container.grid_rowconfigure(0, weight=1)
        
        self.vault_panel = ctk.CTkFrame(self.vault_container, fg_color=COLORS["bg_card"], corner_radius=12)
        self.vault_panel.grid(row=0, column=0, sticky="nsew")
        self.vault_panel.grid_columnconfigure(0, weight=1)
        self.vault_panel.grid_rowconfigure(1, weight=1)
        
        # Table Header
        self.th = ctk.CTkFrame(self.vault_panel, fg_color="transparent", height=30)
        self.th.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="ew")
        self.th.pack_propagate(False)
        
        ctk.CTkLabel(self.th, text="Threat Identifier", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=150, anchor="w").pack(side="left", padx=(15, 5))
        ctk.CTkLabel(self.th, text="Original File Location", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], anchor="w").pack(side="left", padx=10, fill="x", expand=True)
        ctk.CTkLabel(self.th, text="Quarantined Date", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=140, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(self.th, text="Actions", font=("Segoe UI", 11, "bold"), text_color=COLORS["text_dim"], width=130, anchor="center").pack(side="right", padx=15)
        
        self.table_scroll = ctk.CTkScrollableFrame(self.vault_panel, fg_color=COLORS["bg_dark"])
        self.table_scroll.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

    def restore_item(self, q_id):
        if self.quarantine.restore_file(q_id):
            self.on_show()

    def delete_item(self, q_id):
        if self.quarantine.delete_permanently(q_id):
            self.on_show()

    def purge_vault(self):
        self.quarantine.clean_vault(older_than_days=30)
        self.on_show()

    def on_show(self):
        # Update summary
        v_size = self.quarantine.get_vault_size()
        
        # Formatting size helper
        def fmt_size(size_bytes):
            if size_bytes == 0: return "0 B"
            s_name = ("B", "KB", "MB", "GB")
            i = int(os.path.cmath.log(size_bytes, 1024))
            p = os.path.cmath.pow(1024, i)
            s = round(size_bytes / p, 2)
            return f"{s} {s_name[i]}"
            
        items = self.quarantine.get_quarantined_files()
        self.sum_lbl.configure(text=f"Vault Size: {fmt_size(v_size)}  |  Total Items: {len(items)}")
        
        # Reload scrollable
        for widget in self.table_scroll.winfo_children():
            widget.destroy()
            
        if not items:
            ctk.CTkLabel(
                self.table_scroll, text="Secure vault is empty. No threats isolated.",
                font=("Segoe UI", 12, "italic"), text_color=COLORS["text_secondary"]
            ).pack(anchor="w", padx=20, pady=20)
        else:
            for item in items:
                row = ctk.CTkFrame(self.table_scroll, fg_color=COLORS["bg_dark"], corner_radius=6, height=50)
                row.pack(fill="x", pady=3, padx=5)
                row.pack_propagate(False)
                
                # Threat name
                ctk.CTkLabel(
                    row, text=item["threat_name"], font=("Segoe UI", 12, "bold"),
                    text_color=COLORS["danger"], width=150, anchor="w"
                ).pack(side="left", padx=(15, 5))
                
                # Location (Truncated)
                loc_trunc = item["original_path"]
                if len(loc_trunc) > 55:
                    loc_trunc = "..." + loc_trunc[-52:]
                ctk.CTkLabel(
                    row, text=loc_trunc, font=("Segoe UI", 11),
                    text_color=COLORS["text_secondary"], anchor="w"
                ).pack(side="left", padx=10, fill="x", expand=True)
                
                # Date
                t_str = item["quarantined_at"]
                try:
                    t_parsed = datetime.fromisoformat(t_str).strftime("%b %d, %Y %I:%M")
                except Exception:
                    t_parsed = t_str
                    
                ctk.CTkLabel(
                    row, text=t_parsed, font=("Segoe UI", 11),
                    text_color=COLORS["text_secondary"], width=140, anchor="w"
                ).pack(side="left", padx=10)
                
                # Actions buttons
                act_frame = ctk.CTkFrame(row, fg_color="transparent")
                act_frame.pack(side="right", padx=15, fill="y")
                
                btn_rest = ctk.CTkButton(
                    act_frame, text="Restore", font=("Segoe UI", 11, "bold"),
                    fg_color=COLORS["bg_hover"], hover_color=COLORS["success"],
                    text_color=COLORS["text"], width=60, height=28, corner_radius=4,
                    command=lambda q=item["id"]: self.restore_item(q)
                )
                btn_rest.pack(side="left", padx=(0, 5), pady=11)
                
                btn_del = ctk.CTkButton(
                    act_frame, text="Delete", font=("Segoe UI", 11, "bold"),
                    fg_color=COLORS["danger_dim"], hover_color=COLORS["danger"],
                    text_color=COLORS["text"], width=60, height=28, corner_radius=4,
                    command=lambda q=item["id"]: self.delete_item(q)
                )
                btn_del.pack(side="left", pady=11)
