"""
Aegis AV - Settings View
Provides configurable toggles, heuristic sensitivities, archive rules, and API keys.
"""

import customtkinter as ctk
import os
from gui.app import COLORS

class SettingsView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.config = app.config
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # ── Header ────────────────────────────────────────────────
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.grid(row=0, column=0, padx=30, pady=(25, 10), sticky="ew")
        
        self.title = ctk.CTkLabel(
            self.header, text="Application Preferences",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        # ── Scrollable Body ───────────────────────────────────────
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.grid(row=1, column=0, padx=30, pady=(10, 30), sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)
        
        # ── Section 1: Detection Engine Options ───────────────────
        self._create_section_label("⚔️ Core Scanners & Engine Configuration")
        
        self.opt_card = ctk.CTkFrame(self.scroll, fg_color=COLORS["bg_card"], corner_radius=12)
        self.opt_card.pack(fill="x", pady=(0, 20))
        self.opt_card.grid_columnconfigure(0, weight=1)
        
        self.sw_quar = self._add_setting_row(
            self.opt_card, "Auto-Quarantine Threats", 
            "Immediately encrypt and isolate detected threats without prompting user.",
            "switch", 0
        )
        
        self.sw_arch = self._add_setting_row(
            self.opt_card, "Scan Compressed Archives", 
            "Extract and scan content within .zip, .rar, .7z files (might extend duration).",
            "switch", 1
        )
        
        self.combo_sens = self._add_setting_row(
            self.opt_card, "Heuristic Sensitivity", 
            "Adjust detection heuristics thresholds (Low reduces false positives, High scans deeper).",
            "combo", 2, values=["low", "medium", "high"]
        )
        
        self.sw_perf = self._add_setting_row(
            self.opt_card, "Extreme Performance Allocation", 
            "Allocates high-priority RAM caches, elevates CPU priority, and maximizes concurrent scheduler threads.",
            "switch", 3
        )
        
        # ── Section 2: Cloud Integration ──────────────────────────
        self._create_section_label("🌐 Threat Intelligence Integrations")
        
        self.cloud_card = ctk.CTkFrame(self.scroll, fg_color=COLORS["bg_card"], corner_radius=12)
        self.cloud_card.pack(fill="x", pady=(0, 20))
        self.cloud_card.grid_columnconfigure(0, weight=1)
        
        self.vt_entry = self._add_setting_row(
            self.cloud_card, "VirusTotal Cloud API Key", 
            "Enables live cloud verification of suspicious file hashes against 70+ antiviruses.",
            "entry", 0, placeholder="Insert API Key..."
        )
        
        self.vt_status_lbl = ctk.CTkLabel(
            self.cloud_card, text="⚪ Cloud Verification: Disabled",
            font=("Segoe UI", 11, "bold"), text_color=COLORS["text_secondary"],
            anchor="w"
        )
        self.vt_status_lbl.grid(row=1, column=0, padx=20, pady=(0, 15), sticky="w")
        
        # ── Section 3: Safe Exclusions ─────────────────────────────
        self._create_section_label("🛡️ Exclusions & Whitelist Path Rules")
        
        self.excl_card = ctk.CTkFrame(self.scroll, fg_color=COLORS["bg_card"], corner_radius=12)
        self.excl_card.pack(fill="x", pady=(0, 25))
        self.excl_card.grid_columnconfigure(0, weight=1)
        
        self.excl_layout = ctk.CTkFrame(self.excl_card, fg_color="transparent")
        self.excl_layout.pack(fill="x", padx=20, pady=15)
        
        self.excl_input = ctk.CTkEntry(
            self.excl_layout, font=("Segoe UI", 12),
            fg_color=COLORS["bg_dark"], border_color=COLORS["border"],
            placeholder_text="Enter folder path or file directory to ignore..."
        )
        self.excl_input.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.add_excl_btn = ctk.CTkButton(
            self.excl_layout, text="Exclude Path", font=("Segoe UI", 12, "bold"),
            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
            text_color=COLORS["bg_dark"], height=32, corner_radius=6,
            command=self.add_exclusion
        )
        self.add_excl_btn.pack(side="right")
        
        self.excl_list = ctk.CTkFrame(self.excl_card, fg_color=COLORS["bg_dark"], height=100, corner_radius=8)
        self.excl_list.pack(fill="x", padx=20, pady=(0, 15))
        self.excl_list_scroll = ctk.CTkScrollableFrame(self.excl_list, fg_color="transparent", height=80)
        self.excl_list_scroll.pack(fill="both", expand=True)

    def _create_section_label(self, label):
        ctk.CTkLabel(
            self.scroll, text=label, font=("Segoe UI", 14, "bold"), text_color=COLORS["text"]
        ).pack(anchor="w", padx=5, pady=(10, 8))

    def _add_setting_row(self, parent, title, desc, element_type, row_idx, values=None, placeholder=None):
        r = ctk.CTkFrame(parent, fg_color="transparent", height=65)
        r.grid(row=row_idx, column=0, sticky="ew")
        r.grid_propagate(False)
        
        # Border separator if row is > 0
        if row_idx > 0:
            sep = ctk.CTkFrame(parent, height=1, fg_color=COLORS["border"])
            sep.grid(row=row_idx, column=0, sticky="new", padx=15)
            
        txts = ctk.CTkFrame(r, fg_color="transparent")
        txts.pack(side="left", padx=20, pady=10)
        
        ctk.CTkLabel(txts, text=title, font=("Segoe UI", 12, "bold"), text_color=COLORS["text"]).pack(anchor="w")
        ctk.CTkLabel(txts, text=desc, font=("Segoe UI", 10), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(1, 0))
        
        elem = None
        if element_type == "switch":
            elem = ctk.CTkSwitch(
                r, text="", width=40, height=20,
                switch_width=36, switch_height=18,
                button_color=COLORS["text_secondary"],
                button_hover_color=COLORS["text"],
                progress_color=COLORS["accent"],
                fg_color=COLORS["bg_dark"],
                command=self.save_settings
            )
            elem.pack(side="right", padx=20, pady=20)
        elif element_type == "combo":
            elem = ctk.CTkOptionMenu(
                r, values=values, font=("Segoe UI", 12),
                fg_color=COLORS["bg_dark"], button_color=COLORS["bg_dark"],
                button_hover_color=COLORS["bg_hover"],
                text_color=COLORS["text"], dropdown_fg_color=COLORS["bg_dark"],
                dropdown_text_color=COLORS["text"],
                dropdown_hover_color=COLORS["bg_hover"],
                height=30, width=120, corner_radius=6,
                command=lambda val: self.save_settings()
            )
            elem.pack(side="right", padx=20, pady=17)
        elif element_type == "entry":
            elem = ctk.CTkEntry(
                r, font=("Segoe UI", 12), width=180, height=30,
                fg_color=COLORS["bg_dark"], border_color=COLORS["border"],
                placeholder_text=placeholder or ""
            )
            elem.pack(side="right", padx=20, pady=17)
            elem.bind("<FocusOut>", lambda e: self.save_settings())
            elem.bind("<Return>", lambda e: self.save_settings())
            
        return elem

    def add_exclusion(self):
        p = self.excl_input.get().strip()
        if not p or not os.path.exists(p):
            return
            
        excls = self.config.get("excluded_paths", [])
        if p not in excls:
            excls.append(p)
            self.config.set("excluded_paths", excls)
            self.excl_input.delete(0, "end")
            self.load_exclusions_list()

    def remove_exclusion(self, p):
        excls = self.config.get("excluded_paths", [])
        if p in excls:
            excls.remove(p)
            self.config.set("excluded_paths", excls)
            self.load_exclusions_list()

    def load_exclusions_list(self):
        for w in self.excl_list_scroll.winfo_children():
            w.destroy()
            
        excls = self.config.get("excluded_paths", [])
        if not excls:
            ctk.CTkLabel(
                self.excl_list_scroll, text="No exclusions configured.",
                font=("Segoe UI", 11, "italic"), text_color=COLORS["text_secondary"]
            ).pack(anchor="w", padx=15, pady=10)
        else:
            for p in excls:
                row = ctk.CTkFrame(self.excl_list_scroll, fg_color="transparent", height=28)
                row.pack(fill="x", pady=1)
                row.pack_propagate(False)
                
                ctk.CTkLabel(row, text=p, font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(side="left", padx=10)
                
                btn = ctk.CTkButton(
                    row, text="✕", font=("Segoe UI", 10, "bold"),
                    fg_color="transparent", text_color=COLORS["danger"],
                    hover_color=COLORS["bg_hover"], width=20, height=20, corner_radius=4,
                    command=lambda path=p: self.remove_exclusion(path)
                )
                btn.pack(side="right", padx=10)

    def save_settings(self):
        self.config.set("auto_quarantine", bool(self.sw_quar.get()))
        self.config.set("scan_archives", bool(self.sw_arch.get()))
        self.config.set("heuristic_sensitivity", self.combo_sens.get())
        self.config.set("virustotal_api_key", self.vt_entry.get().strip())
        self.config.set("performance_mode", bool(self.sw_perf.get()))
        
        # Sync engines sensitivity on scanner
        self.app.scanner.engine.heuristic_engine.sensitivity = self.combo_sens.get()
        self.app.scanner.engine.heuristic_engine.threshold = \
            self.app.scanner.engine.heuristic_engine.SENSITIVITY_THRESHOLDS.get(self.combo_sens.get(), 40)
        self.update_vt_status()
        self.app.apply_performance_mode()

    def update_vt_status(self):
        key = self.config.get("virustotal_api_key", "").strip()
        if key:
            self.vt_status_lbl.configure(text="🟢 Cloud Verification: Enabled (API Key Configured)", text_color=COLORS["success"])
        else:
            self.vt_status_lbl.configure(text="⚪ Cloud Verification: Disabled (No API Key)", text_color=COLORS["text_secondary"])

    def on_show(self):
        # Sync switch states
        if self.config.get("auto_quarantine"):
            self.sw_quar.select()
        else:
            self.sw_quar.deselect()
            
        if self.config.get("scan_archives"):
            self.sw_arch.select()
        else:
            self.sw_arch.deselect()
            
        if self.config.get("performance_mode"):
            self.sw_perf.select()
        else:
            self.sw_perf.deselect()
            
        self.combo_sens.set(self.config.get("heuristic_sensitivity", "medium"))
        
        self.vt_entry.delete(0, "end")
        self.vt_entry.insert(0, self.config.get("virustotal_api_key", ""))
        
        self.load_exclusions_list()
        self.update_vt_status()
