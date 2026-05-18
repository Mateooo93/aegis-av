"""
Aegis AV - Scanner View
Provides Quick, Full, and Custom file systems scanning with interactive progress.
"""

import customtkinter as ctk
import os
import time
from gui.app import COLORS

class ScannerView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self.scanner = app.scanner
        self.job = None
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # ── Header ────────────────────────────────────────────────
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.grid(row=0, column=0, padx=30, pady=(25, 10), sticky="ew")
        
        self.title = ctk.CTkLabel(
            self.header, text="Malware Scanner",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        # ── Main Content ──────────────────────────────────────────
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=1, column=0, padx=30, pady=10, sticky="nsew")
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)
        
        # ── View 1: Scan Selection (Pre-scan) ────────────────────
        self.selection_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.selection_frame.grid(row=0, column=0, sticky="nsew")
        self.selection_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        self._create_scan_card("quick", "Quick Scan", "⚡", 
                               "Scans commonly targeted locations (Downloads, Desktop, AppData) and loaded memory processes.",
                               0)
        self._create_scan_card("full", "Full System Scan", "🔍", 
                               "Scans all system directories, local registry keys, connected storage devices, and archives.",
                               1)
        self._create_scan_card("custom", "Custom Directory Scan", "📁", 
                               "Select a specific file path or folder directory to analyze using Aegis's multi-engines.",
                               2)
        
        # ── View 2: Scan In-Progress ─────────────────────────────
        self.progress_frame = ctk.CTkFrame(self.main_container, fg_color=COLORS["bg_card"], corner_radius=12)
        self.progress_frame.grid_columnconfigure(0, weight=1)
        
        self.scan_title = ctk.CTkLabel(self.progress_frame, text="Quick Scan Active...", font=("Segoe UI", 16, "bold"), text_color=COLORS["accent"])
        self.scan_title.grid(row=0, column=0, padx=30, pady=(20, 5), sticky="w")
        
        self.current_file_lbl = ctk.CTkLabel(self.progress_frame, text="Scanning: initialization...", font=("Segoe UI", 11), text_color=COLORS["text_secondary"], anchor="w")
        self.current_file_lbl.grid(row=1, column=0, padx=30, pady=(0, 15), sticky="ew")
        
        self.bar_container = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        self.bar_container.grid(row=2, column=0, padx=30, pady=(0, 20), sticky="ew")
        self.bar_container.grid_columnconfigure(0, weight=1)
        
        self.progress_bar = ctk.CTkProgressBar(self.bar_container, fg_color=COLORS["bg_dark"], progress_color=COLORS["accent"], height=10)
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        self.progress_bar.set(0)
        
        self.progress_percent = ctk.CTkLabel(self.bar_container, text="0%", font=("Segoe UI", 12, "bold"), text_color=COLORS["accent"])
        self.progress_percent.grid(row=0, column=1, padx=(15, 0))
        
        # Stat grid inside progress
        self.stats_grid = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        self.stats_grid.grid(row=3, column=0, padx=30, pady=(0, 20), sticky="ew")
        self.stats_grid.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        self._add_prog_stat("Files Scanned", "0", 0)
        self._add_prog_stat("Threats Found", "0", 1, color=COLORS["danger"])
        self._add_prog_stat("Elapsed Time", "00:00", 2)
        self._add_prog_stat("Scan Rate", "0 files/s", 3)
        
        # Threat log under progress
        ctk.CTkLabel(self.progress_frame, text="⚡ Real-time Scan Log", font=("Segoe UI", 13, "bold"), text_color=COLORS["text"]).grid(row=4, column=0, padx=30, pady=(10, 5), sticky="w")
        
        self.scan_log = ctk.CTkScrollableFrame(self.progress_frame, fg_color=COLORS["bg_dark"], height=180, corner_radius=8)
        self.scan_log.grid(row=5, column=0, padx=30, pady=(0, 20), sticky="ew")
        
        # Control Buttons
        self.controls = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        self.controls.grid(row=6, column=0, padx=30, pady=(0, 25), sticky="w")
        
        self.pause_btn = ctk.CTkButton(self.controls, text="Pause Scan", font=("Segoe UI", 12, "bold"), fg_color=COLORS["bg_hover"], text_color=COLORS["text"], width=100, height=34, corner_radius=6, command=self.toggle_pause)
        self.pause_btn.pack(side="left", padx=(0, 10))
        
        self.cancel_btn = ctk.CTkButton(self.controls, text="Cancel Scan", font=("Segoe UI", 12, "bold"), fg_color=COLORS["danger_dim"], hover_color=COLORS["danger"], text_color=COLORS["text"], width=100, height=34, corner_radius=6, command=self.cancel_scan)
        self.cancel_btn.pack(side="left")

    def _create_scan_card(self, scan_key, title, icon, desc, col):
        card = ctk.CTkFrame(self.selection_frame, fg_color=COLORS["bg_card"], corner_radius=12)
        card.grid(row=0, column=col, padx=8 if col == 1 else 0, pady=10, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        
        lbl_icon = ctk.CTkLabel(card, text=icon, font=("Segoe UI Emoji", 40))
        lbl_icon.grid(row=0, column=0, pady=(35, 10))
        
        lbl_title = ctk.CTkLabel(card, text=title, font=("Segoe UI", 16, "bold"), text_color=COLORS["text"])
        lbl_title.grid(row=1, column=0, pady=(0, 10))
        
        lbl_desc = ctk.CTkLabel(card, text=desc, font=("Segoe UI", 12), text_color=COLORS["text_secondary"], wraplength=220, justify="center")
        lbl_desc.grid(row=2, column=0, padx=20, pady=(0, 35))
        
        btn = ctk.CTkButton(
            card, text="Initiate",
            font=("Segoe UI", 13, "bold"), fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"], text_color=COLORS["bg_dark"],
            height=36, corner_radius=8,
            command=lambda k=scan_key: self.start_scan(k)
        )
        btn.grid(row=3, column=0, padx=25, pady=(0, 30), sticky="ew")

    def _add_prog_stat(self, label, init_val, col, color=None):
        frame = ctk.CTkFrame(self.stats_grid, fg_color="transparent")
        frame.grid(row=0, column=col, sticky="ew")
        
        lbl_txt = ctk.CTkLabel(frame, text=label, font=("Segoe UI", 11), text_color=COLORS["text_secondary"])
        lbl_txt.pack(anchor="center")
        
        lbl_val = ctk.CTkLabel(frame, text=init_val, font=("Segoe UI", 18, "bold"), text_color=color or COLORS["text"])
        lbl_val.pack(anchor="center", pady=(2, 0))
        
        if not hasattr(self, "_prog_lbls"):
            self._prog_lbls = {}
        self._prog_lbls[label] = lbl_val

    def start_scan(self, scan_type):
        target = ""
        if scan_type == "custom":
            from tkinter import filedialog
            target = filedialog.askdirectory(title="Select Folder to Scan")
            if not target:
                return
                
        # Toggle layouts
        self.selection_frame.grid_forget()
        self.progress_frame.grid(row=0, column=0, sticky="nsew")
        
        # Init progress state
        self.scan_title.configure(text=f"{scan_type.title()} Scan Running...")
        self.current_file_lbl.configure(text="Initializing engine...")
        self.progress_bar.set(0)
        self.progress_percent.configure(text="0%")
        self._prog_lbls["Files Scanned"].configure(text="0")
        self._prog_lbls["Threats Found"].configure(text="0")
        self._prog_lbls["Elapsed Time"].configure(text="00:00")
        self._prog_lbls["Scan Rate"].configure(text="0 files/s")
        
        # Clear scrollable log
        for widget in self.scan_log.winfo_children():
            widget.destroy()
            
        self.log_message("System engines loaded. Initiating scans...", COLORS["accent"])
        
        vt_key = self.app.config.get("virustotal_api_key", "").strip()
        if vt_key:
            self.log_message("🌐 Cloud Verification: ACTIVE (VirusTotal API Key loaded)", COLORS["accent"])
        else:
            self.log_message("🌐 Cloud Verification: LOCAL ONLY (No API key found in Settings)", COLORS["text_secondary"])
        
        # Start Scan thread
        callbacks = {
            "on_progress": self.on_progress,
            "on_threat": self.on_threat,
            "on_complete": self.on_complete,
            "on_error": self.on_error
        }
        
        self.job = self.scanner._start_scan(scan_type, target, callbacks)
        self.pause_btn.configure(text="Pause Scan", fg_color=COLORS["bg_hover"])

    def on_progress(self, job):
        self.progress_bar.set(job.progress / 100)
        self.progress_percent.configure(text=f"{job.progress}%")
        self._prog_lbls["Files Scanned"].configure(text=f"{job.scanned_files:,} / {job.total_files:,}")
        self._prog_lbls["Threats Found"].configure(text=str(job.threats_found))
        
        # Format elapsed
        minutes = int(job.elapsed_time // 60)
        seconds = int(job.elapsed_time % 60)
        self._prog_lbls["Elapsed Time"].configure(text=f"{minutes:02d}:{seconds:02d}")
        
        # Format rate
        self._prog_lbls["Scan Rate"].configure(text=f"{job.scan_rate:.1f} files/s")
        
        # Update current path
        trunc = job.current_file
        if len(trunc) > 80:
            trunc = "..." + trunc[-77:]
        self.current_file_lbl.configure(text=f"Scanning: {trunc}")

    def on_threat(self, job, file_path, detections):
        for d in detections:
            trunc = file_path
            if len(trunc) > 60:
                trunc = "..." + trunc[-57:]
            self.log_message(f"⚠️ THREAT: [{d.engine}] {d.threat_name} at {trunc}", COLORS["danger"])
            
    def on_complete(self, job):
        self.log_message(f"Scan finished! Processed {job.scanned_files} files. {job.threats_found} threat(s) detected.", COLORS["success"] if job.threats_found == 0 else COLORS["danger"])
        self.pause_btn.configure(text="Back", fg_color=COLORS["accent"], text_color=COLORS["bg_dark"], command=self.reset_layout)
        self.cancel_btn.configure(state="disabled")

    def on_error(self, job, err):
        self.log_message(f"🛑 Error occurred: {err}", COLORS["danger"])
        self.pause_btn.configure(text="Back", fg_color=COLORS["accent"], text_color=COLORS["bg_dark"], command=self.reset_layout)
        self.cancel_btn.configure(state="disabled")

    def toggle_pause(self):
        if not self.job or not self.job.running:
            return
        if self.job.paused:
            self.job.resume()
            self.pause_btn.configure(text="Pause Scan", fg_color=COLORS["bg_hover"], text_color=COLORS["text"])
            self.log_message("Scan resumed by user.", COLORS["info"])
        else:
            self.job.pause()
            self.pause_btn.configure(text="Resume Scan", fg_color=COLORS["accent_dim"], text_color=COLORS["accent"])
            self.log_message("Scan paused by user.", COLORS["warning"])

    def cancel_scan(self):
        if self.job and self.job.running:
            self.job.cancel()
            self.log_message("Scan cancelled by user.", COLORS["warning"])

    def reset_layout(self):
        self.progress_frame.grid_forget()
        self.selection_frame.grid(row=0, column=0, sticky="nsew")
        self.pause_btn.configure(command=self.toggle_pause, text="Pause Scan", text_color=COLORS["text"])
        self.cancel_btn.configure(state="normal")
        self.job = None

    def log_message(self, text, color=None):
        row = ctk.CTkFrame(self.scan_log, fg_color="transparent", height=24)
        row.pack(fill="x", anchor="w", pady=1)
        
        lbl = ctk.CTkLabel(row, text=f"[{time.strftime('%H:%M:%S')}] {text}", font=("Consolas", 11), text_color=color or COLORS["text_secondary"])
        lbl.pack(side="left", padx=5)

    def on_show(self):
        if not self.job or not self.job.running:
            self.reset_layout()
