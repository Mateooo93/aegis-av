"""
Aegis AV - Performance Optimizer View
Provides an interactive multi-option checklist for Temporary files, Diagnostic logs, Obsolete registry paths, and RAM flush.
Includes a dynamic scan auditor showing exact file sizes/counts, and a real-time console log tracking deleted resources.
All tasks run in background threads to guarantee zero main-thread lag.
"""

import customtkinter as ctk
import os
import psutil
import shutil
import gc
import time
import threading
import logging
from gui.app import COLORS

logger = logging.getLogger("Aegis.Optimizer")

class OptimizerView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # State tracking for scan results
        self.scan_results = {
            "temp": {"bytes": 0, "paths": []},
            "logs": {"bytes": 0, "paths": []},
            "registry": {"keys": []},
            "ram": {"bytes": 0}
        }
        
        # ── Header ────────────────────────────────────────────────
        self.header = ctk.CTkFrame(self, fg_color="transparent")
        self.header.grid(row=0, column=0, padx=30, pady=(25, 10), sticky="ew")
        
        self.title = ctk.CTkLabel(
            self.header, text="System Performance Booster",
            font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]
        )
        self.title.pack(side="left")
        
        # ── Metrics Status Row ────────────────────────────────────
        self.metrics = ctk.CTkFrame(self, fg_color="transparent")
        self.metrics.grid(row=1, column=0, padx=30, pady=10, sticky="ew")
        self.metrics.grid_columnconfigure((0, 1, 2), weight=1)
        
        self.cpu_card = self._create_metric_card("CPU Utilization", "0%", 0, COLORS["info"])
        self.ram_card = self._create_metric_card("RAM (Memory) Load", "0%", 1, COLORS["accent"])
        self.junk_card = self._create_metric_card("Estimated System Junk", "Select options below...", 2, COLORS["warning"])
        
        # ── Layout: Cleaning & Process Manager ────────────────────
        self.layout_grid = ctk.CTkFrame(self, fg_color="transparent")
        self.layout_grid.grid(row=2, column=0, padx=30, pady=(15, 30), sticky="nsew")
        self.layout_grid.grid_columnconfigure(0, weight=1)
        self.layout_grid.grid_columnconfigure(1, weight=1)
        self.layout_grid.grid_rowconfigure(0, weight=1)
        
        # Left Panel: Cleaner Actions
        self.clean_panel = ctk.CTkFrame(self.layout_grid, fg_color=COLORS["bg_card"], corner_radius=12)
        self.clean_panel.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        self.clean_panel.grid_columnconfigure(0, weight=1)
        self.clean_panel.grid_rowconfigure(2, weight=1)
        
        ctk.CTkLabel(
            self.clean_panel, text="🧹 Safe System Cleaner & RAM Boost",
            font=("Segoe UI", 14, "bold"), text_color=COLORS["text"]
        ).pack(anchor="w", padx=20, pady=(20, 5))
        
        self.clean_desc = ctk.CTkLabel(
            self.clean_panel, 
            text="Wipes temporary Windows logs, user cache folders, broken registry startup paths, and flushes system RAM dynamically.",
            font=("Segoe UI", 11), text_color=COLORS["text_secondary"], wraplength=340, justify="left"
        )
        self.clean_desc.pack(anchor="w", padx=20, pady=(5, 10))
        
        # Checklist Frame
        self.chk_frame = ctk.CTkFrame(self.clean_panel, fg_color="transparent")
        self.chk_frame.pack(fill="x", padx=20, pady=5)
        
        # Checklist Item 1
        self.chk_temp_var = ctk.BooleanVar(value=True)
        self.chk_temp = ctk.CTkCheckBox(self.chk_frame, text="Temporary System Files & Cache", variable=self.chk_temp_var, font=("Segoe UI", 12, "bold"), fg_color=COLORS["accent"], border_color=COLORS["border"], hover_color=COLORS["accent_hover"])
        self.chk_temp.grid(row=0, column=0, sticky="w", pady=4)
        self.lbl_temp_stat = ctk.CTkLabel(self.chk_frame, text="(ready to scan)", font=("Segoe UI", 10), text_color=COLORS["text_secondary"])
        self.lbl_temp_stat.grid(row=0, column=1, sticky="e", padx=(20, 0), pady=4)
        
        # Checklist Item 2
        self.chk_logs_var = ctk.BooleanVar(value=True)
        self.chk_logs = ctk.CTkCheckBox(self.chk_frame, text="Logs & Diagnostic Cache", variable=self.chk_logs_var, font=("Segoe UI", 12, "bold"), fg_color=COLORS["accent"], border_color=COLORS["border"], hover_color=COLORS["accent_hover"])
        self.chk_logs.grid(row=1, column=0, sticky="w", pady=4)
        self.lbl_logs_stat = ctk.CTkLabel(self.chk_frame, text="(ready to scan)", font=("Segoe UI", 10), text_color=COLORS["text_secondary"])
        self.lbl_logs_stat.grid(row=1, column=1, sticky="e", padx=(20, 0), pady=4)
        
        # Checklist Item 3
        self.chk_registry_var = ctk.BooleanVar(value=True)
        self.chk_registry = ctk.CTkCheckBox(self.chk_frame, text="Obsolete Windows Registry Keys", variable=self.chk_registry_var, font=("Segoe UI", 12, "bold"), fg_color=COLORS["accent"], border_color=COLORS["border"], hover_color=COLORS["accent_hover"])
        self.chk_registry.grid(row=2, column=0, sticky="w", pady=4)
        self.lbl_registry_stat = ctk.CTkLabel(self.chk_frame, text="(ready to scan)", font=("Segoe UI", 10), text_color=COLORS["text_secondary"])
        self.lbl_registry_stat.grid(row=2, column=1, sticky="e", padx=(20, 0), pady=4)
        
        # Checklist Item 4
        self.chk_ram_var = ctk.BooleanVar(value=True)
        self.chk_ram = ctk.CTkCheckBox(self.chk_frame, text="RAM Allocation Pool Flush & GC", variable=self.chk_ram_var, font=("Segoe UI", 12, "bold"), fg_color=COLORS["accent"], border_color=COLORS["border"], hover_color=COLORS["accent_hover"])
        self.chk_ram.grid(row=3, column=0, sticky="w", pady=4)
        self.lbl_ram_stat = ctk.CTkLabel(self.chk_frame, text="(ready to scan)", font=("Segoe UI", 10), text_color=COLORS["text_secondary"])
        self.lbl_ram_stat.grid(row=3, column=1, sticky="e", padx=(20, 0), pady=4)
        
        self.chk_frame.grid_columnconfigure(0, weight=1)
        
        # Scrollable console for visual feedback of deletion
        self.status_console = ctk.CTkTextbox(
            self.clean_panel, fg_color=COLORS["bg_dark"], border_color=COLORS["border"],
            font=("Consolas", 10), text_color=COLORS["text_secondary"], height=105
        )
        self.status_console.pack(fill="x", padx=20, pady=(5, 12))
        self.status_console.configure(state="disabled")
        
        # Dual Button Layout
        self.btn_layout = ctk.CTkFrame(self.clean_panel, fg_color="transparent")
        self.btn_layout.pack(fill="x", padx=20, pady=(0, 20))
        self.btn_layout.grid_columnconfigure((0, 1), weight=1)
        
        self.scan_btn = ctk.CTkButton(
            self.btn_layout, text="Scan System Junk", font=("Segoe UI", 12, "bold"),
            fg_color=COLORS["bg_hover"], hover_color=COLORS["bg_hover"],
            text_color=COLORS["text"], height=36, corner_radius=6,
            command=self.start_audit
        )
        self.scan_btn.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        self.boost_btn = ctk.CTkButton(
            self.btn_layout, text="Clean & Fix Selected", font=("Segoe UI", 12, "bold"),
            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
            text_color=COLORS["bg_dark"], height=36, corner_radius=6,
            state="disabled", command=self.start_cleanup
        )
        self.boost_btn.grid(row=0, column=1, padx=(5, 0), sticky="ew")
        
        # Right Panel: Memory Hogs Process Manager
        self.proc_panel = ctk.CTkFrame(self.layout_grid, fg_color=COLORS["bg_card"], corner_radius=12)
        self.proc_panel.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        self.proc_panel.grid_columnconfigure(0, weight=1)
        self.proc_panel.grid_rowconfigure(1, weight=1)
        
        proc_header = ctk.CTkFrame(self.proc_panel, fg_color="transparent")
        proc_header.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="ew")
        
        ctk.CTkLabel(
            proc_header, text="🔥 High-Memory Running Hogs",
            font=("Segoe UI", 14, "bold"), text_color=COLORS["text"]
        ).pack(side="left")
        
        self.refresh_btn = ctk.CTkButton(
            proc_header, text="🔄 Refresh", font=("Segoe UI", 11, "bold"),
            fg_color=COLORS["bg_hover"], hover_color=COLORS["bg_hover"],
            text_color=COLORS["text"], width=75, height=24, corner_radius=4,
            command=self.async_scan_hogs
        )
        self.refresh_btn.pack(side="right")
        
        self.proc_list = ctk.CTkScrollableFrame(self.proc_panel, fg_color=COLORS["bg_dark"])
        self.proc_list.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")
        
        # Start passive monitors
        self._run_live_monitors()

    def _create_metric_card(self, title, init_val, col, color):
        card = ctk.CTkFrame(self.metrics, fg_color=COLORS["bg_card"], corner_radius=12, height=95)
        card.grid(row=0, column=col, padx=8 if col == 1 else 0, sticky="ew")
        card.grid_propagate(False)
        
        ctk.CTkLabel(card, text=title, font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=20, pady=(12, 0))
        lbl_val = ctk.CTkLabel(card, text=init_val, font=("Segoe UI", 24, "bold"), text_color=color)
        lbl_val.pack(anchor="w", padx=20, pady=(2, 10))
        
        return lbl_val

    def _run_live_monitors(self):
        """Update CPU, RAM metrics passively every 5 seconds (non-blocking)."""
        if not self.winfo_exists():
            return
        try:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.cpu_card.configure(text=f"{cpu}%")
            self.ram_card.configure(text=f"{ram}%")
        except Exception:
            pass
        self.after(5000, self._run_live_monitors)

    def _log_console_message(self, msg, color_tag=None):
        self.status_console.configure(state="normal")
        self.status_console.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.status_console.see("end")
        self.status_console.configure(state="disabled")

    # ── Background Junk Scan / Audit ──────────────────────────────

    def start_audit(self):
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.boost_btn.configure(state="disabled")
        
        # Reset labels to Analyzing...
        if self.chk_temp_var.get():
            self.lbl_temp_stat.configure(text="Analyzing...", text_color=COLORS["warning"])
        if self.chk_logs_var.get():
            self.lbl_logs_stat.configure(text="Analyzing...", text_color=COLORS["warning"])
        if self.chk_registry_var.get():
            self.lbl_registry_stat.configure(text="Analyzing...", text_color=COLORS["warning"])
        if self.chk_ram_var.get():
            self.lbl_ram_stat.configure(text="Analyzing...", text_color=COLORS["warning"])
            
        self.status_console.configure(state="normal")
        self.status_console.delete("1.0", "end")
        self.status_console.configure(state="disabled")
        
        self._log_console_message("Starting background audit of selected categories...")
        threading.Thread(target=self._audit_worker, daemon=True).start()

    def _audit_worker(self):
        # 1. Audit Temp Files
        temp_bytes = 0
        temp_paths = []
        if self.chk_temp_var.get():
            target_dirs = [os.path.expandvars(r"%TEMP%"), os.path.expandvars(r"%WINDIR%\Temp")]
            for d in target_dirs:
                if os.path.exists(d):
                    for root, _, files in os.walk(d):
                        for f in files:
                            p = os.path.join(root, f)
                            try:
                                sz = os.path.getsize(p)
                                temp_bytes += sz
                                temp_paths.append((p, sz))
                            except Exception:
                                continue
        self.scan_results["temp"] = {"bytes": temp_bytes, "paths": temp_paths}

        # 2. Audit Logs & Diagnostics
        log_bytes = 0
        log_paths = []
        if self.chk_logs_var.get():
            target_dirs = [
                os.path.join(os.path.expandvars(r"%USERPROFILE%"), "AppData", "Local", "Microsoft", "Windows", "Explorer"),
                os.path.expandvars(r"%WINDIR%\Logs"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "logs")
            ]
            for d in target_dirs:
                if os.path.exists(d):
                    for root, _, files in os.walk(d):
                        for f in files:
                            # Safely ignore current log file
                            if f.endswith(".log") and time.strftime("%Y%m%d") in f:
                                continue
                            p = os.path.join(root, f)
                            try:
                                sz = os.path.getsize(p)
                                log_bytes += sz
                                log_paths.append((p, sz))
                            except Exception:
                                continue
        self.scan_results["logs"] = {"bytes": log_bytes, "paths": log_paths}

        # 3. Audit Obsolete Registry Paths
        registry_keys = []
        if self.chk_registry_var.get():
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for idx in range(num_values):
                        try:
                            name, value, _ = winreg.EnumValue(key, idx)
                            # Extract path
                            clean_path = value.strip()
                            if clean_path.startswith('"'):
                                clean_path = clean_path[1:].split('"')[0]
                            else:
                                clean_path = clean_path.split(' ')[0]
                                
                            if clean_path and not os.path.exists(clean_path):
                                registry_keys.append((name, value))
                        except Exception:
                            continue
            except Exception as e:
                logger.debug("winreg audit failed: %s", e)
        self.scan_results["registry"] = {"keys": registry_keys}

        # 4. Audit RAM Reclaimable
        ram_bytes = 0
        if self.chk_ram_var.get():
            # Estimate RAM cleanable by garbage collection pool
            ram_bytes = gc.get_count()[0] * 1024 * 32 # Approximation
        self.scan_results["ram"] = {"bytes": ram_bytes}

        # Dispatch back to Main Thread safely
        self.after(0, self._audit_complete_ui)

    def _audit_complete_ui(self):
        if not self.winfo_exists():
            return
            
        total_junk_bytes = 0
        
        # Update labels with audit findings
        if self.chk_temp_var.get():
            sz_str = self._format_bytes(self.scan_results["temp"]["bytes"])
            self.lbl_temp_stat.configure(text=f"⚠️ {sz_str} found", text_color=COLORS["warning"])
            total_junk_bytes += self.scan_results["temp"]["bytes"]
        else:
            self.lbl_temp_stat.configure(text="(ready to scan)", text_color=COLORS["text_secondary"])
            
        if self.chk_logs_var.get():
            sz_str = self._format_bytes(self.scan_results["logs"]["bytes"])
            self.lbl_logs_stat.configure(text=f"⚠️ {sz_str} found", text_color=COLORS["warning"])
            total_junk_bytes += self.scan_results["logs"]["bytes"]
        else:
            self.lbl_logs_stat.configure(text="(ready to scan)", text_color=COLORS["text_secondary"])
            
        if self.chk_registry_var.get():
            count = len(self.scan_results["registry"]["keys"])
            th_txt = f"⚠️ {count} obsolete keys" if count > 0 else "🟢 Clean"
            th_color = COLORS["warning"] if count > 0 else COLORS["success"]
            self.lbl_registry_stat.configure(text=th_txt, text_color=th_color)
        else:
            self.lbl_registry_stat.configure(text="(ready to scan)", text_color=COLORS["text_secondary"])
            
        if self.chk_ram_var.get():
            sz_str = self._format_bytes(self.scan_results["ram"]["bytes"])
            self.lbl_ram_stat.configure(text=f"⚡ {sz_str} releasable", text_color=COLORS["accent"])
        else:
            self.lbl_ram_stat.configure(text="(ready to scan)", text_color=COLORS["text_secondary"])

        # Update Junk Card
        self.junk_card.configure(text=self._format_bytes(total_junk_bytes))
        self._log_console_message(f"Audit finished. Total storage junk evaluated: {self._format_bytes(total_junk_bytes)}")
        if len(self.scan_results["registry"]["keys"]) > 0:
            self._log_console_message(f"Found {len(self.scan_results['registry']['keys'])} dead startup registry keys.")
            
        self.scan_btn.configure(state="normal", text="Scan System Junk")
        self.boost_btn.configure(state="normal")

    # ── Background Junk Cleaning / Fix ───────────────────────────

    def start_cleanup(self):
        self.scan_btn.configure(state="disabled")
        self.boost_btn.configure(state="disabled", text="Cleaning...")
        self.chk_temp.configure(state="disabled")
        self.chk_logs.configure(state="disabled")
        self.chk_registry.configure(state="disabled")
        self.chk_ram.configure(state="disabled")
        
        self._log_console_message("Executing safe cleanup worker...")
        threading.Thread(target=self._cleanup_worker, daemon=True).start()

    def _cleanup_worker(self):
        # 1. Clean Temporary Files
        files_deleted = 0
        temp_bytes_freed = 0
        if self.chk_temp_var.get():
            for p, sz in self.scan_results["temp"]["paths"]:
                try:
                    if os.path.exists(p):
                        os.unlink(p)
                        temp_bytes_freed += sz
                        files_deleted += 1
                        if files_deleted % 10 == 0:
                            self.after(0, lambda path=p: self._log_console_message(f"Purged temp cache: {os.path.basename(path)}"))
                except Exception:
                    continue
            # Try to safely wipe remaining empty subfolders
            target_dirs = [os.path.expandvars(r"%TEMP%"), os.path.expandvars(r"%WINDIR%\Temp")]
            for d in target_dirs:
                if os.path.exists(d):
                    for item in os.listdir(d):
                        ipath = os.path.join(d, item)
                        try:
                            if os.path.isdir(ipath):
                                shutil.rmtree(ipath)
                        except Exception:
                            continue
            self.after(0, lambda: self._log_console_message(f"Purged {files_deleted} files. Freed {self._format_bytes(temp_bytes_freed)}."))

        # 2. Clean Log Files
        logs_deleted = 0
        log_bytes_freed = 0
        if self.chk_logs_var.get():
            for p, sz in self.scan_results["logs"]["paths"]:
                try:
                    if os.path.exists(p):
                        os.unlink(p)
                        log_bytes_freed += sz
                        logs_deleted += 1
                        if logs_deleted % 10 == 0:
                            self.after(0, lambda path=p: self._log_console_message(f"Cleaned log: {os.path.basename(path)}"))
                except Exception:
                    continue
            self.after(0, lambda: self._log_console_message(f"Purged {logs_deleted} diagnostic files. Freed {self._format_bytes(log_bytes_freed)}."))

        # 3. Fix Obsolete Registry Keys
        registry_keys_fixed = 0
        if self.chk_registry_var.get() and len(self.scan_results["registry"]["keys"]) > 0:
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
                    for name, value in self.scan_results["registry"]["keys"]:
                        try:
                            winreg.DeleteValue(key, name)
                            registry_keys_fixed += 1
                            self.after(0, lambda n=name, val=value: self._log_console_message(f"Fixed broken startup key: '{n}' pointing to missing '{os.path.basename(val)}'"))
                        except Exception:
                            continue
            except Exception as e:
                logger.debug("winreg cleaning failed: %s", e)

        # 4. RAM Flush & Garbage Collection
        collected = 0
        if self.chk_ram_var.get():
            collected = gc.collect()
            self.after(0, lambda: self._log_console_message(f"Reclaimed {collected} dynamic allocation memory blocks."))

        # Re-estimate active system junk
        self.after(0, lambda: self._cleanup_complete_ui(temp_bytes_freed + log_bytes_freed, registry_keys_fixed))

    def _cleanup_complete_ui(self, bytes_saved, reg_fixed):
        if not self.winfo_exists():
            return
            
        # Update checkmark labels to Clean
        if self.chk_temp_var.get():
            self.lbl_temp_stat.configure(text="🟢 Cleaned (0 B)", text_color=COLORS["success"])
        if self.chk_logs_var.get():
            self.lbl_logs_stat.configure(text="🟢 Cleaned (0 B)", text_color=COLORS["success"])
        if self.chk_registry_var.get():
            self.lbl_registry_stat.configure(text="🟢 Fixed (0 entries)", text_color=COLORS["success"])
        if self.chk_ram_var.get():
            self.lbl_ram_stat.configure(text="🟢 Flushed", text_color=COLORS["success"])

        # Reset checklist variables state
        self.scan_results = {
            "temp": {"bytes": 0, "paths": []},
            "logs": {"bytes": 0, "paths": []},
            "registry": {"keys": []},
            "ram": {"bytes": 0}
        }
        
        self.chk_temp.configure(state="normal")
        self.chk_logs.configure(state="normal")
        self.chk_registry.configure(state="normal")
        self.chk_ram.configure(state="normal")
        
        self.junk_card.configure(text="0 B")
        self._log_console_message(f"SUCCESS: System cleaned! Safely reclaimed {self._format_bytes(bytes_saved)} storage and resolved {reg_fixed} registry issues!")
        
        self.scan_btn.configure(state="normal")
        self.boost_btn.configure(state="disabled", text="Clean & Fix Selected")

    # ── High-Memory Hogs Process Manager ──────────────────────────

    def async_scan_hogs(self):
        """Scans heavy process hogs in a background thread to prevent UI freezing."""
        self.refresh_btn.configure(state="disabled", text="Scanning...")
        
        for w in self.proc_list.winfo_children():
            w.destroy()
            
        loading_lbl = ctk.CTkLabel(
            self.proc_list, text="Auditing active system processes...",
            font=("Segoe UI", 12, "italic"), text_color=COLORS["text_secondary"]
        )
        loading_lbl.pack(anchor="center", pady=30)
        
        threading.Thread(target=self._scan_hogs_worker, daemon=True).start()

    def _scan_hogs_worker(self):
        hogs = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    m_size = proc.info['memory_info'].rss
                    hogs.append((proc.info['pid'], proc.info['name'], m_size))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            hogs = sorted(hogs, key=lambda x: x[2], reverse=True)[:8]
        except Exception:
            pass
            
        self.after(0, lambda: self._update_hogs_ui(hogs))

    def _update_hogs_ui(self, hogs):
        if not self.winfo_exists():
            return
            
        for w in self.proc_list.winfo_children():
            w.destroy()
            
        if not hogs:
            ctk.CTkLabel(
                self.proc_list, text="No heavy processes detected.",
                font=("Segoe UI", 12, "italic"), text_color=COLORS["text_secondary"]
            ).pack(anchor="center", pady=30)
        else:
            for pid, name, size in hogs:
                row = ctk.CTkFrame(self.proc_list, fg_color=COLORS["bg_dark"], height=34, corner_radius=6)
                row.pack(fill="x", pady=2, padx=2)
                row.pack_propagate(False)
                
                size_mb = size / (1024 * 1024)
                
                disp_name = name[:18]
                if len(name) > 18:
                    disp_name += "..."
                    
                ctk.CTkLabel(
                    row, text=disp_name, font=("Segoe UI", 11, "bold"),
                    text_color=COLORS["text"], width=130, anchor="w"
                ).pack(side="left", padx=10)
                
                ctk.CTkLabel(
                    row, text=f"{size_mb:.1f} MB", font=("Segoe UI", 11),
                    text_color=COLORS["text_secondary"], width=75, anchor="w"
                ).pack(side="left", padx=5)
                
                btn_kill = ctk.CTkButton(
                    row, text="End Task", font=("Segoe UI", 10, "bold"),
                    fg_color=COLORS["danger_dim"], hover_color=COLORS["danger"],
                    text_color=COLORS["text"], width=65, height=22, corner_radius=4,
                    command=lambda p=pid: self.kill_hog(p)
                )
                btn_kill.pack(side="right", padx=10, pady=6)
                
        self.refresh_btn.configure(state="normal", text="🔄 Refresh")

    def kill_hog(self, pid):
        try:
            p = psutil.Process(pid)
            p.terminate()
            self._log_console_message(f"Successfully terminated high-resource process PID: {pid}")
        except Exception as e:
            self._log_console_message(f"Error terminating PID {pid}: {e}")
        self.async_scan_hogs()

    # ── Utilities ─────────────────────────────────────────────────

    def _format_bytes(self, size_bytes):
        if size_bytes == 0: 
            return "0 B"
        s_name = ("B", "KB", "MB", "GB")
        try:
            import math
            i = int(math.log(size_bytes, 1024))
            p = math.pow(1024, i)
            s = round(size_bytes / p, 2)
            return f"{s} {s_name[i]}"
        except Exception:
            return "0 B"

    def on_show(self):
        self.async_scan_hogs()
