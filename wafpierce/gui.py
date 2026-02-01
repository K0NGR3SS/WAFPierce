"""Tkinter GUI for WAFPierce (subprocess-backed)

This GUI runs the existing CLI module `wafpierce.pierce` in a subprocess so
we don't need to modify any scanner code. That lets the GUI provide a
responsive Start / Stop experience and save results to disk.

Run with:
    python3 -m wafpierce.gui
"""
from __future__ import annotations

import sys
import threading
import queue
import subprocess
import tempfile
import json
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Any, Optional


class PierceGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WAFPierce - GUI")
        # Apply a dark theme before building UI
        try:
            self._apply_dark_theme()
        except Exception:
            # If theme application fails, proceed with defaults
            pass
        self._build_ui()

        self._queue: "queue.Queue[Any]" = queue.Queue()
        self._proc: Optional[subprocess.Popen] = None
        self._scan_thread = None
        self._results = []
        self._tmp_result_paths = []
        self._abort = False

        # Start polling queue
        self.root.after(100, self._poll_queue)

    def _apply_dark_theme(self) -> None:
        """Apply a simple dark color scheme with red/orange/blue accents.

        This uses ttk.Style where possible and falls back to widget-specific
        configuration for classic widgets (Listbox, Text).
        """
        # Core palette
        bg = "#696969"           # page background (near-black)
        panel_bg = "#FFFFFF"     # panels/frames
        fg = "#FF0000"           # primary foreground (pale blue/white)
        hint_blue = '#4da6ff'    # blue accent
        hint_orange = '#ff8c42'  # orange accent
        hint_red = '#ff4d4d'     # red accent

        # Root/window background
        try:
            self.root.configure(bg=bg)
        except Exception:
            pass

        style = ttk.Style(self.root)
        # Use clam for better theming support if available
        try:
            style.theme_use('clam')
        except Exception:
            pass

        # Frame and label styles
        style.configure('TFrame', background=panel_bg)
        style.configure('TLabel', background=panel_bg, foreground=fg)

        # Button styling with orange accents for primary actions
        style.configure('TButton', background=panel_bg, foreground=fg)
        style.map('TButton', background=[('active', hint_blue)], foreground=[('disabled', '#7a7f86')])

        # Entry / Spinbox styling
        style.configure('TEntry', fieldbackground='#0b0c0f', foreground=fg)
        style.configure('TSpinbox', fieldbackground='#0b0c0f', foreground=fg)

        # Progressbar accents
        style.configure('Horizontal.TProgressbar', troughcolor=panel_bg, background=hint_blue)

        # Text and Listbox (classic widgets) need manual config after creation
        # We'll store palette on the instance for later use when creating widgets
        self._palette = {
            'bg': bg,
            'panel_bg': panel_bg,
            'fg': fg,
            'hint_blue': hint_blue,
            'hint_orange': hint_orange,
            'hint_red': hint_red,
            'text_bg': '#0b0c0f',
            'select_bg': '#2b2f34'
        }
    def _build_ui(self) -> None:
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(sticky="nsew")

        # Target input + controls
        ttk.Label(frm, text="Target URL:").grid(column=0, row=0, sticky="w")
        self.target_var = tk.StringVar()
        entry = ttk.Entry(frm, textvariable=self.target_var, width=60)
        entry.grid(column=1, row=0, columnspan=2, sticky="we")
        self.add_btn = ttk.Button(frm, text="Add", command=self.add_target)
        self.add_btn.grid(column=3, row=0, sticky="w")

        # Targets listbox
        ttk.Label(frm, text="Targets:").grid(column=0, row=1, sticky="nw")
        self.targets_listbox = tk.Listbox(frm, height=6, selectmode=tk.SINGLE)
        self.targets_listbox.grid(column=1, row=1, columnspan=2, rowspan=2, sticky="nsew")
        targets_sb = ttk.Scrollbar(frm, orient="vertical", command=self.targets_listbox.yview)
        targets_sb.grid(column=3, row=1, rowspan=2, sticky="ns")
        self.targets_listbox['yscrollcommand'] = targets_sb.set

        self.remove_btn = ttk.Button(frm, text="Remove", command=self.remove_selected)
        self.remove_btn.grid(column=0, row=2, sticky="w")

        self.loadfile_btn = ttk.Button(frm, text="Load from file...", command=self.load_targets_from_file)
        self.loadfile_btn.grid(column=0, row=3, sticky="w")

        # Threading/options
        ttk.Label(frm, text="Threads:").grid(column=0, row=4, sticky="w")
        self.threads_var = tk.IntVar(value=10)
        ttk.Spinbox(frm, from_=1, to=200, textvariable=self.threads_var, width=6).grid(column=1, row=4, sticky="w")

        ttk.Label(frm, text="Delay (s):").grid(column=2, row=4, sticky="e")
        self.delay_var = tk.DoubleVar(value=0.2)
        ttk.Spinbox(frm, from_=0.0, to=5.0, increment=0.05, textvariable=self.delay_var, width=6).grid(column=3, row=4, sticky="w")

        # Buttons: Start / Stop / Save / Clear
        self.start_btn = ttk.Button(frm, text="Start Scan", command=self.start_scan)
        self.start_btn.grid(column=0, row=5, pady=(8, 8), sticky="w")

        self.stop_btn = ttk.Button(frm, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(column=1, row=5, pady=(8, 8), sticky="w")

        self.save_btn = ttk.Button(frm, text="Save Results...", command=self.save_results, state="disabled")
        self.save_btn.grid(column=2, row=5, pady=(8, 8), sticky="w")

        self.clear_btn = ttk.Button(frm, text="Clear Log", command=self._clear_log)
        self.clear_btn.grid(column=3, row=5, pady=(8, 8), sticky="w")

        # Status + progress
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm, textvariable=self.status_var).grid(column=0, row=6, columnspan=4, sticky="w")

        self.progress = ttk.Progressbar(frm, mode="indeterminate")
        self.progress.grid(column=0, row=7, columnspan=4, sticky="we", pady=(4, 8))

        # Log area
        self.log = tk.Text(frm, wrap="word", height=20, width=90, state="disabled")
        self.log.grid(column=0, row=8, columnspan=4, sticky="nsew")

        sb = ttk.Scrollbar(frm, orient="vertical", command=self.log.yview)
        sb.grid(column=4, row=8, sticky="ns")
        self.log['yscrollcommand'] = sb.set

        # Apply palette to classic widgets if available
        pal = getattr(self, '_palette', None)
        if pal:
            try:
                entry.configure(background=pal['text_bg'], foreground=pal['fg'], insertbackground=pal['hint_orange'])
            except Exception:
                pass
            try:
                self.targets_listbox.configure(background=pal['text_bg'], foreground=pal['fg'], selectbackground=pal['select_bg'])
            except Exception:
                pass
            try:
                self.log.configure(background=pal['text_bg'], foreground=pal['fg'], insertbackground=pal['hint_orange'], selectbackground=pal['select_bg'])
            except Exception:
                pass

        # Layout resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(8, weight=1)

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.configure(state="disabled")

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(tk.END, text)
        self.log.see(tk.END)
        self.log.configure(state="disabled")
    def add_target(self) -> None:
        t = self.target_var.get().strip()
        if not t:
            return
        # avoid duplicates
        existing = list(self.targets_listbox.get(0, tk.END))
        if t in existing:
            return
        self.targets_listbox.insert(tk.END, t)
        self.target_var.set("")

    def remove_selected(self) -> None:
        sel = self.targets_listbox.curselection()
        if not sel:
            return
        self.targets_listbox.delete(sel[0])

    def load_targets_from_file(self) -> None:
        path = filedialog.askopenfilename(title="Open target list", filetypes=[('Text files','*.txt'), ('All files','*.*')])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # add if not present
                    if line not in self.targets_listbox.get(0, tk.END):
                        self.targets_listbox.insert(tk.END, line)
        except Exception as e:
            messagebox.showerror('Load failed', f'Failed to load targets: {e}')

    def start_scan(self) -> None:
        if self._scan_thread is not None:
            return

        # Collect targets from listbox; fallback to single entry
        targets = list(self.targets_listbox.get(0, tk.END))
        if not targets:
            t = self.target_var.get().strip()
            if t:
                targets = [t]

        if not targets:
            messagebox.showwarning("Missing target", "Please add at least one target or enter a target URL")
            return

        threads = int(self.threads_var.get())
        delay = float(self.delay_var.get())

        # reset state
        self._results = []
        self._tmp_result_paths = []
        self._abort = False

        # UI state
        self.status_var.set(f"Running ({len(targets)} target(s))")
        self.progress.start(50)
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.save_btn.config(state="disabled")

        # Start scan thread
        self._scan_thread = threading.Thread(target=self._scan_worker, args=(targets, threads, delay), daemon=True)
        self._scan_thread.start()

    def _scan_worker(self, targets: list, threads: int, delay: float) -> None:
        q = self._queue
        for idx, target in enumerate(targets, start=1):
            if self._abort:
                q.put(f"[!] Aborted before starting {target}\n")
                break

            q.put(f"\n[*] Starting target {idx}/{len(targets)}: {target}\n")

            # prepare tmp path
            tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            tmpf.close()
            tmp_path = tmpf.name
            self._tmp_result_paths.append(tmp_path)

            cmd = [sys.executable, "-m", "wafpierce.pierce", target, "-t", str(threads), "-d", str(delay), "-o", tmp_path]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            except Exception as e:
                q.put(f"[!] Failed to start scanner for {target}: {e}\n")
                continue

            self._proc = proc
            # stream output
            try:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        q.put(line)
                        if self._abort:
                            try:
                                proc.terminate()
                            except:
                                pass
                            break
            except Exception as e:
                q.put(f"[!] Error reading output for {target}: {e}\n")

            proc.wait()
            self._proc = None

            # try load results
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            self._results.extend(data)
                            q.put(f"[+] Loaded {len(data)} result(s) from {tmp_path}\n")
                        else:
                            q.put(f"[!] Results file for {target} did not contain a list\n")
                except Exception:
                    q.put(f"[!] No JSON results or failed to parse results for {target}\n")

            if self._abort:
                q.put("[!] Scan aborted by user\n")
                break

        # finished all targets or aborted
        q.put({"__finished__": True})

    def stop_scan(self) -> None:
        if self._scan_thread is None and self._proc is None:
            return

        if messagebox.askyesno("Stop scan", "Are you sure you want to stop the running scan?"):
            self._abort = True
            if self._proc is not None:
                try:
                    self._proc.terminate()
                except Exception as e:
                    self._append_log(f"[!] Failed to terminate process: {e}\n")
            self.status_var.set("Stopping...")

    def save_results(self) -> None:
        if not self._results:
            messagebox.showinfo("No results", "There are no results to save yet.")
            return

        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json'), ('All files', '*.*')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self._results, f, indent=2)
            messagebox.showinfo('Saved', f'Results saved to {path}')
        except Exception as e:
            messagebox.showerror('Save failed', f'Failed to save results: {e}')

    def _poll_queue(self) -> None:
        q = self._queue
        try:
            while True:
                item = q.get_nowait()
                if isinstance(item, dict) and item.get('__finished__'):
                    # Process finished
                    self._proc = None
                    self._scan_thread = None
                    self.progress.stop()
                    self.status_var.set("Idle")
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    if self._results:
                        self.save_btn.config(state="normal")
                    self._append_log("[+] Run finished\n")
                    continue

                self._append_log(str(item))
        except queue.Empty:
            pass

        self.root.after(100, self._poll_queue)


def main() -> None:
    root = tk.Tk()
    app = PierceGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
