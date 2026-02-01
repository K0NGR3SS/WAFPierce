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
import concurrent.futures
import time

# path to bundled logo if present
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'logo_Temp', 'logo_wafpierce.png')


class PierceGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WAFPierce - GUI")
        # set window icon from bundled logo if available (tkinter)
        try:
            if os.path.exists(LOGO_PATH):
                img = tk.PhotoImage(file=LOGO_PATH)
                try:
                    self.root.iconphoto(False, img)
                    # keep a reference
                    self._tk_icon = img
                except Exception:
                    pass
        except Exception:
            pass
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
        # track multiple running subprocesses when doing GUI-level parallelism
        self._running_procs = {}
        self._results = []
        self._tmp_result_paths = []
        # map target -> tmp result path (populated when scan starts for a target)
        self._target_tmp_map = {}
        self._abort = False

        # Start polling queue
        self.root.after(100, self._poll_queue)

    def _apply_dark_theme(self) -> None:
        """Apply a dark color scheme similar to the attached reference.

        Uses ttk.Style for themed widgets and falls back to direct widget
        config for classic widgets (Text, Listbox).
        """
        # Colors chosen to match the screenshot's dark slate appearance
        bg = '#17181b'           # window background
        panel_bg = '#1f2328'     # panel background
        fg = '#d7e1ea'           # foreground text
        hint_blue = '#3b82f6'    # blue accent
        hint_orange = '#ff8c42'  # orange accent
        hint_red = '#ff4d4d'     # red accent

        # Try to set window background
        try:
            self.root.configure(bg=bg)
        except Exception:
            pass

        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except Exception:
            pass

        # Base styles
        style.configure('TFrame', background=panel_bg)
        style.configure('TLabel', background=panel_bg, foreground=fg)
        style.configure('TEntry', fieldbackground='#16181a', foreground=fg)
        style.configure('TSpinbox', fieldbackground='#16181a', foreground=fg)

        # Buttons: create accent and danger variants
        style.configure('TButton', background=panel_bg, foreground=fg)
        style.configure('Accent.TButton', foreground=fg, background=panel_bg)
        style.map('Accent.TButton', background=[('!disabled', hint_orange), ('active', hint_blue)])
        style.configure('Danger.TButton', foreground=fg, background=panel_bg)
        style.map('Danger.TButton', background=[('!disabled', hint_red), ('active', '#ff8080')])

        # Notebook tabs
        style.configure('TNotebook', background=panel_bg)
        style.configure('TNotebook.Tab', background=panel_bg, foreground=fg)
        style.map('TNotebook.Tab', background=[('selected', '#272b30')], foreground=[('selected', fg)])

        # Progressbar color
        style.configure('Horizontal.TProgressbar', troughcolor=panel_bg, background=hint_blue)

        # Store palette for classic widgets
        self._palette = {
            'bg': bg,
            'panel_bg': panel_bg,
            'fg': fg,
            'hint_blue': hint_blue,
            'hint_orange': hint_orange,
            'hint_red': hint_red,
            'text_bg': '#16181a',
            'select_bg': '#272b30'
        }
    def _build_ui(self) -> None:
        # Root padding and overall paned layout
        self.root.configure(padx=8, pady=8)
        main_pane = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        main_pane.grid(sticky='nsew')

        # Left panel: controls + targets
        left = ttk.Frame(main_pane, width=360)
        right = ttk.Frame(main_pane)
        main_pane.add(left, weight=0)
        main_pane.add(right, weight=1)

        # Toolbar (top of left pane)
        toolbar = ttk.Frame(left)
        toolbar.pack(fill='x', padx=6, pady=(6, 4))

        self.start_btn = ttk.Button(toolbar, text="Start", command=self.start_scan, style='Accent.TButton')
        self.start_btn.pack(side='left', padx=(0, 6))
        self.stop_btn = ttk.Button(toolbar, text="Stop", command=self.stop_scan, state="disabled", style='Danger.TButton')
        self.stop_btn.pack(side='left', padx=(0, 6))
        self.save_btn = ttk.Button(toolbar, text="Save", command=self.save_results, state="disabled", style='Accent.TButton')
        self.save_btn.pack(side='left', padx=(0, 6))
        self.copy_btn = ttk.Button(toolbar, text="Copy", command=self.copy_output)
        self.copy_btn.pack(side='left', padx=(0, 6))
        # Auto-clean toggle and manual cleanup
        self.auto_clean_var = tk.BooleanVar(value=False)
        try:
            self.auto_clean_chk = ttk.Checkbutton(toolbar, text='Auto-clean', variable=self.auto_clean_var)
            self.auto_clean_chk.pack(side='left', padx=(6,0))
        except Exception:
            pass
        try:
            self.clean_btn = ttk.Button(toolbar, text='Clean tmp', command=self.clean_tmp_files)
            self.clean_btn.pack(side='left', padx=(6,0))
        except Exception:
            pass

        # Target entry
        entry_frame = ttk.Frame(left)
        entry_frame.pack(fill='x', padx=6, pady=(2, 6))
        ttk.Label(entry_frame, text="Target URL:").pack(side='left')
        self.target_var = tk.StringVar()
        entry = ttk.Entry(entry_frame, textvariable=self.target_var)
        entry.pack(side='left', fill='x', expand=True, padx=(6, 6))
        self.add_btn = ttk.Button(entry_frame, text="Add", command=self.add_target)
        self.add_btn.pack(side='left')
        # Allow Enter to add quickly
        try:
            entry.bind('<Return>', lambda e: self.add_target())
        except Exception:
            pass

        # Targets treeview with status column
        ttk.Label(left, text="Targets:").pack(anchor='w', padx=6)
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill='both', expand=True, padx=6, pady=(2, 6))
        cols = ('target', 'status')
        self.targets_tree = ttk.Treeview(tree_frame, columns=cols, show='headings', selectmode='browse', height=8)
        self.targets_tree.heading('target', text='Target')
        self.targets_tree.heading('status', text='Status')
        self.targets_tree.column('target', width=220, anchor='w')
        self.targets_tree.column('status', width=100, anchor='center')
        self.targets_tree.pack(side='left', fill='both', expand=True)
        tree_sb = ttk.Scrollbar(tree_frame, orient='vertical', command=self.targets_tree.yview)
        tree_sb.pack(side='left', fill='y')
        self.targets_tree.configure(yscrollcommand=tree_sb.set)
        # double-click a row to open per-target details
        try:
            self.targets_tree.bind('<Double-1>', self.show_target_details)
        except Exception:
            pass
        # configure visual tags for statuses
        try:
            # subtle backgrounds to indicate state; text colors chosen for contrast
            self.targets_tree.tag_configure('queued', background=self._palette.get('panel_bg', '#1f2328'), foreground=self._palette.get('fg', '#d7e1ea'))
            self.targets_tree.tag_configure('running', background=self._palette.get('hint_blue', '#3b82f6'), foreground='#ffffff')
            self.targets_tree.tag_configure('done', background='#163f19', foreground='#d7ffdf')
            self.targets_tree.tag_configure('noresults', background=self._palette.get('text_bg', '#16181a'), foreground='#999999')
            self.targets_tree.tag_configure('parseerror', background=self._palette.get('hint_red', '#ff4d4d'), foreground='#ffffff')
            self.targets_tree.tag_configure('aborted', background=self._palette.get('hint_red', '#ff4d4d'), foreground='#ffffff')
        except Exception:
            pass

        # targets control buttons
        btns = ttk.Frame(left)
        btns.pack(fill='x', padx=6)
        self.remove_btn = ttk.Button(btns, text="Remove", command=self.remove_selected)
        self.remove_btn.pack(side='left')
        self.loadfile_btn = ttk.Button(btns, text="Load...", command=self.load_targets_from_file)
        self.loadfile_btn.pack(side='left', padx=(6, 0))

        # Options at bottom-left
        options = ttk.Frame(left)
        options.pack(fill='x', padx=6, pady=(6, 6))
        ttk.Label(options, text="Threads:").pack(side='left')
        self.threads_var = tk.IntVar(value=10)
        ttk.Spinbox(options, from_=1, to=200, textvariable=self.threads_var, width=6).pack(side='left', padx=(4, 12))
        ttk.Label(options, text="Delay (s):").pack(side='left')
        self.delay_var = tk.DoubleVar(value=0.2)
        ttk.Spinbox(options, from_=0.0, to=5.0, increment=0.05, textvariable=self.delay_var, width=6).pack(side='left', padx=(4, 0))

        # Right pane: status, progress, log
        top_right = ttk.Frame(right)
        top_right.pack(fill='x', padx=6, pady=(6, 2))
        self.status_var = tk.StringVar(value='Idle')
        ttk.Label(top_right, textvariable=self.status_var).pack(side='left')
        self.progress = ttk.Progressbar(top_right, mode='indeterminate')
        self.progress.pack(side='right', fill='x', expand=True)

        # status legend
        try:
            legend = ttk.Frame(right)
            legend.pack(fill='x', padx=6, pady=(4, 0))
            def _legend_item(text, bg):
                frm = ttk.Frame(legend)
                lbl = tk.Label(frm, text='   ', bg=bg)
                lbl.pack(side='left', padx=(0,6))
                ttk.Label(frm, text=text).pack(side='left')
                return frm
            _legend_item('Queued', self._palette.get('panel_bg', '#1f2328')).pack(side='left', padx=(0,8))
            _legend_item('Running', self._palette.get('hint_blue', '#3b82f6')).pack(side='left', padx=(0,8))
            _legend_item('Done', '#163f19').pack(side='left', padx=(0,8))
            _legend_item('Error', self._palette.get('hint_red', '#ff4d4d')).pack(side='left', padx=(0,8))
        except Exception:
            pass

        # Log area inside a labelframe
        log_frame = ttk.Labelframe(right, text='Output')
        log_frame.pack(fill='both', expand=True, padx=6, pady=(6, 6))
        # Use a monospace font for logs on Windows where available
        log_font = ('Consolas', 10) if sys.platform.startswith('win') else ('Courier New', 10)
        self.log = tk.Text(log_frame, wrap='word', height=20, width=80, state='disabled', font=log_font)
        self.log.pack(side='left', fill='both', expand=True)
        # add a subtle watermark/logo behind the log area (best-effort)
        try:
            if os.path.exists(LOGO_PATH):
                try:
                    img = tk.PhotoImage(file=LOGO_PATH)
                    # keep a reference to avoid GC
                    self._logo_img = img
                    wm = tk.Label(log_frame, image=img, bg=self._palette.get('text_bg', '#16181a'))
                    # place in center; lower it so the text stays above
                    wm.place(relx=0.5, rely=0.5, anchor='center')
                    try:
                        wm.lower(self.log)
                    except Exception:
                        pass
                    self._logo_label = wm
                except Exception:
                    pass
        except Exception:
            pass
        sb = ttk.Scrollbar(log_frame, orient='vertical', command=self.log.yview)
        sb.pack(side='left', fill='y')
        self.log['yscrollcommand'] = sb.set

        # Apply palette to classic widgets if available (entry and text)
        pal = getattr(self, '_palette', None)
        if pal:
            try:
                entry.configure(background=pal['text_bg'], foreground=pal['fg'], insertbackground=pal['hint_orange'])
            except Exception:
                pass
            try:
                self.log.configure(background=pal['text_bg'], foreground=pal['fg'], insertbackground=pal['hint_orange'], selectbackground=pal['select_bg'])
            except Exception:
                pass

        # Layout resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_pane.pack(fill='both', expand=True)

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.configure(state="disabled")

    def copy_output(self) -> None:
        """Copy the contents of the log to the clipboard."""
        try:
            content = self.log.get("1.0", tk.END).rstrip()
        except Exception:
            content = ''

        if not content:
            messagebox.showinfo("Copy", "No output to copy")
            return

        try:
            # Use the root window's clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            # optional: also update selection
            try:
                self.root.update()
            except Exception:
                pass
            messagebox.showinfo("Copied", "Log output copied to clipboard")
        except Exception as e:
            messagebox.showerror("Copy failed", f"Failed to copy to clipboard: {e}")

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(tk.END, text)
        self.log.see(tk.END)
        self.log.configure(state="disabled")
    def add_target(self) -> None:
        try:
            raw = self.target_var.get().strip()
            if not raw:
                return

            # Support adding multiple targets separated by commas or newlines
            parts = []
            for part in raw.replace(',', '\n').splitlines():
                s = part.strip()
                if s:
                    parts.append(s)

            # avoid duplicates
            existing = [self.targets_tree.set(ch, 'target') for ch in self.targets_tree.get_children()]
            for t in parts:
                if t in existing:
                    # skip duplicates
                    continue
                iid = self.targets_tree.insert('', 'end', values=(t, 'Queued'))
                try:
                    self.targets_tree.item(iid, tags=('queued',))
                except Exception:
                    pass
            self.target_var.set("")
        except Exception as e:
            messagebox.showerror('Add failed', f'Failed to add target: {e}')

    def show_target_details(self, event: Optional[tk.Event] = None) -> None:
        """Show JSON results for the selected target in a popup.

        If the per-target temporary JSON file exists, pretty-print it. If JSON
        parsing fails, show the raw file contents. If no results exist yet,
        inform the user.
        """
        sel = self.targets_tree.selection()
        if not sel:
            return
        # support single selection (first)
        item = sel[0]
        target = self.targets_tree.set(item, 'target')

        tmp_path = self._target_tmp_map.get(target)
        if not tmp_path or not os.path.exists(tmp_path):
            messagebox.showinfo('No results', f'No results available yet for {target}')
            return

        # attempt to load JSON; if that fails, show raw text
        content = None
        pretty = None
        try:
            with open(tmp_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                pretty = json.dumps(data, indent=2, ensure_ascii=False)
                content = pretty
        except Exception:
            try:
                with open(tmp_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
            except Exception as e:
                messagebox.showerror('Read failed', f'Failed to read results for {target}: {e}')
                return

        # show in a popup window
        popup = tk.Toplevel(self.root)
        popup.title(f'Results — {target}')
        popup.transient(self.root)
        popup.geometry('800x480')

        frm = ttk.Frame(popup, padding=8)
        frm.pack(fill='both', expand=True)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill='x', pady=(0, 6))
        def _save():
            path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json'),('All files','*.*')])
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as out:
                    out.write(content)
                messagebox.showinfo('Saved', f'Results saved to {path}')
            except Exception as e:
                messagebox.showerror('Save failed', f'Failed to save: {e}')

        def _copy():
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(content)
                try:
                    self.root.update()
                except Exception:
                    pass
                messagebox.showinfo('Copied', 'Results copied to clipboard')
            except Exception as e:
                messagebox.showerror('Copy failed', f'Failed to copy to clipboard: {e}')

        ttk.Button(btn_frame, text='Save...', command=_save).pack(side='left')
        ttk.Button(btn_frame, text='Copy', command=_copy).pack(side='left', padx=(6,0))

        text_frame = ttk.Frame(frm)
        text_frame.pack(fill='both', expand=True)
        font = ('Consolas', 10) if sys.platform.startswith('win') else ('Courier New', 10)
        txt = tk.Text(text_frame, wrap='none', font=font)
        txt.pack(side='left', fill='both', expand=True)
        vs = ttk.Scrollbar(text_frame, orient='vertical', command=txt.yview)
        vs.pack(side='left', fill='y')
        hs = ttk.Scrollbar(text_frame, orient='horizontal', command=txt.xview)
        hs.pack(side='bottom', fill='x')
        txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        txt.insert('1.0', content)
        txt.configure(state='disabled')

    def clean_tmp_files(self, silent: bool = False) -> None:
        """Remove temporary per-target JSON files tracked by the GUI.

        If silent is True, don't show confirmation or result messageboxes.
        """
        paths = list(self._target_tmp_map.values()) + list(self._tmp_result_paths)
        # unique and existing
        unique = []
        for p in paths:
            if not p:
                continue
            if p in unique:
                continue
            if os.path.exists(p):
                unique.append(p)

        if not unique:
            if not silent:
                messagebox.showinfo('Clean', 'No temporary result files to remove')
            return

        if not silent:
            if not messagebox.askyesno('Clean temporary files', f'Remove {len(unique)} temp file(s)?'):
                return

        removed = 0
        for p in unique:
            try:
                os.remove(p)
                removed += 1
            except Exception:
                pass

        # clear maps for removed files
        for t, p in list(self._target_tmp_map.items()):
            if not os.path.exists(p):
                self._target_tmp_map.pop(t, None)

        self._tmp_result_paths = [p for p in self._tmp_result_paths if os.path.exists(p)]

        if not silent:
            messagebox.showinfo('Clean', f'Removed {removed} file(s)')


    def remove_selected(self) -> None:
        sel = self.targets_tree.selection()
        if not sel:
            return
        for s in sel:
            self.targets_tree.delete(s)

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
                    # add if not present (check tree)
                    existing = [self.targets_tree.set(ch, 'target') for ch in self.targets_tree.get_children()]
                    if line not in existing:
                        self.targets_tree.insert('', 'end', values=(line, 'Queued'))
        except Exception as e:
            messagebox.showerror('Load failed', f'Failed to load targets: {e}')

    def start_scan(self) -> None:
        if self._scan_thread is not None:
            return

        # Collect targets from tree; fallback to single entry
        targets = [self.targets_tree.set(ch, 'target') for ch in self.targets_tree.get_children()]
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
        self._target_tmp_map = {}
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

        # Decide GUI-level concurrency: respect the threads setting but at least 1
        max_workers = max(1, min(len(targets), max(1, int(threads))))

        threads_list: list[threading.Thread] = []
        sem = threading.Semaphore(max_workers)

        def run_target(target: str, idx: int):
            nonlocal q
            # Acquire slot
            sem.acquire()
            if self._abort:
                q.put(f"[!] Aborted before starting {target}\n")
                sem.release()
                return

            q.put(f"\n[*] Starting target {idx}/{len(targets)}: {target}\n")
            q.put({"__target_update__": target, "status": "Running", "idx": idx})

            # prepare tmp path
            tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            tmpf.close()
            tmp_path = tmpf.name
            try:
                self._target_tmp_map[target] = tmp_path
            except Exception:
                pass
            try:
                self._tmp_result_paths.append(tmp_path)
            except Exception:
                pass

            cmd = [sys.executable, "-m", "wafpierce.pierce", target, "-t", str(threads), "-d", str(delay), "-o", tmp_path]
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            proc = None
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    bufsize=1,
                    env=env,
                )
            except Exception as e:
                q.put(f"[!] Failed to start scanner for {target}: {e}\n")
                if proc:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                sem.release()
                return

            # record running proc so we can terminate on abort
            try:
                self._running_procs[target] = proc
            except Exception:
                pass

            # stream output
            try:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        q.put(line)
                        if self._abort:
                            try:
                                proc.terminate()
                            except Exception:
                                pass
                            break
            except Exception as e:
                q.put(f"[!] Error reading output for {target}: {e}\n")

            proc.wait()

            # remove from running map
            try:
                self._running_procs.pop(target, None)
            except Exception:
                pass

            # try load results
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            self._results.extend(data)
                            q.put(f"[+] Loaded {len(data)} result(s) from {tmp_path}\n")
                            q.put({"__target_update__": target, "status": "Done", "count": len(data)})
                        else:
                            q.put(f"[!] Results file for {target} did not contain a list\n")
                            q.put({"__target_update__": target, "status": "NoResults"})
                except Exception:
                    q.put(f"[!] No JSON results or failed to parse results for {target}\n")
                    q.put({"__target_update__": target, "status": "ParseError"})

            if self._abort:
                q.put("[!] Scan aborted by user\n")
                q.put({"__target_update__": target, "status": "Aborted"})

            sem.release()

        # Start a thread for each target; the semaphore will limit concurrency
        for idx, target in enumerate(targets, start=1):
            t = threading.Thread(target=run_target, args=(target, idx), daemon=True)
            threads_list.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads_list:
            while t.is_alive():
                if self._abort:
                    # terminate all running processes
                    for p in list(self._running_procs.values()):
                        try:
                            p.terminate()
                        except Exception:
                            pass
                    break
                time.sleep(0.05)

        q.put({"__finished__": True})

    def stop_scan(self) -> None:
        # If there's nothing running, ignore
        if self._scan_thread is None and not self._running_procs and self._proc is None:
            return

        if messagebox.askyesno("Stop scan", "Are you sure you want to stop the running scan?"):
            self._abort = True
            # terminate any tracked running subprocesses
            try:
                for p in list(self._running_procs.values()):
                    try:
                        p.terminate()
                    except Exception:
                        pass
            except Exception:
                pass
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
            # optionally clean up temp files after successful save
            try:
                if getattr(self, 'auto_clean_var', None) and self.auto_clean_var.get():
                    self.clean_tmp_files(silent=True)
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror('Save failed', f'Failed to save results: {e}')

    def _poll_queue(self) -> None:
        q = self._queue
        try:
            while True:
                item = q.get_nowait()
                # Handle special dict messages
                if isinstance(item, dict):
                    if item.get('__finished__'):
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
                        # auto-clean temp files if requested
                        try:
                            if getattr(self, 'auto_clean_var', None) and self.auto_clean_var.get():
                                self.clean_tmp_files(silent=True)
                        except Exception:
                            pass
                        continue

                    # per-target status update
                    tgt = item.get('__target_update__')
                    if tgt:
                        status = item.get('status', '')
                        # find matching tree item and update status column
                        for ch in self.targets_tree.get_children():
                            if self.targets_tree.set(ch, 'target') == tgt:
                                display = status
                                if status == 'Done' and 'count' in item:
                                    display = f"✅ Done ({item.get('count')})"
                                elif status == 'Running':
                                    display = f"▶ Running"
                                elif status == 'Queued':
                                    display = f"• Queued"
                                elif status in ('NoResults', 'ParseError'):
                                    display = f"❌ {status}"
                                elif status == 'Aborted':
                                    display = f"⏹ Aborted"
                                self.targets_tree.set(ch, 'status', display)
                                # apply tag/color
                                tag = status.lower()
                                if tag == 'noresults':
                                    tag = 'noresults'
                                if tag not in ('queued','running','done','noresults','parseerror','aborted'):
                                    # normalize common names
                                    if tag == 'nresults':
                                        tag = 'noresults'
                                    else:
                                        tag = tag
                                try:
                                    self.targets_tree.item(ch, tags=(tag,))
                                except Exception:
                                    pass
                                break
                        # also append a short line to the log
                        self._append_log(f"[>] {tgt} -> {status}\n")
                        continue

                # Default: append as text
                self._append_log(str(item))
        except queue.Empty:
            pass

        self.root.after(100, self._poll_queue)


def main() -> None:
    # Prefer a Qt-based GUI when PySide6 is available for a modern look.
    try:
        from PySide6 import QtWidgets, QtCore
        from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                                       QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
                                       QTextEdit, QLabel, QFileDialog, QMessageBox, QCheckBox,
                                       QSpinBox, QDoubleSpinBox)
        from PySide6.QtCore import QObject, Signal
        from PySide6.QtGui import QBrush, QColor

        class QtWorker(QObject):
            finished = Signal()
            log_line = Signal(str)
            target_update = Signal(str, str, int)
            tmp_created = Signal(str, str)
            results_emitted = Signal(object)

            def __init__(self, targets, threads, delay, parent=None):
                super().__init__(parent)
                self.targets = targets
                self.threads = threads
                self.delay = delay
                self._abort = False
                # track running subprocesses so abort() can terminate them
                self._running_procs = {}

            def abort(self):
                self._abort = True
                # try to terminate any running subprocesses
                try:
                    for p in list(getattr(self, '_running_procs', {}).values()):
                        try:
                            p.terminate()
                        except Exception:
                            pass
                except Exception:
                    pass

            def run(self):
                # run targets concurrently up to the configured thread limit
                max_workers = max(1, min(len(self.targets), max(1, int(self.threads))))
                self._running_procs = {}

                def run_one(target: str, idx: int):
                    if self._abort:
                        self.log_line.emit(f"[!] Aborted before starting {target}\n")
                        return

                    self.log_line.emit(f"\n[*] Starting target {idx}/{len(self.targets)}: {target}\n")
                    self.target_update.emit(target, 'Running', idx)

                    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
                    tmpf.close()
                    tmp_path = tmpf.name
                    try:
                        self.tmp_created.emit(target, tmp_path)
                    except Exception:
                        pass

                    cmd = [sys.executable, '-m', 'wafpierce.pierce', target, '-t', str(self.threads), '-d', str(self.delay), '-o', tmp_path]
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    try:
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', bufsize=1, env=env)
                    except Exception as e:
                        self.log_line.emit(f"[!] Failed to start scanner for {target}: {e}\n")
                        return

                    self._running_procs[target] = proc

                    try:
                        if proc.stdout is not None:
                            for line in proc.stdout:
                                self.log_line.emit(line)
                                if self._abort:
                                    try:
                                        proc.terminate()
                                    except Exception:
                                        pass
                                    break
                    except Exception as e:
                        self.log_line.emit(f"[!] Error reading output for {target}: {e}\n")

                    proc.wait()
                    self._running_procs.pop(target, None)

                    if os.path.exists(tmp_path):
                        try:
                            with open(tmp_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                if isinstance(data, list):
                                    self.log_line.emit(f"[+] Loaded {len(data)} result(s) from {tmp_path}\n")
                                    try:
                                        self.results_emitted.emit(data)
                                    except Exception:
                                        pass
                                    self.target_update.emit(target, 'Done', len(data))
                                else:
                                    self.log_line.emit(f"[!] Results file for {target} did not contain a list\n")
                                    self.target_update.emit(target, 'NoResults', 0)
                        except Exception:
                            self.log_line.emit(f"[!] No JSON results or failed to parse results for {target}\n")
                            self.target_update.emit(target, 'ParseError', 0)

                    if self._abort:
                        self.log_line.emit('[!] Scan aborted by user\n')
                        self.target_update.emit(target, 'Aborted', 0)

                # run with a small thread pool inside this QThread
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                        futures = [ex.submit(run_one, target, idx) for idx, target in enumerate(self.targets, start=1)]
                        for fut in concurrent.futures.as_completed(futures):
                            if self._abort:
                                # terminate any remaining procs
                                for p in list(self._running_procs.values()):
                                    try:
                                        p.terminate()
                                    except Exception:
                                        pass
                                break
                except Exception as e:
                    self.log_line.emit(f"[!] Worker execution error: {e}\n")

                self.finished.emit()

        class PierceQtApp(QWidget):
            def __init__(self):
                super().__init__()
                self.setWindowTitle('WAFPierce - GUI (Qt)')
                self.resize(1000, 640)

                self._worker_thread = None
                self._worker = None
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}

                self._build_ui()

            def _build_ui(self):
                v = QVBoxLayout(self)

                # top controls
                top = QHBoxLayout()
                self.target_edit = QLineEdit()
                add_btn = QPushButton('Add')
                add_btn.clicked.connect(self.add_target)
                top.addWidget(QLabel('Target URL:'))
                top.addWidget(self.target_edit)
                top.addWidget(add_btn)
                v.addLayout(top)

                # options (threads / delay)
                opts = QHBoxLayout()
                self.threads_spin = QSpinBox()
                self.threads_spin.setRange(1, 200)
                self.threads_spin.setValue(10)
                self.delay_spin = QDoubleSpinBox()
                self.delay_spin.setRange(0.0, 5.0)
                self.delay_spin.setSingleStep(0.05)
                self.delay_spin.setValue(0.2)
                opts.addWidget(QLabel('Threads:'))
                opts.addWidget(self.threads_spin)
                opts.addSpacing(10)
                opts.addWidget(QLabel('Delay (s):'))
                opts.addWidget(self.delay_spin)
                v.addLayout(opts)

                # legend for status colors
                try:
                    legend_h = QHBoxLayout()
                    def _legend_label(text, color):
                        lbl = QLabel(text)
                        lbl.setStyleSheet(f'background:{color}; padding:4px; color: white; border-radius:3px')
                        return lbl
                    legend_h.addWidget(_legend_label('Queued', '#2b2f33'))
                    legend_h.addWidget(_legend_label('Running', '#3b82f6'))
                    legend_h.addWidget(_legend_label('Done', '#163f19'))
                    legend_h.addWidget(_legend_label('Error', '#ff4d4d'))
                    v.addLayout(legend_h)
                except Exception:
                    pass

                # middle: tree and log
                middle = QHBoxLayout()
                self.tree = QTreeWidget()
                self.tree.setColumnCount(2)
                self.tree.setHeaderLabels(['Target', 'Status'])
                self.tree.itemDoubleClicked.connect(self.show_target_details)
                middle.addWidget(self.tree, 2)

                right_v = QVBoxLayout()
                self.log = QTextEdit()
                self.log.setReadOnly(True)
                # attempt to set a faint watermark background using the bundled logo
                try:
                    if os.path.exists(LOGO_PATH):
                        from PySide6.QtGui import QPixmap, QPainter
                        from PySide6.QtCore import Qt
                        pix = QPixmap(LOGO_PATH)
                        if not pix.isNull():
                            # scale to a reasonable size for a watermark
                            scaled = pix.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                            tmpf.close()
                            trans = QPixmap(scaled.size())
                            trans.fill(Qt.transparent)
                            p = QPainter(trans)
                            try:
                                p.setOpacity(0.08)
                                p.drawPixmap(0, 0, scaled)
                            finally:
                                p.end()
                            trans.save(tmpf.name)
                            # use a posix-style path for Qt stylesheets (works cross-platform)
                            try:
                                from pathlib import Path
                                css_path = Path(tmpf.name).as_posix()
                            except Exception:
                                css_path = tmpf.name.replace('\\', '/')
                            # set as background image for the QTextEdit
                            self.log.setStyleSheet(
                                f"background-image: url('{css_path}'); background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
                            )
                            # keep path so it isn't GC'd and can be cleaned later
                            self._qt_watermark_tmp = tmpf.name
                except Exception:
                    pass
                right_v.addWidget(QLabel('Output'))
                right_v.addWidget(self.log, 1)
                middle.addLayout(right_v, 3)
                v.addLayout(middle, 1)

                # bottom controls
                bottom = QHBoxLayout()
                self.start_btn = QPushButton('Start')
                self.start_btn.clicked.connect(self.start_scan)
                self.stop_btn = QPushButton('Stop')
                self.stop_btn.setEnabled(False)
                self.stop_btn.clicked.connect(self.stop_scan)
                self.save_btn = QPushButton('Save')
                self.save_btn.setEnabled(False)
                self.save_btn.clicked.connect(self.save_results)
                self.auto_clean_chk = QCheckBox('Auto-clean')
                self.clean_btn = QPushButton('Clean tmp')
                self.clean_btn.clicked.connect(self.clean_tmp_files)
                bottom.addWidget(self.start_btn)
                bottom.addWidget(self.stop_btn)
                bottom.addWidget(self.save_btn)
                bottom.addWidget(self.auto_clean_chk)
                bottom.addWidget(self.clean_btn)
                v.addLayout(bottom)

            def append_log(self, text: str):
                self.log.append(text)

            def add_target(self):
                text = self.target_edit.text().strip()
                if not text:
                    return
                parts = [p.strip() for p in text.replace(',', '\n').splitlines() if p.strip()]
                existing = [self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
                for p in parts:
                    if p in existing:
                        continue
                    it = QTreeWidgetItem([p, 'Queued'])
                    it.setData(0, 0, p)
                    self.tree.addTopLevelItem(it)
                self.target_edit.clear()

            def start_scan(self):
                if self._worker_thread is not None:
                    return
                targets = [self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
                if not targets:
                    t = self.target_edit.text().strip()
                    if t:
                        targets = [t]
                if not targets:
                    QMessageBox.warning(self, 'Missing target', 'Please add at least one target')
                    return
                threads = int(self.threads_spin.value())
                delay = float(self.delay_spin.value())
                # reset
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}

                self._worker = QtWorker(targets, threads, delay)
                self._worker_thread = QtCore.QThread()
                self._worker.moveToThread(self._worker_thread)
                self._worker.log_line.connect(self.append_log)
                self._worker.target_update.connect(self._on_target_update)
                self._worker.tmp_created.connect(self._on_tmp_created)
                self._worker.results_emitted.connect(self._on_results_emitted)
                self._worker.finished.connect(self._on_finished)
                self._worker_thread.started.connect(self._worker.run)
                self._worker_thread.start()
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
                # disable controls while running
                try:
                    self.threads_spin.setEnabled(False)
                    self.delay_spin.setEnabled(False)
                except Exception:
                    pass

            def stop_scan(self):
                if self._worker:
                    self._worker.abort()
                self.stop_btn.setEnabled(False)
                self.append_log('[!] Stop requested')

            def _on_target_update(self, target, status, extra):
                # update tree row matching target
                for i in range(self.tree.topLevelItemCount()):
                    it = self.tree.topLevelItem(i)
                    if it.text(0) == target:
                        if status == 'Done':
                            it.setText(1, f'Done ({extra})')
                            try:
                                it.setBackground(0, QBrush(QColor('#163f19')))
                            except Exception:
                                pass
                        elif status == 'Running':
                            it.setText(1, 'Running')
                            try:
                                it.setBackground(0, QBrush(QColor('#3b82f6')))
                            except Exception:
                                pass
                        else:
                            it.setText(1, status)
                        break

            def _on_tmp_created(self, target, tmp_path):
                try:
                    self._target_tmp_map[target] = tmp_path
                except Exception:
                    pass
                try:
                    self._tmp_result_paths.append(tmp_path)
                except Exception:
                    pass

            def _on_results_emitted(self, data):
                try:
                    if isinstance(data, list):
                        self._results.extend(data)
                        # enable save button when we have any results
                        if self._results:
                            self.save_btn.setEnabled(True)
                except Exception:
                    pass

            def _on_finished(self):
                self.append_log('[+] Run finished')
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                try:
                    self.threads_spin.setEnabled(True)
                    self.delay_spin.setEnabled(True)
                except Exception:
                    pass
                if self.auto_clean_chk.isChecked():
                    self.clean_tmp_files(silent=True)
                # clean up worker thread
                try:
                    if self._worker_thread is not None:
                        self._worker_thread.quit()
                        self._worker_thread.wait()
                except Exception:
                    pass
                self._worker = None
                self._worker_thread = None

            def save_results(self):
                path, _ = QFileDialog.getSaveFileName(self, 'Save results', filter='JSON (*.json)')
                if not path:
                    return
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(self._results, f, indent=2)
                    QMessageBox.information(self, 'Saved', f'Results saved to {path}')
                    if self.auto_clean_chk.isChecked():
                        self.clean_tmp_files(silent=True)
                except Exception as e:
                    QMessageBox.critical(self, 'Save failed', str(e))

            def show_target_details(self, item, col=None):
                target = item.text(0)
                tmp = self._target_tmp_map.get(target)
                if not tmp or not os.path.exists(tmp):
                    QMessageBox.information(self, 'No results', f'No results for {target}')
                    return
                try:
                    with open(tmp, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        pretty = json.dumps(data, indent=2, ensure_ascii=False)
                except Exception:
                    with open(tmp, 'r', encoding='utf-8', errors='replace') as f:
                        pretty = f.read()
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(f'Results — {target}')
                dlg.resize(800, 480)
                layout = QtWidgets.QVBoxLayout(dlg)
                te = QTextEdit()
                te.setPlainText(pretty)
                te.setReadOnly(True)
                layout.addWidget(te)
                dlg.exec()

            def clean_tmp_files(self, silent: bool = False):
                paths = list(self._target_tmp_map.values()) + list(self._tmp_result_paths)
                unique = []
                for p in paths:
                    if not p or p in unique:
                        continue
                    if os.path.exists(p):
                        unique.append(p)
                if not unique:
                    if not silent:
                        QMessageBox.information(self, 'Clean', 'No temporary result files to remove')
                    return
                if not silent:
                    if QMessageBox.question(self, 'Clean', f'Remove {len(unique)} files?') != QMessageBox.Yes:
                        return
                removed = 0
                for p in unique:
                    try:
                        os.remove(p)
                        removed += 1
                    except Exception:
                        pass
                # cleanup mapping
                for t, p in list(self._target_tmp_map.items()):
                    if not os.path.exists(p):
                        self._target_tmp_map.pop(t, None)
                self._tmp_result_paths = [p for p in self._tmp_result_paths if os.path.exists(p)]
                if not silent:
                    QMessageBox.information(self, 'Clean', f'Removed {removed} file(s)')

        def run_qt():
            app = QApplication([])
            # set application icon from bundled logo when available
            try:
                if os.path.exists(LOGO_PATH):
                    from PySide6.QtGui import QIcon
                    icon = QIcon(LOGO_PATH)
                    app.setWindowIcon(icon)
            except Exception:
                pass
            w = PierceQtApp()
            w.show()
            # run the Qt event loop and capture exit code so we can cleanup the tmp watermark
            rc = app.exec()
            try:
                tmp = getattr(w, '_qt_watermark_tmp', None)
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except Exception:
                        pass
            except Exception:
                pass
            return rc

        # run Qt GUI
        return_code = run_qt()
        sys.exit(return_code)
    except Exception:
        # Fall back to the existing tkinter GUI implementation
        root = tk.Tk()
        app = PierceGUI(root)
        root.mainloop()


if __name__ == '__main__':
    main()
