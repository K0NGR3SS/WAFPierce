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
import time
import concurrent.futures
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont
from typing import Optional

# path to bundled logo (used for watermark/icon)
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'logo_Temp', 'logo_wafpierce.png')

def _get_config_path() -> str:
    if os.name == 'nt':
        base = os.getenv('APPDATA') or os.path.expanduser('~')
    else:
        base = os.path.join(os.path.expanduser('~'), '.config')
    d = os.path.join(base, 'wafpierce')
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return os.path.join(d, 'gui_prefs.json')

#defualt settings , change if you want different ones for the application 
def _load_prefs() -> dict:
    path = _get_config_path()
    defaults = {
        'theme': 'dark',
        'font_size': 12,
        'watermark': True,
        'threads': 5,
        'concurrent': 1,
        'use_concurrent': False,
    }
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    defaults.update(data)
    except Exception:
        pass
    return defaults


def _save_prefs(prefs: dict) -> None:
    path = _get_config_path()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(prefs, f, indent=2)
    except Exception:
        pass



class PierceGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('WAFPierce - GUI (Tk)')

        # state
        self._prefs = _load_prefs()
        self._queue: queue.Queue = queue.Queue()
        self._results: list = []
        self._tmp_result_paths: list = []
        self._target_tmp_map: dict = {}
        self._per_target: dict = {}
        self._running_procs: dict = {}
        self._scan_thread: Optional[threading.Thread] = None
        self._abort = False

        self._build_ui()
        self._apply_prefs(self._prefs)
        self.root.after(100, self._poll_queue)

    def _apply_prefs(self, prefs: dict) -> None:
        theme = prefs.get('theme', 'dark')
        if theme == 'light':
            bg = '#f5f6f7'
            text_bg = '#ffffff'
            fg = '#111'
        else:
            bg = '#0f1112'
            text_bg = '#16181a'
            fg = '#d7e1ea'

        try:
            self.root.configure(bg=bg)
        except Exception:
            pass

        try:
            fam = self._choose_mono_font(int(prefs.get('font_size', 11)))
            self.log.configure(font=fam, background=text_bg, foreground=fg, insertbackground=fg)
        except Exception:
            pass

        try:
            if prefs.get('watermark', True) and os.path.exists(LOGO_PATH):
                img = tk.PhotoImage(file=LOGO_PATH)
                self._logo_img = img
                wm = tk.Label(self.log.master, image=img, bg=text_bg)
                wm.place(relx=0.5, rely=0.5, anchor='center')
                try:
                    wm.lower(self.log)
                except Exception:
                    pass
                self._logo_label = wm
            else:
                if getattr(self, '_logo_label', None):
                    try:
                        self._logo_label.place_forget()
                    except Exception:
                        pass
        except Exception:
            pass

    def _choose_mono_font(self, size: int):
        try:
            fams = set(tkfont.families())
            for cand in ("JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"):
                if cand in fams:
                    return (cand, int(size))
        except Exception:
            pass
        return ('Consolas' if sys.platform.startswith('win') else 'Courier New', int(size))

    def _build_ui(self) -> None:
        root = self.root
        root.geometry('980x640')

        main = ttk.Panedwindow(root, orient=tk.HORIZONTAL)
        main.pack(fill='both', expand=True, padx=8, pady=8)

        left = ttk.Frame(main, width=360)
        right = ttk.Frame(main)
        main.add(left, weight=0)
        main.add(right, weight=1)

        toolbar = ttk.Frame(left)
        toolbar.pack(fill='x', padx=6, pady=(6, 4))
        self.start_btn = ttk.Button(toolbar, text='Start', command=self.start_scan)
        self.start_btn.pack(side='left')
        self.stop_btn = ttk.Button(toolbar, text='Stop', command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=(6, 0))
        self.save_btn = ttk.Button(toolbar, text='Save', command=self.save_results, state='disabled')
        self.save_btn.pack(side='left', padx=(6, 0))
        ttk.Button(toolbar, text='Clear', command=lambda: self.clean_tmp_files(clear_targets=True)).pack(side='left', padx=(6, 0))
        ttk.Button(toolbar, text='⚙', command=self._open_settings).pack(side='right')

        entry_frame = ttk.Frame(left)
        entry_frame.pack(fill='x', padx=6, pady=(6, 6))
        ttk.Label(entry_frame, text='Target URL:').pack(side='left')
        self.target_var = tk.StringVar()
        entry = ttk.Entry(entry_frame, textvariable=self.target_var)
        entry.pack(side='left', fill='x', expand=True, padx=(6, 6))
        ttk.Button(entry_frame, text='Add', command=self.add_target).pack(side='left')

        ttk.Label(left, text='Targets:').pack(anchor='w', padx=6)
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill='both', expand=True, padx=6, pady=(2, 6))
        self.targets_tree = ttk.Treeview(tree_frame, columns=('target', 'status'), show='headings', height=12)
        self.targets_tree.heading('target', text='Target')
        self.targets_tree.heading('status', text='Status')
        self.targets_tree.column('target', anchor='w')
        self.targets_tree.column('status', width=120, anchor='center')
        self.targets_tree.pack(side='left', fill='both', expand=True)
        sb = ttk.Scrollbar(tree_frame, orient='vertical', command=self.targets_tree.yview)
        sb.pack(side='left', fill='y')
        self.targets_tree.configure(yscrollcommand=sb.set)
        self.targets_tree.bind('<Double-1>', self.show_target_details)

        opts = ttk.Frame(left)
        opts.pack(fill='x', padx=6, pady=(6, 6))
        ttk.Label(opts, text='Threads:').pack(side='left')
        self.threads_var = tk.IntVar(value=int(self._prefs.get('threads', 5)))
        ttk.Spinbox(opts, from_=1, to=200, textvariable=self.threads_var, width=6).pack(side='left', padx=(4, 12))
        ttk.Label(opts, text='Concurrent:').pack(side='left')
        self.concurrent_var = tk.IntVar(value=int(self._prefs.get('concurrent', 2)))
        ttk.Spinbox(opts, from_=1, to=200, textvariable=self.concurrent_var, width=6).pack(side='left', padx=(4, 12))
        self.use_concurrent_var = tk.BooleanVar(value=bool(self._prefs.get('use_concurrent', False)))
        ttk.Checkbutton(opts, text='Use concurrent targets', variable=self.use_concurrent_var).pack(side='left', padx=(6, 0))
        ttk.Label(opts, text='Delay (s):').pack(side='left', padx=(6, 0))
        self.delay_var = tk.DoubleVar(value=0.2)
        ttk.Spinbox(opts, from_=0.0, to=5.0, increment=0.05, textvariable=self.delay_var, width=6).pack(side='left', padx=(4, 0))

        top_right = ttk.Frame(right)
        top_right.pack(fill='x', padx=6, pady=(6, 2))
        self.status_var = tk.StringVar(value='Idle')
        ttk.Label(top_right, textvariable=self.status_var).pack(side='left')
        self.progress = ttk.Progressbar(top_right, mode='indeterminate')
        self.progress.pack(side='right', fill='x', expand=True)

        log_frame = ttk.Labelframe(right, text='Output')
        log_frame.pack(fill='both', expand=True, padx=6, pady=(6, 6))
        fam, sz = self._choose_mono_font(int(self._prefs.get('font_size', 11)))
        self.log = tk.Text(log_frame, wrap='word', state='disabled', font=(fam, sz))
        self.log.pack(side='left', fill='both', expand=True)
        sb2 = ttk.Scrollbar(log_frame, orient='vertical', command=self.log.yview)
        sb2.pack(side='left', fill='y')
        self.log.configure(yscrollcommand=sb2.set)

    def add_target(self) -> None:
        raw = self.target_var.get().strip()
        if not raw:
            return
        parts = [p.strip() for p in raw.replace(',', '\n').splitlines() if p.strip()]
        existing = [self.targets_tree.set(ch, 'target') for ch in self.targets_tree.get_children()]
        for t in parts:
            if t in existing:
                continue
            iid = self.targets_tree.insert('', 'end', values=(t, 'Queued'))
            self.targets_tree.item(iid, tags=('queued',))
        self.target_var.set('')

    def show_target_details(self, event: Optional[tk.Event] = None) -> None:
        sel = self.targets_tree.selection()
        if not sel:
            return
        item = sel[0]
        target = self.targets_tree.set(item, 'target')
        tmp = self._target_tmp_map.get(target)
        if not tmp or not os.path.exists(tmp):
            messagebox.showinfo('No results', f'No results for {target}')
            return
        try:
            with open(tmp, 'r', encoding='utf-8') as f:
                data = json.load(f)
                pretty = json.dumps(data, indent=2, ensure_ascii=False)
        except Exception:
            with open(tmp, 'r', encoding='utf-8', errors='replace') as f:
                pretty = f.read()
        dlg = tk.Toplevel(self.root)
        dlg.title(f'Results — {target}')
        dlg.geometry('800x480')
        te = tk.Text(dlg, wrap='none')
        te.pack(fill='both', expand=True)
        te.insert('1.0', pretty)
        te.configure(state='disabled')

    def start_scan(self) -> None:
        if self._scan_thread is not None:
            return
        targets = [self.targets_tree.set(ch, 'target') for ch in self.targets_tree.get_children()]
        if not targets:
            t = self.target_var.get().strip()
            if t:
                targets = [t]
        if not targets:
            messagebox.showwarning('Missing target', 'Please add at least one target')
            return

        threads = int(self.threads_var.get())
        delay = float(self.delay_var.get())
        concurrent_targets = int(self.concurrent_var.get())
        use_concurrent = bool(self.use_concurrent_var.get())

        self._results = []
        self._tmp_result_paths = []
        self._target_tmp_map = {}
        self._abort = False

        self.status_var.set(f'Running ({len(targets)} targets)')
        self.progress.start(50)
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

        self._scan_thread = threading.Thread(target=self._scan_worker, args=(targets, threads, delay, concurrent_targets, use_concurrent), daemon=True)
        self._scan_thread.start()

    def _scan_worker(self, targets, threads, delay, concurrent_targets, use_concurrent):
        sem = threading.Semaphore(1 if not use_concurrent else max(1, min(len(targets), concurrent_targets)))

        def run_target(idx, target):
            if self._abort:
                self._queue.put(f'[!] Aborted before starting {target}\n')
                return
            sem.acquire()
            self._queue.put(f"\n[*] Starting target {idx}/{len(targets)}: {target}\n")
            self._queue.put({'__target_update__': target, 'status': 'Running', 'idx': idx})

            tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
            tmpf.close()
            tmp_path = tmpf.name
            self._target_tmp_map[target] = tmp_path
            self._tmp_result_paths.append(tmp_path)

            cmd = [sys.executable, '-m', 'wafpierce.pierce', target, '-t', str(threads), '-d', str(delay), '-o', tmp_path]
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', env=env)
            except Exception as e:
                self._queue.put(f"[!] Failed to start scanner for {target}: {e}\n")
                sem.release()
                return

            self._running_procs[target] = proc
            log_lines = []
            try:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        log_lines.append(line)
                        self._queue.put(line)
                        if self._abort:
                            try:
                                proc.terminate()
                            except Exception:
                                pass
                            break
            except Exception as e:
                self._queue.put(f"[!] Error reading output for {target}: {e}\n")

            proc.wait()
            self._running_procs.pop(target, None)

            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            self._results.extend(data)
                            self._per_target[target] = {'done': list(data), 'errors': []}
                            self._queue.put(f"[+] Loaded {len(data)} result(s) from {tmp_path}\n")
                            self._queue.put({'__target_update__': target, 'status': 'Done', 'count': len(data)})
                        else:
                            self._queue.put(f"[!] Results file for {target} did not contain a list\n")
                            self._queue.put({'__target_update__': target, 'status': 'NoResults'})
                except Exception:
                    self._queue.put(f"[!] No JSON results or failed to parse results for {target}\n")
                    self._queue.put({'__target_update__': target, 'status': 'ParseError'})

            if self._abort:
                self._queue.put('[!] Scan aborted by user\n')
                self._queue.put({'__target_update__': target, 'status': 'Aborted'})

            sem.release()

        threads_list = []
        for idx, target in enumerate(targets, start=1):
            t = threading.Thread(target=run_target, args=(idx, target), daemon=True)
            threads_list.append(t)
            t.start()

        for t in threads_list:
            while t.is_alive():
                if self._abort:
                    for p in list(self._running_procs.values()):
                        try:
                            p.terminate()
                        except Exception:
                            pass
                    break
                time.sleep(0.05)

        self._queue.put({'__finished__': True})

    def stop_scan(self) -> None:
        if not self._scan_thread and not self._running_procs:
            return
        if messagebox.askyesno('Stop scan', 'Are you sure you want to stop the running scan?'):
            self._abort = True
            for p in list(self._running_procs.values()):
                try:
                    p.terminate()
                except Exception:
                    pass
            self.status_var.set('Stopping...')

    def save_results(self) -> None:
        if not self._results:
            messagebox.showinfo('No results', 'There are no results to save yet.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json'), ('All files', '*.*')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self._results, f, indent=2)
            messagebox.showinfo('Saved', f'Results saved to {path}')
        except Exception as e:
            messagebox.showerror('Save failed', str(e))

    def clean_tmp_files(self, silent: bool = False, clear_targets: bool = False) -> None:
        paths = list(self._target_tmp_map.values()) + list(self._tmp_result_paths)
        unique = []
        for p in paths:
            if not p or p in unique:
                continue
            if os.path.exists(p):
                unique.append(p)
        if not unique:
            if not silent:
                messagebox.showinfo('Clean', 'No temporary result files to remove')
            if clear_targets:
                for ch in list(self.targets_tree.get_children()):
                    try:
                        self.targets_tree.delete(ch)
                    except Exception:
                        pass
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}
                try:
                    # clear the log and update legend counters
                    self.log.configure(state='normal')
                    self.log.delete('1.0', tk.END)
                    self.log.configure(state='disabled')
                except Exception:
                    pass
                try:
                    self._update_legend_counts()
                except Exception:
                    pass
            return
        if not silent and not messagebox.askyesno('Clean temporary files', f'Remove {len(unique)} temp file(s)?'):
            return
        removed = 0
        for p in unique:
            try:
                os.remove(p)
                removed += 1
            except Exception:
                pass
        for t, p in list(self._target_tmp_map.items()):
            if not os.path.exists(p):
                self._target_tmp_map.pop(t, None)
        if clear_targets:
            try:
                for ch in list(self.targets_tree.get_children()):
                    try:
                        self.targets_tree.delete(ch)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                self.log.configure(state='normal')
                self.log.delete('1.0', tk.END)
                self.log.configure(state='disabled')
            except Exception:
                pass
            try:
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}
            except Exception:
                pass
        try:
            self._update_legend_counts()
        except Exception:
            pass

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self._queue.get_nowait()
                if isinstance(item, dict) and item.get('__finished__'):
                    self._scan_thread = None
                    self.progress.stop()
                    self.status_var.set('Idle')
                    self.start_btn.config(state='normal')
                    self.stop_btn.config(state='disabled')
                    if self._results:
                        self.save_btn.config(state='normal')
                    self._append_log('[+] Run finished\n')
                    continue
                if isinstance(item, dict):
                    tgt = item.get('__target_update__')
                    if tgt:
                        status = item.get('status', '')
                        for ch in self.targets_tree.get_children():
                            if self.targets_tree.set(ch, 'target') == tgt:
                                display = status
                                if status == 'Done' and 'count' in item:
                                    display = f"✅ Done ({item.get('count')})"
                                elif status == 'Running':
                                    display = '▶ Running'
                                elif status in ('NoResults', 'ParseError'):
                                    display = f'❌ {status}'
                                elif status == 'Aborted':
                                    display = '⏹ Aborted'
                                self.targets_tree.set(ch, 'status', display)
                                break
                        self._append_log(f"[>] {tgt} -> {status}\n")
                        continue
                self._append_log(str(item))
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _append_log(self, text: str) -> None:
        self.log.configure(state='normal')
        self.log.insert(tk.END, text)
        self.log.see(tk.END)
        self.log.configure(state='disabled')

    def _update_legend_counts(self) -> None:
        """Safe no-op/update for legend counters used by Qt and (optionally) Tk.

        The Qt UI defines `_legend_labels` and an `_update_legend_counts` method
        on its class; for parity we provide a safe method here so calling code
        can be shared. If no legend labels exist this will do nothing.
        """
        try:
            # If Tk UI has legend labels, they should be stored in self._legend_labels
            labels = getattr(self, '_legend_labels', None)
            if not labels:
                return
            # Count states from the tree, similar to Qt implementation
            counts = {'queued': 0, 'running': 0, 'done': 0, 'error': 0}
            for ch in self.targets_tree.get_children():
                st = (self.targets_tree.set(ch, 'status') or '').lower()
                if 'running' in st:
                    counts['running'] += 1
                elif 'done' in st:
                    counts['done'] += 1
                elif 'error' in st or '❌' in st or 'parseerror' in st or 'noresults' in st or 'aborted' in st:
                    counts['error'] += 1
                else:
                    counts['queued'] += 1
            mapping = {'queued': 'Queued', 'running': 'Running', 'done': 'Done', 'error': 'Error'}
            for k, v in counts.items():
                lbl = labels.get(k)
                if not lbl:
                    continue
                try:
                    # Tk label is a widget; set text accordingly
                    lbl.config(text=f"{mapping.get(k, k.title())} ({v})")
                except Exception:
                    # ignore errors updating labels
                    pass
        except Exception:
            pass

    def _open_settings(self) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title('Settings')
        dlg.transient(self.root)
        dlg.grab_set()
        frm = ttk.Frame(dlg, padding=10)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text='Theme:').grid(row=0, column=0, sticky='w')
        theme_var = tk.StringVar(value=self._prefs.get('theme', 'dark'))
        ttk.Radiobutton(frm, text='Dark', variable=theme_var, value='dark').grid(row=0, column=1, sticky='w')
        ttk.Radiobutton(frm, text='Light', variable=theme_var, value='light').grid(row=0, column=2, sticky='w')

        ttk.Label(frm, text='Font size:').grid(row=1, column=0, sticky='w', pady=(8, 0))
        font_size_var = tk.IntVar(value=int(self._prefs.get('font_size', 11)))
        ttk.Spinbox(frm, from_=8, to=20, textvariable=font_size_var, width=6).grid(row=1, column=1, sticky='w', pady=(8, 0))

        watermark_var = tk.BooleanVar(value=bool(self._prefs.get('watermark', True)))
        ttk.Checkbutton(frm, text='Show watermark/logo', variable=watermark_var).grid(row=2, column=0, columnspan=3, sticky='w', pady=(8, 0))

        btns = ttk.Frame(frm)
        btns.grid(row=3, column=0, columnspan=3, pady=(12, 0))

        def _save_and_apply():
            try:
                self._prefs['theme'] = theme_var.get()
                self._prefs['font_size'] = int(font_size_var.get())
                self._prefs['watermark'] = bool(watermark_var.get())
                _save_prefs(self._prefs)
            except Exception:
                pass
            try:
                self._apply_prefs(self._prefs)
            except Exception:
                pass
            try:
                dlg.grab_release()
            except Exception:
                pass
            try:
                dlg.destroy()
            except Exception:
                pass

        ttk.Button(btns, text='Save', command=_save_and_apply).pack(side='left', padx=(0, 6))
        ttk.Button(btns, text='Cancel', command=lambda: dlg.destroy()).pack(side='left')



def main() -> None:
    # Prefer a Qt-based GUI when PySide6 is available for a modern look.
    try:
        from PySide6 import QtWidgets, QtCore
        from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                                       QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
                                       QTextEdit, QLabel, QFileDialog, QMessageBox, QCheckBox,
                                       QSpinBox, QDoubleSpinBox)
        from PySide6.QtCore import QObject, Signal
        from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase

        class QtWorker(QObject):
            finished = Signal()
            log_line = Signal(str)
            target_update = Signal(str, str, int)
            tmp_created = Signal(str, str)
            results_emitted = Signal(object)
            # emit per-target summary: target, done_list, errors_list
            target_summary = Signal(str, object, object)

            def __init__(self, targets, threads, delay, concurrent=1, use_concurrent=True, parent=None):
                super().__init__(parent)
                self.targets = targets
                self.threads = threads
                self.delay = delay
                self.concurrent = concurrent
                self.use_concurrent = use_concurrent
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
                if not getattr(self, 'use_concurrent', True):
                    max_workers = 1
                else:
                    max_workers = max(1, min(len(self.targets), max(1, int(self.concurrent))))
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

                    log_lines = []
                    try:
                        if proc.stdout is not None:
                            for line in proc.stdout:
                                log_lines.append(line)
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
                                done_list = data if isinstance(data, list) else []
                                if isinstance(data, list):
                                    self.log_line.emit(f"[+] Loaded {len(data)} result(s) from {tmp_path}\n")
                                    try:
                                        self.results_emitted.emit(data)
                                    except Exception:
                                        pass
                                    # parse errors from log_lines
                                    errors = []
                                    joined = '\n'.join(log_lines).lower()
                                    import re
                                    m = re.search(r"\[!\] Warning: (\d+) techniques encountered errors", joined)
                                    if m:
                                        try:
                                            cnt = int(m.group(1))
                                            errors.append(f"{cnt} technique errors")
                                        except Exception:
                                            pass
                                    # also collect traceback / exception lines
                                    for ln in log_lines:
                                        low = ln.lower()
                                        if 'traceback' in low or 'exception' in low or 'error:' in low:
                                            errors.append(ln.strip())
                                    try:
                                        self.target_summary.emit(target, done_list, errors)
                                    except Exception:
                                        pass
                                    self.target_update.emit(target, 'Done', len(done_list))
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
                # per-target storage for Qt: {'done': [], 'errors': [], 'tmp': path}
                self._per_target_results = {}

                # load prefs and build UI
                try:
                    self._prefs = _load_prefs()
                except Exception:
                    self._prefs = {'theme': 'dark', 'font_size': 11}
                self._build_ui()
                try:
                    self._apply_qt_prefs(self._prefs)
                except Exception:
                    pass

            def _build_ui(self):
                v = QVBoxLayout(self)

                # top controls
                top = QHBoxLayout()
                self.target_edit = QLineEdit()
                add_btn = QPushButton('Add')
                add_btn.clicked.connect(self.add_target)
                remove_btn = QPushButton('Remove')
                remove_btn.clicked.connect(self.remove_selected)
                top.addWidget(QLabel('Target URL:'))
                top.addWidget(self.target_edit)
                top.addWidget(add_btn)
                top.addWidget(remove_btn)
                # small compact settings button at the top-right
                try:
                    top.addStretch()
                    sbtn = QPushButton('⚙')
                    sbtn.setFixedSize(28, 28)
                    sbtn.clicked.connect(self._open_qt_settings)
                    top.addWidget(sbtn)
                except Exception:
                    pass
                v.addLayout(top)

                # options (threads / delay)
                opts = QHBoxLayout()
                self.threads_spin = QSpinBox()
                self.threads_spin.setRange(1, 200)
                self.threads_spin.setValue(5)
                self.delay_spin = QDoubleSpinBox()
                self.delay_spin.setRange(0.0, 5.0)
                self.delay_spin.setSingleStep(0.05)
                self.delay_spin.setValue(0.2)
                self.concurrent_spin = QSpinBox()
                self.concurrent_spin.setRange(1, 200)
                self.concurrent_spin.setValue(2)
                # default to sequential execution (one target at a time)
                self.use_concurrent_chk = QCheckBox('Use concurrent targets')
                self.use_concurrent_chk.setChecked(False)
                opts.addWidget(QLabel('Threads:'))
                opts.addWidget(self.threads_spin)
                opts.addWidget(QLabel('Concurrent:'))
                opts.addWidget(self.concurrent_spin)
                opts.addWidget(self.use_concurrent_chk)
                opts.addSpacing(10)
                opts.addWidget(QLabel('Delay (s):'))
                opts.addWidget(self.delay_spin)
                v.addLayout(opts)

                # legend for status colors
                try:
                    legend_h = QHBoxLayout()
                    # keep references so we can update counts live
                    self._legend_labels = {}
                    def _legend_label(key, text, color):
                        lbl = QLabel(f"{text} (0)")
                        lbl.setStyleSheet(f'background:{color}; padding:4px; color: white; border-radius:3px')
                        self._legend_labels[key] = lbl
                        return lbl
                    legend_h.addWidget(_legend_label('queued', 'Queued', '#2b2f33'))
                    legend_h.addWidget(_legend_label('running', 'Running', '#3b82f6'))
                    legend_h.addWidget(_legend_label('done', 'Done', '#163f19'))
                    legend_h.addWidget(_legend_label('error', 'Error', '#ff4d4d'))
                    v.addLayout(legend_h)
                except Exception:
                    pass

                # middle: tree and log
                middle = QHBoxLayout()
                self.tree = QTreeWidget()
                self.tree.setColumnCount(2)
                self.tree.setHeaderLabels(['Target', 'Status'])
                self.tree.itemDoubleClicked.connect(self.show_target_details)
                # single-click status to open details as well
                try:
                    self.tree.itemClicked.connect(self._on_qt_item_clicked)
                except Exception:
                    pass
                middle.addWidget(self.tree, 2)

                right_v = QVBoxLayout()
                self.log = QTextEdit()
                self.log.setReadOnly(True)
                # Prefer modern fonts for Qt widgets when available
                try:
                    mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                    try:
                        families = set(QFontDatabase.families())
                    except Exception:
                        # fallback when API differs or method is not available
                        try:
                            families = set(QFontDatabase().families())
                        except Exception:
                            families = set()
                    mono = next((f for f in mono_candidates if f in families), None)
                    if mono:
                        self.log.setFont(QFont(mono, 10))
                    else:
                        ui_candidates = ["Segoe UI", "Inter", "Helvetica", "Arial"]
                        ui = next((f for f in ui_candidates if f in families), None)
                        if ui:
                            self.log.setFont(QFont(ui, 10))
                except Exception:
                    pass
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
                # cleanup button: clear temp files and also clear the UI
                self.clean_btn = QPushButton('Clear')
                # when clicked by user from the UI, also clear the site list and outputs
                try:
                    self.clean_btn.clicked.connect(lambda: self.clean_tmp_files(False, True))
                except Exception:
                    try:
                        self.clean_btn.clicked.connect(self.clean_tmp_files)
                    except Exception:
                        pass
                # removed bottom Settings button (moved to top controls)
                bottom.addWidget(self.start_btn)
                bottom.addWidget(self.stop_btn)
                bottom.addWidget(self.save_btn)
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
                try:
                    self._update_legend_counts()
                except Exception:
                    pass

            def _on_qt_item_clicked(self, item, col):
                try:
                    # if user clicked the status column (index 1) or the status text indicates done/error
                    status = item.text(1).lower()
                    if col == 1 or 'done' in status or 'error' in status or '❌' in item.text(1):
                        self.show_target_details(item, col)
                except Exception:
                    pass

            def remove_selected(self):
                # remove selected top-level items from the tree
                sels = self.tree.selectedItems()
                if not sels:
                    return
                for it in sels:
                    try:
                        idx = self.tree.indexOfTopLevelItem(it)
                        self.tree.takeTopLevelItem(idx)
                    except Exception:
                        try:
                            # fallback: iterate and remove by text match
                            txt = it.text(0)
                            for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                                if self.tree.topLevelItem(i).text(0) == txt:
                                    self.tree.takeTopLevelItem(i)
                        except Exception:
                            pass
                try:
                    self._update_legend_counts()
                except Exception:
                    pass

            def clear_all(self):
                """Remove all targets and clear logs and internal state for the Qt UI."""
                try:
                    # request abort of any running worker
                    try:
                        if getattr(self, '_worker', None):
                            self._worker.abort()
                    except Exception:
                        pass
                    # remove all items
                    for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                        try:
                            self.tree.takeTopLevelItem(i)
                        except Exception:
                            pass
                    # clear log and reset internal state
                    try:
                        self.log.clear()
                    except Exception:
                        try:
                            self.log.setPlainText('')
                        except Exception:
                            pass
                    self._results = []
                    self._tmp_result_paths = []
                    self._target_tmp_map = {}
                    self._per_target_results = {}
                    try:
                        self.save_btn.setEnabled(False)
                    except Exception:
                        pass
                except Exception:
                    pass

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

                concurrent = int(self.concurrent_spin.value())
                use_concurrent = bool(self.use_concurrent_chk.isChecked())
                self._worker = QtWorker(targets, threads, delay, concurrent, use_concurrent)
                self._worker_thread = QtCore.QThread()
                self._worker.moveToThread(self._worker_thread)
                self._worker.log_line.connect(self.append_log)
                self._worker.target_update.connect(self._on_target_update)
                self._worker.tmp_created.connect(self._on_tmp_created)
                self._worker.results_emitted.connect(self._on_results_emitted)
                self._worker.target_summary.connect(self._on_target_summary)
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
                try:
                    self._update_legend_counts()
                except Exception:
                    pass

            def _on_tmp_created(self, target, tmp_path):
                try:
                    self._target_tmp_map[target] = tmp_path
                except Exception:
                    pass
                try:
                    self._tmp_result_paths.append(tmp_path)
                except Exception:
                    pass
                # ensure per-target entry exists
                try:
                    self._per_target_results.setdefault(target, {'done': [], 'errors': [], 'tmp': tmp_path})
                    self._per_target_results[target]['tmp'] = tmp_path
                except Exception:
                    pass

            def _update_legend_counts(self):
                try:
                    if not getattr(self, '_legend_labels', None):
                        return
                    counts = {'queued': 0, 'running': 0, 'done': 0, 'error': 0}
                    for i in range(self.tree.topLevelItemCount()):
                        it = self.tree.topLevelItem(i)
                        st = (it.text(1) or '').lower()
                        if 'running' in st:
                            counts['running'] += 1
                        elif 'done' in st:
                            counts['done'] += 1
                        elif 'error' in st or '❌' in it.text(1) or 'parseerror' in st or 'noresults' in st or 'aborted' in st:
                            counts['error'] += 1
                        else:
                            counts['queued'] += 1
                    mapping = {'queued': 'Queued', 'running': 'Running', 'done': 'Done', 'error': 'Error'}
                    for k, v in counts.items():
                        lbl = self._legend_labels.get(k)
                        if not lbl:
                            continue
                        try:
                            lbl.setText(f"{mapping.get(k, k.title())} ({v})")
                        except Exception:
                            try:
                                lbl.setText(f"{mapping.get(k, k.title())} ({v})")
                            except Exception:
                                pass
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

            def _on_target_summary(self, target, done_list, errors):
                try:
                    self._per_target_results[target] = {
                        'done': list(done_list) if isinstance(done_list, list) else [],
                        'errors': list(errors) if isinstance(errors, list) else [],
                        'tmp': self._target_tmp_map.get(target)
                    }
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
                # auto-clean removed; no automatic cleanup on finish
                # clean up worker thread
                try:
                    if self._worker_thread is not None:
                        self._worker_thread.quit()
                        self._worker_thread.wait()
                except Exception:
                    pass
                self._worker = None
                self._worker_thread = None
                try:
                    self._update_legend_counts()
                except Exception:
                    pass

            def _open_qt_settings(self):
                try:
                    dlg = QtWidgets.QDialog(self)
                    dlg.setWindowTitle('Settings')
                    layout = QtWidgets.QVBoxLayout(dlg)

                    # theme
                    h = QtWidgets.QHBoxLayout()
                    h.addWidget(QLabel('Theme:'))
                    theme_combo = QtWidgets.QComboBox()
                    theme_combo.addItems(['dark', 'light'])
                    # load existing pref
                    try:
                        prefs = _load_prefs()
                        theme_combo.setCurrentText(prefs.get('theme', 'dark'))
                    except Exception:
                        pass
                    h.addWidget(theme_combo)
                    layout.addLayout(h)

                    # font size
                    h2 = QtWidgets.QHBoxLayout()
                    h2.addWidget(QLabel('Font size (only in outputs):'))
                    font_spin = QSpinBox()
                    font_spin.setRange(8, 20)
                    try:
                        font_spin.setValue(int(_load_prefs().get('font_size', 11)))
                    except Exception:
                        font_spin.setValue(11)
                    h2.addWidget(font_spin)
                    layout.addLayout(h2)

                    # watermark
                    wm_chk = QCheckBox('Show watermark/logo')
                    try:
                        wm_chk.setChecked(bool(_load_prefs().get('watermark', True)))
                    except Exception:
                        wm_chk.setChecked(True)
                    layout.addWidget(wm_chk)

                    btn_h = QtWidgets.QHBoxLayout()
                    save_btn = QPushButton('Save')
                    cancel_btn = QPushButton('Cancel')
                    btn_h.addWidget(save_btn)
                    btn_h.addWidget(cancel_btn)
                    layout.addLayout(btn_h)

                    def _save_qt():
                        try:
                            prefs = _load_prefs()
                            prefs['theme'] = theme_combo.currentText()
                            prefs['font_size'] = int(font_spin.value())
                            prefs['watermark'] = bool(wm_chk.isChecked())
                            _save_prefs(prefs)
                            self._apply_qt_prefs(prefs)
                        except Exception:
                            pass
                        try:
                            dlg.accept()
                        except Exception:
                            dlg.close()

                    save_btn.clicked.connect(_save_qt)
                    cancel_btn.clicked.connect(dlg.reject)
                    # live apply handlers so changes are visible immediately
                    try:
                        def _live_theme(val: str):
                            try:
                                prefs = _load_prefs()
                                prefs['theme'] = val
                                _save_prefs(prefs)
                                self._apply_qt_prefs(prefs)
                            except Exception:
                                pass
                        theme_combo.currentTextChanged.connect(_live_theme)
                    except Exception:
                        pass
                    try:
                        def _live_font(val: int):
                            try:
                                prefs = _load_prefs()
                                prefs['font_size'] = int(val)
                                _save_prefs(prefs)
                                self._apply_qt_prefs(prefs)
                            except Exception:
                                pass
                        font_spin.valueChanged.connect(_live_font)
                    except Exception:
                        pass
                    try:
                        def _live_wm(checked: bool):
                            try:
                                prefs = _load_prefs()
                                prefs['watermark'] = bool(checked)
                                _save_prefs(prefs)
                                self._apply_qt_prefs(prefs)
                            except Exception:
                                pass
                        wm_chk.toggled.connect(_live_wm)
                    except Exception:
                        pass
                    dlg.exec()
                except Exception:
                    pass

            def _apply_qt_prefs(self, prefs: dict):
                try:
                    size = int(prefs.get('font_size', 11))
                except Exception:
                    size = 11
                try:
                    mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                    try:
                        families = set(QFontDatabase.families())
                    except Exception:
                        try:
                            families = set(QFontDatabase().families())
                        except Exception:
                            families = set()
                    mono = next((f for f in mono_candidates if f in families), None)
                    if mono:
                        f = QFont(mono, size)
                        self.log.setFont(f)
                    else:
                        # fallback: do nothing
                        pass
                except Exception:
                    pass
                # handle watermark visibility and theme
                try:
                    # Theme: apply a minimal stylesheet for light/dark
                    theme = prefs.get('theme', 'dark')
                    if theme == 'light':
                        try:
                            self.setStyleSheet('QWidget { background: #f5f6f7; color: #111; }')
                            self.log.setStyleSheet('background: #ffffff; color: #111;')
                        except Exception:
                            pass
                    else:
                        try:
                            self.setStyleSheet('')
                            # if watermark is present we set it below
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    if not prefs.get('watermark', True):
                        try:
                            self.log.setStyleSheet("")
                        except Exception:
                            pass
                    else:
                        # ensure watermark tmp exists and apply as background
                        try:
                            tmp = getattr(self, '_qt_watermark_tmp', None)
                            if not tmp or not os.path.exists(tmp):
                                tmp = self._create_qt_watermark()
                            if tmp and os.path.exists(tmp):
                                try:
                                    from pathlib import Path
                                    css_path = Path(tmp).as_posix()
                                except Exception:
                                    css_path = tmp.replace('\\', '/')
                                try:
                                    self.log.setStyleSheet(
                                        f"background-image: url('{css_path}'); background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
                                    )
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception:
                    pass

            def _create_qt_watermark(self):
                try:
                    if not os.path.exists(LOGO_PATH):
                        return None
                    from PySide6.QtGui import QPixmap, QPainter
                    from PySide6.QtCore import Qt
                    pix = QPixmap(LOGO_PATH)
                    if pix.isNull():
                        return None
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
                    self._qt_watermark_tmp = tmpf.name
                    return tmpf.name
                except Exception:
                    return None

            def save_results(self):
                path, _ = QFileDialog.getSaveFileName(self, 'Save results', filter='JSON (*.json)')
                if not path:
                    return
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(self._results, f, indent=2)
                    QMessageBox.information(self, 'Saved', f'Results saved to {path}')
                    # auto-clean removed; do not clean automatically after save
                except Exception as e:
                    QMessageBox.critical(self, 'Save failed', str(e))

            def show_target_details(self, item, col=None):
                target = item.text(0)
                tmp = self._target_tmp_map.get(target)
                per = self._per_target_results.get(target, {})
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

                header = ''
                try:
                    done_count = len(per.get('done', [])) if per.get('done') is not None else 'Unknown'
                    errors = per.get('errors', [])
                    header = f"Done: {done_count}\nErrors: {len(errors)}\n\n"
                    if errors:
                        header += "Errors details:\n" + "\n".join(str(e) for e in errors) + "\n\n"
                except Exception:
                    header = ''

                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(f'Results — {target}')
                dlg.resize(800, 480)
                layout = QtWidgets.QVBoxLayout(dlg)
                te = QTextEdit()
                # try to apply a modern font to the details dialog as well
                try:
                    mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                    try:
                        families = set(QFontDatabase.families())
                    except Exception:
                        try:
                            families = set(QFontDatabase().families())
                        except Exception:
                            families = set()
                    mono = next((f for f in mono_candidates if f in families), None)
                    if mono:
                        te.setFont(QFont(mono, 10))
                except Exception:
                    pass
                te.setPlainText(header + pretty)
                te.setReadOnly(True)
                layout.addWidget(te)
                dlg.exec()

            def clean_tmp_files(self, silent: bool = False, clear_targets: bool = False):
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
                    # still clear targets/logs if requested
                    if clear_targets:
                        try:
                            for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                                try:
                                    self.tree.takeTopLevelItem(i)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        try:
                            self.log.clear()
                        except Exception:
                            try:
                                self.log.setPlainText('')
                            except Exception:
                                pass
                        self._results = []
                        self._tmp_result_paths = []
                        self._target_tmp_map = {}
                        self._per_target_results = {}
                        try:
                            self.save_btn.setEnabled(False)
                        except Exception:
                            pass
                    try:
                        self._update_legend_counts()
                    except Exception:
                        pass
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
                # If requested also clear targets and outputs
                if clear_targets:
                    try:
                        for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                            try:
                                self.tree.takeTopLevelItem(i)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        self.log.clear()
                    except Exception:
                        try:
                            self.log.setPlainText('')
                        except Exception:
                            pass
                    self._results = []
                    self._tmp_result_paths = []
                    self._target_tmp_map = {}
                    self._per_target_results = {}
                    try:
                        self.save_btn.setEnabled(False)
                    except Exception:
                        pass
                try:
                    self._update_legend_counts()
                except Exception:
                    pass

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

#    \|/          (__)    <-- GUI made by Marwan-verse
#         `\------(oo)
#           ||    (__)
#           ||w--||     \|/
#       \|/
