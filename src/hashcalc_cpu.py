import csv
import ctypes
import hashlib
import os
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
import zlib

APP_NAME = "HashCalc CPU"
VERSION = "1.2.5"
CHUNK_SIZE = 4 * 1024 * 1024

ALGORITHMS = [
    ("CRC32", "crc32"), ("MD5", "md5"), ("SHA-1", "sha1"),
    ("SHA-224", "sha224"), ("SHA-256", "sha256"), ("SHA-384", "sha384"),
    ("SHA-512", "sha512"), ("SHA3-256", "sha3_256"),
    ("SHA3-512", "sha3_512"), ("BLAKE2b", "blake2b"), ("BLAKE2s", "blake2s"),
]
DISPLAY_NAME = {algorithm: name for name, algorithm in ALGORITHMS}


def format_size(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.2f} {unit}"
        value /= 1024


def format_duration(seconds):
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.3f} sec"

    total_seconds = int(round(seconds))
    minutes, secs = divmod(total_seconds, 60)
    if minutes < 60:
        return f"{minutes} min {secs:02d} sec"

    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} hr {minutes:02d} min"

    days, hours = divmod(hours, 24)
    return f"{days} day{'s' if days != 1 else ''} {hours:02d} hr"


def calculate_file_hashes(path, selected, progress_callback=None, cancel_event=None):
    """Hash one file, feeding every selected algorithm from one disk read pass."""
    hashers = {a: hashlib.new(a) for a in selected if a != "crc32"}
    algorithm_times = {a: 0.0 for a in selected}
    crc = 0
    total = os.path.getsize(path)
    processed = 0

    with open(path, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break

            if "crc32" in selected:
                t0 = time.perf_counter()
                crc = zlib.crc32(chunk, crc)
                algorithm_times["crc32"] += time.perf_counter() - t0

            for algorithm, hasher in hashers.items():
                t0 = time.perf_counter()
                hasher.update(chunk)
                algorithm_times[algorithm] += time.perf_counter() - t0

            processed += len(chunk)
            if cancel_event is not None and cancel_event.is_set():
                return None

            if progress_callback:
                progress_callback(processed, total)

    results = {}
    if "crc32" in selected:
        results["crc32"] = f"{crc & 0xFFFFFFFF:08x}"
    for algorithm, hasher in hashers.items():
        results[algorithm] = hasher.hexdigest()

    return results, algorithm_times


def _windows_file_attributes(path):
    """Return Windows file attributes, or 0 when unavailable."""
    if os.name != "nt":
        return 0
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == 0xFFFFFFFF:
            return 0
        return attrs
    except (AttributeError, OSError):
        return 0


def classify_paths(paths):
    """Classify dropped/selected paths without allowing mixed file/folder input."""
    files = [p for p in paths if os.path.isfile(p)]
    folders = [p for p in paths if os.path.isdir(p)]
    if files and folders:
        return "mixed", files, folders
    if folders:
        return ("folder" if len(folders) == 1 else "multiple_folders"), files, folders
    if files:
        return ("file" if len(files) == 1 else "multiple_files"), files, folders
    return "empty", files, folders


def is_hidden_or_system(path):
    """Detect hidden/system entries on Windows; use dot-prefix on other systems."""
    if os.name == "nt":
        attrs = _windows_file_attributes(path)
        return bool(attrs & 0x2 or attrs & 0x4)  # FILE_ATTRIBUTE_HIDDEN/SYSTEM
    return os.path.basename(path).startswith(".")


def collect_folder_files(folder, include_subfolders=False, include_hidden_system=False,
                         cancel_event=None, progress_callback=None):
    """Return regular files included by folder-mode options and any scan errors."""
    files = []
    errors = []

    def visit(directory):
        try:
            with os.scandir(directory) as entries:
                entries = list(entries)
        except OSError as exc:
            errors.append((directory, str(exc)))
            return

        for entry in entries:
            if cancel_event is not None and cancel_event.is_set():
                return

            path = entry.path
            if not include_hidden_system and is_hidden_or_system(path):
                continue

            try:
                if entry.is_file(follow_symlinks=False):
                    files.append(path)
                elif include_subfolders and entry.is_dir(follow_symlinks=False):
                    visit(path)
            except OSError as exc:
                errors.append((path, str(exc)))

    visit(folder)
    if progress_callback:
        progress_callback(len(files), len(files), "Scan complete")
    return files, errors


def calculate_folder_hashes(folder, selected, include_subfolders=False,
                            include_hidden_system=False, progress_callback=None,
                            cancel_event=None):
    """Hash each included file once and return rows suitable for a manifest."""
    files, scan_errors = collect_folder_files(
        folder,
        include_subfolders=include_subfolders,
        include_hidden_system=include_hidden_system,
        cancel_event=cancel_event,
        progress_callback=progress_callback,
    )

    if cancel_event is not None and cancel_event.is_set():
        return None

    rows = []
    total_files = len(files)
    for index, path in enumerate(files, start=1):
        if cancel_event is not None and cancel_event.is_set():
            return None

        def file_progress(done, total):
            if progress_callback:
                progress_callback(index - 1 + (done / total if total else 1),
                                  total_files, os.path.relpath(path, folder))

        try:
            result = calculate_file_hashes(
                path, selected, file_progress, cancel_event
            )
            if result is None:
                return None
            hashes, _algorithm_times = result
            size = os.path.getsize(path)
            rows.append({
                "path": os.path.relpath(path, folder),
                "size": size,
                "hashes": hashes,
                "status": "OK",
            })
        except OSError as exc:
            rows.append({
                "path": os.path.relpath(path, folder),
                "size": None,
                "hashes": {},
                "status": f"Error: {exc}",
            })

        if progress_callback:
            progress_callback(index, total_files, os.path.relpath(path, folder))

    return rows, scan_errors


class HashCalcApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} {VERSION}")
        self.root.geometry("1050x720")
        self.root.minsize(900, 620)
        self.file_path = tk.StringVar()
        self.status = tk.StringVar(value="Select a file or folder and choose one or more algorithms.")
        self.progress = tk.DoubleVar(value=0)
        self.expected_hash = tk.StringVar()
        self.speed_text = tk.StringVar(value="")
        self.eta_text = tk.StringVar(value="")
        self.mode_var = tk.StringVar(value="File")
        self.selected_paths = []
        self._old_wndproc = None
        self._wndproc = None
        self.include_subfolders = tk.BooleanVar(value=False)
        self.include_hidden_system = tk.BooleanVar(value=False)
        self.cancel_event = None
        self.folder_rows = []
        self.folder_scan_errors = []
        self.folder_selected = []
        self.algorithm_vars = {a: tk.BooleanVar(value=(a == "sha256")) for _, a in ALGORITHMS}
        self.result_vars = {a: tk.StringVar(value="Not calculated") for _, a in ALGORITHMS}
        self.result_times = {a: 0.0 for _, a in ALGORITHMS}
        self.build_ui()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=14)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(6, weight=1)

        ttk.Label(main, text=APP_NAME, font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 14))

        ttk.Label(main, text="Hash mode:").grid(row=1, column=0, sticky="w")
        mode_combo = ttk.Combobox(
            main, textvariable=self.mode_var, values=("File", "Multiple Files", "Folder"),
            state="readonly", width=10
        )
        mode_combo.grid(row=1, column=1, sticky="w", padx=8)
        mode_combo.bind("<<ComboboxSelected>>", self.mode_changed)

        self.path_label = ttk.Label(main, text="File:")
        self.path_label.grid(row=2, column=0, sticky="w")
        ttk.Entry(main, textvariable=self.file_path).grid(
            row=2, column=1, sticky="ew", padx=8)
        self.browse_button = ttk.Button(main, text="Browse...", command=self.browse)
        self.browse_button.grid(row=2, column=2, padx=(0, 8))
        button_frame = ttk.Frame(main)
        button_frame.grid(row=2, column=3, sticky="e")
        self.calculate_button = ttk.Button(
            button_frame, text="Calculate Selected", command=self.start_hashing)
        self.calculate_button.pack(side="left")
        self.cancel_button = ttk.Button(
            button_frame, text="Cancel", command=self.cancel_hashing, state="disabled")
        self.cancel_button.pack(side="left", padx=(6, 0))

        options = ttk.Frame(main)
        options.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(4, 8))
        self.subfolders_check = ttk.Checkbutton(
            options, text="Include subfolders", variable=self.include_subfolders)
        self.subfolders_check.pack(side="left", padx=(0, 18))
        self.hidden_check = ttk.Checkbutton(
            options, text="Include hidden/system files", variable=self.include_hidden_system)
        self.hidden_check.pack(side="left")

        self.file_info = ttk.Label(main, text="No file or folder selected.")
        self.file_info.grid(row=4, column=0, columnspan=4, sticky="w", pady=(0, 8))

        selection = ttk.LabelFrame(main, text="Algorithms to calculate", padding=10)
        selection.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(0, 10))
        for i, (name, algorithm) in enumerate(ALGORITHMS):
            ttk.Checkbutton(selection, text=name, variable=self.algorithm_vars[algorithm]).grid(
                row=i // 4, column=i % 4, sticky="w", padx=(4, 22), pady=3)

        controls = ttk.Frame(selection)
        controls.grid(row=3, column=0, columnspan=4, sticky="w", pady=(7, 0))
        ttk.Button(controls, text="Select All", command=self.select_all).pack(side="left", padx=(0, 6))
        ttk.Button(controls, text="Clear All", command=self.clear_all).pack(side="left", padx=6)
        ttk.Button(controls, text="SHA-256 Only", command=self.sha256_only).pack(side="left", padx=6)
        ttk.Button(controls, text="MD5 + SHA-256", command=self.md5_sha256).pack(side="left", padx=6)
        ttk.Button(controls, text="Benchmark", command=self.open_benchmark).pack(side="left", padx=6)
        self.export_txt_button = ttk.Button(controls, text="Export TXT", command=self.export_txt, state="disabled")
        self.export_txt_button.pack(side="left", padx=6)
        self.export_csv_button = ttk.Button(controls, text="Export CSV", command=self.export_csv, state="disabled")
        self.export_csv_button.pack(side="left", padx=6)

        table = ttk.Frame(main)
        table.grid(row=6, column=0, columnspan=4, sticky="nsew", padx=(0, 10))
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(table, columns=("algorithm", "hash", "action"), show="headings")
        self.tree.heading("algorithm", text="Algorithm")
        self.tree.heading("hash", text="Hash")
        self.tree.heading("action", text="Action")
        self.tree.column("algorithm", width=110, minwidth=90, anchor="w", stretch=False)
        self.tree.column("hash", width=400, minwidth=240, anchor="w", stretch=True)
        self.tree.column("action", width=60, minwidth=60, anchor="center", stretch=False)
        for name, algorithm in ALGORITHMS:
            self.tree.insert("", "end", iid=algorithm, values=(name, "Not calculated", "", ""))
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree_scrollbar = scrollbar
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<ButtonRelease-1>", self.tree_click)

        self.folder_tree = ttk.Treeview(table, columns=("path", "size", "hashes", "status", "action"), show="headings")
        self.folder_tree.heading("path", text="File")
        self.folder_tree.heading("size", text="Size")
        self.folder_tree.heading("hashes", text="Hashes")
        self.folder_tree.heading("status", text="Status")
        self.folder_tree.heading("action", text="Action")
        self.folder_tree.column("path", width=300, minwidth=180, anchor="w", stretch=True)
        self.folder_tree.column("size", width=85, minwidth=70, anchor="center", stretch=False)
        self.folder_tree.column("hashes", width=410, minwidth=240, anchor="w", stretch=True)
        self.folder_tree.column("status", width=90, minwidth=70, anchor="center", stretch=False)
        self.folder_tree.column("action", width=65, minwidth=60, anchor="center", stretch=False)
        self.folder_tree.grid(row=0, column=0, sticky="nsew")
        self.folder_tree.grid_remove()
        # Reuse the main table scrollbar; its command is switched with the mode.

        compare = ttk.LabelFrame(main, text="Hash verification", padding=10)
        compare.grid(row=7, column=0, columnspan=4, sticky="ew", pady=(12, 8))
        compare.columnconfigure(1, weight=1)
        ttk.Label(compare, text="Expected hash:").grid(row=0, column=0, sticky="w")
        ttk.Entry(compare, textvariable=self.expected_hash).grid(
            row=0, column=1, sticky="ew", padx=8)
        ttk.Button(compare, text="Compare", command=self.compare_all_calculated).grid(row=0, column=2)
        self.compare_label = ttk.Label(compare, text="")
        self.compare_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        bottom = ttk.Frame(main)
        bottom.grid(row=8, column=0, columnspan=4, sticky="ew")
        bottom.columnconfigure(0, weight=1)
        status_row = ttk.Frame(bottom)
        status_row.grid(row=0, column=0, sticky="ew")
        status_row.columnconfigure(0, weight=1)
        ttk.Label(status_row, textvariable=self.status).grid(row=0, column=0, sticky="w")
        ttk.Label(status_row, textvariable=self.speed_text).grid(row=0, column=1, padx=(10, 0), sticky="e")
        ttk.Label(status_row, textvariable=self.eta_text).grid(row=0, column=2, padx=(10, 0), sticky="e")
        ttk.Button(status_row, text="Copy All", command=self.copy_all).grid(row=0, column=3, padx=(12, 0), sticky="e")
        ttk.Progressbar(bottom, variable=self.progress, maximum=100).grid(
            row=1, column=0, sticky="ew", pady=(6, 0))

        self.mode_changed()
        self.enable_windows_drag_drop()

    def mode_changed(self, _event=None):
        mode = self.mode_var.get()
        folder = mode == "Folder"
        multi = mode == "Multiple Files"
        self.path_label.config(text="Folder:" if folder else ("Files:" if multi else "File:"))
        self.browse_button.config(text="Browse Folder..." if folder else ("Browse Files..." if multi else "Browse..."))
        if folder:
            self.tree.grid_remove()
            self.folder_tree.grid()
            self.folder_tree.configure(yscrollcommand=self.tree_scrollbar.set)
            self.tree_scrollbar.configure(command=self.folder_tree.yview)
            self.subfolders_check.config(state="normal")
            self.hidden_check.config(state="normal")
        elif multi:
            self.tree.grid_remove()
            self.folder_tree.grid()
            self.folder_tree.configure(yscrollcommand=self.tree_scrollbar.set)
            self.tree_scrollbar.configure(command=self.folder_tree.yview)
            self.subfolders_check.config(state="disabled")
            self.hidden_check.config(state="disabled")
        else:
            self.folder_tree.grid_remove()
            self.tree.grid()
            self.tree.configure(yscrollcommand=self.tree_scrollbar.set)
            self.tree_scrollbar.configure(command=self.tree.yview)
            self.subfolders_check.config(state="disabled")
            self.hidden_check.config(state="disabled")
        self.clear_results_only()
        self.selected_paths = []

    def browse(self):
        mode = self.mode_var.get()
        if mode == "Folder":
            path = filedialog.askdirectory(title="Select a folder")
            if path:
                self.accept_paths([path])
        elif mode == "Multiple Files":
            paths = filedialog.askopenfilenames(title="Select one or more files")
            if paths:
                self.accept_paths(list(paths))
        else:
            path = filedialog.askopenfilename(title="Select a file")
            if path:
                self.accept_paths([path])

    def accept_paths(self, paths):
        paths = [os.path.abspath(p) for p in paths]
        if not paths:
            return
        kind, files, folders = classify_paths(paths)
        if kind == "mixed":
            messagebox.showerror(APP_NAME, "Files and folders cannot be mixed. Please select either files or folders.")
            return
        if kind == "multiple_folders":
            messagebox.showerror(APP_NAME, "Multiple folders not allowed. Please select one folder at a time.")
            return
        if kind == "folder":
            self.mode_var.set("Folder")
            self.mode_changed()
            self.file_path.set(folders[0])
            self.selected_paths = folders[:]
            self.file_info.config(text=f"Folder: {folders[0]}")
        elif len(files) == 1:
            self.mode_var.set("File")
            self.mode_changed()
            self.file_path.set(files[0])
            self.selected_paths = files[:]
            self.file_info.config(text=f"{os.path.basename(files[0])} — {format_size(os.path.getsize(files[0]))}")
        else:
            self.mode_var.set("Multiple Files")
            self.mode_changed()
            self.selected_paths = files[:]
            self.file_path.set(f"{len(files)} files selected")
            total = sum(os.path.getsize(p) for p in files)
            self.file_info.config(text=f"{len(files)} files — {format_size(total)} total")
        self.expected_hash.set("")
        self.compare_label.config(text="")
        self.progress.set(0)
        self.clear_folder_tree()
        self.folder_rows = []
        self.folder_scan_errors = []
        self.export_txt_button.config(state="disabled")
        self.export_csv_button.config(state="disabled")

    def enable_windows_drag_drop(self):
        if os.name != "nt":
            return
        try:
            import ctypes.wintypes as wintypes
            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32
            shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
            shell32.DragAcceptFiles.restype = None
            user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.GetWindowLongPtrW.restype = ctypes.c_void_p
            user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            user32.SetWindowLongPtrW.restype = ctypes.c_void_p
            user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.CallWindowProcW.restype = ctypes.c_ssize_t
            shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
            shell32.DragQueryFileW.restype = wintypes.UINT
            shell32.DragFinish.argtypes = [wintypes.HANDLE]
            shell32.DragFinish.restype = None
            self._user32 = user32
            self._shell32 = shell32
            hwnd = self.root.winfo_id()
            shell32.DragAcceptFiles(hwnd, True)
            WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
            self._old_wndproc = user32.GetWindowLongPtrW(hwnd, -4)
            self._drop_queue = []

            def wndproc(h, msg, wparam, lparam):
                if msg == 0x0233:  # WM_DROPFILES
                    hdrop = wparam
                    count = shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
                    paths = []
                    for i in range(count):
                        length = shell32.DragQueryFileW(hdrop, i, None, 0)
                        buf = ctypes.create_unicode_buffer(length + 1)
                        shell32.DragQueryFileW(hdrop, i, buf, length + 1)
                        paths.append(buf.value)
                    shell32.DragFinish(hdrop)
                    # Do not call Tk from inside the native Windows callback.
                    # Queue the paths and let the Tk event loop consume them.
                    self._drop_queue.append(paths)
                    return 0
                return user32.CallWindowProcW(self._old_wndproc, h, msg, wparam, lparam)

            self._wndproc = WNDPROC(wndproc)
            user32.SetWindowLongPtrW(hwnd, -4, ctypes.cast(self._wndproc, ctypes.c_void_p).value)

            def process_drop_queue():
                if self._drop_queue:
                    queued = self._drop_queue.pop(0)
                    self.accept_paths(queued)
                if self.root.winfo_exists():
                    self.root.after(50, process_drop_queue)

            self.root.after(50, process_drop_queue)
        except Exception as exc:
            self._old_wndproc = None
            self._wndproc = None
            self.status.set(f"Drag-and-drop unavailable: {exc}")

    def select_all(self):
        for var in self.algorithm_vars.values():
            var.set(True)

    def clear_folder_tree(self):
        for item in self.folder_tree.get_children():
            self.folder_tree.delete(item)

    def clear_results_only(self):
        for name, algorithm in ALGORITHMS:
            self.result_vars[algorithm].set("Not calculated")
            self.result_times[algorithm] = 0.0
            self.tree.item(algorithm, values=(name, "Not calculated", ""))
        self.clear_folder_tree()
        self.folder_rows = []
        self.folder_scan_errors = []
        self.expected_hash.set("")
        self.compare_label.config(text="")
        self.progress.set(0)
        self.speed_text.set("")
        self.eta_text.set("")
        self.export_txt_button.config(state="disabled")
        self.export_csv_button.config(state="disabled")

    def clear_all(self):
        if self.cancel_event is not None:
            self.cancel_event.set()
        for var in self.algorithm_vars.values():
            var.set(False)
        self.clear_results_only()
        self.status.set("Cleared — select algorithms to begin.")
        self.cancel_event = None

    def sha256_only(self):
        for algorithm, var in self.algorithm_vars.items():
            var.set(algorithm == "sha256")

    def md5_sha256(self):
        for algorithm, var in self.algorithm_vars.items():
            var.set(algorithm in ("md5", "sha256"))

    def get_selected(self):
        return [a for a, var in self.algorithm_vars.items() if var.get()]

    def start_hashing(self):
        mode = self.mode_var.get()
        if mode == "Folder":
            self.start_folder_hashing()
        elif mode == "Multiple Files":
            self.start_multiple_file_hashing()
        else:
            self.start_file_hashing()

    def start_multiple_file_hashing(self):
        paths = list(self.selected_paths)
        if not paths or not all(os.path.isfile(p) for p in paths):
            messagebox.showwarning(APP_NAME, "Select one or more files first.")
            return
        selected = self.get_selected()
        if not selected:
            messagebox.showwarning(APP_NAME, "Select at least one algorithm.")
            return
        self.folder_rows = []
        self.folder_scan_errors = []
        self.folder_selected = selected[:]
        self.clear_folder_tree()
        self.calculate_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.export_txt_button.config(state="disabled")
        self.export_csv_button.config(state="disabled")
        self.progress.set(0)
        self.speed_text.set("")
        self.eta_text.set("")
        self.status.set(f"Hashing {len(paths)} file(s)...")
        self.cancel_event = threading.Event()
        start = time.perf_counter()

        def worker():
            rows = []
            total_files = len(paths)
            try:
                for index, path in enumerate(paths, start=1):
                    if self.cancel_event.is_set():
                        self.root.after(0, self.hashing_cancelled)
                        return
                    def progress_callback(done, total):
                        file_fraction = done / total if total else 1.0
                        pct = ((index - 1) + file_fraction) * 100 / total_files
                        self.root.after(0, lambda p=pct, n=os.path.basename(path): self.update_progress(p, 0, 0, f"Hashing {n}..."))
                    try:
                        result = calculate_file_hashes(path, selected, progress_callback, self.cancel_event)
                        if result is None:
                            self.root.after(0, self.hashing_cancelled)
                            return
                        hashes, _times = result
                        rows.append({"path": path, "size": os.path.getsize(path), "hashes": hashes, "status": "OK"})
                    except OSError as exc:
                        rows.append({"path": path, "size": None, "hashes": {}, "status": f"Error: {exc}"})
                    pct = index * 100 / total_files
                    self.root.after(0, lambda p=pct, n=os.path.basename(path): self.update_progress(p, 0, 0, f"Finished {n}"))
                elapsed = time.perf_counter() - start
                self.root.after(0, lambda: self.finish_multiple_file_hashing(rows, elapsed))
            except Exception as exc:
                self.root.after(0, lambda e=exc: self.hashing_error(e, multiple=True))

        threading.Thread(target=worker, daemon=True).start()

    def finish_multiple_file_hashing(self, rows, elapsed):
        self.folder_rows = rows
        self.folder_selected = list(self.folder_selected)
        self.clear_folder_tree()
        for row in rows:
            display_path = row["path"]
            hash_text = " | ".join(f"{DISPLAY_NAME[a]}: {row['hashes'][a]}" for a in self.folder_selected if a in row["hashes"])
            self.folder_tree.insert("", "end", values=(display_path, format_size(row["size"]) if row["size"] is not None else "—", hash_text, row["status"], "Copy" if row["hashes"] else ""))
        self.progress.set(100)
        ok_count = sum(1 for r in rows if r["status"] == "OK")
        error_count = len(rows) - ok_count
        self.status.set(f"Completed — {ok_count} file(s) hashed" + (f", {error_count} error(s)" if error_count else "") + f". Total time: {format_duration(elapsed)}")
        self.calculate_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.cancel_event = None
        self.export_txt_button.config(state="normal" if rows else "disabled")
        self.export_csv_button.config(state="normal" if rows else "disabled")

    def start_file_hashing(self):
        path = self.file_path.get().strip()
        if not path:
            messagebox.showwarning(APP_NAME, "Select a file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror(APP_NAME, "The selected file does not exist.")
            return
        selected = self.get_selected()
        if not selected:
            messagebox.showwarning(APP_NAME, "Select at least one algorithm.")
            return

        for name, algorithm in ALGORITHMS:
            text = "Calculating..." if algorithm in selected else "Not selected"
            self.result_vars[algorithm].set(text)
            self.result_times[algorithm] = 0.0
            self.tree.item(algorithm, values=(name, text, ""))

        self.calculate_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.progress.set(0)
        self.expected_hash.set("")
        self.compare_label.config(text="")
        self.status.set(f"Hashing {len(selected)} selected algorithm(s)...")
        self.speed_text.set("")
        self.eta_text.set("")
        self.cancel_event = threading.Event()
        start = time.perf_counter()

        def progress_callback(done, total):
            percent = 100.0 if total == 0 else done * 100.0 / total
            elapsed = time.perf_counter() - start
            mbps = done / elapsed / (1024 * 1024) if elapsed else 0
            eta = (max(0, total - done) / (done / elapsed)) if done and elapsed else 0
            self.root.after(0, lambda p=percent, s=mbps, e=eta: self.update_progress(p, s, e))

        def worker():
            try:
                hash_output = calculate_file_hashes(path, selected, progress_callback, self.cancel_event)
                elapsed = time.perf_counter() - start
                if hash_output is None:
                    self.root.after(0, self.hashing_cancelled)
                    return
                results, algorithm_times = hash_output
                size = os.path.getsize(path)
                gbps = size / elapsed / (1024 ** 3) if elapsed else 0
                self.root.after(0, lambda: self.finish_hashing(results, algorithm_times, selected, elapsed, gbps))
            except Exception as exc:
                self.root.after(0, lambda e=exc: self.hashing_error(e))

        threading.Thread(target=worker, daemon=True).start()

    def start_folder_hashing(self):
        folder = self.file_path.get().strip()
        if not folder:
            messagebox.showwarning(APP_NAME, "Select a folder first.")
            return
        if not os.path.isdir(folder):
            messagebox.showerror(APP_NAME, "The selected folder does not exist.")
            return
        selected = self.get_selected()
        if not selected:
            messagebox.showwarning(APP_NAME, "Select at least one algorithm.")
            return

        self.clear_folder_tree()
        self.folder_rows = []
        self.folder_scan_errors = []
        self.folder_selected = selected[:]
        self.calculate_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.export_txt_button.config(state="disabled")
        self.export_csv_button.config(state="disabled")
        self.progress.set(0)
        self.expected_hash.set("")
        self.compare_label.config(text="")
        self.speed_text.set("")
        self.eta_text.set("")
        self.status.set("Scanning folder...")
        self.cancel_event = threading.Event()
        start = time.perf_counter()

        def progress_callback(done, total, current):
            if current == "Scan complete":
                self.root.after(0, lambda: self.update_folder_progress(0, "Scan complete — hashing files..."))
                return
            percent = min(100.0, done * 100.0 / total) if total else 0.0
            self.root.after(0, lambda p=percent, c=current: self.update_folder_progress(p, c))

        def worker():
            try:
                result = calculate_folder_hashes(
                    folder, selected,
                    include_subfolders=self.include_subfolders.get(),
                    include_hidden_system=self.include_hidden_system.get(),
                    progress_callback=progress_callback,
                    cancel_event=self.cancel_event,
                )
                if result is None:
                    self.root.after(0, self.hashing_cancelled)
                    return
                rows, errors = result
                elapsed = time.perf_counter() - start
                self.root.after(0, lambda: self.finish_folder_hashing(rows, errors, elapsed))
            except Exception as exc:
                self.root.after(0, lambda e=exc: self.hashing_error(e, folder=True))

        threading.Thread(target=worker, daemon=True).start()

    def update_progress(self, percent, mbps, eta, status_text=None):
        self.progress.set(percent)
        self.status.set(status_text or f"Hashing... {percent:.1f}%")
        if mbps:
            self.speed_text.set(f"{mbps:.1f} MB/s")
        if eta:
            self.eta_text.set(f"ETA: {format_duration(eta)}")

    def update_folder_progress(self, percent, current):
        self.progress.set(percent)
        self.status.set(f"Hashing folder... {percent:.1f}%")
        self.speed_text.set(current)

    def cancel_hashing(self):
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.status.set("Cancelling...")
            self.cancel_button.config(state="disabled")

    def hashing_cancelled(self):
        self.cancel_event = None
        self.calculate_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.status.set("Cancelled.")
        self.eta_text.set("")

    def finish_hashing(self, results, algorithm_times, selected, elapsed, gbps):
        for name, algorithm in ALGORITHMS:
            if algorithm in selected:
                value = results[algorithm]
                self.result_vars[algorithm].set(value)
                self.tree.item(algorithm, values=(name, value, "Copy"))
        self.progress.set(100)
        self.status.set(f"Completed — Total time: {format_duration(elapsed)}")
        self.speed_text.set(f"Avg: {gbps:.2f} GB/s")
        self.calculate_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.cancel_event = None
        self.export_txt_button.config(state="normal")
        self.export_csv_button.config(state="normal")

    def finish_folder_hashing(self, rows, errors, elapsed):
        self.folder_rows = rows
        self.folder_scan_errors = errors
        self.clear_folder_tree()
        selected = self.folder_selected
        for row in rows:
            hash_text = " | ".join(
                f"{DISPLAY_NAME[a]}: {row['hashes'][a]}"
                for a in selected if a in row["hashes"]
            )
            self.folder_tree.insert(
                "", "end",
                values=(row["path"], format_size(row["size"]) if row["size"] is not None else "—",
                        hash_text, row["status"], "Copy" if row["hashes"] else "")
            )

        ok_count = sum(1 for row in rows if row["status"] == "OK")
        error_count = sum(1 for row in rows if row["status"] != "OK") + len(errors)
        if error_count:
            self.status.set(
                f"Completed — {ok_count} file(s) hashed, {error_count} error(s) skipped. "
                f"Total time: {format_duration(elapsed)}"
            )
        else:
            self.status.set(
                f"Completed — {ok_count} file(s) hashed. Total time: {format_duration(elapsed)}"
            )
        self.progress.set(100)
        self.speed_text.set("")
        self.eta_text.set("")
        self.calculate_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.cancel_event = None
        self.export_txt_button.config(state="normal" if rows else "disabled")
        self.export_csv_button.config(state="normal" if rows else "disabled")

        if not rows and errors:
            messagebox.showwarning(
                APP_NAME,
                "No readable files were found. Check the folder and permissions."
            )

    def hashing_error(self, exc, folder=False, multiple=False):
        self.calculate_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.cancel_event = None
        self.status.set("Error.")
        self.eta_text.set("")
        messagebox.showerror(APP_NAME, f"Could not hash the {'folder' if folder else ('selected files' if multiple else 'file')}:\n\n{exc}")

    def tree_click(self, event):
        mode = self.mode_var.get()
        if mode == "File":
            item = self.tree.identify_row(event.y)
            column = self.tree.identify_column(event.x)
            if item and column == "#3":
                value = self.result_vars[item].get()
                if value not in ("Not calculated", "Not selected", "Calculating..."):
                    self.root.clipboard_clear()
                    self.root.clipboard_append(value)
                    self.status.set(f"{DISPLAY_NAME[item]} copied to clipboard.")
            return

        if mode in ("Folder", "Multiple Files"):
            item = self.folder_tree.identify_row(event.y)
            column = self.folder_tree.identify_column(event.x)
            if not item or column != "#5":
                return
            try:
                index = self.folder_tree.index(item)
                row = self.folder_rows[index]
            except (IndexError, ValueError):
                return
            if not row.get("hashes"):
                return
            lines = [f"File: {row['path']}", f"Size: {format_size(row['size']) if row['size'] is not None else '—'}"]
            lines.extend(f"{DISPLAY_NAME[a]}: {row['hashes'][a]}" for a in self.folder_selected if a in row["hashes"])
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(lines))
            self.status.set(f"Hashes copied: {os.path.basename(row['path'])}")

    def copy_all(self):
        if self.mode_var.get() in ("Folder", "Multiple Files") and self.folder_rows:
            lines = []
            for row in self.folder_rows:
                hashes = " | ".join(
                    f"{DISPLAY_NAME[a]}: {row['hashes'][a]}"
                    for a in self.folder_selected if a in row["hashes"]
                )
                lines.append(f"{row['path']} | {format_size(row['size'])} | {hashes} | {row['status']}")
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(lines))
            self.status.set("Folder results copied to clipboard.")
            return

        lines = []
        for name, algorithm in ALGORITHMS:
            value = self.result_vars[algorithm].get()
            if value not in ("Not calculated", "Not selected", "Calculating..."):
                lines.append(f"{name}: {value}")
        if not lines:
            messagebox.showinfo(APP_NAME, "Calculate at least one hash first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status.set("Calculated hashes copied to clipboard.")

    def compare_all_calculated(self):
        if self.mode_var.get() != "File":
            self.compare_label.config(text="Verification against folder manifests is not implemented yet.")
            return
        expected = self.expected_hash.get().strip().lower().replace(" ", "")
        if not expected:
            self.compare_label.config(text="Enter the expected hash.")
            return
        matches = []
        possible = []
        for name, algorithm in ALGORITHMS:
            actual = self.result_vars[algorithm].get()
            if actual in ("Not calculated", "Not selected", "Calculating..."):
                continue
            if len(actual) == len(expected):
                possible.append(name)
            if actual.lower() == expected:
                matches.append(name)
        if matches:
            self.compare_label.config(text="✓ MATCH — " + ", ".join(matches))
        elif possible:
            self.compare_label.config(text="✗ No match — checked: " + ", ".join(possible))
        else:
            self.compare_label.config(text="✗ No match among calculated hashes.")

    def build_file_hash_text(self):
        path = self.selected_paths[0] if self.selected_paths else self.file_path.get().strip()
        lines = [
            "HashCalc CPU Hash Results",
            "=========================",
            f"Version: {VERSION}",
            f"File: {path}",
            f"Size: {format_size(os.path.getsize(path))}",
            f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
            "",
        ]
        for name, algorithm in ALGORITHMS:
            value = self.result_vars[algorithm].get()
            if value not in ("Not calculated", "Not selected", "Calculating..."):
                lines.append(f"{name}: {value}")
        return "\n".join(lines)

    def build_file_hash_csv(self):
        rows = []
        path = self.selected_paths[0] if self.selected_paths else self.file_path.get().strip()
        size = os.path.getsize(path)
        for name, algorithm in ALGORITHMS:
            value = self.result_vars[algorithm].get()
            if value not in ("Not calculated", "Not selected", "Calculating..."):
                rows.append({"File": path, "Size": size, "Algorithm": name, "Hash": value})
        return rows

    def build_folder_manifest_text(self):
        folder = self.file_path.get().strip() if self.mode_var.get() == "Folder" else "Selected files"
        lines = ["HashCalc CPU Folder Manifest" if self.mode_var.get() == "Folder" else "HashCalc CPU Multiple File Results",
                 "=" * 28, f"Version: {VERSION}", f"Root folder: {folder}",
                 f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
                 f"Include subfolders: {'Yes' if self.mode_var.get() == 'Folder' and self.include_subfolders.get() else 'No'}",
                 f"Include hidden/system files: {'Yes' if self.mode_var.get() == 'Folder' and self.include_hidden_system.get() else 'No'}",
                 "Algorithms: " + ", ".join(DISPLAY_NAME[a] for a in self.folder_selected), "",
                 "File | Size | " + " | ".join(DISPLAY_NAME[a] for a in self.folder_selected) + " | Status", "-" * 80]
        for row in self.folder_rows:
            values = [row["path"], format_size(row["size"]) if row["size"] is not None else "—"]
            values.extend(row["hashes"].get(a, "") for a in self.folder_selected)
            values.append(row["status"])
            lines.append(" | ".join(values))
        if self.folder_scan_errors:
            lines.extend(["", "Scan errors:"])
            lines.extend(f"{path}: {error}" for path, error in self.folder_scan_errors)
        return "\n".join(lines)

    def _suggest_export_name(self, ext):
        mode = self.mode_var.get()
        if mode == "File":
            base = os.path.basename(self.selected_paths[0] if self.selected_paths else self.file_path.get().strip())
            return f"{base}.hashes{ext}"
        if mode == "Folder":
            base = os.path.basename(os.path.normpath(self.file_path.get().strip())) or "Folder"
            return f"{base}.hashes{ext}"
        return f"HashCalc-CPU-hashes{ext}"

    def export_txt(self):
        if self.mode_var.get() == "File":
            if not any(self.result_vars[a].get() not in ("Not calculated", "Not selected", "Calculating...") for _, a in ALGORITHMS):
                return
            content = self.build_file_hash_text()
            title = "Export Hashes as TXT"
        else:
            if not self.folder_rows:
                return
            content = self.build_folder_manifest_text()
            title = "Export Hashes as TXT"
        path = filedialog.asksaveasfilename(title=title, initialfile=self._suggest_export_name(".txt"), defaultextension=".txt", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="") as file:
                file.write(content)
            self.status.set(f"Hashes exported: {os.path.basename(path)}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not export hashes:\n\n{exc}")

    def export_csv(self):
        mode = self.mode_var.get()
        if mode == "File":
            rows = self.build_file_hash_csv()
            if not rows:
                return
            path = filedialog.asksaveasfilename(title="Export Hashes as CSV", initialfile=self._suggest_export_name(".csv"), defaultextension=".csv", filetypes=(("CSV files", "*.csv"), ("All files", "*.*")))
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8-sig", newline="") as file:
                    writer = csv.DictWriter(file, fieldnames=["File", "Size", "Algorithm", "Hash"])
                    writer.writeheader()
                    writer.writerows(rows)
                self.status.set(f"Hashes exported: {os.path.basename(path)}")
            except OSError as exc:
                messagebox.showerror(APP_NAME, f"Could not export hashes:\n\n{exc}")
            return
        if not self.folder_rows:
            return
        path = filedialog.asksaveasfilename(title="Export Hashes as CSV", initialfile=self._suggest_export_name(".csv"), defaultextension=".csv", filetypes=(("CSV files", "*.csv"), ("All files", "*.*")))
        if not path:
            return
        try:
            fieldnames = ["File", "Size"] + [DISPLAY_NAME[a] for a in self.folder_selected] + ["Status"]
            with open(path, "w", encoding="utf-8-sig", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                for row in self.folder_rows:
                    record = {"File": row["path"], "Size": row["size"] if row["size"] is not None else ""}
                    record.update({DISPLAY_NAME[a]: row["hashes"].get(a, "") for a in self.folder_selected})
                    record["Status"] = row["status"]
                    writer.writerow(record)
            self.status.set(f"Hashes exported: {os.path.basename(path)}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not export hashes:\n\n{exc}")

    def copy_benchmark_results(self, size_text, result_tree):
        rows = []
        for item in result_tree.get_children():
            values = result_tree.item(item, "values")
            if values:
                rows.append(tuple(values))
        if not rows:
            messagebox.showinfo(APP_NAME, "Run the benchmark first.")
            return
        size_mb = size_text.split()[0]
        report = self.build_benchmark_report(size_mb, rows)
        self.root.clipboard_clear()
        self.root.clipboard_append(report)
        self.root.update()
        messagebox.showinfo(APP_NAME, "Benchmark results copied to the clipboard.")

    def benchmark(self):
        window = tk.Toplevel(self.root)
        window.title("HashCalc CPU Benchmark")
        window.geometry("720x520")
        window.minsize(620, 420)
        frame = ttk.Frame(window, padding=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)
        ttk.Label(frame, text="CPU Hash Benchmark", font=("Segoe UI", 16, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Label(frame, text="Test data:").grid(row=1, column=0, sticky="w")
        size_var = tk.StringVar(value="256 MB")
        size_combo = ttk.Combobox(frame, textvariable=size_var,
                                  values=("64 MB", "128 MB", "256 MB", "512 MB"),
                                  state="readonly", width=12)
        size_combo.grid(row=1, column=1, sticky="w")
        ttk.Label(frame, text="Measures hashing CPU speed in RAM; disk speed is excluded.").grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(6, 8))
        progress = ttk.Progressbar(frame, orient="horizontal", mode="determinate", maximum=100)
        progress.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        phase = tk.StringVar(value="Ready.")
        ttk.Label(frame, textvariable=phase).grid(row=4, column=0, columnspan=3, sticky="w", pady=(0, 8))
        result_tree = ttk.Treeview(frame, columns=("algorithm", "time", "speed"), show="headings")
        result_tree.heading("algorithm", text="Algorithm")
        result_tree.heading("time", text="Time")
        result_tree.heading("speed", text="Throughput")
        result_tree.column("algorithm", width=150, anchor="w")
        result_tree.column("time", width=120, anchor="center")
        result_tree.column("speed", width=160, anchor="center")
        result_tree.grid(row=5, column=0, columnspan=3, sticky="nsew")
        bottom = ttk.Frame(frame)
        bottom.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        bottom.columnconfigure(0, weight=1)
        status = tk.StringVar(value="Ready.")
        ttk.Label(bottom, textvariable=status).grid(row=0, column=0, sticky="w")
        buttons = ttk.Frame(bottom)
        buttons.grid(row=0, column=1, sticky="e")
        cancel_button = ttk.Button(buttons, text="Cancel", state="disabled")
        cancel_button.pack(side="left", padx=(0, 6))
        copy_button = ttk.Button(buttons, text="Copy Results", command=lambda: self.copy_benchmark_results(size_var.get(), result_tree))
        copy_button.pack(side="left", padx=(0, 6))
        run_button = ttk.Button(buttons, text="Run Benchmark")
        run_button.pack(side="left")
        benchmark_cancel_event = threading.Event()

        def benchmark_cancelled():
            status.set("Benchmark cancelled.")
            phase.set("Cancelled.")
            run_button.config(state="normal")
            cancel_button.config(state="disabled")
            copy_button.config(state="normal")
            size_combo.config(state="readonly")

        def run():
            benchmark_cancel_event.clear()
            run_button.config(state="disabled")
            cancel_button.config(state="normal")
            copy_button.config(state="disabled")
            size_combo.config(state="disabled")
            progress["value"] = 0
            status.set("Starting benchmark...")
            phase.set("Preparing test data...")
            window.update_idletasks()

            def worker():
                try:
                    size_mb = int(size_var.get().split()[0])
                    total_bytes = size_mb * 1024 * 1024
                    chunk_size = 4 * 1024 * 1024
                    parts = []
                    generated = 0
                    while generated < total_bytes:
                        if benchmark_cancel_event.is_set():
                            self.root.after(0, benchmark_cancelled)
                            return
                        n = min(chunk_size, total_bytes - generated)
                        chunk = bytes(((generated + i) * 31 + 17) & 0xFF for i in range(n))
                        parts.append(chunk)
                        generated += n
                        pct = generated * 100 / total_bytes
                        self.root.after(0, lambda p=pct: (progress.configure(value=p), phase.set(f"Generating test data... {p:.0f}%")))
                    data = b"".join(parts)
                    if benchmark_cancel_event.is_set():
                        self.root.after(0, benchmark_cancelled)
                        return
                    self.root.after(0, lambda: (progress.configure(value=0), phase.set("Test data ready — starting CPU tests...")))
                    rows = []
                    for index, (name, algorithm) in enumerate(ALGORITHMS):
                        if benchmark_cancel_event.is_set():
                            self.root.after(0, benchmark_cancelled)
                            return
                        self.root.after(0, lambda n=name, i=index: phase.set(f"Benchmarking {n}... {i + 1}/{len(ALGORITHMS)}"))
                        t0 = time.perf_counter()
                        if algorithm == "crc32":
                            zlib.crc32(data)
                        else:
                            h = hashlib.new(algorithm)
                            h.update(data)
                            h.digest()
                        elapsed = time.perf_counter() - t0
                        speed = total_bytes / elapsed / (1024 * 1024)
                        row = (name, format_duration(elapsed), f"{speed:,.1f} MB/s")
                        rows.append(row)
                        self.root.after(0, lambda r=row, count=len(rows): (result_tree.insert("", "end", values=r), progress.configure(value=(count * 100 / len(ALGORITHMS)))))
                    self.root.after(0, lambda: (status.set(f"Finished — {size_mb} MB per algorithm. Higher MB/s is faster."), phase.set("Benchmark complete."), progress.configure(value=100), run_button.config(state="normal"), cancel_button.config(state="disabled"), copy_button.config(state="normal"), size_combo.config(state="readonly")))
                except Exception as exc:
                    self.root.after(0, lambda: (status.set("Benchmark failed."), phase.set("Benchmark failed."), run_button.config(state="normal"), cancel_button.config(state="disabled"), copy_button.config(state="normal"), size_combo.config(state="readonly"), messagebox.showerror(APP_NAME, f"Benchmark failed:\n\n{exc}", parent=window)))

            threading.Thread(target=worker, daemon=True).start()

        def cancel_benchmark():
            benchmark_cancel_event.set()
            cancel_button.config(state="disabled")
            phase.set("Cancelling...")
            status.set("Stopping benchmark safely...")

        cancel_button.config(command=cancel_benchmark)
        run_button.config(command=run)

    def on_close(self):
        if self.cancel_event is not None:
            self.cancel_event.set()
        if os.name == "nt" and self._old_wndproc and self._user32:
            try:
                hwnd = self.root.winfo_id()
                self._user32.SetWindowLongPtrW(hwnd, -4, self._old_wndproc)
            except Exception:
                pass
        self.root.destroy()

    def build_benchmark_report(self, size_mb, rows):
        lines = ["HashCalc CPU Benchmark", "=" * 28, f"Test data: {size_mb} MB",
                 "Test type: CPU hashing in RAM (disk speed excluded)", "",
                 f"{'Algorithm':<12} {'Time':>12} {'Throughput':>16}", "-" * 42]
        for name, elapsed_text, speed_text in rows:
            lines.append(f"{name:<12} {elapsed_text:>12} {speed_text:>16}")
        lines.extend(["", "Higher MB/s is faster."])
        return "\n".join(lines)

    def open_benchmark(self):
        self.benchmark()


if __name__ == "__main__":
    root = tk.Tk()
    app = HashCalcApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
