import hashlib
import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zlib

APP_NAME = "HashCalc CPU"
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

    # Keep sub-minute timings precise enough to distinguish fast hashes.
    # perf_counter() provides much finer resolution than the display.
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

class HashCalcApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1050x720")
        self.root.minsize(900, 620)
        self.file_path = tk.StringVar()
        self.status = tk.StringVar(value="Select a file and choose one or more algorithms.")
        self.progress = tk.DoubleVar(value=0)
        self.expected_hash = tk.StringVar()
        self.speed_text = tk.StringVar(value="")
        self.eta_text = tk.StringVar(value="")
        self.cancel_event = None
        self.algorithm_vars = {a: tk.BooleanVar(value=(a == "sha256")) for _, a in ALGORITHMS}
        self.result_vars = {a: tk.StringVar(value="Not calculated") for _, a in ALGORITHMS}
        self.result_times = {a: 0.0 for _, a in ALGORITHMS}
        self.build_ui()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=14)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(4, weight=1)

        ttk.Label(main, text=APP_NAME, font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 14))
        ttk.Label(main, text="File:").grid(row=1, column=0, sticky="w")
        ttk.Entry(main, textvariable=self.file_path).grid(
            row=1, column=1, sticky="ew", padx=8)
        ttk.Button(main, text="Browse...", command=self.browse).grid(
            row=1, column=2, padx=(0, 8))
        button_frame = ttk.Frame(main)
        button_frame.grid(row=1, column=3, sticky="e")
        self.calculate_button = ttk.Button(
            button_frame, text="Calculate Selected", command=self.start_hashing)
        self.calculate_button.pack(side="left")
        self.cancel_button = ttk.Button(
            button_frame, text="Cancel", command=self.cancel_hashing, state="disabled")
        self.cancel_button.pack(side="left", padx=(6, 0))

        self.file_info = ttk.Label(main, text="No file selected.")
        self.file_info.grid(row=2, column=0, columnspan=4, sticky="w", pady=8)

        selection = ttk.LabelFrame(main, text="Algorithms to calculate", padding=10)
        selection.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(0, 10))
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

        table = ttk.Frame(main)
        table.grid(row=4, column=0, columnspan=4, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(table, columns=("algorithm", "hash", "time", "action"), show="headings")
        self.tree.heading("algorithm", text="Algorithm")
        self.tree.heading("hash", text="Hash")
        self.tree.heading("time", text="Hash Time")
        self.tree.heading("action", text="Action")
        self.tree.column("algorithm", width=110, anchor="w", stretch=False)
        # Keep the table within the startup window; the hash column absorbs
        # available width instead of making the Treeview wider than the GUI.
        self.tree.column("hash", width=400, anchor="w", stretch=True)
        self.tree.column("time", width=90, anchor="center", stretch=False)
        self.tree.column("action", width=60, anchor="center", stretch=False)
        for name, algorithm in ALGORITHMS:
            self.tree.insert("", "end", iid=algorithm, values=(name, "Not calculated", "", ""))
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<ButtonRelease-1>", self.tree_click)

        compare = ttk.LabelFrame(main, text="Hash verification", padding=10)
        compare.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(12, 8))
        compare.columnconfigure(1, weight=1)

        ttk.Label(compare, text="Expected hash:").grid(
            row=0, column=0, sticky="w")

        ttk.Entry(compare, textvariable=self.expected_hash).grid(
            row=0, column=1, sticky="ew", padx=8)

        ttk.Button(
            compare, text="Compare", command=self.compare_all_calculated
        ).grid(row=0, column=2)

        self.compare_label = ttk.Label(compare, text="")
        self.compare_label.grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))


        # Bottom status area uses separate rows instead of rowspan/columnspan.
        # This prevents Copy All from overlapping the progress bar.
        bottom = ttk.Frame(main)
        bottom.grid(row=6, column=0, columnspan=4, sticky="ew")
        bottom.columnconfigure(0, weight=1)

        status_row = ttk.Frame(bottom)
        status_row.grid(row=0, column=0, sticky="ew")
        status_row.columnconfigure(0, weight=1)

        ttk.Label(status_row, textvariable=self.status).grid(
            row=0, column=0, sticky="w")
        ttk.Label(status_row, textvariable=self.speed_text).grid(
            row=0, column=1, padx=(10, 0), sticky="e")
        ttk.Label(status_row, textvariable=self.eta_text).grid(
            row=0, column=2, padx=(10, 0), sticky="e")
        ttk.Button(status_row, text="Copy All", command=self.copy_all).grid(
            row=0, column=3, padx=(12, 0), sticky="e")

        ttk.Progressbar(
            bottom, variable=self.progress, maximum=100
        ).grid(row=1, column=0, sticky="ew", pady=(6, 0))


    def browse(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.file_path.set(path)
            self.expected_hash.set("")
            self.compare_label.config(text="")
            self.progress.set(0)
            self.file_info.config(
                text=f"{os.path.basename(path)} — {format_size(os.path.getsize(path))}")

    def select_all(self):
        for var in self.algorithm_vars.values():
            var.set(True)

    def clear_all(self):
        # "Clear All" means reset the working set, not just uncheck boxes.
        # It removes displayed hashes and releases the Python hash objects
        # held by the completed operation as soon as this method returns.
        if self.cancel_event is not None:
            self.cancel_event.set()

        for var in self.algorithm_vars.values():
            var.set(False)

        for name, algorithm in ALGORITHMS:
            self.result_vars[algorithm].set("Not calculated")
            self.tree.item(
                algorithm,
                values=(name, "Not calculated", "", "")
            )

        self.expected_hash.set("")
        self.compare_label.config(text="")
        self.progress.set(0)
        self.status.set("Cleared — select algorithms to begin.")
        self.speed_text.set("")
        self.eta_text.set("")
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
            self.tree.item(algorithm, values=(name, text, "", ""))

        self.calculate_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.progress.set(0)
        self.expected_hash.set("")
        self.compare_label.config(text="")
        self.status.set(f"Hashing {len(selected)} selected algorithm(s)...")
        self.speed_text.set("")
        self.eta_text.set("")
        self.compare_label.config(text="")
        self.cancel_event = threading.Event()
        start = time.perf_counter()

        def progress_callback(done, total):
            percent = 100.0 if total == 0 else done * 100.0 / total
            elapsed = time.perf_counter() - start
            mbps = done / elapsed / (1024 * 1024) if elapsed else 0

            if done and elapsed:
                remaining = max(0, total - done)
                eta = remaining / (done / elapsed)
            else:
                eta = 0

            self.root.after(
                0,
                lambda p=percent, s=mbps, e=eta:
                self.update_progress(p, s, e)
            )

        def worker():
            try:
                hash_output = calculate_file_hashes(
                    path, selected, progress_callback, self.cancel_event
                )

                elapsed = time.perf_counter() - start

                if hash_output is None:
                    self.root.after(0, self.hashing_cancelled)
                    return

                results, algorithm_times = hash_output
                size = os.path.getsize(path)
                gbps = size / elapsed / (1024 ** 3) if elapsed else 0
                self.root.after(
                    0,
                    lambda: self.finish_hashing(
                        results, algorithm_times, selected, elapsed, gbps
                    )
                )
            except Exception as exc:
                self.root.after(0, lambda e=exc: self.hashing_error(e))

        threading.Thread(target=worker, daemon=True).start()

    def update_progress(self, percent, mbps, eta):
        self.progress.set(percent)
        self.status.set(f"Hashing... {percent:.1f}%")
        self.speed_text.set(f"{mbps:.1f} MB/s")

        self.eta_text.set(f"ETA: {format_duration(eta)}")

    def cancel_hashing(self):
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.status.set("Cancelling...")
            self.cancel_button.config(state="disabled")

    def hashing_cancelled(self):
        self.cancel_event = None
        self.calculate_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.cancel_button.config(state="disabled")
        self.status.set("Cancelled.")
        self.eta_text.set("")

    def finish_hashing(self, results, algorithm_times, selected, elapsed, gbps):
        for name, algorithm in ALGORITHMS:
            if algorithm in selected:
                value = results[algorithm]
                self.result_vars[algorithm].set(value)
                self.result_times[algorithm] = algorithm_times[algorithm]
                self.tree.item(
                    algorithm,
                    values=(
                        name,
                        value,
                        format_duration(algorithm_times[algorithm]),
                        "Copy"
                    )
                )
        self.progress.set(100)
        self.status.set(f"Complete — {format_duration(elapsed)}")
        self.speed_text.set(f"Avg: {gbps:.2f} GB/s")
        self.calculate_button.config(state="normal")

    def hashing_error(self, exc):
        self.calculate_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.cancel_event = None
        self.status.set("Error.")
        self.eta_text.set("")
        messagebox.showerror(APP_NAME, f"Could not hash the file:\n\n{exc}")

    def tree_click(self, event):
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if item and column == "#4":
            value = self.result_vars[item].get()
            if value not in ("Not calculated", "Not selected", "Calculating..."):
                self.root.clipboard_clear()
                self.root.clipboard_append(value)
                self.status.set(f"{DISPLAY_NAME[item]} copied to clipboard.")

    def copy_all(self):
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
            self.compare_label.config(
                text="✓ MATCH — " + ", ".join(matches))
            return

        if possible:
            self.compare_label.config(
                text="✗ No match — checked: " + ", ".join(possible))
        else:
            self.compare_label.config(
                text="✗ No match among calculated hashes.")

    def copy_benchmark_results(self, size_text, result_tree):
        rows = []
        for item in result_tree.get_children():
            values = result_tree.item(item, "values")
            if values:
                rows.append(tuple(values))

        if not rows:
            messagebox.showinfo(
                APP_NAME,
                "Run the benchmark first.",
            )
            return

        size_mb = size_text.split()[0]
        report = self.build_benchmark_report(size_mb, rows)

        self.root.clipboard_clear()
        self.root.clipboard_append(report)
        self.root.update()

        messagebox.showinfo(
            APP_NAME,
            "Benchmark results copied to the clipboard."
        )

    def benchmark(self):
        window = tk.Toplevel(self.root)
        window.title("HashCalc CPU Benchmark")
        window.geometry("720x520")
        window.minsize(620, 420)

        frame = ttk.Frame(window, padding=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)

        ttk.Label(
            frame,
            text="CPU Hash Benchmark",
            font=("Segoe UI", 16, "bold")
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        ttk.Label(frame, text="Test data:").grid(row=1, column=0, sticky="w")
        size_var = tk.StringVar(value="256 MB")
        size_combo = ttk.Combobox(
            frame,
            textvariable=size_var,
            values=("64 MB", "128 MB", "256 MB", "512 MB"),
            state="readonly",
            width=12
        )
        size_combo.grid(row=1, column=1, sticky="w")

        ttk.Label(
            frame,
            text="Measures hashing CPU speed in RAM; disk speed is excluded."
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 8))

        progress = ttk.Progressbar(
            frame, orient="horizontal", mode="determinate", maximum=100
        )
        progress.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 8))

        phase = tk.StringVar(value="Ready.")
        ttk.Label(frame, textvariable=phase).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(0, 8))

        result_tree = ttk.Treeview(
            frame,
            columns=("algorithm", "time", "speed"),
            show="headings"
        )
        result_tree.heading("algorithm", text="Algorithm")
        result_tree.heading("time", text="Time")
        result_tree.heading("speed", text="Throughput")
        result_tree.column("algorithm", width=150, anchor="w")
        result_tree.column("time", width=120, anchor="center")
        result_tree.column("speed", width=160, anchor="center")
        result_tree.grid(row=5, column=0, columnspan=3, sticky="nsew")

        # Bottom controls use a dedicated frame so status text and buttons
        # can never overlap, even when the window is resized.
        bottom = ttk.Frame(frame)
        bottom.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        bottom.columnconfigure(0, weight=1)

        status = tk.StringVar(value="Ready.")
        ttk.Label(bottom, textvariable=status).grid(
            row=0, column=0, sticky="w")

        buttons = ttk.Frame(bottom)
        buttons.grid(row=0, column=1, sticky="e")

        cancel_button = ttk.Button(buttons, text="Cancel", state="disabled")
        cancel_button.pack(side="left", padx=(0, 6))

        copy_button = ttk.Button(
            buttons, text="Copy Results",
            command=lambda: self.copy_benchmark_results(
                size_var.get(), result_tree)
        )
        copy_button.pack(side="left", padx=(0, 6))

        run_button = ttk.Button(buttons, text="Run Benchmark")
        run_button.pack(side="left")

        benchmark_cancel_event = threading.Event()

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

                    # Generate in chunks so progress can be shown and the UI
                    # stays responsive. The benchmark buffer is assembled once
                    # and then reused for every algorithm.
                    chunk_size = 4 * 1024 * 1024
                    parts = []
                    generated = 0

                    while generated < total_bytes:
                        if benchmark_cancel_event.is_set():
                            self.root.after(0, benchmark_cancelled)
                            return

                        n = min(chunk_size, total_bytes - generated)
                        chunk = bytes(
                            ((generated + i) * 31 + 17) & 0xFF
                            for i in range(n)
                        )
                        parts.append(chunk)
                        generated += n

                        pct = generated * 100 / total_bytes
                        self.root.after(
                            0,
                            lambda p=pct: (
                                progress.configure(value=p),
                                phase.set(
                                    f"Generating test data... {p:.0f}%"
                                )
                            )
                        )

                    data = b"".join(parts)

                    if benchmark_cancel_event.is_set():
                        self.root.after(0, benchmark_cancelled)
                        return

                    self.root.after(
                        0,
                        lambda: (
                            progress.configure(value=0),
                            phase.set("Test data ready — starting CPU tests...")
                        )
                    )

                    rows = []

                    for index, (name, algorithm) in enumerate(ALGORITHMS):
                        if benchmark_cancel_event.is_set():
                            self.root.after(0, benchmark_cancelled)
                            return

                        self.root.after(
                            0,
                            lambda n=name, i=index: phase.set(
                                f"Benchmarking {n}... "
                                f"{i + 1}/{len(ALGORITHMS)}"
                            )
                        )

                        t0 = time.perf_counter()

                        if algorithm == "crc32":
                            value = zlib.crc32(data)
                        else:
                            h = hashlib.new(algorithm)
                            h.update(data)
                            h.digest()

                        elapsed = time.perf_counter() - t0
                        speed = total_bytes / elapsed / (1024 * 1024)

                        row = (
                            name,
                            format_duration(elapsed),
                            f"{speed:,.1f} MB/s"
                        )
                        rows.append(row)

                        self.root.after(
                            0,
                            lambda r=row, count=len(rows): (
                                result_tree.insert("", "end", values=r),
                                progress.configure(
                                    value=(count * 100 / len(ALGORITHMS))
                                )
                            )
                        )

                    self.root.after(
                        0,
                        lambda: (
                            status.set(
                                f"Finished — {size_mb} MB per algorithm. "
                                "Higher MB/s is faster."
                            ),
                            phase.set("Benchmark complete."),
                            progress.configure(value=100),
                            run_button.config(state="normal"),
                            cancel_button.config(state="disabled"),
                            copy_button.config(state="normal"),
                            size_combo.config(state="readonly")
                        )
                    )

                except Exception as exc:
                    self.root.after(
                        0,
                        lambda: (
                            status.set("Benchmark failed."),
                            phase.set("Benchmark failed."),
                            run_button.config(state="normal"),
                            cancel_button.config(state="disabled"),
                            copy_button.config(state="normal"),
                            size_combo.config(state="readonly"),
                            messagebox.showerror(
                                APP_NAME,
                                f"Benchmark failed:\n\n{exc}",
                                parent=window
                            )
                        )
                    )

            threading.Thread(target=worker, daemon=True).start()

        def benchmark_cancelled():
            status.set("Benchmark cancelled.")
            phase.set("Cancelled.")
            run_button.config(state="normal")
            cancel_button.config(state="disabled")
            copy_button.config(state="normal")
            size_combo.config(state="readonly")

        def cancel_benchmark():
            benchmark_cancel_event.set()
            cancel_button.config(state="disabled")
            phase.set("Cancelling...")
            status.set("Stopping benchmark safely...")

        cancel_button.config(command=cancel_benchmark)
        run_button.config(command=run)

    def build_benchmark_report(self, size_mb, rows):
        lines = [
            "HashCalc CPU Benchmark",
            "=" * 28,
            f"Test data: {size_mb} MB",
            "Test type: CPU hashing in RAM (disk speed excluded)",
            "",
            f"{'Algorithm':<12} {'Time':>12} {'Throughput':>16}",
            "-" * 42,
        ]

        for name, elapsed_text, speed_text in rows:
            lines.append(f"{name:<12} {elapsed_text:>12} {speed_text:>16}")

        lines.extend([
            "",
            "Higher MB/s is faster."
        ])
        return "\n".join(lines)

    def open_benchmark(self):
        self.benchmark()

if __name__ == "__main__":
    root = tk.Tk()
    HashCalcApp(root)
    root.mainloop()
