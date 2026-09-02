# HashCalc CPU

A lightweight Windows desktop file hasher and CPU hash benchmark written in Python and Tkinter.

## For Windows users — no Python required

Download the latest **standalone Windows executable** from the project's GitHub **Releases** page.

The executable bundles the Python runtime and required application components. A separate Python installation is **not required**.

The source code remains available for inspection, development, and troubleshooting.

## Features

### File hashing
- CRC32
- MD5
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA3-256
- SHA3-512
- BLAKE2b
- BLAKE2s

### Input and drag-and-drop
- Drag and drop files or a folder onto the application window.
- One dropped file selects **File** mode automatically.
- Multiple dropped files select **Multiple Files** mode automatically.
- One dropped folder selects **Folder** mode automatically.
- Multiple folders are not allowed.
- Files and folders cannot be mixed in one drop.

### Folder hashing
- Select a folder instead of a single file.
- Include subfolders is **off by default**.
- Include hidden/system files is **off by default**.
- Hash every included file using the selected algorithms from one read pass.
- Show relative path, size, hashes, status, and a per-file Copy action for each file.
- Export folder results as TXT or CSV manifests.

### Multiple file hashing
- Select or drop multiple files without scanning their containing folders.
- Hash each selected file once and feed all selected algorithms from the same read pass.
- Show each file, size, hashes, status, and a per-file Copy action.
- Export the selected-file results as TXT or CSV.

### Hash export
- File mode supports TXT and CSV export.
- Suggested filenames use `<filename>.hashes.txt` or `<filename>.hashes.csv`.
- Folder exports use `<folder>.hashes.txt` or `<folder>.hashes.csv`.
- Multiple-file exports use `HashCalc-CPU-hashes.txt` or `HashCalc-CPU-hashes.csv`.

### Hashing workflow
- Select only the algorithms you need.
- Reads the input file in chunks.
- Feeds selected algorithms from the same file-read pass.
- Shows the resulting hash and per-algorithm processing time.
- Copy an individual hash or all results.
- Cancel long-running file hashing.
- Clear calculated results.

### Verification
Paste an expected checksum and HashCalc compares it against the hashes that were actually calculated.

The verification system does not assume that an expected checksum is SHA-256. It compares against the calculated digests, including algorithms with the same hexadecimal output length.

### CPU benchmark
- Select test size.
- Generate test data in RAM so disk speed is excluded.
- Measure each algorithm independently.
- Report elapsed time and throughput.
- Show progress during test-data generation.
- Show the currently running algorithm.
- Cancel the benchmark safely.
- Copy benchmark results.

## System Requirements

### Windows
- Windows 10 or Windows 11
- **64-bit Windows (x64)**
- No Python installation required when using the official Windows executable

> The official HashCalc CPU Windows executable is built for 64-bit x86-64 Windows. It does not support 32-bit (x86) Windows.

## Windows standalone build

The project uses PyInstaller to package the application.

The resulting executable is a GUI application, so no console window is required during normal use.

### Build locally

On Windows:

```text
python -m pip install pyinstaller
pyinstaller packaging/HashCalc_CPU.spec
```

The executable will be placed under:

```text
dist/HashCalc_CPU/
```

The release workflow in `.github/workflows/build-windows.yml` can build the Windows package automatically on GitHub.

## Run from source

For developers with Python 3.11+:

```text
python src/hashcalc_cpu.py
```

No third-party packages are needed to run the application from source.

## Benchmark notes

The benchmark measures hashing speed against a RAM-resident test buffer. It is not a laboratory-grade benchmark.

CPU frequency, thermal state, background processes, Python/OpenSSL versions, and system load can affect results.

For comparisons, use the same test size and similar system conditions.

## Security note

MD5 and SHA-1 are retained for compatibility and identification. They should not be treated as collision-resistant cryptographic signatures for security-sensitive applications.

For modern integrity verification, SHA-256 or stronger algorithms are generally preferable.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md)
- [`docs/BENCHMARK.md`](docs/BENCHMARK.md)
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`SECURITY.md`](SECURITY.md)

## License

MIT. See [`LICENSE`](LICENSE).
