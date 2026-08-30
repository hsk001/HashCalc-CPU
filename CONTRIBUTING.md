# Contributing

Bug reports, testing feedback, documentation improvements, and code contributions are welcome.

## Development

The application itself uses Python standard-library modules.

PyInstaller is only needed to create the standalone Windows distribution.

Build:

```text
python -m pip install pyinstaller
pyinstaller packaging/HashCalc_CPU.spec
```

Basic syntax check:

```text
python -m py_compile src/hashcalc_cpu.py
```

## Design principles

- Avoid unnecessary disk I/O.
- Keep the GUI responsive during long operations.
- Do not silently calculate hashes the user did not request.
- Do not modify input files.
- Keep verification deterministic.
- Keep the application simple and inspectable.
