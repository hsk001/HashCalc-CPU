# Troubleshooting

## I don't have Python

You do not need Python when using the standalone Windows release executable.

If you are running the source code directly, Python 3.11+ is required.

## The EXE does not start

Try launching it from Command Prompt to capture an error if a console-enabled diagnostic build is available.

Also check Windows Security/antivirus quarantine history if the executable was blocked.

Only download releases from the project's official GitHub repository.

## A hash does not match

Check:
1. The correct file was selected.
2. The expected checksum was copied completely.
3. There are no extra spaces or characters.
4. The expected checksum belongs to the same file.
5. The file has not changed since the checksum was generated.

## Large files seem slow

A full-file hash necessarily has to process the entire file.

For large GGUF and other multi-gigabyte files, select only the algorithms you need.

## Benchmark takes time

Larger test sizes process more data for every algorithm. The benchmark window provides progress and status information.

Use **Cancel** if required.

## Reporting a bug

Include:
- Windows version
- HashCalc version
- whether you used the standalone EXE or Python source
- Python version if running from source
- exact error message/traceback
- approximate file size
- operation being performed

Do not upload private or sensitive files merely to demonstrate a checksum problem.
