# Changelog

## 1.2.5
- Added a per-file `Copy` action to Multiple Files and Folder result tables.
- Added a dedicated `Action` column alongside `Status` so result state and user actions are clearly separated.
- Adjusted result-table column sizing and minimum widths so columns fit within the application window, with right-side breathing room.


## 1.2.4
- Removed the per-algorithm `CPU Hash Time` column from the main hashing results table.
- The main UI now focuses on the user-relevant end-to-end `Total time` shown in the status bar.
- CPU timing remains available in the dedicated Benchmark view, where algorithm performance is the purpose of the measurement.

## 1.2.3
- Fixed a Windows Tkinter crash caused by calling Tk from inside the native WM_DROPFILES callback. Dropped paths are now queued by the native callback and consumed by the Tk event loop.
- Kept the v1.2.2 timing terminology cleanup: CPU Hash Time and Total time.


## 1.2.2

- Renamed the main results timing column from `Hash Time` to `CPU Hash Time` to distinguish algorithm processing time from end-to-end operation time.
- Changed completion status wording to explicitly label end-to-end duration as `Total time`.
- Applied the timing terminology consistently to File, Multiple Files, and Folder modes.

## 1.2.1

- Fixed Windows drag-and-drop: `DragAcceptFiles` is correctly called from `shell32.dll` (the previous build incorrectly called it through `user32.dll`, causing drag-and-drop initialization to fail silently).
- Made the test suite compatible with the GitHub Actions `unittest` test runner.

## v1.2.0

- Added Windows drag-and-drop support using the native Windows file-drop mechanism.
- Added automatic File, Multiple Files, and Folder mode selection for drops.
- Added multiple-file hashing without recursive folder scanning.
- Reject mixed file/folder drops with a clear error message.
- Reject multiple-folder drops with a clear error message.
- Added TXT and CSV export for File mode.
- Added TXT and CSV export for Multiple Files mode.
- Added suggested export filenames based on the selected input.
- Added tests for dropped-path classification.


## v1.1.0

- Added folder hashing mode.
- Folder hashing is non-recursive by default.
- Hidden/system files are excluded by default.
- Added explicit options to include subfolders and hidden/system files.
- Reused the existing one-read-per-file multi-algorithm hashing path.
- Added per-file folder results with relative path, size, hashes, and status.
- Added TXT and CSV folder manifest export.
- Added folder hashing tests.


## v16

- Added GitHub-ready Windows packaging.
- Added PyInstaller spec for a standalone executable.
- Added GitHub Actions workflow for Windows builds.
- Updated README to distinguish standalone users from Python developers.
- Added documentation for executable distribution and troubleshooting.

## v15

- Increased displayed timing precision to three decimal places for sub-minute timings.

## v14

- Fixed results table layout so it remains inside the startup window.
