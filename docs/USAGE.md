# Usage

## Windows users

Use the standalone executable from GitHub Releases. Python does not need to be installed.

## File hashing

Click **Browse...** and choose a file. HashCalc processes files as binary data and does not modify the input file.

Select only the algorithms you need, then click **Calculate Selected**. The main hasher reads the file in chunks and feeds each selected algorithm from the same read pass. This avoids unnecessary repeated disk reads for multi-gigabyte files.

Each result includes the algorithm, digest, and a **Copy** action.

## Folder hashing

Change **Hash mode** to **Folder**, then click **Browse Folder...**.

Folder mode is deliberately conservative by default:

- **Include subfolders:** OFF by default. Only files directly inside the selected folder are included.
- **Include hidden/system files:** OFF by default. Hidden and Windows system entries are excluded unless explicitly enabled.

Enable either option when you need a broader scan. Folder hashing processes each included file as binary data and feeds all selected algorithms from the same read pass.

The folder results table shows the relative file path, size, selected hashes, status, and a per-file **Copy** action. The Multiple Files table uses the same layout. Files that cannot be read are reported instead of being silently treated as successful.

Click **Export TXT Manifest** or **Export CSV Manifest** after a folder hash completes to save the calculated file list and digests.

The manifest represents the files included in that particular scan; HashCalc does not invent a single cryptographic "folder hash".

## Verify

For file mode, paste an expected checksum into **Expected hash** and click **Compare**.

The comparison is performed against hashes that have already been calculated. Hash length is not treated as proof of which algorithm produced the checksum.

Folder-manifest verification is not part of v1.1.0; v1.1 focuses on creating and exporting folder manifests.

## Benchmark

Open **Benchmark**, select a test size, and run it.

The benchmark creates the test buffer in RAM and then measures each algorithm independently. The progress bar and phase text indicate that the application is working.

Click **Cancel** to stop at a safe point.

Use **Copy Results** to copy a plain-text benchmark report.


## Drag and drop

On Windows, files and folders can be dropped directly onto the HashCalc CPU window. The application detects the selection and chooses the appropriate mode automatically:

- One file → File mode
- Multiple files → Multiple Files mode
- One folder → Folder mode
- Multiple folders → not allowed
- Files and folders together → not allowed

## Exporting hashes

Hash results can be exported from File, Multiple Files, and Folder modes as TXT or CSV. The Save dialog suggests a useful filename based on the current input.
