# Usage

## Windows users

Use the standalone executable from GitHub Releases. Python does not need to be installed.

## Select a file

Click **Browse...** and choose the file to hash.

HashCalc processes files as binary data and does not modify the input file.

## Select algorithms

Select only the algorithms you need.

For very large files, avoid calculating every algorithm unless you actually need every digest.

## Calculate

Click **Calculate Selected**.

The main hasher reads the file in chunks and feeds each selected algorithm from the same read pass. This avoids unnecessary repeated disk reads for multi-gigabyte files.

Each result includes the algorithm, digest, processing time, and a copy action.

## Verify

Paste an expected checksum into **Expected hash** and click **Compare**.

The comparison is performed against hashes that have already been calculated. Hash length is not treated as proof of which algorithm produced the checksum.

## Benchmark

Open **Benchmark**, select a test size, and run it.

The benchmark creates the test buffer in RAM and then measures each algorithm independently. The progress bar and phase text indicate that the application is working.

Click **Cancel** to stop at a safe point.

Use **Copy Results** to copy a plain-text benchmark report.
