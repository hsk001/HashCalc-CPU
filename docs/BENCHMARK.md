# Benchmark Design

The normal file hasher and the CPU benchmark intentionally use different workloads.

## Normal file hashing

The file is read once in chunks:

```text
File
 |
 | read chunk
 v
+--------+--------+--------+--------+
| MD5    | SHA-1  | SHA-256| ...    |
+--------+--------+--------+--------+
 |
 v
next chunk
```

This minimizes disk I/O when several hashes are selected.

## CPU benchmark

The benchmark first generates one test buffer in RAM:

```text
RAM test buffer
 |
 +--> CRC32   -> measure -> result
 +--> MD5     -> measure -> result
 +--> SHA-1   -> measure -> result
 +--> SHA-256 -> measure -> result
 +--> ...
```

Each algorithm is timed independently against the same buffer. The test therefore focuses on CPU-side hashing rather than file-storage throughput.

## Throughput

```text
MB/s = test size in MiB / elapsed seconds
```

Higher MB/s means faster processing for that algorithm on the tested system.

## Interpretation

Results can vary with CPU frequency, thermal state, background load, Python version, OpenSSL implementation, and operating-system scheduling.

The benchmark is best used for practical comparisons on the same machine.
