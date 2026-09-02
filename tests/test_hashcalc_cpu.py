import ctypes
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import hashcalc_cpu


class HashCalcTests(unittest.TestCase):
    def test_algorithms_available(self):
        for name, algorithm in hashcalc_cpu.ALGORITHMS:
            if algorithm == "crc32":
                self.assertIsInstance(zlib.crc32(b"test"), int)
            else:
                h = hashlib.new(algorithm)
                h.update(b"test")
                self.assertTrue(h.hexdigest())

    def test_folder_non_recursive_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root_file = root / "root.txt"
            nested = root / "nested"
            nested.mkdir()
            nested_file = nested / "nested.txt"
            hidden_file = root / ".hidden.txt"
            root_file.write_bytes(b"root")
            nested_file.write_bytes(b"nested")
            hidden_file.write_bytes(b"hidden")
            if os.name == "nt":
                set_hidden = ctypes.windll.kernel32.SetFileAttributesW
                set_hidden.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
                set_hidden.restype = ctypes.c_bool
                self.assertTrue(set_hidden(str(hidden_file), 0x2))  # FILE_ATTRIBUTE_HIDDEN

            files, errors = hashcalc_cpu.collect_folder_files(str(root))

            self.assertEqual(errors, [])
            self.assertIn(str(root_file), files)
            self.assertNotIn(str(nested_file), files)
            self.assertNotIn(str(hidden_file), files)

    def test_folder_options_include_subfolders_and_hidden(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root_file = root / "root.txt"
            nested = root / "nested"
            nested.mkdir()
            nested_file = nested / "nested.txt"
            hidden_file = root / ".hidden.txt"
            root_file.write_bytes(b"root")
            nested_file.write_bytes(b"nested")
            hidden_file.write_bytes(b"hidden")
            if os.name == "nt":
                set_hidden = ctypes.windll.kernel32.SetFileAttributesW
                set_hidden.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
                set_hidden.restype = ctypes.c_bool
                self.assertTrue(set_hidden(str(hidden_file), 0x2))  # FILE_ATTRIBUTE_HIDDEN

            files, errors = hashcalc_cpu.collect_folder_files(
                str(root), include_subfolders=True, include_hidden_system=True
            )

            self.assertEqual(errors, [])
            self.assertIn(str(root_file), files)
            self.assertIn(str(nested_file), files)
            self.assertIn(str(hidden_file), files)

    def test_folder_hashes_match_standard_library(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "sample.bin"
            data = b"HashCalc CPU folder test\x00" * 100
            target.write_bytes(data)

            result = hashcalc_cpu.calculate_folder_hashes(
                str(root), ["crc32", "sha256"]
            )

            self.assertIsNotNone(result)
            rows, errors = result
            self.assertEqual(errors, [])
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["status"], "OK")
            self.assertEqual(row["path"], "sample.bin")
            self.assertEqual(row["size"], len(data))
            self.assertEqual(row["hashes"]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(row["hashes"]["crc32"], f"{zlib.crc32(data) & 0xFFFFFFFF:08x}")

    def test_classify_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            f1 = root / "one.bin"
            f2 = root / "two.bin"
            d1 = root / "folder1"
            d2 = root / "folder2"
            f1.write_bytes(b"1")
            f2.write_bytes(b"2")
            d1.mkdir()
            d2.mkdir()

            self.assertEqual(hashcalc_cpu.classify_paths([str(f1)])[0], "file")
            self.assertEqual(hashcalc_cpu.classify_paths([str(f1), str(f2)])[0], "multiple_files")
            self.assertEqual(hashcalc_cpu.classify_paths([str(d1)])[0], "folder")
            self.assertEqual(hashcalc_cpu.classify_paths([str(d1), str(d2)])[0], "multiple_folders")
            self.assertEqual(hashcalc_cpu.classify_paths([str(f1), str(d1)])[0], "mixed")


if __name__ == "__main__":
    unittest.main()
