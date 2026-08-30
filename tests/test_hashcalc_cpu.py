import hashlib
import zlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import hashcalc_cpu


def test_algorithms_available():
    for name, algorithm in hashcalc_cpu.ALGORITHMS:
        if algorithm == "crc32":
            assert isinstance(zlib.crc32(b"test"), int)
        else:
            h = hashlib.new(algorithm)
            h.update(b"test")
            assert h.hexdigest()


if __name__ == "__main__":
    test_algorithms_available()
    print("HashCalc CPU basic tests: OK")
