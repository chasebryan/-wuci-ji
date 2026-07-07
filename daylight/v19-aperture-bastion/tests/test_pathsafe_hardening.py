from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from src.pathsafe import PathSafetyError, atomic_write_bytes, read_public_bytes


class PathsafeHardeningTests(unittest.TestCase):
    def test_atomic_write_rejects_symlinked_parent(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unsupported")
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            real_parent = tmp / "real-parent"
            real_parent.mkdir()
            linked_parent = tmp / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(PathSafetyError):
                atomic_write_bytes(linked_parent / "out.txt", b"blocked\n")

    def test_read_public_bytes_rejects_symlink_and_size_overrun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            target = tmp / "target.txt"
            target.write_bytes(b"safe bytes\n")
            with self.assertRaises(PathSafetyError):
                read_public_bytes(target, "target", max_bytes=3)

            if not hasattr(os, "symlink"):
                return
            link = tmp / "link.txt"
            link.symlink_to(target)
            with self.assertRaises(PathSafetyError):
                read_public_bytes(link, "link")


if __name__ == "__main__":
    unittest.main()
