from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path

from tests.helpers import PACKAGE_ROOT

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None


class PackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pyproject = PACKAGE_ROOT / "pyproject.toml"

    def test_pyproject_exists(self) -> None:
        self.assertTrue(self.pyproject.is_file())

    @unittest.skipIf(tomllib is None, "tomllib requires Python 3.11+")
    def test_pyproject_metadata(self) -> None:
        data = tomllib.loads(self.pyproject.read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["name"], "daylight-meridian")
        self.assertEqual(data["project"]["version"], "15.0.0")
        self.assertEqual(data["project"]["scripts"]["daylight-meridian"], "src.cli:main")
        self.assertIn("src", data["tool"]["setuptools"]["packages"])

    def test_version_matches_package(self) -> None:
        from src import __version__

        self.assertEqual(__version__, "15.0.0")

    def test_entry_point_target_is_callable(self) -> None:
        from src import cli

        self.assertTrue(callable(cli.main))
        # argparse --version action prints to stdout and exits 0.
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
