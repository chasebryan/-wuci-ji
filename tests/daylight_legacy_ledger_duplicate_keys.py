#!/usr/bin/env python3
from __future__ import annotations

import importlib
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def load_ledger_module(version_root: Path):
    for module_name in list(sys.modules):
        if module_name == "src" or module_name.startswith("src."):
            del sys.modules[module_name]
    sys.path.insert(0, str(version_root))
    try:
        return importlib.import_module("src.ledger")
    finally:
        sys.path.pop(0)


def assert_duplicate_keys_rejected(name: str, version_root: Path) -> None:
    module = load_ledger_module(version_root)
    with tempfile.TemporaryDirectory(prefix=f"{name}-ledger-") as tmp_name:
        path = Path(tmp_name) / "ledger.jsonl"
        path.write_text('{"entry_id":"one","entry_id":"two"}\n', encoding="utf-8")
        try:
            module.load_jsonl(path)
        except module.LedgerError as exc:
            assert "duplicate JSON key" in str(exc)
        else:
            raise AssertionError(f"{name} accepted duplicate JSON keys")


def main() -> int:
    assert_duplicate_keys_rejected("v14c_ledger", REPO / "daylight/v14c-plus")
    assert_duplicate_keys_rejected("v15_meridian_ledger", REPO / "daylight/v15-meridian")
    assert_duplicate_keys_rejected("v15_solstice_ledger", REPO / "daylight/v15-solstice")
    print("daylight legacy ledger duplicate-key tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
