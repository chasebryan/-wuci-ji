from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src import solstice_bridge


def build_solstice_artifact(root: Path) -> Path:
    ledger_path, corpus_path = solstice_bridge.solstice_examples()
    out_dir = root / "solstice"
    solstice_bridge.build_solstice_artifact(
        ledger_path=ledger_path,
        corpus_path=corpus_path,
        out_dir=out_dir,
        command_label="analemma-test",
    )
    return out_dir


def write_json(root: Path, name: str, data: dict[str, Any]) -> Path:
    path = root / name
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
