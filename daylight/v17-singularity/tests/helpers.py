from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from src import v16_bridge


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def build_upstream(root: Path) -> tuple[Path, Path, Path]:
    ledger_path, corpus_path = v16_bridge.solstice_examples()
    solstice = root / "solstice"
    zenith = root / "zenith"
    analemma = root / "analemma"
    v16_bridge.build_solstice_artifact(
        ledger_path=ledger_path,
        corpus_path=corpus_path,
        out_dir=solstice,
        command_label="singularity-test",
    )
    v16_bridge.build_zenith_report(solstice_artifact_dir=solstice, out_dir=zenith)
    v16_bridge.build_analemma_report(solstice_artifact_dir=solstice, out_dir=analemma)
    return solstice, zenith, analemma


def write_json(root: Path, name: str, data: dict[str, Any]) -> Path:
    path = root / name
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def record(kind: str, value: str, *, key: str = "surface") -> dict[str, Any]:
    return {
        key: value,
        "verified": True,
        "valid": True,
        "fixture_material_used": False,
        "offensive_tooling_included": False,
        "evidence_digest": digest(f"{kind}:{value}"),
    }

