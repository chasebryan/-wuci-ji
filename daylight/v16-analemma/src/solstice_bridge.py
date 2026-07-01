"""Bridge to the sibling Daylight v15+ Solstice artifact verifier."""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
SOLSTICE_ROOT = REPO_ROOT / "daylight" / "v15-solstice"
SOLSTICE_SRC = SOLSTICE_ROOT / "src"
SOLSTICE_PACKAGE = "_daylight_v15_solstice_for_analemma"


class SolsticeBridgeError(ValueError):
    pass


def _load_package() -> None:
    if SOLSTICE_PACKAGE in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        SOLSTICE_PACKAGE,
        SOLSTICE_SRC / "__init__.py",
        submodule_search_locations=[str(SOLSTICE_SRC)],
    )
    if spec is None or spec.loader is None:
        raise SolsticeBridgeError("cannot load Daylight v15+ Solstice package")
    module = importlib.util.module_from_spec(spec)
    sys.modules[SOLSTICE_PACKAGE] = module
    spec.loader.exec_module(module)


def _module(name: str) -> Any:
    _load_package()
    return importlib.import_module(f"{SOLSTICE_PACKAGE}.{name}")


def load_and_verify(artifact_dir: Path | str) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir)
    artifact_verify = _module("artifact_verify")
    artifact_verify.verify_artifact_dir(artifact_dir)
    scorecard = json.loads((artifact_dir / "scorecard.v15-solstice.json").read_text(encoding="utf-8"))
    manifest = json.loads((artifact_dir / "artifact-manifest.solstice.json").read_text(encoding="utf-8"))
    body = scorecard["score_body"]
    return {
        "artifact_dir": artifact_dir,
        "scorecard": scorecard,
        "manifest": manifest,
        "claim_score_M": int(body["final_score_M"]),
        "perfect_score_M": int(body["perfect_score_M"]),
        "open_internal_residue_M": int(body["open_internal_residue_M"]),
        "open_external_residue_M": int(body["open_external_residue_M"]),
        "external_residue_M": int(body["external_residue_M"]),
        "closed_obligations": body["closed_obligations"],
        "open_obligations": body["open_obligations"],
        "claim_boundary": body["claim_boundary"],
        "scorecard_digest": scorecard["scorecard_digest"],
        "artifact_manifest_digest": manifest["artifact_manifest_digest"],
        "weight_vector_digest": body["weight_vector_digest"],
        "evidence_resolution_digest": body["evidence_resolution_digest"],
        "score_body_digest": scorecard["score_body_digest"],
        "output_ledger_head": scorecard["output_ledger_head"],
    }


def build_solstice_artifact(
    *,
    ledger_path: Path | str,
    corpus_path: Path | str,
    out_dir: Path | str,
    command_label: str,
) -> dict[str, Any]:
    artifact_verify = _module("artifact_verify")
    solstice_harness = _module("solstice_harness")
    return artifact_verify.build_artifact(
        ledger_path=ledger_path,
        corpus_path=corpus_path,
        out_dir=out_dir,
        command_label=command_label,
        weights_path=solstice_harness.DEFAULT_WEIGHTS,
        obligations_path=solstice_harness.DEFAULT_OBLIGATIONS,
        rootset_path=solstice_harness.DEFAULT_ROOTSET,
    )


def solstice_examples() -> tuple[Path, Path]:
    return (
        SOLSTICE_ROOT / "examples" / "ledger.seed.jsonl",
        SOLSTICE_ROOT / "examples" / "corpus.seed.jsonl",
    )
