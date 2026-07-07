"""Bridge to the sibling Daylight v15+ Solstice verifier package."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

from .canonical_json import load_json_file_no_duplicates

REPO_ROOT = Path(__file__).resolve().parents[3]
SOLSTICE_ROOT = REPO_ROOT / "daylight" / "v15-solstice"
SOLSTICE_SRC = SOLSTICE_ROOT / "src"
SOLSTICE_PACKAGE = "_daylight_v15_solstice"


class SolsticeBridgeError(ValueError):
    pass


def _load_solstice_package() -> None:
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
    _load_solstice_package()
    return importlib.import_module(f"{SOLSTICE_PACKAGE}.{name}")


def load_artifact(artifact_dir: Path | str) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir)
    manifest_path = artifact_dir / "artifact-manifest.solstice.json"
    scorecard_path = artifact_dir / "scorecard.v15-solstice.json"
    receipt_path = artifact_dir / "reproducibility-receipt.v15-solstice.json"
    output_ledger_path = artifact_dir / "output-ledger.v15-solstice.jsonl"
    if not manifest_path.is_file():
        raise SolsticeBridgeError(f"missing Solstice manifest: {manifest_path}")
    return {
        "artifact_dir": artifact_dir,
        "manifest": load_json_file_no_duplicates(manifest_path, "Solstice manifest"),
        "scorecard": load_json_file_no_duplicates(scorecard_path, "Solstice scorecard"),
        "receipt": load_json_file_no_duplicates(receipt_path, "Solstice receipt"),
        "output_ledger_path": output_ledger_path,
    }


def verify_artifact(artifact_dir: Path | str) -> dict[str, Any]:
    artifact_verify = _module("artifact_verify")
    solstice_harness = _module("solstice_harness")
    artifact_verify.verify_artifact_dir(artifact_dir)
    loaded = load_artifact(artifact_dir)
    scorecard = loaded["scorecard"]
    body = scorecard["score_body"]
    return {
        "ok": True,
        "artifact_dir": str(Path(artifact_dir)),
        "scorecard": scorecard,
        "manifest": loaded["manifest"],
        "receipt": loaded["receipt"],
        "scorecard_digest": scorecard["scorecard_digest"],
        "artifact_manifest_digest": loaded["manifest"]["artifact_manifest_digest"],
        "score_body_digest": scorecard["score_body_digest"],
        "obligations_digest": body["obligations_digest"],
        "weight_vector_digest": body["weight_vector_digest"],
        "input_ledger_head": body["input_ledger_head"],
        "corpus_snapshot_digest": body["corpus_snapshot_digest"],
        "q_vector": body["q_vector"],
        "final_score_M": body["final_score_M"],
        "open_internal_residue_M": body["open_internal_residue_M"],
        "open_external_residue_M": body["open_external_residue_M"],
        "claim_boundary": body["claim_boundary"],
        "scorecard_digest_fn": solstice_harness.scorecard_digest,
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
