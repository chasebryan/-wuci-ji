"""Adapters for verified Daylight v15/v16 artifacts consumed by v17."""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from .canonical_json import load_json_path, reject_float, sha256_bytes


REPO_ROOT = Path(__file__).resolve().parents[3]
SOLSTICE_ROOT = REPO_ROOT / "daylight" / "v15-solstice"
ZENITH_ROOT = REPO_ROOT / "daylight" / "v16-zenith"
ANALEMMA_ROOT = REPO_ROOT / "daylight" / "v16-analemma"


class BridgeError(ValueError):
    pass


def _load_package(alias: str, src_dir: Path) -> None:
    if alias in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        alias,
        src_dir / "__init__.py",
        submodule_search_locations=[str(src_dir)],
    )
    if spec is None or spec.loader is None:
        raise BridgeError(f"cannot load package at {src_dir}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)


def _module(alias: str, src_dir: Path, name: str) -> Any:
    _load_package(alias, src_dir)
    return importlib.import_module(f"{alias}.{name}")


def _solstice(name: str) -> Any:
    return _module("_daylight_v15_solstice_for_singularity", SOLSTICE_ROOT / "src", name)


def _zenith(name: str) -> Any:
    return _module("_daylight_v16_zenith_for_singularity", ZENITH_ROOT / "src", name)


def _analemma(name: str) -> Any:
    return _module("_daylight_v16_analemma_for_singularity", ANALEMMA_ROOT / "src", name)


def solstice_examples() -> tuple[Path, Path]:
    return (
        SOLSTICE_ROOT / "examples" / "ledger.seed.jsonl",
        SOLSTICE_ROOT / "examples" / "corpus.seed.jsonl",
    )


def build_solstice_artifact(*, ledger_path: Path | str, corpus_path: Path | str, out_dir: Path | str, command_label: str) -> dict[str, Any]:
    artifact_verify = _solstice("artifact_verify")
    solstice_harness = _solstice("solstice_harness")
    return artifact_verify.build_artifact(
        ledger_path=ledger_path,
        corpus_path=corpus_path,
        out_dir=out_dir,
        command_label=command_label,
        weights_path=solstice_harness.DEFAULT_WEIGHTS,
        obligations_path=solstice_harness.DEFAULT_OBLIGATIONS,
        rootset_path=solstice_harness.DEFAULT_ROOTSET,
    )


def verify_solstice_artifact(artifact_dir: Path | str) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir)
    artifact_verify = _solstice("artifact_verify")
    artifact_verify.verify_artifact_dir(artifact_dir)
    scorecard = load_json_path(artifact_dir / "scorecard.v15-solstice.json")
    manifest = load_json_path(artifact_dir / "artifact-manifest.solstice.json")
    receipt = load_json_path(artifact_dir / "reproducibility-receipt.v15-solstice.json")
    body = scorecard["score_body"]
    return {
        "ok": True,
        "artifact_dir": artifact_dir,
        "scorecard": scorecard,
        "manifest": manifest,
        "receipt": receipt,
        "final_score_M": int(body["final_score_M"]),
        "perfect_score_M": int(body["perfect_score_M"]),
        "open_internal_residue_M": int(body["open_internal_residue_M"]),
        "open_external_residue_M": int(body["open_external_residue_M"]),
        "claim_boundary": body["claim_boundary"],
        "scorecard_digest": scorecard["scorecard_digest"],
        "score_body_digest": scorecard["score_body_digest"],
        "artifact_manifest_digest": manifest["artifact_manifest_digest"],
        "receipt_digest": manifest["receipt_digest"],
        "output_ledger_head": manifest["output_ledger_head"],
        "sha256sums_digest": sha256_bytes((artifact_dir / "SHA256SUMS").read_bytes()),
    }


def build_zenith_report(*, solstice_artifact_dir: Path | str, out_dir: Path | str, evidence_path: Path | str | None = None) -> dict[str, Any]:
    zenith = _zenith("zenith_verifier")
    return zenith.build_report_artifact(
        solstice_artifact_dir=solstice_artifact_dir,
        out_dir=out_dir,
        evidence_path=evidence_path,
    )


def verify_zenith_report_dir(report_dir: Path | str | None) -> dict[str, Any] | None:
    if report_dir is None:
        return None
    report_dir = Path(report_dir)
    zenith = _zenith("zenith_verifier")
    zenith.verify_report_dir(report_dir)
    report = load_json_path(report_dir / "zenith-report.json")
    resolution = load_json_path(report_dir / "zenith-resolution.json")
    manifest = load_json_path(report_dir / "zenith-manifest.json")
    reject_float(report, "zenith_report")
    reject_float(resolution, "zenith_resolution")
    reject_float(manifest, "zenith_manifest")
    return {
        "ok": True,
        "report_dir": report_dir,
        "report": report,
        "resolution": resolution,
        "manifest": manifest,
        "report_digest": manifest["zenith_report_digest"],
        "resolution_digest": manifest["zenith_resolution_digest"],
        "manifest_digest": sha256_bytes((report_dir / "zenith-manifest.json").read_bytes()),
        "closed_obligations": set(report.get("closed_zenith_obligations", [])),
        "score_inflation_M": int(report.get("score_inflation_M", 0)),
    }


def build_analemma_report(
    *,
    solstice_artifact_dir: Path | str,
    out_dir: Path | str,
    evidence_path: Path | str | None = None,
    history_path: Path | str | None = None,
) -> dict[str, Any]:
    analemma = _analemma("analemma")
    return analemma.build_report_artifact(
        solstice_artifact_dir,
        out_dir=out_dir,
        evidence_path=evidence_path,
        history_path=history_path,
    )


def verify_analemma_report_dir(report_dir: Path | str | None) -> dict[str, Any] | None:
    if report_dir is None:
        return None
    report_dir = Path(report_dir)
    analemma = _analemma("analemma")
    analemma.verify_report_dir(report_dir)
    report = load_json_path(report_dir / "analemma-report.json")
    resolution = load_json_path(report_dir / "analemma-resolution.json")
    manifest = load_json_path(report_dir / "analemma-manifest.json")
    reject_float(report, "analemma_report")
    reject_float(resolution, "analemma_resolution")
    reject_float(manifest, "analemma_manifest")
    return {
        "ok": True,
        "report_dir": report_dir,
        "report": report,
        "resolution": resolution,
        "manifest": manifest,
        "report_digest": manifest["analemma_report_digest"],
        "resolution_digest": manifest["analemma_resolution_digest"],
        "manifest_digest": manifest["analemma_manifest_digest"],
        "score_inflation_M": int(report.get("score_inflation_M", 0)),
    }

