"""Solstice artifact construction and closure verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import __version__
from . import ledger as ledger_model
from . import solstice_harness
from .canonical_json import CanonicalJSONError, canonical_sha256, load_json_file_no_duplicates, read_regular_bytes


REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_VERSION = "daylight-v15-solstice-artifact-manifest-v0.1"
D_ARTIFACT = "DAYLIGHT-v15-SOLSTICE-ARTIFACT:"
GENERATED_DATE = "2026-07-01"


class ArtifactError(ValueError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repo_relative(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(REPO_ROOT))
    except ValueError:
        return str(resolved)


def _artifact_input_name(label: str, path: Path) -> str:
    suffix = path.suffix or ".dat"
    safe_label = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in label)
    return f"inputs/{safe_label}{suffix}"


def _manifest_input_record(label: str, path: Path, extra_files: dict[str, bytes]) -> dict[str, str]:
    data = read_regular_bytes(path, f"Solstice input {label}")
    resolved = Path(path).resolve(strict=True)
    try:
        repo_path = str(resolved.relative_to(REPO_ROOT))
    except ValueError:
        artifact_name = _artifact_input_name(label, path)
        extra_files[artifact_name] = data
        return {"path": artifact_name, "sha256": _sha256_bytes(data)}
    return {"path": repo_path, "sha256": _sha256_bytes(data)}


def _resolve_manifest_path(path_text: str, artifact_dir: Path) -> Path:
    if not isinstance(path_text, str) or not path_text:
        raise ArtifactError("manifest path must be a non-empty relative path")
    candidate = Path(path_text)
    if candidate.is_absolute():
        raise ArtifactError(f"absolute manifest path rejected: {path_text}")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise ArtifactError(f"unsafe manifest path rejected: {path_text}")
    repo_candidate = REPO_ROOT / candidate
    if repo_candidate.exists():
        resolved = repo_candidate.resolve(strict=True)
        try:
            resolved.relative_to(REPO_ROOT)
        except ValueError as exc:
            raise ArtifactError(f"manifest path escapes repository: {path_text}") from exc
        return resolved
    resolved_artifact = (artifact_dir / candidate).resolve(strict=True)
    try:
        resolved_artifact.relative_to(artifact_dir.resolve(strict=True))
    except ValueError as exc:
        raise ArtifactError(f"manifest path escapes artifact directory: {path_text}") from exc
    return resolved_artifact


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _jsonl_bytes(entries: list[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n" for entry in entries).encode("utf-8")


def _load_json(path: Path, context: str) -> Any:
    try:
        return load_json_file_no_duplicates(path, context)
    except CanonicalJSONError as exc:
        raise ArtifactError(str(exc)) from exc


def manifest_digest(manifest: dict[str, Any]) -> str:
    body = {key: value for key, value in manifest.items() if key != "artifact_manifest_digest"}
    return canonical_sha256(body, D_ARTIFACT)


def _frontier_report(scorecard: dict[str, Any]) -> dict[str, Any]:
    body = scorecard["score_body"]
    return {
        "report_version": "daylight-v15-solstice-frontier-report-v0.1",
        "status": scorecard["status"],
        "final_score_M": body["final_score_M"],
        "perfect_score_M": body["perfect_score_M"],
        "internal_ceiling_M": body["internal_ceiling_M"],
        "external_residue_M": body["external_residue_M"],
        "open_internal_residue_M": body["open_internal_residue_M"],
        "open_external_residue_M": body["open_external_residue_M"],
        "open_obligations": body["open_obligations"],
        "boundary": body["claim_boundary"],
    }


def build_artifact(
    *,
    ledger_path: Path | str,
    corpus_path: Path | str,
    out_dir: Path | str,
    command_label: str,
    weights_path: Path | str = solstice_harness.DEFAULT_WEIGHTS,
    obligations_path: Path | str = solstice_harness.DEFAULT_OBLIGATIONS,
    rootset_path: Path | str | None = solstice_harness.DEFAULT_ROOTSET,
) -> dict[str, Any]:
    ledger_path = Path(ledger_path)
    corpus_path = Path(corpus_path)
    weights_path = Path(weights_path)
    obligations_path = Path(obligations_path)
    rootset = Path(rootset_path) if rootset_path is not None else None
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scorecard, receipt, output_ledger = solstice_harness.generate_scorecard(
        ledger_path=ledger_path,
        corpus_path=corpus_path,
        weights_path=weights_path,
        obligations_path=obligations_path,
        rootset_path=rootset,
        command=command_label,
    )
    frontier = _frontier_report(scorecard)

    outputs: dict[str, bytes] = {
        "scorecard.v15-solstice.json": _json_bytes(scorecard),
        "reproducibility-receipt.v15-solstice.json": _json_bytes(receipt),
        "output-ledger.v15-solstice.jsonl": _jsonl_bytes(output_ledger),
        "frontier-report.v15-solstice.json": _json_bytes(frontier),
    }
    input_paths = {
        "obligations": obligations_path,
        "weights": weights_path,
        "input_ledger": ledger_path,
        "corpus": corpus_path,
    }
    if rootset is not None:
        input_paths["external_rootset"] = rootset

    extra_files: dict[str, bytes] = {}
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "artifact": "Daylight v15+ Solstice",
        "package_version": __version__,
        "generated_date": GENERATED_DATE,
        "command": command_label,
        "inputs": {
            name: _manifest_input_record(name, Path(path), extra_files)
            for name, path in sorted(input_paths.items())
        },
        "outputs": {
            name: {"path": name, "sha256": _sha256_bytes(data)}
            for name, data in sorted(outputs.items())
        },
        "score_body_digest": scorecard["score_body_digest"],
        "scorecard_digest": scorecard["scorecard_digest"],
        "receipt_digest": scorecard["reproducibility_receipt_digest"],
        "score_entry_digest": scorecard["score_entry_digest"],
        "output_ledger_head": scorecard["output_ledger_head"],
        "final_score_M": scorecard["score_body"]["final_score_M"],
        "internal_ceiling_M": scorecard["score_body"]["internal_ceiling_M"],
        "external_residue_M": scorecard["score_body"]["external_residue_M"],
        "residue_to_perfect_M": scorecard["score_body"]["residue_to_perfect_M"],
        "boundary": scorecard["score_body"]["claim_boundary"],
    }
    manifest["artifact_manifest_digest"] = manifest_digest(manifest)
    outputs["artifact-manifest.solstice.json"] = _json_bytes(manifest)
    sha_lines = [
        f"{_sha256_bytes(data)}  {name}\n"
        for name, data in sorted(outputs.items())
    ]
    outputs["SHA256SUMS"] = "".join(sha_lines).encode("utf-8")

    for name, data in {**extra_files, **outputs}.items():
        (out_dir / name).parent.mkdir(parents=True, exist_ok=True)
        (out_dir / name).write_bytes(data)
    return manifest


def _verify_hash(path: Path, expected: str) -> None:
    try:
        data = read_regular_bytes(path, f"Solstice artifact file {path}")
    except CanonicalJSONError as exc:
        raise ArtifactError(str(exc)) from exc
    actual = _sha256_bytes(data)
    if actual != expected:
        raise ArtifactError(f"sha256 mismatch for {path}: {actual} != {expected}")


def verify_artifact_dir(path: Path | str) -> None:
    artifact_dir = Path(path)
    manifest_path = artifact_dir / "artifact-manifest.solstice.json"
    scorecard_path = artifact_dir / "scorecard.v15-solstice.json"
    receipt_path = artifact_dir / "reproducibility-receipt.v15-solstice.json"
    output_ledger_path = artifact_dir / "output-ledger.v15-solstice.jsonl"
    sums_path = artifact_dir / "SHA256SUMS"
    manifest = _load_json(manifest_path, "Solstice artifact manifest")
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise ArtifactError("unsupported artifact manifest version")
    if manifest_digest(manifest) != manifest.get("artifact_manifest_digest"):
        raise ArtifactError("artifact manifest digest mismatch")

    for group in ("inputs", "outputs"):
        entries = manifest.get(group, {})
        if not isinstance(entries, dict):
            raise ArtifactError(f"manifest {group} must be an object")
        for _, info in entries.items():
            file_path = _resolve_manifest_path(info["path"], artifact_dir)
            _verify_hash(file_path, info["sha256"])
    try:
        manifest_bytes = read_regular_bytes(manifest_path, "Solstice artifact manifest")
    except CanonicalJSONError as exc:
        raise ArtifactError(str(exc)) from exc
    _verify_hash(manifest_path, _sha256_bytes(manifest_bytes))

    try:
        expected_sums = "".join(
            f"{_sha256_bytes(read_regular_bytes(artifact_dir / name, f'Solstice output {name}'))}  {name}\n"
            for name in sorted(list(manifest["outputs"]) + ["artifact-manifest.solstice.json"])
        )
        actual_sums = read_regular_bytes(sums_path, "Solstice SHA256SUMS").decode("utf-8")
    except (CanonicalJSONError, UnicodeDecodeError) as exc:
        raise ArtifactError(str(exc)) from exc
    if actual_sums != expected_sums:
        raise ArtifactError("SHA256SUMS does not match artifact files")

    scorecard = _load_json(scorecard_path, "Solstice scorecard")
    receipt = _load_json(receipt_path, "Solstice receipt")
    if scorecard.get("artifact_manifest_digest") not in (None, manifest["artifact_manifest_digest"]):
        raise ArtifactError("scorecard artifact_manifest_digest disagrees with manifest")
    inputs = manifest["inputs"]
    rootset_info = inputs.get("external_rootset")
    solstice_harness.verify_scorecard(
        scorecard,
        ledger_path=_resolve_manifest_path(inputs["input_ledger"]["path"], artifact_dir),
        corpus_path=_resolve_manifest_path(inputs["corpus"]["path"], artifact_dir),
        output_ledger_path=output_ledger_path,
        weights_path=_resolve_manifest_path(inputs["weights"]["path"], artifact_dir),
        obligations_path=_resolve_manifest_path(inputs["obligations"]["path"], artifact_dir),
        rootset_path=_resolve_manifest_path(rootset_info["path"], artifact_dir) if rootset_info else None,
        receipt=receipt,
    )
    if ledger_model.frozen_head(output_ledger_path)[1] != manifest.get("output_ledger_head"):
        raise ArtifactError("manifest output ledger head mismatch")
