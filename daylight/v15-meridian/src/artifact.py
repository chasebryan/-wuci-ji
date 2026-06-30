"""Deterministic release-artifact builder for Daylight v15 Meridian.

Produces a self-describing artifact directory from frozen evidence: scorecard,
reproducibility receipt, frontier report (JSON + Markdown), the output ledger, a
manifest binding every input and output by SHA-256, and a SHA256SUMS file. The
output is byte-reproducible: the manifest carries the fixed generation date
2026-06-30 and repository-relative paths, never wall-clock time or absolute paths.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import __version__
from . import api
from . import corpus as _corpus
from . import daylight_harness as _harness
from . import ledger as _ledger

REPO_ROOT = api.PACKAGE_ROOT.parents[1]
GENERATED_DATE = "2026-06-30"
BOUNDARY_STATEMENT = (
    "Daylight v15 Meridian is a deterministic research-evidence scoring artifact. "
    "It verifies that a score is derived from pinned obligations and witnessed "
    "evidence; it is not production cryptography, runtime containment, external "
    "certification, government validation, or a claim of post-quantum security."
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repo_relative(path: Path) -> str:
    path = Path(path).resolve()
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_artifact(
    *,
    ledger_path: Path | str,
    corpus_path: Path | str,
    out_dir: Path | str,
    command_label: str,
    weights_path: Path | str = api.DEFAULT_WEIGHTS,
    obligations_path: Path | str = api.DEFAULT_OBLIGATIONS,
) -> dict[str, Any]:
    ledger_path = Path(ledger_path)
    corpus_path = Path(corpus_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scorecard, receipt, scorecard_entries = _harness.generate_scorecard(
        ledger_path=ledger_path,
        corpus_path=corpus_path,
        weights_path=Path(weights_path),
        obligations_path=Path(obligations_path),
        command="artifact",
    )

    registry = api.load_registry(obligations_path)
    ledger_entries = _ledger.load_jsonl(ledger_path)
    snapshot = _corpus.freeze_corpus(_corpus.load_jsonl(corpus_path))
    closed = api.resolve_closed_obligations(registry, ledger_entries, snapshot)
    frontier = api.frontier_status(registry, closed, weights_path=weights_path)
    frontier_md = api.frontier_markdown(frontier)

    # Materialize the output ledger (the scorecard append) deterministically.
    ledger_lines = "".join(
        json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n" for entry in scorecard_entries
    ).encode("utf-8")

    outputs: dict[str, bytes] = {
        "scorecard.v15-meridian.json": _json_bytes(scorecard),
        "reproducibility-receipt.v15-meridian.json": _json_bytes(receipt),
        "frontier-report.v15-meridian.json": _json_bytes(frontier),
        "frontier-report.v15-meridian.md": (frontier_md if frontier_md.endswith("\n") else frontier_md + "\n").encode("utf-8"),
        "ledger.with-scorecard.jsonl": ledger_lines,
    }

    inputs = {
        "obligation_registry": Path(obligations_path),
        "weight_vector": Path(weights_path),
        "ledger": ledger_path,
        "corpus": corpus_path,
    }
    input_digests = {
        name: {"path": _repo_relative(path), "sha256": _sha256_bytes(Path(path).read_bytes())}
        for name, path in inputs.items()
    }

    manifest = {
        "manifest_version": "daylight-v15-meridian-artifact-manifest-v0.1",
        "artifact": "Daylight v15 Meridian",
        "package_version": __version__,
        "generated_date": GENERATED_DATE,
        "command": command_label,
        "obligations_version": scorecard["obligations_version"],
        "obligations_digest": scorecard["obligations_digest"],
        "final_score_M": scorecard["final_score_M"],
        "internal_ceiling_M": frontier["internal_ceiling_M"],
        "perfect_score_M": frontier["perfect_score_M"],
        "external_residue_M": frontier["structural_external_residue_M"],
        "residue_to_perfect_M": scorecard["residue_to_perfect_M"],
        "scorecard_digest": scorecard["scorecard_digest"],
        "inputs": input_digests,
        "outputs": {
            name: {"sha256": _sha256_bytes(data)} for name, data in sorted(outputs.items())
        },
        "boundary": BOUNDARY_STATEMENT,
    }
    manifest_bytes = _json_bytes(manifest)
    outputs["artifact-manifest.json"] = manifest_bytes

    sha256sums = "".join(
        f"{_sha256_bytes(data)}  {name}\n" for name, data in sorted(outputs.items())
    ).encode("utf-8")
    outputs["SHA256SUMS"] = sha256sums

    for name, data in outputs.items():
        (out_dir / name).write_bytes(data)

    return manifest
