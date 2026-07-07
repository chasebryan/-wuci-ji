"""Append-only JSONL ledger for Daylight v15+ Solstice evidence.

Forked from v14C+. Two additions:

* new evidence classes (``proof``, ``release_repro``, ``traceability_map``,
  ``doc``, ``external_attestation``) so obligations can bind to richer evidence;
* optional, hash-covered ``closes_obligations`` and ``external_signer_id`` fields
  so an evidence entry can declare which obligations it discharges.

The witness + transcript discipline is unchanged: no entry without a witness and a
transcript digest, and the entry digest covers every field including the new ones.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .canonical_json import canonical_sha256


ENTRY_DOMAIN = "DAYLIGHT-v15-SOLSTICE-LEDGER-ENTRY:"
HEAD_DOMAIN = "DAYLIGHT-v15-SOLSTICE-LEDGER-HEAD:"
GENESIS_HEAD = canonical_sha256({"genesis": "daylight-v15-solstice-v0.1"}, HEAD_DOMAIN)
VERSION_TAG = "daylight-v15-solstice-v0.1"
SUPPORTED_ENTRY_TYPES = {
    "source",
    "build",
    "test",
    "adversarial_run",
    "harness_execution",
    "corpus_snapshot",
    "scorecard",
    "claim",
    "downgrade",
    "proof",
    "release_repro",
    "traceability_map",
    "doc",
    "external_attestation",
}
FIXED_TIMESTAMP = "2026-06-30T00:00:00Z"


class LedgerError(ValueError):
    pass


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise LedgerError(f"duplicate JSON key rejected: {key}")
        out[key] = value
    return out


def _without_digest(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key != "entry_digest"}


def entry_digest(entry: dict[str, Any]) -> str:
    return canonical_sha256(_without_digest(entry), ENTRY_DOMAIN)


def next_head(previous_head: str, digest: str) -> str:
    return canonical_sha256({"entry_digest": digest, "previous_head": previous_head}, HEAD_DOMAIN)


def verify_entry(entry: dict[str, Any], expected_previous_head: str) -> str:
    missing = [
        field
        for field in (
            "entry_id",
            "entry_type",
            "artifact_digest",
            "previous_head",
            "entry_digest",
            "witness",
            "transcript_digest",
            "timestamp_utc",
            "version_tag",
            "evidence_binding",
            "signatures",
        )
        if field not in entry
    ]
    if missing:
        raise LedgerError("ledger entry missing fields: " + ", ".join(missing))
    if entry["entry_type"] not in SUPPORTED_ENTRY_TYPES:
        raise LedgerError(f"unsupported ledger entry type: {entry['entry_type']}")
    if entry["previous_head"] != expected_previous_head:
        raise LedgerError("ledger previous_head mismatch")
    witness = entry.get("witness")
    if not isinstance(witness, dict) or not witness.get("witness_type") or not witness.get("witness_digest"):
        raise LedgerError("ledger append rejected: missing witness")
    if not entry.get("transcript_digest"):
        raise LedgerError("ledger append rejected: missing transcript digest")
    closes = entry.get("closes_obligations", [])
    if not isinstance(closes, list) or any(not isinstance(item, str) or not item for item in closes):
        raise LedgerError("closes_obligations must be a list of non-empty strings")
    if entry["entry_type"] == "external_attestation" and "external_signer_id" not in entry:
        raise LedgerError("external_attestation entry missing external_signer_id")
    actual_digest = entry_digest(entry)
    if actual_digest != entry["entry_digest"]:
        raise LedgerError("ledger entry_digest mismatch")
    return next_head(expected_previous_head, actual_digest)


def verify_entries(entries: Iterable[dict[str, Any]]) -> str:
    head = GENESIS_HEAD
    seen_ids: set[str] = set()
    for entry in entries:
        entry_id = str(entry.get("entry_id", ""))
        if entry_id in seen_ids:
            raise LedgerError(f"duplicate ledger entry id: {entry_id}")
        seen_ids.add(entry_id)
        head = verify_entry(entry, head)
    return head


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not path.exists():
        return entries
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            entry = json.loads(stripped, object_pairs_hook=_reject_duplicate_json_pairs)
        except (json.JSONDecodeError, LedgerError) as exc:
            raise LedgerError(f"invalid ledger JSON at line {line_no}: {exc}") from exc
        if not isinstance(entry, dict):
            raise LedgerError(f"ledger line {line_no} is not an object")
        entries.append(entry)
    return entries


def write_jsonl(path: Path, entries: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n" for entry in entries)
    path.write_text(text, encoding="utf-8")


def entry_types(entries: Iterable[dict[str, Any]]) -> set[str]:
    return {str(entry.get("entry_type", "")) for entry in entries}


def append_entry(
    entries: list[dict[str, Any]],
    *,
    entry_type: str,
    artifact_digest: str,
    witness: dict[str, Any] | None,
    transcript_digest: str | None,
    evidence_binding: str = VERSION_TAG,
    timestamp_utc: str = FIXED_TIMESTAMP,
    entry_id: str | None = None,
    signatures: list[Any] | None = None,
    closes_obligations: list[str] | None = None,
    external_signer_id: str | None = None,
) -> tuple[list[dict[str, Any]], str]:
    if entry_type not in SUPPORTED_ENTRY_TYPES:
        raise LedgerError(f"unsupported ledger entry type: {entry_type}")
    if not witness:
        raise LedgerError("ledger append rejected: missing witness")
    if not transcript_digest:
        raise LedgerError("ledger append rejected: missing transcript digest")
    previous_head = verify_entries(entries)
    resolved_id = entry_id or f"ledger-entry-{len(entries) + 1:04d}-{entry_type}"
    entry = {
        "entry_id": resolved_id,
        "entry_type": entry_type,
        "artifact_digest": artifact_digest,
        "previous_head": previous_head,
        "entry_digest": "",
        "witness": witness,
        "transcript_digest": transcript_digest,
        "timestamp_utc": timestamp_utc,
        "version_tag": VERSION_TAG,
        "evidence_binding": evidence_binding,
        "signatures": signatures or [],
        "closes_obligations": list(closes_obligations or []),
    }
    if entry_type == "external_attestation":
        entry["external_signer_id"] = external_signer_id or ""
    entry["entry_digest"] = entry_digest(entry)
    new_head = verify_entry(entry, previous_head)
    return entries + [entry], new_head


def frozen_head(path: Path) -> tuple[list[dict[str, Any]], str]:
    entries = load_jsonl(path)
    return entries, verify_entries(entries)
