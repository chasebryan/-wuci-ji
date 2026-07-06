"""Append-only JSONL ledger for Daylight v14C+ evidence."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .canonical_json import canonical_sha256


ENTRY_DOMAIN = "DAYLIGHT-v14C+-LEDGER-ENTRY:"
HEAD_DOMAIN = "DAYLIGHT-v14C+-LEDGER-HEAD:"
GENESIS_HEAD = canonical_sha256({"genesis": "daylight-v14c-plus-v0.2"}, HEAD_DOMAIN)
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
}
FIXED_TIMESTAMP = "2026-06-30T00:00:00Z"


class LedgerError(ValueError):
    pass


def _reject_symlink_ancestors(path: Path) -> None:
    current = path.parent
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise LedgerError(f"ledger path parent must not be a symlink: {current}")
        current = current.parent


def _read_regular_text(path: Path) -> str:
    if not path.exists():
        return ""
    _reject_symlink_ancestors(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise LedgerError(f"could not inspect ledger: {path}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise LedgerError(f"ledger must not be a symlink: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise LedgerError(f"ledger must be a regular file: {path}")
    if before.st_nlink > 1:
        raise LedgerError(f"ledger must not be hardlinked: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            after = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise LedgerError(f"ledger changed while opening: {path}")
            return handle.read()
    except OSError as exc:
        raise LedgerError(f"could not read ledger: {path}") from exc


def _atomic_write_text(path: Path, text: str) -> None:
    _reject_symlink_ancestors(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise LedgerError(f"ledger output must not be a symlink: {path}")
        if not stat.S_ISREG(info.st_mode):
            raise LedgerError(f"ledger output must be a regular file: {path}")
        if info.st_nlink > 1:
            raise LedgerError(f"ledger output must not be hardlinked: {path}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


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
    text = _read_regular_text(path)
    if not text:
        return entries
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"invalid ledger JSON at line {line_no}: {exc}") from exc
        if not isinstance(entry, dict):
            raise LedgerError(f"ledger line {line_no} is not an object")
        entries.append(entry)
    return entries


def write_jsonl(path: Path, entries: Iterable[dict[str, Any]]) -> None:
    text = "".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n" for entry in entries)
    _atomic_write_text(path, text)


def entry_types(entries: Iterable[dict[str, Any]]) -> set[str]:
    return {str(entry.get("entry_type", "")) for entry in entries}


def append_entry(
    entries: list[dict[str, Any]],
    *,
    entry_type: str,
    artifact_digest: str,
    witness: dict[str, Any] | None,
    transcript_digest: str | None,
    evidence_binding: str = "daylight-v14c-plus-v0.2",
    timestamp_utc: str = FIXED_TIMESTAMP,
    entry_id: str | None = None,
    signatures: list[Any] | None = None,
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
        "version_tag": "daylight-v14c-plus-v0.2",
        "evidence_binding": evidence_binding,
        "signatures": signatures or [],
    }
    entry["entry_digest"] = entry_digest(entry)
    new_head = verify_entry(entry, previous_head)
    return entries + [entry], new_head


def frozen_head(path: Path) -> tuple[list[dict[str, Any]], str]:
    entries = load_jsonl(path)
    return entries, verify_entries(entries)
