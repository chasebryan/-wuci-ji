"""Daylight v18 Binaric Transition Ledger."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import binaric_vector
from .canonical_json import canonical_sha256, dumps_canonical, json_bytes, load_json_no_floats, loads_json_no_floats, reject_floats_recursive
from . import user_ceremony


TRANSITION_VERSION = "daylight-v18-bastion-transition-v0.1"
LEDGER_VERSION = "daylight-v18-bastion-transition-ledger-v0.1"
D_TRANSITION = user_ceremony.D_TRANSITION
D_TRANSITION_LOG = "DAYLIGHT-v18-BASTION-TRANSITION-LOG:"
D_TRANSITION_HEAD = "DAYLIGHT-v18-BASTION-TRANSITION-HEAD:"
GENESIS_HEAD = canonical_sha256({"genesis": LEDGER_VERSION}, D_TRANSITION_HEAD)

TRANSITION_REQUIRED_KEYS = {
    "transition_version",
    "transition_id",
    "before_vector_digest",
    "after_vector_digest",
    "changed_fields",
    "reason",
    "user_ceremony",
    "accepted",
    "boundary",
}
TRANSITION_OPTIONAL_KEYS = {
    "user_proof",
    "allowed_version_transition",
    "policy_change_authorized",
}
TRANSITION_ALLOWED_KEYS = TRANSITION_REQUIRED_KEYS | TRANSITION_OPTIONAL_KEYS
LEDGER_GENESIS_KEYS = {"ledger_version", "genesis_head"}
LEDGER_ENTRY_KEYS = {
    "entry_id",
    "transition_digest",
    "previous_head",
    "entry_digest",
    "head",
    "transition_record",
}
HEX64 = set("0123456789abcdef")


class TransitionLedgerError(ValueError):
    pass


def _require_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - HEX64:
        raise TransitionLedgerError(f"{name} must be lowercase hex digest length 64")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TransitionLedgerError(f"{name} must be boolean")
    return value


def vector_record_valid(vector: dict[str, Any]) -> bool:
    try:
        binaric_vector.validate_vector_shape(vector)
    except (ValueError, binaric_vector.BinaricVectorError):
        return False
    return True


def diff_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    ignored = {"vector_digest", "previous_vector_digest", "user_verification_digest"}
    fields = sorted((set(before) | set(after)) - ignored)
    return [field for field in fields if before.get(field) != after.get(field)]


def make_challenge(before: dict[str, Any], after: dict[str, Any], reason: str) -> dict[str, Any]:
    binaric_vector.validate_vector_shape(before)
    binaric_vector.validate_vector_shape(after)
    changed = diff_fields(before, after)
    return {
        "challenge_version": "daylight-v18-bastion-transition-challenge-v0.1",
        "before_vector_digest": before["vector_digest"],
        "after_vector_digest": after["vector_digest"],
        "changed_fields": changed,
        "reason": reason,
        "challenge_digest": user_ceremony.challenge_digest(before["vector_digest"], after["vector_digest"], changed, reason),
    }


def propose_transition(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    reason: str,
    transition_id: str = "transition-0001",
    user_id: str = "local-user",
) -> dict[str, Any]:
    binaric_vector.validate_vector_shape(before)
    binaric_vector.validate_vector_shape(after)
    if not isinstance(reason, str) or not reason:
        raise TransitionLedgerError("reason must be a non-empty string")
    if not isinstance(transition_id, str) or not transition_id:
        raise TransitionLedgerError("transition_id must be a non-empty string")
    changed = diff_fields(before, after)
    transition: dict[str, Any] = {
        "transition_version": TRANSITION_VERSION,
        "transition_id": transition_id,
        "before_vector_digest": before["vector_digest"],
        "after_vector_digest": after["vector_digest"],
        "changed_fields": changed,
        "reason": reason,
        "user_ceremony": user_ceremony.make_ceremony(before["vector_digest"], after["vector_digest"], changed, reason, user_id=user_id),
        "accepted": True,
        "boundary": "research local user authorization proof; not production identity",
    }
    if before.get("policy_digest") != after.get("policy_digest"):
        transition["policy_change_authorized"] = True
    if before.get("version") != after.get("version"):
        transition["allowed_version_transition"] = True
    return transition


def validate_transition_shape(transition: dict[str, Any], *, require_proof: bool = True) -> None:
    reject_floats_recursive(transition, "transition")
    if not isinstance(transition, dict):
        raise TransitionLedgerError("transition must be an object")
    unknown = set(transition) - TRANSITION_ALLOWED_KEYS
    if unknown:
        raise TransitionLedgerError(f"unknown transition fields: {sorted(unknown)}")
    missing = TRANSITION_REQUIRED_KEYS - set(transition)
    if missing:
        raise TransitionLedgerError(f"missing transition fields: {sorted(missing)}")
    if require_proof and "user_proof" not in transition:
        raise TransitionLedgerError("missing user_proof")
    if transition["transition_version"] != TRANSITION_VERSION:
        raise TransitionLedgerError("unsupported transition version")
    if not isinstance(transition["transition_id"], str) or not transition["transition_id"]:
        raise TransitionLedgerError("transition_id must be a non-empty string")
    _require_digest(transition["before_vector_digest"], "before_vector_digest")
    _require_digest(transition["after_vector_digest"], "after_vector_digest")
    if not isinstance(transition["changed_fields"], list) or not all(isinstance(item, str) for item in transition["changed_fields"]):
        raise TransitionLedgerError("changed_fields must be list[string]")
    if transition["changed_fields"] != sorted(transition["changed_fields"]):
        raise TransitionLedgerError("changed_fields must be sorted")
    if not isinstance(transition["reason"], str) or not transition["reason"]:
        raise TransitionLedgerError("reason must be a non-empty string")
    user_ceremony.validate_ceremony(transition["user_ceremony"])
    _require_bool(transition["accepted"], "accepted")
    if not isinstance(transition["boundary"], str) or not transition["boundary"]:
        raise TransitionLedgerError("boundary must be a non-empty string")
    if "user_proof" in transition:
        _require_digest(transition["user_proof"], "user_proof")
    if "allowed_version_transition" in transition:
        _require_bool(transition["allowed_version_transition"], "allowed_version_transition")
    if "policy_change_authorized" in transition:
        _require_bool(transition["policy_change_authorized"], "policy_change_authorized")


def transition_digest(transition: dict[str, Any]) -> str:
    validate_transition_shape(transition, require_proof=False)
    return user_ceremony.transition_digest(transition)


def sign_transition(transition: dict[str, Any], passphrase: str) -> dict[str, Any]:
    validate_transition_shape(transition, require_proof=False)
    signed = user_ceremony.sign_transition(transition, passphrase)
    validate_transition_shape(signed, require_proof=True)
    return signed


def verify_transition(
    before: dict[str, Any],
    after: dict[str, Any],
    transition: dict[str, Any],
    *,
    passphrase: str | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    for name, vector in (("before", before), ("after", after)):
        try:
            binaric_vector.validate_vector_shape(vector)
        except (ValueError, binaric_vector.BinaricVectorError) as exc:
            blockers.append(f"{name} vector invalid: {exc}")
    try:
        validate_transition_shape(transition, require_proof=True)
    except (ValueError, user_ceremony.UserCeremonyError, TransitionLedgerError) as exc:
        blockers.append(f"transition invalid: {exc}")
    digest = ""
    if not blockers:
        digest = transition_digest(transition)
        if transition["before_vector_digest"] != before["vector_digest"]:
            blockers.append("before_vector_digest mismatch")
        if transition["after_vector_digest"] != after["vector_digest"]:
            blockers.append("after_vector_digest mismatch")
        actual_changed = diff_fields(before, after)
        if transition["changed_fields"] != actual_changed:
            blockers.append("changed_fields does not match actual diff")
        if after.get("previous_vector_digest") != before["vector_digest"]:
            blockers.append("previous_vector_digest chain break")
        if before.get("version") != after.get("version") and transition.get("allowed_version_transition") is not True:
            blockers.append("vector version changed without explicit allowed_version_transition")
        metadata = after.get("executable_metadata", {})
        if isinstance(metadata, dict) and metadata.get("runtime_containment_claim") is True:
            blockers.append("runtime containment claim is not allowed")
        if before.get("policy_digest") != after.get("policy_digest") and transition.get("policy_change_authorized") is not True:
            blockers.append("policy digest changed without policy_change_authorized")
        if transition.get("accepted") is not True:
            blockers.append("accepted must be true")
        if passphrase is None:
            blockers.append("user passphrase required")
        else:
            try:
                if not user_ceremony.verify_user_proof(transition, passphrase):
                    blockers.append("user proof invalid")
            except (ValueError, user_ceremony.UserCeremonyError) as exc:
                blockers.append(f"user proof invalid: {exc}")
    return {
        "transition_valid": not blockers,
        "transition_digest": digest,
        "before_vector_digest": before.get("vector_digest"),
        "after_vector_digest": after.get("vector_digest"),
        "changed_fields": transition.get("changed_fields") if isinstance(transition, dict) else [],
        "blockers": blockers,
    }


def load_transition(path: Path | str, *, require_proof: bool = True) -> dict[str, Any]:
    transition = load_json_no_floats(path)
    validate_transition_shape(transition, require_proof=require_proof)
    return transition


def init_ledger(path: Path | str) -> dict[str, Any]:
    genesis = {"ledger_version": LEDGER_VERSION, "genesis_head": GENESIS_HEAD}
    Path(path).write_bytes(dumps_canonical(genesis) + b"\n")
    return genesis


def _load_ledger_lines(path: Path | str) -> list[dict[str, Any]]:
    ledger_path = Path(path)
    if not ledger_path.exists():
        raise TransitionLedgerError(f"ledger missing: {ledger_path}")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = loads_json_no_floats(line)
        if not isinstance(record, dict):
            raise TransitionLedgerError(f"ledger line {line_number} must be an object")
        records.append(record)
    return records


def load_ledger(path: Path | str) -> list[dict[str, Any]]:
    return _load_ledger_lines(path)


def _validate_genesis(record: dict[str, Any]) -> None:
    unknown = set(record) - LEDGER_GENESIS_KEYS
    missing = LEDGER_GENESIS_KEYS - set(record)
    if unknown or missing:
        raise TransitionLedgerError("ledger genesis invalid")
    if record["ledger_version"] != LEDGER_VERSION or record["genesis_head"] != GENESIS_HEAD:
        raise TransitionLedgerError("ledger genesis mismatch")


def entry_digest_for_transition(transition: dict[str, Any]) -> str:
    validate_transition_shape(transition, require_proof=True)
    return canonical_sha256(transition, D_TRANSITION_LOG)


def head_for_entry(previous_head: str, entry_digest: str) -> str:
    _require_digest(previous_head, "previous_head")
    _require_digest(entry_digest, "entry_digest")
    return canonical_sha256({"previous_head": previous_head, "entry_digest": entry_digest}, D_TRANSITION_HEAD)


def make_entry(transition: dict[str, Any], previous_head: str, index: int) -> dict[str, Any]:
    validate_transition_shape(transition, require_proof=True)
    entry_digest = entry_digest_for_transition(transition)
    return {
        "entry_id": f"transition-ledger-entry-{index:04d}",
        "transition_digest": transition_digest(transition),
        "previous_head": previous_head,
        "entry_digest": entry_digest,
        "head": head_for_entry(previous_head, entry_digest),
        "transition_record": transition,
    }


def _validate_entry(entry: dict[str, Any], expected_previous_head: str) -> str:
    unknown = set(entry) - LEDGER_ENTRY_KEYS
    missing = LEDGER_ENTRY_KEYS - set(entry)
    if unknown:
        raise TransitionLedgerError(f"unknown ledger entry fields: {sorted(unknown)}")
    if missing:
        raise TransitionLedgerError(f"missing ledger entry fields: {sorted(missing)}")
    if not isinstance(entry["entry_id"], str) or not entry["entry_id"]:
        raise TransitionLedgerError("entry_id must be a non-empty string")
    _require_digest(entry["transition_digest"], "transition_digest")
    _require_digest(entry["previous_head"], "previous_head")
    _require_digest(entry["entry_digest"], "entry_digest")
    _require_digest(entry["head"], "head")
    if entry["previous_head"] != expected_previous_head:
        raise TransitionLedgerError("ledger previous_head mismatch")
    transition = entry["transition_record"]
    validate_transition_shape(transition, require_proof=True)
    if transition_digest(transition) != entry["transition_digest"]:
        raise TransitionLedgerError("ledger transition_digest mismatch")
    if entry_digest_for_transition(transition) != entry["entry_digest"]:
        raise TransitionLedgerError("ledger entry_digest mismatch")
    expected_head = head_for_entry(entry["previous_head"], entry["entry_digest"])
    if entry["head"] != expected_head:
        raise TransitionLedgerError("ledger head mismatch")
    return entry["head"]


def verify_ledger_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        return {"ledger_valid": False, "head": "", "entries": 0, "blockers": ["ledger empty"]}
    blockers: list[str] = []
    try:
        _validate_genesis(records[0])
        current_head = GENESIS_HEAD
        seen_entry_ids: set[str] = set()
        seen_transition_digests: set[str] = set()
        for entry in records[1:]:
            if entry.get("entry_id") in seen_entry_ids:
                raise TransitionLedgerError("duplicate entry_id")
            if entry.get("transition_digest") in seen_transition_digests:
                raise TransitionLedgerError("duplicate transition_digest")
            current_head = _validate_entry(entry, current_head)
            seen_entry_ids.add(entry["entry_id"])
            seen_transition_digests.add(entry["transition_digest"])
    except (ValueError, TransitionLedgerError, user_ceremony.UserCeremonyError) as exc:
        blockers.append(str(exc))
        current_head = ""
    return {
        "ledger_valid": not blockers,
        "head": current_head,
        "entries": max(0, len(records) - 1),
        "blockers": blockers,
    }


def verify_ledger_file(path: Path | str) -> dict[str, Any]:
    return verify_ledger_records(_load_ledger_lines(path))


def append_transition(ledger_path: Path | str, transition: dict[str, Any]) -> dict[str, Any]:
    records = _load_ledger_lines(ledger_path)
    result = verify_ledger_records(records)
    if not result["ledger_valid"]:
        raise TransitionLedgerError(f"ledger invalid: {result['blockers']}")
    entry = make_entry(transition, result["head"], result["entries"] + 1)
    records.append(entry)
    Path(ledger_path).write_bytes(b"".join(dumps_canonical(record) + b"\n" for record in records))
    return entry


def transition_digest_in_ledger(records: list[dict[str, Any]], digest: str) -> bool:
    _require_digest(digest, "transition_digest")
    return any(record.get("transition_digest") == digest for record in records[1:])


def tamper_accepted(
    before: dict[str, Any],
    after: dict[str, Any],
    transition: dict[str, Any],
    ledger_records: list[dict[str, Any]],
    *,
    passphrase: str | None,
) -> dict[str, Any]:
    transition_result = verify_transition(before, after, transition, passphrase=passphrase)
    ledger_result = verify_ledger_records(ledger_records)
    blockers = list(transition_result["blockers"]) + list(ledger_result["blockers"])
    digest = transition_result["transition_digest"]
    if not digest:
        try:
            digest = transition_digest(transition)
        except (ValueError, TransitionLedgerError, user_ceremony.UserCeremonyError):
            digest = ""
    if digest and ledger_result["ledger_valid"] and not transition_digest_in_ledger(ledger_records, digest):
        blockers.append("transition digest not included in ledger")
    return {
        "tamper_accepted": not blockers,
        "transition_valid": transition_result["transition_valid"],
        "ledger_valid": ledger_result["ledger_valid"],
        "transition_digest": digest,
        "ledger_head": ledger_result["head"],
        "blockers": blockers,
    }


def write_json(path: Path | str, value: dict[str, Any]) -> None:
    Path(path).write_bytes(json_bytes(value))
