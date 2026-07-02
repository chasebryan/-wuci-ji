"""Daylight v18 tamper-transition checks."""

from __future__ import annotations

from typing import Any

from . import binaric_vector
from . import transition_ledger


class TamperLogicError(ValueError):
    pass


def _field_changed(before: dict[str, Any], after: dict[str, Any], key: str) -> bool:
    return before.get(key) != after.get(key)


def _legacy_tamper_check(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    binaric_vector.validate_vector_shape(before)
    binaric_vector.validate_vector_shape(after)
    blockers: list[str] = []
    changed: list[str] = []
    previous = after.get("previous_vector_digest")
    if previous != before["vector_digest"]:
        blockers.append("previous_vector_digest chain break")
    for key in ("file_sha256", "file_sha3_512", "size_bytes", "section_digests"):
        if _field_changed(before, after, key):
            changed.append(key)
    if any(key in changed for key in ("file_sha256", "file_sha3_512", "size_bytes", "section_digests")):
        changed.append("binary_state")
    if _field_changed(before, after, "policy_digest"):
        changed.append("policy_digest")
    if _field_changed(before, after, "event_horizon_scorecard_digest"):
        changed.append("event_horizon_scorecard_digest")
    changed = sorted(set(changed))
    user_verified = "user_verification_digest" in after
    critical = {
        "binary_state": "binary state changed without user verification",
        "policy_digest": "policy digest changed without user verification",
        "event_horizon_scorecard_digest": "event horizon scorecard digest changed without user verification",
    }
    if not user_verified:
        for key, reason in critical.items():
            if key in changed:
                blockers.append(reason)
    transition_allowed = not blockers
    if not changed and transition_allowed:
        status = "no_tamper"
    elif user_verified and transition_allowed:
        status = "tamper_user_verified_pending_acceptance"
    else:
        status = "tamper_rejected"
    return {
        "tamper_detected": bool(changed),
        "changed_vectors": changed,
        "user_verification_present": user_verified,
        "transition_allowed": transition_allowed,
        "accepted": False,
        "status": status,
        "blockers": blockers,
        "before_vector_digest": before["vector_digest"],
        "after_vector_digest": after["vector_digest"],
    }


def tamper_check(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    transition: dict[str, Any] | None = None,
    ledger_records: list[dict[str, Any]] | None = None,
    passphrase: str | None = None,
    legacy_digest_marker: bool = False,
) -> dict[str, Any]:
    if legacy_digest_marker:
        result = _legacy_tamper_check(before, after)
        result["legacy_digest_marker"] = True
        return result

    binaric_vector.validate_vector_shape(before)
    binaric_vector.validate_vector_shape(after)
    changed = transition_ledger.diff_fields(before, after)
    if after.get("previous_vector_digest") != before["vector_digest"]:
        changed = sorted(set(changed + ["previous_vector_digest"]))
    blockers: list[str] = []
    if changed and transition is None:
        blockers.append("transition record required")
    if changed and ledger_records is None:
        blockers.append("transition ledger required")

    transition_digest = ""
    ledger_head = ""
    if changed and transition is not None and ledger_records is not None:
        result = transition_ledger.tamper_accepted(before, after, transition, ledger_records, passphrase=passphrase)
        transition_digest = result["transition_digest"]
        ledger_head = result["ledger_head"]
        blockers.extend(result["blockers"])

    transition_allowed = not blockers
    if not changed and transition_allowed:
        status = "no_tamper"
    elif transition_allowed:
        status = "tamper_transition_accepted"
    else:
        status = "tamper_rejected"
    return {
        "tamper_detected": bool(changed),
        "changed_vectors": changed,
        "user_verification_present": False,
        "legacy_digest_marker": False,
        "transition_allowed": transition_allowed,
        "accepted": bool(changed) and transition_allowed,
        "status": status,
        "blockers": blockers,
        "before_vector_digest": before["vector_digest"],
        "after_vector_digest": after["vector_digest"],
        "transition_digest": transition_digest,
        "ledger_head": ledger_head,
    }


def tamper_check_files(
    before_path: str,
    after_path: str,
    *,
    transition_path: str | None = None,
    ledger_path: str | None = None,
    passphrase: str | None = None,
    legacy_digest_marker: bool = False,
) -> dict[str, Any]:
    before = binaric_vector.load_vector(before_path)
    after = binaric_vector.load_vector(after_path)
    transition = transition_ledger.load_transition(transition_path) if transition_path else None
    ledger_records = transition_ledger.load_ledger(ledger_path) if ledger_path else None
    return tamper_check(
        before,
        after,
        transition=transition,
        ledger_records=ledger_records,
        passphrase=passphrase,
        legacy_digest_marker=legacy_digest_marker,
    )
