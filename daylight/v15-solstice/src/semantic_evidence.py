"""Semantic evidence checks for Daylight v15+ Solstice.

The Meridian registry already made q-values obligation-derived. Solstice tightens
the closure predicate: naming an obligation in ``closes_obligations`` is only
necessary. Score-closing evidence must also match the obligation kind/class,
carry witness and transcript binding, be replay-bound where applicable, and pass
the class-specific semantic shape check.
"""

from __future__ import annotations

import re
from typing import Any

from .canonical_json import canonical_sha256


SEMANTIC_VERIFIER_DOMAIN = "DAYLIGHT-v15-SOLSTICE-SEMANTIC-VERIFIER:"
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SemanticEvidenceError(ValueError):
    pass


def is_hex_sha256(value: Any) -> bool:
    return isinstance(value, str) and HEX_SHA256_RE.fullmatch(value) is not None


def semantic_verifier_digest(evidence_class: str) -> str:
    return canonical_sha256(
        {
            "verifier": f"daylight-v15-solstice-semantic-{evidence_class}",
            "rules": [
                "kind_class_match",
                "witness_bound",
                "transcript_bound",
                "replay_bound_for_corpus_closure",
                "digest_shape_checked",
            ],
        },
        SEMANTIC_VERIFIER_DOMAIN,
    )


def _names_obligation(projection: dict[str, Any], obligation_id: str) -> bool:
    closes = projection.get("closes_obligations", [])
    return isinstance(closes, list) and obligation_id in closes


def kind_class_match(obligation: dict[str, Any], projection: dict[str, Any]) -> bool:
    return (
        projection.get("evidence_kind") == obligation.get("evidence_kind")
        and projection.get("evidence_class") == obligation.get("evidence_class")
    )


def witness_bound(projection: dict[str, Any]) -> bool:
    witness = projection.get("witness")
    return (
        isinstance(witness, dict)
        and isinstance(witness.get("witness_type"), str)
        and bool(witness.get("witness_type"))
        and is_hex_sha256(witness.get("witness_digest"))
    )


def transcript_bound(projection: dict[str, Any]) -> bool:
    return is_hex_sha256(projection.get("transcript_digest"))


def replay_bound(projection: dict[str, Any]) -> bool:
    if projection.get("evidence_kind") != "corpus":
        return transcript_bound(projection)
    return (
        isinstance(projection.get("replay_command"), str)
        and bool(projection.get("replay_command"))
        and isinstance(projection.get("expected_stage"), str)
        and bool(projection.get("expected_stage"))
        and is_hex_sha256(projection.get("result_digest"))
    )


def semantic_verifier(obligation: dict[str, Any], projection: dict[str, Any]) -> bool:
    evidence_class = obligation.get("evidence_class")
    if evidence_class == "external_attestation":
        return False
    if projection.get("evidence_kind") == "ledger":
        return is_hex_sha256(projection.get("artifact_digest"))
    if projection.get("evidence_kind") == "corpus":
        return (
            is_hex_sha256(projection.get("input_digest"))
            and isinstance(projection.get("linked_ledger_entry"), str)
            and bool(projection.get("linked_ledger_entry"))
            and is_hex_sha256(projection.get("result_digest"))
        )
    return False


def semantic_evidence_valid(obligation: dict[str, Any], projection: dict[str, Any]) -> bool:
    return (
        _names_obligation(projection, str(obligation.get("id", "")))
        and kind_class_match(obligation, projection)
        and witness_bound(projection)
        and transcript_bound(projection)
        and replay_bound(projection)
        and semantic_verifier(obligation, projection)
    )


def ledger_projection(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_kind": "ledger",
        "evidence_class": entry.get("entry_type"),
        "closes_obligations": entry.get("closes_obligations", []),
        "witness": entry.get("witness"),
        "transcript_digest": entry.get("transcript_digest"),
        "artifact_digest": entry.get("artifact_digest"),
        "signatures": entry.get("signatures", []),
        "external_signer_id": entry.get("external_signer_id"),
    }


def corpus_projection(corpus_entry: dict[str, Any], linked_ledger_entry: dict[str, Any] | None) -> dict[str, Any]:
    linked = linked_ledger_entry or {}
    return {
        "evidence_kind": "corpus",
        "evidence_class": corpus_entry.get("category"),
        "closes_obligations": corpus_entry.get("closes_obligations", []),
        "input_digest": corpus_entry.get("input_digest"),
        "linked_ledger_entry": corpus_entry.get("linked_ledger_entry"),
        "replay_command": corpus_entry.get("replay_command"),
        "expected_stage": corpus_entry.get("expected_stage"),
        "result_digest": corpus_entry.get("result_digest"),
        "witness": linked.get("witness"),
        "transcript_digest": linked.get("transcript_digest"),
    }
