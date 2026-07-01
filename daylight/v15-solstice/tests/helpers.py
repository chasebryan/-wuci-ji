from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src import corpus, external_attestation, ledger
from src.canonical_json import canonical_sha256


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
OBLIGATIONS = PACKAGE_ROOT / "rules" / "obligations.v15.json"

# Internal-complete evidence plan: one ledger entry per evidence class, each naming
# the internal obligations it discharges. Closing every internal obligation lands
# the harness on the internal ceiling (998,900M).
INTERNAL_LEDGER_PLAN: list[tuple[str, list[str]]] = [
    ("source", ["o.q8.classical_margin_source"]),
    ("build", ["o.q5.evidence_sheaf_build"]),
    (
        "test",
        [
            "o.q1.master_law_executable",
            "o.q2.formal_density_tests",
            "o.q4.fail_closed_tests",
            "o.q6.boundary_matrix_tests",
            "o.q8.kat_vector_tests",
            "o.q10.implementation_tests",
        ],
    ),
    ("adversarial_run", ["o.q6.surface_adversarial_run", "o.q11.falsification_harness"]),
    ("harness_execution", ["o.q4.gate_harness_execution", "o.q9.reproducibility_harness"]),
    ("corpus_snapshot", ["o.q3.subtractive_corpus", "o.q11.falsification_corpus_snapshot"]),
    ("claim", ["o.q1.doctrine_claim_bound", "o.q12.claim_communication"]),
    ("downgrade", ["o.q3.downgrade_machine"]),
    ("proof", ["o.q2.exact_rational_proof"]),
    ("release_repro", ["o.q5.release_reproduction"]),
    ("traceability_map", ["o.q10.traceability_map"]),
    ("doc", ["o.q12.documentation_complete"]),
]

# Negative-evidence corpus plan. Three categories discharge corpus-bound survival
# obligations; the rest are coverage-only negative evidence.
CORPUS_PLAN: list[tuple[str, list[str]]] = [
    ("adversarial_input", ["o.q7.modeled_adversary_corpus"]),
    ("transcript_mismatch", ["o.q7.transcript_survival_corpus"]),
    ("statistical_outlier", ["o.q9.statistical_outlier_corpus"]),
    ("boundary_violation", []),
    ("proof_failure", []),
    ("downgrade_trigger", []),
    ("manual_score_mutation", []),
    ("reproducibility_failure", []),
]

# External-attestation plan: each genuine external attestation carries a signer id
# distinct from the harness identity and closes one external obligation. Appending
# all of them is what lifts the score from the internal ceiling to 1,000,000M.
EXTERNAL_PLAN: list[tuple[str, str, list[str]]] = [
    ("formal-methods-auditor", "ext:formal-methods-auditor", ["o.q2.external_formal_methods_audit"]),
    ("release-reproduction-auditor", "ext:release-reproduction-auditor", ["o.q5.external_downstream_packaging_audit"]),
    ("boundary-fuzz-auditor", "ext:boundary-fuzz-auditor", ["o.q6.external_boundary_fuzz_audit"]),
    ("red-team", "ext:red-team", ["o.q7.external_red_team"]),
    ("post-quantum-crypto-auditor", "ext:post-quantum-crypto-auditor", ["o.q8.external_pq_crypto_audit"]),
    ("independent-replicator", "ext:independent-replicator", ["o.q9.external_independent_replication"]),
    ("provenance-auditor", "ext:provenance-auditor", ["o.q10.external_provenance_audit"]),
    ("external-falsifier", "ext:external-falsifier", ["o.q11.external_falsification_program"]),
    ("communication-reviewer", "ext:communication-reviewer", ["o.q12.external_communication_review"]),
]


def witness(label: str) -> dict[str, str]:
    return {
        "witness_type": label,
        "witness_digest": canonical_sha256({"witness": label}, "DAYLIGHT-v15-SOLSTICE-TEST-WITNESS:"),
    }


def transcript(label: str) -> str:
    return canonical_sha256({"transcript": label}, "DAYLIGHT-v15-SOLSTICE-TEST-TRANSCRIPT:")


def artifact(label: str) -> str:
    return canonical_sha256({"artifact": label}, "DAYLIGHT-v15-SOLSTICE-TEST-ARTIFACT:")


def seed_ledger_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for entry_type, closes in INTERNAL_LEDGER_PLAN:
        entries, _ = ledger.append_entry(
            entries,
            entry_type=entry_type,
            artifact_digest=artifact(entry_type),
            witness=witness(entry_type),
            transcript_digest=transcript(entry_type),
            closes_obligations=closes,
        )
    return entries


def append_external_attestations(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = list(entries)
    for role, signer, closes in EXTERNAL_PLAN:
        result, _ = ledger.append_entry(
            result,
            entry_type="external_attestation",
            artifact_digest=artifact(f"external:{role}"),
            witness=witness("external_attestation"),
            transcript_digest=transcript(f"external:{role}"),
            closes_obligations=closes,
            external_signer_id=signer,
        )
    return result


def seed_corpus_entries() -> list[dict[str, Any]]:
    entries = []
    for category, closes in CORPUS_PLAN:
        entry = {
            "corpus_entry_id": f"corpus-{category}",
            "category": category,
            "generator": "daylight-v15-meridian-seed",
            "input_digest": artifact(category),
            "observed_behavior": "rejected",
            "classification": "negative-evidence",
            "coverage_contribution": "required",
            "linked_ledger_entry": "ledger-entry-0004-adversarial_run",
            "timestamp_utc": ledger.FIXED_TIMESTAMP,
        }
        if closes:
            entry["closes_obligations"] = closes
            entry["replay_command"] = f"python -m daylight.solstice.replay {category}"
            entry["expected_stage"] = "rejected"
            entry["result_digest"] = canonical_sha256(
                {"category": category, "stage": "rejected"},
                "DAYLIGHT-v15-SOLSTICE-TEST-REPLAY:",
            )
        corpus.validate_entry(entry)
        entries.append(entry)
    return entries


def demo_rootset(role: str, root_key: str = "solstice-test-root-key") -> dict[str, Any]:
    rootset = {
        "rootset_version": external_attestation.ROOTSET_VERSION,
        "reviewed_commit": external_attestation.ZERO_COMMIT,
        "allowed_roots": [
            {
                "external_role": role,
                "root_key_digest": external_attestation.root_key_digest(root_key),
                "scheme": "hmac-sha256",
                "root_key": root_key,
            }
        ],
        "role_policies": {
            role: {
                "external_role": role,
                "quorum_k": 1,
                "reviewed_commit": external_attestation.ZERO_COMMIT,
                "require_distinct_reviewers": True,
                "require_distinct_root_keys": True,
            }
        },
    }
    rootset["rootset_digest"] = external_attestation.rootset_digest(rootset)
    return rootset


def append_signed_external_attestation(
    entries: list[dict[str, Any]],
    *,
    obligation_id: str,
    role: str,
    signer: str,
    root_key: str = "solstice-test-root-key",
) -> list[dict[str, Any]]:
    attestation = external_attestation.build_attestation(
        obligation_id=obligation_id,
        external_role=role,
        external_signer_id=signer,
        reviewer_identity=f"reviewer:{signer}",
        root_key=root_key,
        report_digest=artifact(f"report:{obligation_id}"),
        artifact_digest_target=artifact(f"target:{obligation_id}"),
        transcript_reference=f"ledger:{obligation_id}",
    )
    result, _ = ledger.append_entry(
        list(entries),
        entry_type="external_attestation",
        artifact_digest=artifact(f"external:{role}"),
        witness=witness("external_attestation"),
        transcript_digest=transcript(f"external:{role}"),
        closes_obligations=[obligation_id],
        signatures=[attestation],
        external_signer_id=signer,
    )
    return result


def write_corpus(path: Path, entries: list[dict[str, Any]]) -> None:
    lines = "".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n" for entry in entries)
    path.write_text(lines, encoding="utf-8")


def write_seed_inputs(root: Path) -> tuple[Path, Path]:
    ledger_path = root / "ledger.seed.jsonl"
    corpus_path = root / "corpus.seed.jsonl"
    ledger.write_jsonl(ledger_path, seed_ledger_entries())
    write_corpus(corpus_path, seed_corpus_entries())
    return ledger_path, corpus_path


def write_perfect_inputs(root: Path) -> tuple[Path, Path]:
    """Seed inputs plus the external attestations that reach 1,000,000M."""
    ledger_path = root / "ledger.perfect.jsonl"
    corpus_path = root / "corpus.seed.jsonl"
    ledger.write_jsonl(ledger_path, append_external_attestations(seed_ledger_entries()))
    write_corpus(corpus_path, seed_corpus_entries())
    return ledger_path, corpus_path


def write_rootset(path: Path, rootset: dict[str, Any]) -> None:
    path.write_text(json.dumps(rootset, indent=2, sort_keys=True) + "\n", encoding="utf-8")
