"""Executable Daylight v16 Zenith assurance contract constants."""

from __future__ import annotations

from typing import Any

from .canonical_json import canonical_sha256


NAME = "Daylight v16 Zenith"
VERSION = "daylight-v16-zenith-v0.1"
M_SCALE = 1_000_000
Z_SCALE = 1000
PERFECT_SCORE_M = 1_000_000
HARNESS_IDENTITY = "daylight-zenith-harness-v0.1"

D_ZENITH_AXIS = "DAYLIGHT-v16-ZENITH-AXIS:"
D_ZENITH_OBLIGATION = "DAYLIGHT-v16-ZENITH-OBLIGATION:"
D_ZENITH_RESOLUTION = "DAYLIGHT-v16-ZENITH-RESOLUTION:"
D_ZENITH_REPORT = "DAYLIGHT-v16-ZENITH-REPORT:"
D_ZENITH_ATTEST = "DAYLIGHT-v16-ZENITH-ATTESTATION:"
D_ZENITH_REBUILD = "DAYLIGHT-v16-ZENITH-REBUILD:"
D_ZENITH_IMPL = "DAYLIGHT-v16-ZENITH-IMPLEMENTATION:"
D_ZENITH_FUZZ = "DAYLIGHT-v16-ZENITH-FUZZ:"
D_ZENITH_LOG_LEAF = "DAYLIGHT-v16-ZENITH-LOG-LEAF:"
D_ZENITH_LOG_NODE = "DAYLIGHT-v16-ZENITH-LOG-NODE:"
D_ZENITH_MANIFEST = "DAYLIGHT-v16-ZENITH-MANIFEST:"
D_ZENITH_AUTHZ = "DAYLIGHT-v16-ZENITH-AUTHORIZATION:"

Z_AXES = [
    "z1_hermetic_solstice_artifact",
    "z2_supply_chain_provenance",
    "z3_reproducible_builds",
    "z4_multi_implementation_agreement",
    "z5_semantic_evidence_replay",
    "z6_adversarial_fuzzing",
    "z7_signed_external_reviews",
    "z8_transparency_log",
    "z9_public_falsification_program",
    "z10_boundary_discipline",
]

Z_AXIS_WEIGHT_M = {
    "z1_hermetic_solstice_artifact": 100000,
    "z2_supply_chain_provenance": 100000,
    "z3_reproducible_builds": 120000,
    "z4_multi_implementation_agreement": 120000,
    "z5_semantic_evidence_replay": 100000,
    "z6_adversarial_fuzzing": 100000,
    "z7_signed_external_reviews": 120000,
    "z8_transparency_log": 80000,
    "z9_public_falsification_program": 80000,
    "z10_boundary_discipline": 80000,
}

Z_OBLIGATIONS: list[dict[str, Any]] = [
    {"id": "z1.solstice_verify_pass", "axis_id": "z1_hermetic_solstice_artifact", "weight": 250, "evidence_kind": "artifact", "evidence_class": "solstice", "verifier_key": "verify_solstice_pass", "scope": "internal"},
    {"id": "z1.weight_vector_pinned", "axis_id": "z1_hermetic_solstice_artifact", "weight": 150, "evidence_kind": "artifact", "evidence_class": "weights", "verifier_key": "verify_weight_digest_pinned", "scope": "internal"},
    {"id": "z1.output_ledger_transition", "axis_id": "z1_hermetic_solstice_artifact", "weight": 200, "evidence_kind": "artifact", "evidence_class": "ledger", "verifier_key": "verify_output_ledger_transition", "scope": "internal"},
    {"id": "z1.manifest_closure", "axis_id": "z1_hermetic_solstice_artifact", "weight": 200, "evidence_kind": "artifact", "evidence_class": "manifest", "verifier_key": "verify_manifest_closure", "scope": "internal"},
    {"id": "z1.no_manual_score_surface", "axis_id": "z1_hermetic_solstice_artifact", "weight": 100, "evidence_kind": "test", "evidence_class": "tamper", "verifier_key": "verify_manual_score_rejected", "scope": "internal"},
    {"id": "z1.claim_boundary_encoded", "axis_id": "z1_hermetic_solstice_artifact", "weight": 100, "evidence_kind": "artifact", "evidence_class": "boundary", "verifier_key": "verify_claim_boundary_encoded", "scope": "internal"},
    {"id": "z2.slsa_provenance", "axis_id": "z2_supply_chain_provenance", "weight": 250, "evidence_kind": "provenance", "evidence_class": "slsa", "verifier_key": "verify_slsa_provenance", "scope": "public"},
    {"id": "z2.in_toto_layout", "axis_id": "z2_supply_chain_provenance", "weight": 250, "evidence_kind": "provenance", "evidence_class": "in_toto", "verifier_key": "verify_in_toto_layout", "scope": "public"},
    {"id": "z2.builder_identity_pinned", "axis_id": "z2_supply_chain_provenance", "weight": 200, "evidence_kind": "provenance", "evidence_class": "builder_identity", "verifier_key": "verify_builder_identity", "scope": "public"},
    {"id": "z2.materials_digest_bound", "axis_id": "z2_supply_chain_provenance", "weight": 150, "evidence_kind": "provenance", "evidence_class": "materials", "verifier_key": "verify_materials_digest", "scope": "public"},
    {"id": "z2.dependency_lock_bound", "axis_id": "z2_supply_chain_provenance", "weight": 150, "evidence_kind": "provenance", "evidence_class": "dependency_lock", "verifier_key": "verify_dependency_lock", "scope": "public"},
    {"id": "z3.rebuild_one", "axis_id": "z3_reproducible_builds", "weight": 225, "evidence_kind": "rebuild", "evidence_class": "independent_rebuild", "verifier_key": "verify_rebuild_one", "scope": "public"},
    {"id": "z3.rebuild_two", "axis_id": "z3_reproducible_builds", "weight": 225, "evidence_kind": "rebuild", "evidence_class": "independent_rebuild", "verifier_key": "verify_rebuild_two", "scope": "public"},
    {"id": "z3.rebuild_three", "axis_id": "z3_reproducible_builds", "weight": 225, "evidence_kind": "rebuild", "evidence_class": "independent_rebuild", "verifier_key": "verify_rebuild_three", "scope": "public"},
    {"id": "z3.distinct_environments", "axis_id": "z3_reproducible_builds", "weight": 125, "evidence_kind": "rebuild", "evidence_class": "environment", "verifier_key": "verify_distinct_rebuild_environments", "scope": "public"},
    {"id": "z3.deterministic_release_archive", "axis_id": "z3_reproducible_builds", "weight": 125, "evidence_kind": "rebuild", "evidence_class": "release_archive", "verifier_key": "verify_deterministic_release_archive", "scope": "public"},
    {"id": "z3.rebuild_receipts_bound", "axis_id": "z3_reproducible_builds", "weight": 75, "evidence_kind": "rebuild", "evidence_class": "receipt", "verifier_key": "verify_rebuild_receipts", "scope": "public"},
    {"id": "z4.python_reference", "axis_id": "z4_multi_implementation_agreement", "weight": 150, "evidence_kind": "implementation", "evidence_class": "python", "verifier_key": "verify_python_reference_output", "scope": "internal"},
    {"id": "z4.rust_verifier", "axis_id": "z4_multi_implementation_agreement", "weight": 225, "evidence_kind": "implementation", "evidence_class": "rust", "verifier_key": "verify_rust_verifier_output", "scope": "internal"},
    {"id": "z4.third_verifier", "axis_id": "z4_multi_implementation_agreement", "weight": 225, "evidence_kind": "implementation", "evidence_class": "third_impl", "verifier_key": "verify_third_verifier_output", "scope": "internal"},
    {"id": "z4.intermediate_digest_agreement", "axis_id": "z4_multi_implementation_agreement", "weight": 250, "evidence_kind": "implementation", "evidence_class": "digest_vector", "verifier_key": "verify_intermediate_digest_agreement", "scope": "internal"},
    {"id": "z4.negative_divergence_tests", "axis_id": "z4_multi_implementation_agreement", "weight": 150, "evidence_kind": "test", "evidence_class": "negative_divergence", "verifier_key": "verify_negative_divergence_tests", "scope": "internal"},
    {"id": "z5.ledger_semantic_replay", "axis_id": "z5_semantic_evidence_replay", "weight": 200, "evidence_kind": "replay", "evidence_class": "ledger", "verifier_key": "verify_ledger_semantic_replay", "scope": "internal"},
    {"id": "z5.corpus_replay", "axis_id": "z5_semantic_evidence_replay", "weight": 250, "evidence_kind": "replay", "evidence_class": "corpus", "verifier_key": "verify_corpus_replay", "scope": "internal"},
    {"id": "z5.proof_replay", "axis_id": "z5_semantic_evidence_replay", "weight": 200, "evidence_kind": "replay", "evidence_class": "proof", "verifier_key": "verify_proof_replay", "scope": "internal"},
    {"id": "z5.release_reproduction_replay", "axis_id": "z5_semantic_evidence_replay", "weight": 200, "evidence_kind": "replay", "evidence_class": "release_repro", "verifier_key": "verify_release_reproduction_replay", "scope": "internal"},
    {"id": "z5.traceability_map_replay", "axis_id": "z5_semantic_evidence_replay", "weight": 150, "evidence_kind": "replay", "evidence_class": "traceability", "verifier_key": "verify_traceability_map_replay", "scope": "internal"},
    {"id": "z6.parser_fuzz", "axis_id": "z6_adversarial_fuzzing", "weight": 200, "evidence_kind": "fuzz", "evidence_class": "parser", "verifier_key": "verify_parser_fuzz", "scope": "public"},
    {"id": "z6.artifact_fuzz", "axis_id": "z6_adversarial_fuzzing", "weight": 175, "evidence_kind": "fuzz", "evidence_class": "artifact", "verifier_key": "verify_artifact_fuzz", "scope": "public"},
    {"id": "z6.envelope_fuzz", "axis_id": "z6_adversarial_fuzzing", "weight": 175, "evidence_kind": "fuzz", "evidence_class": "envelope", "verifier_key": "verify_envelope_fuzz", "scope": "public"},
    {"id": "z6.ledger_corpus_fuzz", "axis_id": "z6_adversarial_fuzzing", "weight": 150, "evidence_kind": "fuzz", "evidence_class": "ledger_corpus", "verifier_key": "verify_ledger_corpus_fuzz", "scope": "public"},
    {"id": "z6.sanitizer_clean", "axis_id": "z6_adversarial_fuzzing", "weight": 150, "evidence_kind": "fuzz", "evidence_class": "sanitizer", "verifier_key": "verify_sanitizer_clean", "scope": "public"},
    {"id": "z6.crash_triage_closed", "axis_id": "z6_adversarial_fuzzing", "weight": 150, "evidence_kind": "fuzz", "evidence_class": "triage", "verifier_key": "verify_crash_triage_closed", "scope": "public"},
    {"id": "z7.two_independent_reviews", "axis_id": "z7_signed_external_reviews", "weight": 250, "evidence_kind": "review", "evidence_class": "review_set", "verifier_key": "verify_two_independent_reviews", "scope": "external"},
    {"id": "z7.formal_methods_review", "axis_id": "z7_signed_external_reviews", "weight": 150, "evidence_kind": "review", "evidence_class": "formal_methods", "verifier_key": "verify_formal_methods_review", "scope": "external"},
    {"id": "z7.crypto_review", "axis_id": "z7_signed_external_reviews", "weight": 150, "evidence_kind": "review", "evidence_class": "crypto", "verifier_key": "verify_crypto_review", "scope": "external"},
    {"id": "z7.boundary_fuzz_review", "axis_id": "z7_signed_external_reviews", "weight": 150, "evidence_kind": "review", "evidence_class": "boundary_fuzz", "verifier_key": "verify_boundary_fuzz_review", "scope": "external"},
    {"id": "z7.independent_replication_review", "axis_id": "z7_signed_external_reviews", "weight": 150, "evidence_kind": "review", "evidence_class": "replication", "verifier_key": "verify_independent_replication_review", "scope": "external"},
    {"id": "z7.production_blockers_review", "axis_id": "z7_signed_external_reviews", "weight": 150, "evidence_kind": "review", "evidence_class": "production_blockers", "verifier_key": "verify_production_blockers_review", "scope": "external"},
    {"id": "z8.log_inclusion", "axis_id": "z8_transparency_log", "weight": 250, "evidence_kind": "log", "evidence_class": "inclusion", "verifier_key": "verify_log_inclusion", "scope": "public"},
    {"id": "z8.signed_tree_head", "axis_id": "z8_transparency_log", "weight": 200, "evidence_kind": "log", "evidence_class": "tree_head", "verifier_key": "verify_signed_tree_head", "scope": "public"},
    {"id": "z8.consistency_proof", "axis_id": "z8_transparency_log", "weight": 200, "evidence_kind": "log", "evidence_class": "consistency", "verifier_key": "verify_log_consistency", "scope": "public"},
    {"id": "z8.append_only_audit", "axis_id": "z8_transparency_log", "weight": 175, "evidence_kind": "log", "evidence_class": "append_only", "verifier_key": "verify_append_only_audit", "scope": "public"},
    {"id": "z8.public_index_manifest", "axis_id": "z8_transparency_log", "weight": 175, "evidence_kind": "log", "evidence_class": "public_index", "verifier_key": "verify_public_index_manifest", "scope": "public"},
    {"id": "z9.challenge_spec", "axis_id": "z9_public_falsification_program", "weight": 200, "evidence_kind": "falsification", "evidence_class": "challenge_spec", "verifier_key": "verify_challenge_spec", "scope": "public"},
    {"id": "z9.break_class_taxonomy", "axis_id": "z9_public_falsification_program", "weight": 150, "evidence_kind": "falsification", "evidence_class": "break_taxonomy", "verifier_key": "verify_break_class_taxonomy", "scope": "public"},
    {"id": "z9.public_reproducer_rule", "axis_id": "z9_public_falsification_program", "weight": 200, "evidence_kind": "falsification", "evidence_class": "reproducer_rule", "verifier_key": "verify_public_reproducer_rule", "scope": "public"},
    {"id": "z9.adjudication_signature", "axis_id": "z9_public_falsification_program", "weight": 200, "evidence_kind": "falsification", "evidence_class": "adjudication", "verifier_key": "verify_adjudication_signature", "scope": "public"},
    {"id": "z9.open_break_ledger", "axis_id": "z9_public_falsification_program", "weight": 150, "evidence_kind": "falsification", "evidence_class": "break_ledger", "verifier_key": "verify_open_break_ledger", "scope": "public"},
    {"id": "z9.zero_critical_open", "axis_id": "z9_public_falsification_program", "weight": 100, "evidence_kind": "falsification", "evidence_class": "critical_breaks", "verifier_key": "verify_zero_critical_open", "scope": "public"},
    {"id": "z10.production_authority_gate", "axis_id": "z10_boundary_discipline", "weight": 175, "evidence_kind": "boundary", "evidence_class": "production_authority", "verifier_key": "verify_production_authority_gate", "scope": "boundary"},
    {"id": "z10.runtime_containment_gate", "axis_id": "z10_boundary_discipline", "weight": 175, "evidence_kind": "boundary", "evidence_class": "runtime_containment", "verifier_key": "verify_runtime_containment_gate", "scope": "boundary"},
    {"id": "z10.pq_claim_gate", "axis_id": "z10_boundary_discipline", "weight": 175, "evidence_kind": "boundary", "evidence_class": "pq_claim", "verifier_key": "verify_pq_claim_gate", "scope": "boundary"},
    {"id": "z10.fixture_quarantine", "axis_id": "z10_boundary_discipline", "weight": 175, "evidence_kind": "boundary", "evidence_class": "fixture_quarantine", "verifier_key": "verify_fixture_quarantine", "scope": "boundary"},
    {"id": "z10.nonclaim_enforcement", "axis_id": "z10_boundary_discipline", "weight": 175, "evidence_kind": "boundary", "evidence_class": "nonclaims", "verifier_key": "verify_nonclaim_enforcement", "scope": "boundary"},
    {"id": "z10.unsupported_fail_closed", "axis_id": "z10_boundary_discipline", "weight": 125, "evidence_kind": "boundary", "evidence_class": "unsupported_platform", "verifier_key": "verify_unsupported_platform_fail_closed", "scope": "boundary"},
]

Z_LEVELS = [
    "Z_REJECT",
    "Z0_PARSE_ONLY",
    "Z1_DIGEST_CLOSED",
    "Z2_EVIDENCE_BOUND",
    "Z3_HERMETIC_SOLSTICE",
    "Z4_REPRODUCIBLE",
    "Z5_ADVERSARIAL_REPRODUCIBLE",
    "Z6_PUBLIC_EXTERNAL_STANDARD",
    "Z7_PRODUCTION_ELIGIBLE",
]

REQUIRED_FUZZ_TARGETS = ["parser", "artifact", "envelope", "ledger_corpus"]
REQUIRED_REVIEW_SCOPES = [
    "formal_methods",
    "crypto",
    "boundary_fuzz",
    "independent_replication",
    "production_blockers",
    "claim_discipline",
]
BREAK_CLASSES = [
    "B0_documentation_ambiguity",
    "B1_score_mismatch",
    "B2_verifier_mismatch",
    "B3_artifact_closure_bypass",
    "B4_unsigned_external_credit_accepted",
    "B5_forged_scorecard_accepted",
    "B6_envelope_opens_without_policy_evidence",
    "B7_production_or_pq_overclaim",
]


def axis_digest() -> str:
    return canonical_sha256(
        {"version": VERSION, "axes": Z_AXES, "axis_weight_M": Z_AXIS_WEIGHT_M},
        D_ZENITH_AXIS,
    )


def obligation_digest() -> str:
    return canonical_sha256(Z_OBLIGATIONS, D_ZENITH_OBLIGATION)


def validate_contract() -> None:
    if list(Z_AXIS_WEIGHT_M) != Z_AXES:
        raise ValueError("Zenith axis order mismatch")
    if sum(Z_AXIS_WEIGHT_M.values()) != M_SCALE:
        raise ValueError("Zenith axis weights must sum to 1000000M")
    seen: set[str] = set()
    for obligation in Z_OBLIGATIONS:
        oid = obligation["id"]
        if oid in seen:
            raise ValueError(f"duplicate Zenith obligation id: {oid}")
        seen.add(oid)
        if obligation["axis_id"] not in Z_AXES:
            raise ValueError(f"unknown Zenith axis: {obligation['axis_id']}")
        weight = obligation["weight"]
        if not isinstance(weight, int) or weight <= 0 or weight > Z_SCALE:
            raise ValueError(f"invalid Zenith obligation weight: {oid}")
    for axis in Z_AXES:
        total = sum(item["weight"] for item in Z_OBLIGATIONS if item["axis_id"] == axis)
        if total != Z_SCALE:
            raise ValueError(f"{axis} obligation weights must sum to 1000, got {total}")


validate_contract()
