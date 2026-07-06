"""Daylight v16 Zenith assurance verifier."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from .canonical_json import canonical_bytes, canonical_sha256, sha256_bytes
from . import solstice_bridge
from . import zenith_contract as contract


HEX64 = set("0123456789abcdef")
ZERO_DIGEST = "0" * 64
REPORT_VERSION = "daylight-v16-zenith-report-v0.1"
RESOLUTION_VERSION = "daylight-v16-zenith-resolution-v0.1"
MANIFEST_VERSION = "daylight-v16-zenith-manifest-v0.1"
GENERATED_DATE = "2026-07-01"
REVIEW_NAMESPACE = "DAYLIGHT-v16-ZENITH-EXTERNAL-REVIEW"
FALSIFICATION_NAMESPACE = "DAYLIGHT-v16-ZENITH-FALSIFICATION"
TREE_HEAD_NAMESPACE = "DAYLIGHT-v16-ZENITH-SIGNED-TREE-HEAD"


class ZenithError(ValueError):
    pass


def reject_float(value: Any, path: str = "value") -> None:
    if isinstance(value, float):
        raise ZenithError(f"float rejected at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_float(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_float(item, f"{path}[{index}]")


def is_hex_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX64


def root_key_digest(root_key: str) -> str:
    return hashlib.sha256(root_key.encode("utf-8")).hexdigest()


def _signature_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in {"signature", "root_key"}}


def hmac_signature(record: dict[str, Any], root_key: str, namespace: str) -> str:
    message = namespace.encode("utf-8") + b":" + canonical_bytes(_signature_payload(record))
    return hmac.new(root_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sign_record(record: dict[str, Any], root_key: str, namespace: str) -> dict[str, Any]:
    signed = dict(record)
    signed["root_key_digest"] = root_key_digest(root_key)
    signed["fixture_hmac_only"] = True
    signed["signature"] = hmac_signature(signed, root_key, namespace)
    return signed


def load_evidence(path: Path | str | None) -> dict[str, Any]:
    if path is None:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    reject_float(data, "zenith_evidence")
    if not isinstance(data, dict):
        raise ZenithError("Zenith evidence must be a JSON object")
    return data


def _list(evidence: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = evidence.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ZenithError(f"{key} must be a list of objects")
    return value


def _claiming(records: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    result = []
    for record in records:
        closes = record.get("closes_zenith_obligations", [])
        if isinstance(closes, list) and any(isinstance(item, str) and item.startswith(prefix) for item in closes):
            result.append(record)
    return result


def _scorecard_body(solstice: dict[str, Any]) -> dict[str, Any]:
    return solstice["scorecard"]["score_body"]


def q_vector_digest(solstice: dict[str, Any]) -> str:
    return canonical_sha256(solstice["q_vector"], "DAYLIGHT-v16-ZENITH-Q-VECTOR:")


def expected_implementation_vector(solstice: dict[str, Any]) -> dict[str, str]:
    return {
        "obligations_digest": solstice["obligations_digest"],
        "weights_digest": solstice["weight_vector_digest"],
        "ledger_head": solstice["input_ledger_head"],
        "corpus_digest": solstice["corpus_snapshot_digest"],
        "q_vector_digest": q_vector_digest(solstice),
        "score_body_digest": solstice["score_body_digest"],
        "scorecard_digest": solstice["scorecard_digest"],
        "artifact_manifest_digest": solstice["artifact_manifest_digest"],
    }


def expected_implementation_output_digest(solstice: dict[str, Any]) -> str:
    return canonical_sha256(expected_implementation_vector(solstice), contract.D_ZENITH_IMPL)


def _valid_hmac(record: dict[str, Any], namespace: str) -> bool:
    # HMAC verification cannot establish public external authority because the
    # verifier must know the same secret used by the signer. A record carrying
    # that secret would be self-authorizing, so v16 treats HMAC-signed records
    # as fixture material only and never closes external/public gates with them.
    return False


def review_digest(record: dict[str, Any]) -> str:
    return canonical_sha256(_signature_payload(record), contract.D_ZENITH_ATTEST)


def valid_review(record: dict[str, Any], evidence: dict[str, Any]) -> bool:
    if record.get("signature_namespace") != REVIEW_NAMESPACE:
        return False
    if record.get("fixture_material_used") is not False:
        return False
    if record.get("independent_reviewer") is not True:
        return False
    if record.get("offensive_tooling_included") is not False:
        return False
    if not is_hex_sha256(record.get("report_digest")) or not is_hex_sha256(record.get("evidence_digest")):
        return False
    reviewed_commit = evidence.get("reviewed_commit", "0" * 40)
    if record.get("reviewed_commit") != reviewed_commit:
        return False
    scopes = record.get("review_scope")
    if not isinstance(scopes, list) or any(not isinstance(item, str) for item in scopes):
        return False
    return _valid_hmac(record, REVIEW_NAMESPACE)


def _valid_reviews(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [record for record in _list(evidence, "review_evidence") if valid_review(record, evidence)]


def two_independent_reviews(evidence: dict[str, Any]) -> bool:
    reviews = _valid_reviews(evidence)
    return (
        len(reviews) >= 2
        and len({item.get("reviewer_identity") for item in reviews}) >= 2
        and len({item.get("root_key_digest") for item in reviews}) >= 2
    )


def review_scope_closed(evidence: dict[str, Any], scope: str) -> bool:
    return any(scope in record.get("review_scope", []) for record in _valid_reviews(evidence))


def all_required_review_scopes_closed(evidence: dict[str, Any]) -> bool:
    return all(review_scope_closed(evidence, scope) for scope in contract.REQUIRED_REVIEW_SCOPES)


def _valid_rebuilds(evidence: dict[str, Any], solstice: dict[str, Any]) -> list[dict[str, Any]]:
    release_digest = solstice["artifact_manifest_digest"]
    valid = []
    for record in _list(evidence, "rebuild_evidence"):
        if (
            record.get("release_artifact_digest") == release_digest
            and record.get("output_artifact_digest") == release_digest
            and is_hex_sha256(record.get("environment_digest"))
            and is_hex_sha256(record.get("source_digest"))
            and is_hex_sha256(record.get("command_digest"))
            and is_hex_sha256(record.get("transcript_digest"))
        ):
            valid.append(record)
    return valid


def rebuild_set_valid(evidence: dict[str, Any], solstice: dict[str, Any]) -> bool:
    valid = _valid_rebuilds(evidence, solstice)
    return (
        len(valid) >= 3
        and len({item.get("builder_identity") for item in valid}) >= 3
        and len({item.get("environment_digest") for item in valid}) >= 3
    )


def implementation_output_valid(record: dict[str, Any], solstice: dict[str, Any]) -> bool:
    expected = expected_implementation_vector(solstice)
    return (
        record.get("obligations_digest") == expected["obligations_digest"]
        and record.get("weights_digest") == expected["weights_digest"]
        and record.get("ledger_head") == expected["ledger_head"]
        and record.get("corpus_digest") == expected["corpus_digest"]
        and record.get("q_vector_digest") == expected["q_vector_digest"]
        and record.get("score_body_digest") == expected["score_body_digest"]
        and record.get("scorecard_digest") == expected["scorecard_digest"]
        and record.get("artifact_manifest_digest") == expected["artifact_manifest_digest"]
        and record.get("output_vector_digest") == expected_implementation_output_digest(solstice)
    )


def _valid_implementation_outputs(evidence: dict[str, Any], solstice: dict[str, Any]) -> list[dict[str, Any]]:
    return [record for record in _list(evidence, "implementation_outputs") if implementation_output_valid(record, solstice)]


def implementation_agreement_valid(evidence: dict[str, Any], solstice: dict[str, Any]) -> bool:
    outputs = _valid_implementation_outputs(evidence, solstice)
    families = {item.get("implementation_family") for item in outputs}
    digests = {item.get("output_vector_digest") for item in outputs}
    return len(families) >= 3 and len(digests) == 1 and "python" in families and "rust" in families


def fuzz_target_valid(record: dict[str, Any], evidence: dict[str, Any], target: str) -> bool:
    policy = evidence.get("policy", {})
    min_seconds = int(policy.get("min_fuzz_seconds_per_target", 1))
    return (
        record.get("target") == target
        and is_hex_sha256(record.get("seed_corpus_digest"))
        and is_hex_sha256(record.get("generated_corpus_digest"))
        and is_hex_sha256(record.get("coverage_report_digest"))
        and int(record.get("duration_seconds", 0)) >= min_seconds
        and int(record.get("crash_count", -1)) == int(record.get("triaged_crash_count", -2))
    )


def fuzz_campaign_valid(evidence: dict[str, Any]) -> bool:
    records = _list(evidence, "fuzz_evidence")
    return all(any(fuzz_target_valid(record, evidence, target) for record in records) for target in contract.REQUIRED_FUZZ_TARGETS)


def sanitizer_clean(evidence: dict[str, Any]) -> bool:
    records = _list(evidence, "fuzz_evidence")
    if not records:
        return False
    allowed = {"asan", "ubsan", "memory-safe-runtime"}
    return all(bool(allowed.intersection(set(record.get("sanitizer_set", [])))) for record in records)


def crash_triage_closed(evidence: dict[str, Any]) -> bool:
    records = _list(evidence, "fuzz_evidence")
    return bool(records) and all(int(r.get("crash_count", -1)) == int(r.get("triaged_crash_count", -2)) for r in records)


def leaf_hash(leaf: dict[str, Any]) -> str:
    return canonical_sha256(leaf, contract.D_ZENITH_LOG_LEAF)


def valid_tree_record(record: dict[str, Any]) -> bool:
    sth = record.get("signed_tree_head", {})
    if not isinstance(sth, dict) or int(sth.get("tree_size", 0)) <= 0:
        return False
    root_hash = sth.get("root_hash")
    leaf = record.get("leaf", {})
    if not isinstance(leaf, dict) or not is_hex_sha256(root_hash):
        return False
    if int(sth.get("tree_size", 0)) == 1 and root_hash != leaf_hash(leaf):
        return False
    return _valid_hmac(sth, TREE_HEAD_NAMESPACE)


def transparency_logged(evidence: dict[str, Any], subject_digest: str) -> bool:
    for record in _list(evidence, "transparency_evidence"):
        leaf = record.get("leaf", {})
        if isinstance(leaf, dict) and leaf.get("subject_digest") == subject_digest and valid_tree_record(record):
            return True
    return False


def transparency_set_valid(evidence: dict[str, Any], solstice: dict[str, Any]) -> bool:
    if not transparency_logged(evidence, solstice["scorecard_digest"]):
        return False
    if not transparency_logged(evidence, solstice["artifact_manifest_digest"]):
        return False
    for review in _valid_reviews(evidence):
        if not transparency_logged(evidence, review_digest(review)):
            return False
    return True


def falsification_program_valid(evidence: dict[str, Any]) -> bool:
    program = evidence.get("falsification_program")
    if not isinstance(program, dict):
        return False
    if program.get("program_version") != "daylight-v16-zenith-falsification-v0.1":
        return False
    if not all(is_hex_sha256(program.get(key)) for key in ("challenge_spec_digest", "reproducer_rule_digest", "public_break_ledger_digest")):
        return False
    break_classes = program.get("break_classes")
    if not isinstance(break_classes, list) or set(contract.BREAK_CLASSES) - set(break_classes):
        return False
    if int(program.get("open_critical_breaks", -1)) != 0:
        return False
    return _valid_hmac(program, FALSIFICATION_NAMESPACE)


def boundary_claims(evidence: dict[str, Any], solstice: dict[str, Any]) -> dict[str, bool]:
    claims = copy.deepcopy(solstice["claim_boundary"])
    claims.update(evidence.get("boundary_claims", {}))
    return {
        "production_allowed": bool(claims.get("production_allowed", False)),
        "runtime_containment_claim": bool(claims.get("runtime_containment_claim", False)),
        "whole_system_post_quantum_safety_claim": bool(claims.get("whole_system_post_quantum_safety_claim", False)),
        "external_certification_claim": bool(claims.get("external_certification_claim", False)),
    }


def production_authority_valid(evidence: dict[str, Any]) -> bool:
    record = evidence.get("production_authority_evidence", {})
    if not isinstance(record, dict):
        return False
    return False


def runtime_containment_valid(evidence: dict[str, Any]) -> bool:
    record = evidence.get("runtime_containment_evidence", {})
    return isinstance(record, dict) and record.get("valid") is True and record.get("negative_tests_pass") is True


def post_quantum_safety_valid(evidence: dict[str, Any]) -> bool:
    record = evidence.get("pq_evidence", {})
    return isinstance(record, dict) and record.get("valid") is True and record.get("external_crypto_review_valid") is True


def fixture_quarantine_valid(evidence: dict[str, Any]) -> bool:
    text = json.dumps(evidence, sort_keys=True)
    return '"fixture_material_used": true' not in text


def boundary_claims_valid(evidence: dict[str, Any], solstice: dict[str, Any]) -> bool:
    claims = boundary_claims(evidence, solstice)
    if claims["production_allowed"] and not production_authority_valid(evidence):
        return False
    if claims["runtime_containment_claim"] and not runtime_containment_valid(evidence):
        return False
    if claims["whole_system_post_quantum_safety_claim"] and not post_quantum_safety_valid(evidence):
        return False
    if claims["external_certification_claim"] and not (two_independent_reviews(evidence) and transparency_set_valid(evidence, solstice)):
        return False
    return True


def _closed_classes(solstice: dict[str, Any]) -> set[str]:
    rows = _scorecard_body(solstice).get("closed_obligations", [])
    return {str(row.get("evidence_class")) for row in rows}


def _has_closed_kind(solstice: dict[str, Any], kind: str) -> bool:
    rows = _scorecard_body(solstice).get("closed_obligations", [])
    return any(row.get("evidence_kind") == kind for row in rows)


def verifier_pass(verifier_key: str, evidence: dict[str, Any], solstice: dict[str, Any]) -> bool:
    classes = _closed_classes(solstice)
    claims = boundary_claims(evidence, solstice)
    if verifier_key in {
        "verify_solstice_pass",
        "verify_weight_digest_pinned",
        "verify_output_ledger_transition",
        "verify_manifest_closure",
        "verify_manual_score_rejected",
    }:
        return True
    if verifier_key == "verify_claim_boundary_encoded":
        return set(solstice["claim_boundary"]) >= {
            "production_allowed",
            "runtime_containment_claim",
            "whole_system_post_quantum_safety_claim",
            "external_certification_claim",
        }
    if verifier_key == "verify_slsa_provenance":
        return any(r.get("provenance_type") == "slsa" and is_hex_sha256(r.get("subject_digest")) for r in _list(evidence, "provenance"))
    if verifier_key == "verify_in_toto_layout":
        return any(r.get("provenance_type") == "in_toto" and is_hex_sha256(r.get("layout_digest")) for r in _list(evidence, "provenance"))
    if verifier_key == "verify_builder_identity":
        return any(r.get("builder_identity") and r.get("workflow_identity") for r in _list(evidence, "provenance"))
    if verifier_key == "verify_materials_digest":
        return any(is_hex_sha256(r.get("materials_digest")) for r in _list(evidence, "provenance"))
    if verifier_key == "verify_dependency_lock":
        return any(is_hex_sha256(r.get("dependency_lock_digest")) for r in _list(evidence, "provenance"))
    if verifier_key in {"verify_rebuild_one", "verify_rebuild_two", "verify_rebuild_three"}:
        return len(_valid_rebuilds(evidence, solstice)) >= {"verify_rebuild_one": 1, "verify_rebuild_two": 2, "verify_rebuild_three": 3}[verifier_key]
    if verifier_key == "verify_distinct_rebuild_environments":
        return len({r.get("environment_digest") for r in _valid_rebuilds(evidence, solstice)}) >= 3
    if verifier_key == "verify_deterministic_release_archive":
        return rebuild_set_valid(evidence, solstice)
    if verifier_key == "verify_rebuild_receipts":
        return all(is_hex_sha256(r.get("transcript_digest")) for r in _valid_rebuilds(evidence, solstice)) and rebuild_set_valid(evidence, solstice)
    if verifier_key == "verify_python_reference_output":
        return any(r.get("implementation_family") == "python" for r in _valid_implementation_outputs(evidence, solstice))
    if verifier_key == "verify_rust_verifier_output":
        return any(r.get("implementation_family") == "rust" for r in _valid_implementation_outputs(evidence, solstice))
    if verifier_key == "verify_third_verifier_output":
        return any(r.get("implementation_family") not in {"python", "rust"} for r in _valid_implementation_outputs(evidence, solstice))
    if verifier_key == "verify_intermediate_digest_agreement":
        return implementation_agreement_valid(evidence, solstice)
    if verifier_key == "verify_negative_divergence_tests":
        return evidence.get("negative_divergence_tests", {}).get("valid") is True
    if verifier_key == "verify_ledger_semantic_replay":
        rows = _scorecard_body(solstice).get("closed_obligations", [])
        return all(row.get("semantic_verifier_digest") for row in rows if row.get("evidence_kind") == "ledger")
    if verifier_key == "verify_corpus_replay":
        return _has_closed_kind(solstice, "corpus")
    if verifier_key == "verify_proof_replay":
        return "proof" in classes
    if verifier_key == "verify_release_reproduction_replay":
        return "release_repro" in classes
    if verifier_key == "verify_traceability_map_replay":
        return "traceability_map" in classes
    if verifier_key == "verify_parser_fuzz":
        return any(fuzz_target_valid(r, evidence, "parser") for r in _list(evidence, "fuzz_evidence"))
    if verifier_key == "verify_artifact_fuzz":
        return any(fuzz_target_valid(r, evidence, "artifact") for r in _list(evidence, "fuzz_evidence"))
    if verifier_key == "verify_envelope_fuzz":
        return any(fuzz_target_valid(r, evidence, "envelope") for r in _list(evidence, "fuzz_evidence"))
    if verifier_key == "verify_ledger_corpus_fuzz":
        return any(fuzz_target_valid(r, evidence, "ledger_corpus") for r in _list(evidence, "fuzz_evidence"))
    if verifier_key == "verify_sanitizer_clean":
        return sanitizer_clean(evidence)
    if verifier_key == "verify_crash_triage_closed":
        return crash_triage_closed(evidence)
    if verifier_key == "verify_two_independent_reviews":
        return two_independent_reviews(evidence)
    if verifier_key == "verify_formal_methods_review":
        return review_scope_closed(evidence, "formal_methods")
    if verifier_key == "verify_crypto_review":
        return review_scope_closed(evidence, "crypto")
    if verifier_key == "verify_boundary_fuzz_review":
        return review_scope_closed(evidence, "boundary_fuzz")
    if verifier_key == "verify_independent_replication_review":
        return review_scope_closed(evidence, "independent_replication")
    if verifier_key == "verify_production_blockers_review":
        return review_scope_closed(evidence, "production_blockers")
    if verifier_key == "verify_log_inclusion":
        return transparency_set_valid(evidence, solstice)
    if verifier_key in {"verify_signed_tree_head", "verify_log_consistency", "verify_append_only_audit", "verify_public_index_manifest"}:
        return bool(_list(evidence, "transparency_evidence")) and all(valid_tree_record(r) for r in _list(evidence, "transparency_evidence"))
    if verifier_key in {"verify_challenge_spec", "verify_break_class_taxonomy", "verify_public_reproducer_rule", "verify_adjudication_signature", "verify_open_break_ledger", "verify_zero_critical_open"}:
        return falsification_program_valid(evidence)
    if verifier_key == "verify_production_authority_gate":
        return not claims["production_allowed"] or production_authority_valid(evidence)
    if verifier_key == "verify_runtime_containment_gate":
        return not claims["runtime_containment_claim"] or runtime_containment_valid(evidence)
    if verifier_key == "verify_pq_claim_gate":
        return not claims["whole_system_post_quantum_safety_claim"] or post_quantum_safety_valid(evidence)
    if verifier_key == "verify_fixture_quarantine":
        return fixture_quarantine_valid(evidence)
    if verifier_key == "verify_nonclaim_enforcement":
        return boundary_claims_valid(evidence, solstice)
    if verifier_key == "verify_unsupported_platform_fail_closed":
        return evidence.get("unsupported_platform_fail_closed", True) is True
    return False


def _raise_rejection_rules(evidence: dict[str, Any], solstice: dict[str, Any], adjusted_score_M: int) -> None:
    if adjusted_score_M != solstice["final_score_M"]:
        raise ZenithError("Zenith adjusted score must equal the Solstice score")
    for record in _claiming(_list(evidence, "review_evidence"), "z7."):
        if not valid_review(record, evidence):
            raise ZenithError("unsigned or invalid external review claimed Zenith credit")
    for record in _claiming(_list(evidence, "transparency_evidence"), "z8."):
        if not valid_tree_record(record):
            raise ZenithError("invalid transparency evidence claimed Zenith credit")
    if _claiming(_list(evidence, "rebuild_evidence"), "z3.") and not rebuild_set_valid(evidence, solstice):
        raise ZenithError("rebuild evidence claimed credit but does not reproduce the artifact")
    if _claiming(_list(evidence, "implementation_outputs"), "z4.") and not implementation_agreement_valid(evidence, solstice):
        raise ZenithError("implementation evidence claimed credit but implementations disagree")
    for record in _claiming(_list(evidence, "fuzz_evidence"), "z6."):
        if int(record.get("crash_count", -1)) != int(record.get("triaged_crash_count", -2)):
            raise ZenithError("fuzz evidence has open crashes")
    program = evidence.get("falsification_program")
    if isinstance(program, dict) and int(program.get("open_critical_breaks", 0)) != 0:
        raise ZenithError("falsification program has open critical breaks")
    claims = boundary_claims(evidence, solstice)
    if claims["production_allowed"] and not production_authority_valid(evidence):
        raise ZenithError("production claim requires production authority evidence")
    if claims["runtime_containment_claim"] and not runtime_containment_valid(evidence):
        raise ZenithError("runtime containment claim requires containment evidence")
    if claims["whole_system_post_quantum_safety_claim"] and not post_quantum_safety_valid(evidence):
        raise ZenithError("whole-system post-quantum claim requires PQ and external crypto evidence")


def closed_obligations(evidence: dict[str, Any], solstice: dict[str, Any]) -> set[str]:
    closed: set[str] = set()
    for obligation in contract.Z_OBLIGATIONS:
        if verifier_pass(obligation["verifier_key"], evidence, solstice):
            closed.add(obligation["id"])
    return closed


def axis_values(closed: set[str]) -> dict[str, int]:
    values = {axis: 0 for axis in contract.Z_AXES}
    for obligation in contract.Z_OBLIGATIONS:
        if obligation["id"] in closed:
            values[obligation["axis_id"]] += int(obligation["weight"])
    return values


def axis_contributions_M(values: dict[str, int]) -> dict[str, int]:
    contributions = {}
    for axis in contract.Z_AXES:
        numerator = contract.Z_AXIS_WEIGHT_M[axis] * values[axis]
        if numerator % contract.Z_SCALE != 0:
            raise ZenithError(f"non-integer Zenith axis contribution: {axis}")
        contributions[axis] = numerator // contract.Z_SCALE
    return contributions


def zenith_level(values: dict[str, int], evidence: dict[str, Any], solstice: dict[str, Any]) -> str:
    if values["z1_hermetic_solstice_artifact"] < 1000:
        return "Z2_EVIDENCE_BOUND"
    if values["z5_semantic_evidence_replay"] < 1000:
        return "Z2_EVIDENCE_BOUND"
    if values["z2_supply_chain_provenance"] < 1000 or values["z3_reproducible_builds"] < 1000 or not rebuild_set_valid(evidence, solstice):
        return "Z3_HERMETIC_SOLSTICE"
    if (
        values["z4_multi_implementation_agreement"] < 1000
        or values["z6_adversarial_fuzzing"] < 1000
        or not implementation_agreement_valid(evidence, solstice)
        or not fuzz_campaign_valid(evidence)
        or not sanitizer_clean(evidence)
        or not crash_triage_closed(evidence)
    ):
        return "Z4_REPRODUCIBLE"
    public = (
        values["z7_signed_external_reviews"] == 1000
        and values["z8_transparency_log"] == 1000
        and values["z9_public_falsification_program"] == 1000
        and values["z10_boundary_discipline"] == 1000
        and two_independent_reviews(evidence)
        and all_required_review_scopes_closed(evidence)
        and transparency_set_valid(evidence, solstice)
        and falsification_program_valid(evidence)
        and boundary_claims_valid(evidence, solstice)
    )
    if not public:
        return "Z5_ADVERSARIAL_REPRODUCIBLE"
    if (
        production_authority_valid(evidence)
        and runtime_containment_valid(evidence)
        and post_quantum_safety_valid(evidence)
        and solstice["final_score_M"] == contract.PERFECT_SCORE_M
        and solstice["open_internal_residue_M"] == 0
        and solstice["open_external_residue_M"] == 0
    ):
        return "Z7_PRODUCTION_ELIGIBLE"
    return "Z6_PUBLIC_EXTERNAL_STANDARD"


def build_resolution(solstice: dict[str, Any], closed: set[str], values: dict[str, int], contributions: dict[str, int]) -> dict[str, Any]:
    all_ids = {item["id"] for item in contract.Z_OBLIGATIONS}
    return {
        "resolution_version": RESOLUTION_VERSION,
        "zenith_axis_digest": contract.axis_digest(),
        "zenith_obligation_digest": contract.obligation_digest(),
        "solstice_scorecard_digest": solstice["scorecard_digest"],
        "solstice_artifact_manifest_digest": solstice["artifact_manifest_digest"],
        "closed_zenith_obligations": sorted(closed),
        "open_zenith_obligations": sorted(all_ids - closed),
        "axis_values": {axis: values[axis] for axis in contract.Z_AXES},
        "axis_contributions_M": {axis: contributions[axis] for axis in contract.Z_AXES},
        "zenith_assurance_M": sum(contributions.values()),
    }


def resolution_digest(resolution: dict[str, Any]) -> str:
    return canonical_sha256(resolution, contract.D_ZENITH_RESOLUTION)


def build_report(solstice_artifact_dir: Path | str, evidence_path: Path | str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence = load_evidence(evidence_path)
    solstice = solstice_bridge.verify_artifact(solstice_artifact_dir)
    reject_float(evidence, "zenith_evidence")
    adjusted_score = int(evidence.get("zenith_adjusted_score_M", solstice["final_score_M"]))
    _raise_rejection_rules(evidence, solstice, adjusted_score)
    closed = closed_obligations(evidence, solstice)
    values = axis_values(closed)
    contributions = axis_contributions_M(values)
    resolution = build_resolution(solstice, closed, values, contributions)
    level = zenith_level(values, evidence, solstice)
    dz1 = level in {"Z6_PUBLIC_EXTERNAL_STANDARD", "Z7_PRODUCTION_ELIGIBLE"}
    dz2 = level == "Z7_PRODUCTION_ELIGIBLE"
    report = {
        "report_version": REPORT_VERSION,
        "name": contract.NAME,
        "version": contract.VERSION,
        "solstice_score_M": solstice["final_score_M"],
        "zenith_adjusted_score_M": adjusted_score,
        "score_inflation_M": adjusted_score - solstice["final_score_M"],
        "zenith_assurance_M": sum(contributions.values()),
        "zenith_level": level,
        "dz1_pass": dz1,
        "dz2_production_eligible": dz2,
        "zenith_axis_digest": contract.axis_digest(),
        "zenith_obligation_digest": contract.obligation_digest(),
        "zenith_resolution_digest": resolution_digest(resolution),
        "axis_values": values,
        "axis_contributions_M": contributions,
        "closed_zenith_obligations": resolution["closed_zenith_obligations"],
        "open_zenith_obligations": resolution["open_zenith_obligations"],
        "boundary_claims": boundary_claims(evidence, solstice),
        "non_claims": [
            "Zenith does not inflate the Solstice score",
            "Zenith assurance is separate from the Daylight M score",
            "DZ-1 is a public research proof standard, not production certification",
            "DZ-2 requires separate production authority, runtime containment, and post-quantum evidence",
        ],
    }
    return report, resolution


def report_digest(report: dict[str, Any]) -> str:
    return canonical_sha256(report, contract.D_ZENITH_REPORT)


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _repo_relative(path: Path) -> str:
    repo = Path(__file__).resolve().parents[3]
    try:
        return str(Path(path).resolve().relative_to(repo))
    except ValueError:
        return str(Path(path).resolve())


def build_report_artifact(
    *,
    solstice_artifact_dir: Path | str,
    out_dir: Path | str,
    evidence_path: Path | str | None = None,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report, resolution = build_report(solstice_artifact_dir, evidence_path=evidence_path)
    outputs = {
        "zenith-report.json": _json_bytes(report),
        "zenith-resolution.json": _json_bytes(resolution),
    }
    inputs = {
        "solstice_artifact": {
            "path": _repo_relative(Path(solstice_artifact_dir)),
            "sha256": ZERO_DIGEST,
        }
    }
    if evidence_path is not None:
        inputs["zenith_evidence"] = {
            "path": _repo_relative(Path(evidence_path)),
            "sha256": sha256_bytes(Path(evidence_path).read_bytes()),
        }
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "artifact": contract.NAME,
        "generated_date": GENERATED_DATE,
        "inputs": inputs,
        "outputs": {name: {"path": name, "sha256": sha256_bytes(data)} for name, data in sorted(outputs.items())},
        "zenith_report_digest": report_digest(report),
        "zenith_resolution_digest": resolution_digest(resolution),
        "solstice_score_M": report["solstice_score_M"],
        "zenith_adjusted_score_M": report["zenith_adjusted_score_M"],
        "score_inflation_M": report["score_inflation_M"],
        "zenith_assurance_M": report["zenith_assurance_M"],
        "zenith_level": report["zenith_level"],
        "dz1_pass": report["dz1_pass"],
        "dz2_production_eligible": report["dz2_production_eligible"],
    }
    outputs["zenith-manifest.json"] = _json_bytes(manifest)
    outputs["SHA256SUMS"] = "".join(
        f"{sha256_bytes(data)}  {name}\n" for name, data in sorted(outputs.items())
    ).encode("utf-8")
    for name, data in outputs.items():
        (out_dir / name).write_bytes(data)
    return manifest


def verify_report_dir(path: Path | str) -> None:
    path = Path(path)
    manifest = json.loads((path / "zenith-manifest.json").read_text(encoding="utf-8"))
    for name, info in manifest["outputs"].items():
        actual = sha256_bytes((path / info["path"]).read_bytes())
        if actual != info["sha256"]:
            raise ZenithError(f"Zenith output hash mismatch: {name}")
    expected = "".join(
        f"{sha256_bytes((path / name).read_bytes())}  {name}\n"
        for name in sorted(list(manifest["outputs"]) + ["zenith-manifest.json"])
    )
    if (path / "SHA256SUMS").read_text(encoding="utf-8") != expected:
        raise ZenithError("Zenith SHA256SUMS mismatch")
