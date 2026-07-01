from __future__ import annotations

import copy
import hashlib
from typing import Any

from src.auth import make_recipient_public_key
from src.evidence import EVIDENCE_CONTEXT_VERSION, PROOF_MASS_DOMAIN
from src.hashing import domain_hash
from src.policy import POLICY_VERSION


def digest(label: str) -> str:
    return hashlib.sha3_512(label.encode("utf-8")).hexdigest()


def proof_mass_statement() -> dict[str, Any]:
    return {
        "baseline": 500_000,
        "regression_debt": 0,
        "staleness_debt": 0,
        "units": [
            {"id": "u.solstice.scorecard", "base_credit": 500_000, "closed": True},
            {"id": "u.analemma.registry", "base_credit": 120_000, "closed": True},
            {"id": "u.future.audit", "base_credit": 80_000, "closed": False},
        ],
    }


def base_context() -> dict[str, Any]:
    statement = proof_mass_statement()
    proof_mass = 620_000
    return {
        "version": EVIDENCE_CONTEXT_VERSION,
        "daylight_claim_score_M": 998_900,
        "analemma_score_A": 1_240_000,
        "proof_mass": proof_mass,
        "proof_mass_baseline": statement["baseline"],
        "proof_mass_digest": domain_hash(PROOF_MASS_DOMAIN, statement),
        "solstice_scorecard_digest": digest("solstice-scorecard"),
        "solstice_artifact_manifest_digest": digest("solstice-artifact-manifest"),
        "analemma_registry_digest": digest("analemma-registry"),
        "zenith_report_digest": digest("zenith-report"),
        "claim_level": "research",
        "production_allowed": False,
        "runtime_containment_claim": False,
        "whole_system_post_quantum_safety_claim": False,
        "external_certification_claim": False,
        "score_inflation_M": 0,
    }


def evidence_artifact() -> dict[str, Any]:
    return {
        "version": "daylight-v16-evidence-artifact-v0.1",
        "context": base_context(),
        "proof_mass_statement": proof_mass_statement(),
        "closed_obligations": [
            "o.solstice.scorecard",
            "o.analemma.registry",
        ],
        "closed_proof_units": [
            "u.solstice.scorecard",
            "u.analemma.registry",
        ],
    }


def base_policy() -> dict[str, Any]:
    return {
        "version": POLICY_VERSION,
        "min_daylight_claim_score_M": 900_000,
        "min_analemma_score_A": 1_000_000,
        "required_claim_level": "research",
        "require_production_allowed": False,
        "require_runtime_containment": False,
        "require_whole_system_pq_safety": False,
        "require_external_certification": False,
        "required_solstice_scorecard_digest": digest("solstice-scorecard"),
        "required_artifact_manifest_digest": digest("solstice-artifact-manifest"),
        "required_analemma_registry_digest": digest("analemma-registry"),
        "required_closed_obligations": [
            "o.solstice.scorecard",
            "o.analemma.registry",
        ],
        "required_proof_units": [
            "u.solstice.scorecard",
            "u.analemma.registry",
        ],
        "require_sender_signature": False,
        "require_backup_signature": False,
        "critical": True,
    }


def recipient() -> dict[str, Any]:
    return make_recipient_public_key(b"mlkem-public-key-fixture", b"dhkem-p384-public-key-fixture")


def kem_material() -> dict[str, str]:
    return {
        "mlkem_ct": b"mlkem-ciphertext-fixture".hex(),
        "dh_ct": b"dhkem-ciphertext-fixture".hex(),
        "ss_mlkem": hashlib.sha3_512(b"mlkem shared secret").digest().hex(),
        "ss_dh": hashlib.sha3_512(b"dh shared secret").digest().hex(),
    }


def clone(value: Any) -> Any:
    return copy.deepcopy(value)
