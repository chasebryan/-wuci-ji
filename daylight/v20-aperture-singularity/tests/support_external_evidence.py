"""Shared builders for external-evidence intake tests.

These helpers construct internally consistent bundles (statement digests,
binding digests, and bundle digests all recompute) so each test can break
exactly one property and assert the matching rejection. They are test-only
material and are never committed reviewer evidence.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from src import ed25519_verify
from src import external_evidence
from src import firewall_profile
from src import verifier_quorum
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]
CAPSULE_PATH = ROOT / "examples/aperture-singularity-capsule.fixture.v20.json"
APERTURE_PATH = ROOT / "examples/input-aperture-capsule.source-snapshot.v19.json"
_TEST_PUBLIC_KEYS_BY_DIGEST: dict[str, bytes] = {}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def key_material_for_signer(signer: str) -> bytes:
    return public_key_bytes_for_signer(signer)


def ed25519_dependency_available() -> bool:
    return True


def _seed_for_signer(signer: str) -> bytes:
    return hashlib.sha256(f"DAYLIGHT-v20-test-ed25519-seed:{signer}".encode("utf-8")).digest()


def _expanded_secret(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    return int.from_bytes(scalar_bytes, "little"), digest[32:]


def public_key_bytes_for_signer(signer: str) -> bytes:
    scalar, _prefix = _expanded_secret(_seed_for_signer(signer))
    public_key_bytes = ed25519_verify._encode_point(ed25519_verify._scalar_mult(scalar, ed25519_verify._BASE_POINT))
    _TEST_PUBLIC_KEYS_BY_DIGEST[hashlib.sha256(public_key_bytes).hexdigest()] = public_key_bytes
    return public_key_bytes


def signature_bytes_for_signer(signer: str, statement_bytes: bytes) -> bytes:
    scalar, prefix = _expanded_secret(_seed_for_signer(signer))
    public_key = public_key_bytes_for_signer(signer)
    r = ed25519_verify._hash_to_scalar(prefix, statement_bytes)
    encoded_r = ed25519_verify._encode_point(ed25519_verify._scalar_mult(r, ed25519_verify._BASE_POINT))
    k = ed25519_verify._hash_to_scalar(encoded_r, public_key, statement_bytes)
    s = (r + k * scalar) % ed25519_verify._L
    return encoded_r + s.to_bytes(32, "little")


def public_key_bytes_for_digest(public_key_digest: str, signer: str) -> bytes:
    return _TEST_PUBLIC_KEYS_BY_DIGEST.get(public_key_digest, public_key_bytes_for_signer(signer))


def load_capsule() -> dict[str, Any]:
    return load_json_no_floats(CAPSULE_PATH)


def load_aperture() -> dict[str, Any]:
    return load_json_no_floats(APERTURE_PATH)


def load_registry() -> dict[str, Any]:
    return load_json_no_floats(external_evidence.PINNED_MATERIAL_PATH)


def has_blocker(report: dict[str, Any], needle: str) -> bool:
    return any(needle in blocker for blocker in report.get("blockers", []))


def build_subject(capsule: dict[str, Any], aperture: dict[str, Any], **over: Any) -> dict[str, Any]:
    subject = {
        "release_tag": capsule["release_tag"],
        "source_commit": capsule["source_commit"],
        "artifact_sha256": aperture["subject_sha256"],
        "artifact_sha3_512": aperture["subject_sha3_512"],
        "artifact_size": aperture["subject_size"],
        "aperture_capsule_digest": capsule["capsule_digest"],
        "score_ceiling_report_digest": external_evidence.score_ceiling_report_digest(capsule),
    }
    subject.update(over)
    return subject


def build_receipt(subject: dict[str, Any], n: int, **over: Any) -> dict[str, Any]:
    receipt = {
        "receipt_id": f"test-rebuild-{n}",
        "builder_identity": f"test-rebuilder-{n}.example.org",
        "builder_independence_class": "external",
        "builder_contact_optional": None,
        "source_commit": subject["source_commit"],
        "release_tag": subject["release_tag"],
        "build_instructions_digest": sha256_text("test build instructions"),
        "environment_digest": sha256_text(f"test build environment {n}"),
        "artifact_sha256": subject["artifact_sha256"],
        "artifact_sha3_512": subject["artifact_sha3_512"],
        "artifact_size": subject["artifact_size"],
        "byte_reproducible": True,
        "fixture": False,
        "claim_usable": True,
    }
    receipt.update(over)
    return receipt


def build_review(n: int = 1, **over: Any) -> dict[str, Any]:
    review = {
        "review_id": f"test-firewall-review-{n}",
        "reviewer_identity": f"test-firewall-reviewer-{n}.example.org",
        "reviewer_independence_class": "external",
        "review_scope": external_evidence.FIREWALL_REVIEW_SCOPE,
        "profile_digest": firewall_profile.profile_digest(),
        "reviewed_rules_digest": external_evidence.firewall_rules_digest(),
        "negative_cases_digest": external_evidence.firewall_negative_cases_digest(),
        "finding_level": "none",
        "fixture": False,
        "claim_usable": True,
    }
    review.update(over)
    return review


def build_vector(
    subject: dict[str, Any],
    n: int,
    family: str,
    canonical_output_digest_value: str,
    **over: Any,
) -> dict[str, Any]:
    vector = {
        "vector_id": f"test-vector-{n}",
        "verifier_family": family,
        "verifier_family_independence_class": "external",
        "verifier_implementation_digest": sha256_text(f"test verifier implementation {family}"),
        "verifier_implementation_kind": "source-tree",
        "input_capsule_digest": subject["aperture_capsule_digest"],
        "canonical_output_schema_id": verifier_quorum.CANONICAL_OUTPUT_SCHEMA_ID,
        "canonical_output_digest": canonical_output_digest_value,
        "output_digest": canonical_output_digest_value,
        "decision": "pass",
        "fixture": False,
        "claim_usable": True,
    }
    vector.update(over)
    return vector


def attest(
    item: dict[str, Any],
    binding_digest: str,
    attestation_id: str,
    signer: str,
    **over: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    overrides = dict(over)
    signature_override = overrides.pop("signature", None)
    statement_digest_override = overrides.pop("statement_digest", None)
    signer_identity = overrides.get("signer_identity", signer)
    public_key_bytes = public_key_bytes_for_signer(signer_identity)
    public_key_digest = hashlib.sha256(public_key_bytes).hexdigest()
    attestation = {
        "attestation_id": attestation_id,
        "subject_digest": binding_digest,
        "signer_identity": signer_identity,
        "signer_independence_class": "external",
        "signature_algorithm": "ed25519",
        "public_key_digest": public_key_digest,
        "verification_material_ref": external_evidence.PINNED_MATERIAL_REF,
        "fixture": item.get("fixture", False),
        "claim_usable": item.get("claim_usable", True),
    }
    attestation.update(overrides)
    attestation["statement_digest"] = external_evidence.attestation_statement_digest(attestation)
    signature = signature_bytes_for_signer(attestation["signer_identity"], external_evidence.attestation_statement_bytes(attestation))
    attestation["signature"] = base64.b64encode(signature).decode()
    if signature_override is not None:
        attestation["signature"] = signature_override
    if statement_digest_override is not None:
        attestation["statement_digest"] = statement_digest_override
    bound = dict(item)
    bound["attestation_ref"] = attestation_id
    return bound, attestation


def assemble(
    subject: dict[str, Any],
    receipts: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    vectors: list[dict[str, Any]],
    extra_attestations: list[dict[str, Any]] | None = None,
    attestation_over: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attestation_over = attestation_over or {}
    bound_receipts: list[dict[str, Any]] = []
    bound_reviews: list[dict[str, Any]] = []
    bound_vectors: list[dict[str, Any]] = []
    attestations: list[dict[str, Any]] = []
    for n, item in enumerate(receipts, start=1):
        bound, attestation = attest(
            item,
            external_evidence.rebuild_receipt_binding_digest(item),
            f"test-att-rebuild-{n}",
            item["builder_identity"],
            **attestation_over,
        )
        bound_receipts.append(bound)
        attestations.append(attestation)
    for n, item in enumerate(reviews, start=1):
        bound, attestation = attest(
            item,
            external_evidence.firewall_review_binding_digest(item),
            f"test-att-review-{n}",
            item["reviewer_identity"],
            **attestation_over,
        )
        bound_reviews.append(bound)
        attestations.append(attestation)
    for n, item in enumerate(vectors, start=1):
        bound, attestation = attest(
            item,
            external_evidence.verifier_vector_binding_digest(item),
            f"test-att-vector-{n}",
            f"test-verifier-{n}.example.org",
            **attestation_over,
        )
        bound_vectors.append(bound)
        attestations.append(attestation)
    attestations.extend(extra_attestations or [])
    body = {
        "schema_id": external_evidence.SCHEMA_ID,
        "schema_version": external_evidence.SCHEMA_VERSION,
        "subject": subject,
        "independent_rebuild_receipts": bound_receipts,
        "firewall_profile_reviews": bound_reviews,
        "claim_usable_verifier_vectors": bound_vectors,
        "pinned_attestations": attestations,
    }
    body["bundle_digest"] = external_evidence.bundle_digest(body)
    return body


def full_bundle(
    capsule: dict[str, Any] | None = None,
    aperture: dict[str, Any] | None = None,
    subject_over: dict[str, Any] | None = None,
    receipt_overs: list[dict[str, Any]] | None = None,
    review_overs: list[dict[str, Any]] | None = None,
    vector_overs: list[dict[str, Any]] | None = None,
    attestation_over: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build (bundle, capsule, aperture) with two receipts, one review, three vectors."""
    capsule = capsule if capsule is not None else load_capsule()
    aperture = aperture if aperture is not None else load_aperture()
    subject = build_subject(capsule, aperture, **(subject_over or {}))
    receipt_overs = receipt_overs if receipt_overs is not None else [{}, {}]
    review_overs = review_overs if review_overs is not None else [{}]
    vector_overs = vector_overs if vector_overs is not None else [{}, {}, {}]
    families = ["alpha-independent", "beta-independent", "gamma-independent", "delta-independent"]
    output_digest = verifier_quorum.canonical_output_digest(verifier_quorum.build_canonical_output(capsule, aperture))
    receipts = [build_receipt(subject, n + 1, **over) for n, over in enumerate(receipt_overs)]
    reviews = [build_review(n + 1, **over) for n, over in enumerate(review_overs)]
    vectors = [
        build_vector(subject, n + 1, families[n % len(families)], output_digest, **over)
        for n, over in enumerate(vector_overs)
    ]
    bundle = assemble(subject, receipts, reviews, vectors, attestation_over=attestation_over)
    return bundle, capsule, aperture


def pin_registry_for(bundle: dict[str, Any]) -> dict[str, Any]:
    """Build a registry pinning every attestation key in the bundle."""
    registry = load_registry()
    signers = []
    seen: set[str] = set()
    for attestation in bundle["pinned_attestations"]:
        if attestation["public_key_digest"] in seen:
            continue
        seen.add(attestation["public_key_digest"])
        signers.append(
            {
                "signer_identity": attestation["signer_identity"],
                "signer_independence_class": "external",
                "signature_algorithm": attestation["signature_algorithm"],
                "public_key_digest": attestation["public_key_digest"],
                "public_key_b64": base64.b64encode(
                    public_key_bytes_for_digest(attestation["public_key_digest"], attestation["signer_identity"])
                ).decode(),
                "pinned_by_commit": sha256_text("test pin commit")[:40],
            }
        )
    registry["pinned_signers"] = signers
    return registry


def evaluate(
    bundle: dict[str, Any],
    capsule: dict[str, Any] | None,
    aperture: dict[str, Any] | None,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return external_evidence.evaluate_bundle(
        bundle,
        pinned_material=registry if registry is not None else load_registry(),
        capsule=capsule,
        aperture_capsule=aperture,
    )


def reseal(bundle: dict[str, Any]) -> dict[str, Any]:
    """Recompute the bundle digest after a mutation (manifest regeneration)."""
    bundle["bundle_digest"] = external_evidence.bundle_digest(bundle)
    return bundle


def has_blocker(report: dict[str, Any], needle: str) -> bool:
    return any(needle in item for item in report["blockers"])
