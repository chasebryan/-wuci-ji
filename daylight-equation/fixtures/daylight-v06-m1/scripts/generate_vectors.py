#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daylight_m1 import *  # noqa: F401,F403


def write_raw_vector(root: Path, vector_id: str, omega_bytes: bytes, expected_stage: str, private_kem_allowed: bool = False, aead_dec_allowed: bool = False, mutation=None):
    d = root / vector_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "omega.cbor.hex").write_text(omega_bytes.hex() + "\n")
    (d / "secrets.json").write_text(json.dumps({k: v.hex() for k, v in {"dk_Q": default_fixture_material()["dk_q"], "sk_C": default_fixture_material()["sk_c"]}.items()}, indent=2, sort_keys=True) + "\n")
    manifest = {
        "vector_id": vector_id,
        "conformance_level": "C1-OPEN-fixture",
        "expected_result": "bottom",
        "expected_rejection_stage": expected_stage,
        "private_kem_allowed": private_kem_allowed,
        "aead_dec_allowed": aead_dec_allowed,
        "public_files": ["omega.cbor.hex"],
        "secret_files": ["secrets.json"],
        "mutation": mutation or {"mutation_name": vector_id},
        "warning": "Fixture crypto only. Not ML-KEM/ML-DSA/SLH-DSA production cryptography.",
    }
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def good_artifact(label: str) -> bytes:
    return f"Daylight v0.6 M1 fixture artifact: {label}".encode("utf-8")


def patch_policy(env, patch_fn):
    env = copy.deepcopy(env)
    policy = env[ENV_AUX_BLOCK][0]
    patch_fn(policy)
    env[ENV_HEADER][10] = hc(policy)
    rebuild_auth_block(env)
    return env


def main():
    vectors = ROOT / "vectors"
    if vectors.exists():
        shutil.rmtree(vectors)
    (vectors / "valid").mkdir(parents=True)
    (vectors / "negative").mkdir(parents=True)

    valid_specs = [
        ("V1_metadata_only_open", dict(content_scope=CONTENT_METADATA_ONLY, aead_id=AEAD_AES_256_GCM, r=1, mu=MU_HYBRID, action=ACTION_OPEN)),
        ("V2_public_commitment_open", dict(content_scope=CONTENT_PUBLIC_COMMITMENT, aead_id=AEAD_AES_256_GCM, r=1, mu=MU_HYBRID, action=ACTION_OPEN)),
        ("V3_reviewed_content_open", dict(content_scope=CONTENT_REVIEWED_CONTENT, aead_id=AEAD_AES_256_GCM, r=1, mu=MU_HYBRID, action=ACTION_OPEN)),
        ("V4_pq_strict_open", dict(content_scope=CONTENT_METADATA_ONLY, aead_id=AEAD_AES_256_GCM, r=2, mu=MU_PQ_STRICT, action=ACTION_OPEN)),
        ("V5_chacha20_open", dict(content_scope=CONTENT_METADATA_ONLY, aead_id=AEAD_CHACHA20_POLY1305, r=1, mu=MU_HYBRID, action=ACTION_OPEN)),
    ]
    base_env = None
    base_secrets = None
    base_trace = None
    for vector_id, kwargs in valid_specs:
        env, secrets, trace = seal_fixture(vector_id, good_artifact(vector_id), **kwargs)
        write_vector_dir(vectors / "valid", vector_id, env, secrets, trace, "artifact", None, True, True)
        if vector_id == "V1_metadata_only_open":
            base_env, base_secrets, base_trace = env, secrets, trace

    assert base_env is not None

    # Parser/schema negatives
    parser_mutations = [
        ("N1_noncanonical_cbor", "noncanonical_cbor", RejectStage.REJECT_PARSE.value),
        ("N2_duplicate_map_key", "duplicate_map_key", RejectStage.REJECT_PARSE.value),
        ("N3_unknown_envelope_key", "unknown_envelope_key", RejectStage.REJECT_SCHEMA.value),
        ("N4_unknown_header_key", "unknown_header_key", RejectStage.REJECT_SCHEMA.value),
        ("N5_wrong_field_type", "wrong_field_type", RejectStage.REJECT_SCHEMA.value),
        ("N6_wrong_enum_value", "wrong_enum_value", RejectStage.REJECT_SUITE.value),
        ("N7_unsorted_roster", "unsorted_roster", RejectStage.REJECT_POLICY.value),
        ("N8_unsorted_policy_array", "unsorted_policy_array", RejectStage.REJECT_POLICY.value),
    ]
    for vector_id, mut, stage in parser_mutations:
        omega, env_obj, has_obj = apply_mutation(base_env, mut)
        if has_obj:
            write_vector_dir(vectors / "negative", vector_id, env_obj, base_secrets, base_trace, "bottom", stage, False, False, {"mutation_name": mut})
        else:
            write_raw_vector(vectors / "negative", vector_id, omega, stage, False, False, {"mutation_name": mut})

    # Public precheck negatives
    public_cases = []

    env = copy.deepcopy(base_env)
    env[ENV_HEADER][1] = b"\x00" * 64
    public_cases.append(("N9_bad_suite_id", env, RejectStage.REJECT_SUITE.value, "bad_suite_id"))

    env = copy.deepcopy(base_env)
    env[ENV_HEADER][10] = b"\x00" * 64
    public_cases.append(("N10_bad_policy_hash", env, RejectStage.REJECT_AUX_HASH.value, "bad_policy_hash"))

    env = copy.deepcopy(base_env)
    env[ENV_HEADER][11] = b"\x00" * 64
    public_cases.append(("N11_bad_keyset_hash", env, RejectStage.REJECT_AUX_HASH.value, "bad_keyset_hash"))

    env = copy.deepcopy(base_env)
    env[ENV_HEADER][15] = b"\x00" * 64
    public_cases.append(("N12_bad_claims_hash", env, RejectStage.REJECT_AUX_HASH.value, "bad_claims_hash"))

    env = copy.deepcopy(base_env)
    env[ENV_KEM_BLOCK][0] = b"\x01" * 64
    public_cases.append(("N13_bad_kem_key_id", env, RejectStage.REJECT_KEM_BLOCK.value, "bad_kem_key_id"))

    env = copy.deepcopy(base_env)
    env[ENV_AUTH_BLOCK][0] = {0: b"not-array"}
    public_cases.append(("N14_bad_auth_block_shape", env, RejectStage.REJECT_AUTH_BLOCK.value, "bad_auth_block_shape"))

    env = copy.deepcopy(base_env)
    env[ENV_AUTH_BLOCK][0][0][1] = b"bad-signature"
    public_cases.append(("N15_bad_ml_dsa_signature", env, RejectStage.REJECT_AUTH_SIGNATURE.value, "bad_ml_dsa_signature"))

    env = copy.deepcopy(base_env)
    env[ENV_AUX_BLOCK][1][8][0] = 2  # t_Q too high
    env[ENV_HEADER][11] = hc(env[ENV_AUX_BLOCK][1])
    env[ENV_AUX_BLOCK][0][5] = [env[ENV_HEADER][11]]
    env[ENV_HEADER][10] = hc(env[ENV_AUX_BLOCK][0])
    rebuild_auth_block(env)
    public_cases.append(("N16_insufficient_q_threshold", env, RejectStage.REJECT_AUTH_SIGNATURE.value, "insufficient_q_threshold"))

    env = copy.deepcopy(base_env)
    env[ENV_AUX_BLOCK][1][8][1] = 2  # u_Q too high
    env[ENV_HEADER][11] = hc(env[ENV_AUX_BLOCK][1])
    env[ENV_AUX_BLOCK][0][5] = [env[ENV_HEADER][11]]
    env[ENV_HEADER][10] = hc(env[ENV_AUX_BLOCK][0])
    rebuild_auth_block(env)
    public_cases.append(("N17_insufficient_domain_count", env, RejectStage.REJECT_AUTH_SIGNATURE.value, "insufficient_domain_count"))

    env, secrets, trace = seal_fixture("N18_bad_review_receipt", good_artifact("N18_bad_review_receipt"), content_scope=CONTENT_PUBLIC_COMMITMENT, review_receipt_override={0: b"fixture-reviewer-1", 1: b"\x00" * 64, 2: b"\x00" * 64})
    public_cases.append(("N18_bad_review_receipt", env, RejectStage.REJECT_REVIEW.value, "bad_review_receipt"))

    policy = copy.deepcopy(default_fixture_material()["policy"])
    policy[4][ACTION_OPEN] = [2, MU_HYBRID]
    env, secrets, trace = seal_fixture("N19_bad_downgrade", good_artifact("N19_bad_downgrade"), policy_override=policy, r=1, action=ACTION_OPEN)
    public_cases.append(("N19_bad_downgrade", env, RejectStage.REJECT_DOWNGRADE.value, "bad_downgrade"))

    policy = copy.deepcopy(default_fixture_material()["policy"])
    policy[9] = [ACTION_RELEASE]
    env, secrets, trace = seal_fixture("N20_missing_required_log", good_artifact("N20_missing_required_log"), policy_override=policy, r=2, action=ACTION_RELEASE)
    public_cases.append(("N20_missing_required_log", env, RejectStage.REJECT_LOG.value, "missing_required_log"))

    for vector_id, env, stage, mut in public_cases:
        write_vector_dir(vectors / "negative", vector_id, env, load_secrets_from_material(), base_trace, "bottom", stage, False, False, {"mutation_name": mut})

    # Private-open negatives.
    private_cases = []
    env = copy.deepcopy(base_env)
    encq = bytearray(env[ENV_KEM_BLOCK][2])
    encq[0] ^= 1
    env[ENV_KEM_BLOCK][2] = bytes(encq)
    rebuild_auth_block(env)
    private_cases.append(("N21_bad_mlkem_ciphertext", env, RejectStage.REJECT_AEAD.value, "bad_mlkem_ciphertext"))

    env = copy.deepcopy(base_env)
    encc = bytearray(env[ENV_KEM_BLOCK][3])
    encc[0] ^= 1
    env[ENV_KEM_BLOCK][3] = bytes(encc)
    rebuild_auth_block(env)
    private_cases.append(("N22_bad_dhkem_encapsulation", env, RejectStage.REJECT_AEAD.value, "bad_dhkem_encapsulation"))

    env = copy.deepcopy(base_env)
    ct = bytearray(env[ENV_CIPHERTEXT])
    ct[-1] ^= 1
    env[ENV_CIPHERTEXT] = bytes(ct)
    rebuild_auth_block(env)
    private_cases.append(("N23_bad_aead_tag", env, RejectStage.REJECT_AEAD.value, "bad_aead_tag"))

    env, secrets, trace = seal_fixture("N24_bad_private_payload_encoding", good_artifact("N24_bad_private_payload_encoding"), private_payload_override=b"\xff")
    private_cases.append(("N24_bad_private_payload_encoding", env, RejectStage.REJECT_PAYLOAD.value, "bad_private_payload_encoding"))

    env = copy.deepcopy(base_env)
    env[ENV_COM_A] = b"\x00" * 32
    rebuild_auth_block(env)
    private_cases.append(("N25_bad_artifact_commitment", env, RejectStage.REJECT_COMMIT.value, "bad_artifact_commitment"))

    artifact = good_artifact("N26_bad_leak_value")
    env, secrets, trace = seal_fixture("N26_bad_leak_value", artifact, leak_value_override=len(artifact) + 1)
    private_cases.append(("N26_bad_leak_value", env, RejectStage.REJECT_LEAK.value, "bad_leak_value"))

    artifact = good_artifact("N27_bad_review_blind")
    wrong_blind = fixture_bytes("wrong.review.blind", 32)
    env, secrets, trace = seal_fixture(
        "N27_bad_review_blind",
        artifact,
        content_scope=CONTENT_REVIEWED_CONTENT,
        private_payload_override=dumps({0: artifact, 1: wrong_blind}),
    )
    private_cases.append(("N27_bad_review_blind", env, RejectStage.REJECT_LEAK.value, "bad_review_blind"))

    for vector_id, env, stage, mut in private_cases:
        # Trace may not exactly match for all mutated private cases; vector runner only needs expected artifact for valid vectors.
        write_vector_dir(vectors / "negative", vector_id, env, base_secrets, base_trace, "bottom", stage, True, True, {"mutation_name": mut})

    print(f"Wrote vectors to {vectors}")


def load_secrets_from_material():
    mat = default_fixture_material()
    return {"dk_Q": mat["dk_q"], "sk_C": mat["sk_c"]}


if __name__ == "__main__":
    main()
