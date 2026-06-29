#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import wuci_cage
import wuci_progress
import wuci_safeio


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "docs" / "wuci_qcage_policy.json"
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "build" / "wuci-witness-bundle"

POLICY_SCHEMA = "wuci-qcage-policy-v1"
DIGEST_VECTOR_SCHEMA = "wuci-qcage-digest-vector-v1"
CRYPTO_INVENTORY_SCHEMA = "wuci-qcage-crypto-inventory-v1"
BUILD_GRAPH_SCHEMA = "wuci-qcage-build-graph-v1"
ATTESTATION_SCHEMA = "wuci-qcage-attestation-v1"
RISK_SCHEMA = "wuci-qcage-risk-v1"
PROFILE = "WUCI-QCAGE-v1"
CLASSIC_AUTHORITY_PROFILE = "FROST-secp256k1-SHA256-v1"
CLASSIC_QUANTUM_STATUS = "quantum-vulnerable-under-crqc"
BOUNDARY_STATEMENT = (
    "Q CAGE v1 provides quantum-aware artifact evidence and downgrade resistance. "
    "It does not claim post-quantum security unless real PQ evidence is verified."
)
MODES = {"compat", "hybrid-required", "pq-required"}
PQ_SIGNATURE_TARGETS = {"ML-DSA", "SLH-DSA", "LMS", "XMSS"}
PQ_KEM_TARGETS = {"ML-KEM", "HQC"}
FUTURE_PQ_TARGETS = PQ_SIGNATURE_TARGETS | PQ_KEM_TARGETS
PUBLIC_EVIDENCE_FILES = {
    "artifact": "wuci-ji.self.wj",
    "manifest": "manifest.txt",
    "warrant_message": "warrant-message.txt",
    "release_receipt": "release-receipt.json",
    "receipt_contract": "receipt-contract.txt",
    "authority_root": "authority-root.txt",
    "release_decision": "release-decision.txt",
    "publish_index": "publish-index.txt",
}
REQUIRED_TOP_LEVEL_FILES = (
    "Makefile",
    "README.md",
    "AGENTS.md",
    "docs/wuci_gate_boundary.json",
    "docs/wuci_gate_receipt_contract.json",
)


class QCageError(RuntimeError):
    pass


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def read_bytes(path: Path, context: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise QCageError(f"could not read {context}: {path}") from exc


def load_json(path: Path, context: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise QCageError(f"could not read {context}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise QCageError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_json(path: Path, value: dict[str, Any], context: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise QCageError(f"could not write {context}: {path}") from exc


def write_text(path: Path, value: str, context: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise QCageError(f"could not write {context}: {path}") from exc


def digest_bytes(value: bytes, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    hasher.update(value)
    return hasher.hexdigest()


def digest_file(
    path: Path,
    algorithm: str,
    ticker_mode: str = "auto",
    label: str | None = None,
) -> str:
    try:
        return wuci_progress.digest_file(
            path,
            algorithm,
            f"QCAGE {algorithm} file",
            ticker_mode=ticker_mode,
            label=label or f"QCAGE {algorithm} {path.name}",
            reject_symlink=True,
        )
    except wuci_safeio.SafeIOError as exc:
        raise QCageError(f"could not hash file: {path}") from exc


def digest_vector_for_file(path: Path, ticker_mode: str = "auto") -> dict[str, Any]:
    return {
        "sha256": digest_file(path, "sha256", ticker_mode),
        "sha384": digest_file(path, "sha384", ticker_mode),
        "sha512": digest_file(path, "sha512", ticker_mode),
    }


def digest_vector_document(path: Path, ticker_mode: str = "auto") -> dict[str, Any]:
    return {
        "schema": DIGEST_VECTOR_SCHEMA,
        "path": path.name,
        **digest_vector_for_file(path, ticker_mode),
        "quantum_preimage_bits": {
            "sha256": quantum_preimage_bits(256),
            "sha384": quantum_preimage_bits(384),
            "sha512": quantum_preimage_bits(512),
        },
        "quantum_collision_bits": {
            "sha256": quantum_collision_bits(256),
            "sha384": quantum_collision_bits(384),
            "sha512": quantum_collision_bits(512),
        },
    }


def quantum_preimage_bits(bits: int) -> int:
    return bits // 2


def quantum_collision_bits(bits: int) -> int:
    return bits // 3


def quantum_migration_debt(t_migrate: int, t_trust: int, t_crqc: int) -> int:
    return max(0, t_migrate + t_trust - t_crqc)


def risk_recommendation(t_migrate: int, t_trust: int, t_crqc: int) -> str:
    if t_trust >= t_crqc:
        return "pq-required-for-long-lived-trust"
    if quantum_migration_debt(t_migrate, t_trust, t_crqc) > 0:
        return "hybrid-required"
    return "compat-acceptable-with-warning"


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise QCageError("QCAGE policy must be a JSON object")
    if policy.get("schema") != POLICY_SCHEMA:
        raise QCageError("QCAGE policy has unsupported schema")
    if policy.get("status") != "quantum-aware-artifact-airlock-v1":
        raise QCageError("QCAGE policy has unsupported status")
    modes = policy.get("modes")
    if not isinstance(modes, dict) or set(modes) != MODES:
        raise QCageError("QCAGE policy modes are not canonical")
    if modes["compat"].get("allow_quantum_safe_claim") is not False:
        raise QCageError("compat mode must not allow quantum_safe claims")
    if modes["hybrid-required"].get("require_pq_signature") is not True:
        raise QCageError("hybrid-required mode must require PQ signatures")
    if modes["pq-required"].get("require_pq_signature") is not True:
        raise QCageError("pq-required mode must require PQ signatures")
    digest_policy = policy.get("digest_policy")
    if not isinstance(digest_policy, dict):
        raise QCageError("QCAGE policy digest_policy must be an object")
    if digest_policy.get("require_digest_vector") != ["sha256", "sha384", "sha512"]:
        raise QCageError("QCAGE policy must require sha256/sha384/sha512")
    if digest_policy.get("minimum_quantum_collision_digest") != "sha384":
        raise QCageError("QCAGE policy minimum quantum collision digest must be sha384")
    if digest_policy.get("preferred_public_evidence_digest") != "sha512":
        raise QCageError("QCAGE policy preferred public evidence digest must be sha512")
    inventory = policy.get("algorithm_inventory")
    if not isinstance(inventory, dict):
        raise QCageError("QCAGE policy algorithm_inventory must be an object")
    for name in ("secp256k1", "x25519"):
        if name not in inventory.get("classical_vulnerable_public_key", []):
            raise QCageError(f"QCAGE policy must mark {name} quantum-vulnerable")
    for name in ("ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS"):
        targets = (
            inventory.get("post_quantum_signature_targets", [])
            + inventory.get("post_quantum_kem_targets", [])
        )
        if name not in targets:
            raise QCageError(f"QCAGE policy must list {name} as a target")
    rejections = set(policy.get("downgrade_rejections", []))
    for rejection in (
        "quantum_safe_true_without_pq_verification",
        "hybrid_required_without_pq_signature",
        "pq_required_with_classic_only_signature",
        "sha256_only_public_evidence",
        "pq_stub_marked_as_real",
        "external_pq_verifier_unpinned",
    ):
        if rejection not in rejections:
            raise QCageError(f"QCAGE policy missing downgrade rejection: {rejection}")
    runtime = policy.get("runtime_claims")
    if not isinstance(runtime, dict):
        raise QCageError("QCAGE policy runtime_claims must be an object")
    if runtime.get("runtime_sandbox_enforced_v1") is not False:
        raise QCageError("QCAGE v1 must not claim runtime sandbox enforcement")
    if runtime.get("quantum_safe_default_v1") is not False:
        raise QCageError("QCAGE v1 must not be quantum-safe by default")
    return policy


def load_policy() -> dict[str, Any]:
    return validate_policy(load_json(POLICY_PATH, "QCAGE policy"))


def crypto_inventory() -> dict[str, Any]:
    return {
        "schema": CRYPTO_INVENTORY_SCHEMA,
        "status": "declared-known-wuci-crypto-surfaces-v1",
        "entries": [
            {
                "algorithm": CLASSIC_AUTHORITY_PROFILE,
                "implemented": True,
                "quantum_status": CLASSIC_QUANTUM_STATUS,
                "replacement_target": "ML-DSA or SLH-DSA/LMS/XMSS hybrid evidence",
                "role": "current classical authorization",
            },
            {
                "algorithm": "secp256k1",
                "implemented": True,
                "quantum_status": CLASSIC_QUANTUM_STATUS,
                "role": "current elliptic curve primitive",
            },
            {
                "algorithm": "x25519",
                "implemented": True,
                "quantum_status": CLASSIC_QUANTUM_STATUS,
                "role": "current classical key-agreement primitive if present",
            },
            {
                "algorithm": "SHA-256",
                "implemented": True,
                "migration": "keep for compatibility, add SHA-384/SHA-512 evidence",
                "quantum_collision_bits": quantum_collision_bits(256),
                "quantum_preimage_bits": quantum_preimage_bits(256),
                "quantum_status": "compatibility-digest",
                "role": "current compatibility digest / assembly primitive",
            },
            {
                "algorithm": "SHA-384",
                "implemented": True,
                "quantum_collision_bits": quantum_collision_bits(384),
                "quantum_preimage_bits": quantum_preimage_bits(384),
                "quantum_status": "quantum-aware-digest",
                "role": "minimum quantum-aware public evidence digest",
            },
            {
                "algorithm": "SHA-512",
                "implemented": True,
                "quantum_collision_bits": quantum_collision_bits(512),
                "quantum_preimage_bits": quantum_preimage_bits(512),
                "quantum_status": "quantum-aware-digest",
                "role": "preferred high-assurance public evidence digest",
            },
            {
                "algorithm": "ChaCha20-Poly1305",
                "implemented": True,
                "note": (
                    "key transport must not depend on classical-only public-key "
                    "crypto for long-lived secrets"
                ),
                "quantum_status": "acceptable-with-256-bit-key",
                "role": "symmetric envelope",
            },
            {
                "algorithm": "ML-KEM",
                "implemented": False,
                "quantum_status": "future-target-not-implemented",
                "role": "future post-quantum KEM target",
            },
            {
                "algorithm": "HQC",
                "implemented": False,
                "quantum_status": "future-target-not-implemented",
                "role": "future post-quantum KEM target",
            },
            {
                "algorithm": "ML-DSA",
                "implemented": False,
                "quantum_status": "future-target-not-implemented",
                "role": "future post-quantum signature target",
            },
            {
                "algorithm": "SLH-DSA",
                "implemented": False,
                "quantum_status": "future-target-not-implemented",
                "role": "future post-quantum signature backup target",
            },
            {
                "algorithm": "LMS",
                "implemented": False,
                "quantum_status": "future-target-not-implemented",
                "role": "future software/firmware signing target",
            },
            {
                "algorithm": "XMSS",
                "implemented": False,
                "quantum_status": "future-target-not-implemented",
                "role": "future software/firmware signing target",
            },
        ],
        "pq_verifier_available": False,
        "tool": "tools/wuci_qcage.py",
    }


def inventory_entries_by_algorithm(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = value.get("entries")
    if not isinstance(entries, list):
        raise QCageError("crypto inventory entries must be a list")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise QCageError("crypto inventory entry must be an object")
        algorithm = entry.get("algorithm")
        if not isinstance(algorithm, str) or not algorithm:
            raise QCageError("crypto inventory entry missing algorithm")
        if algorithm in result:
            raise QCageError(f"crypto inventory duplicates algorithm: {algorithm}")
        result[algorithm] = entry
    return result


def validate_crypto_inventory(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QCageError("crypto inventory must be a JSON object")
    if value.get("schema") != CRYPTO_INVENTORY_SCHEMA:
        raise QCageError("crypto inventory has unsupported schema")
    entries = inventory_entries_by_algorithm(value)
    expected = inventory_entries_by_algorithm(crypto_inventory())
    if set(entries) != set(expected):
        raise QCageError("crypto inventory algorithms are not canonical")
    for name in ("secp256k1", "x25519", CLASSIC_AUTHORITY_PROFILE):
        if entries[name].get("quantum_status") != CLASSIC_QUANTUM_STATUS:
            raise QCageError(f"crypto inventory must mark {name} quantum-vulnerable")
    for name in FUTURE_PQ_TARGETS:
        if entries[name].get("implemented") is not False:
            raise QCageError(f"{name} is not implemented by a real QCAGE v1 verifier")
    for entry in entries.values():
        status = entry.get("quantum_status")
        if status == "quantum-safe":
            raise QCageError("crypto inventory cannot mark algorithms quantum-safe in v1")
        if entry.get("implemented") is True and entry["algorithm"] in FUTURE_PQ_TARGETS:
            raise QCageError("PQ verifier implementation claim is not allowed in v1")
    if value.get("pq_verifier_available") is not False:
        raise QCageError("QCAGE v1 has no built-in real PQ verifier")
    return value


def repo_file_digest(
    repo: Path,
    relative: Path,
    ticker_mode: str = "auto",
) -> dict[str, str]:
    path = repo / relative
    return {
        "path": relative.as_posix(),
        "sha512": digest_file(path, "sha512", ticker_mode, f"QCAGE graph {relative.as_posix()}"),
    }


def sorted_digest_entries(
    repo: Path,
    pattern: str,
    ticker_mode: str = "auto",
) -> list[dict[str, str]]:
    return [
        repo_file_digest(repo, path.relative_to(repo), ticker_mode)
        for path in sorted(repo.glob(pattern), key=lambda p: p.as_posix())
        if path.is_file()
    ]


def build_graph(repo: Path, ticker_mode: str = "auto") -> dict[str, Any]:
    repo = repo.resolve()
    top_level = []
    for filename in REQUIRED_TOP_LEVEL_FILES:
        path = repo / filename
        if path.is_file():
            top_level.append(repo_file_digest(repo, Path(filename), ticker_mode))
    return {
        "schema": BUILD_GRAPH_SCHEMA,
        "repo": repo.name,
        "python_version": sys.version.split()[0],
        "top_level_files": top_level,
        "src_asm": sorted_digest_entries(repo, "src/*.s", ticker_mode),
        "tools_python": sorted_digest_entries(repo, "tools/wuci_*.py", ticker_mode),
        "tests_python": sorted_digest_entries(repo, "tests/wuci_*.py", ticker_mode),
    }


def validate_build_graph(
    value: Any,
    repo: Path = REPO_ROOT,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QCageError("build graph must be a JSON object")
    if value.get("schema") != BUILD_GRAPH_SCHEMA:
        raise QCageError("build graph has unsupported schema")
    expected = build_graph(repo, ticker_mode)
    if value != expected:
        raise QCageError("build graph does not match current repository state")
    if not value.get("src_asm"):
        raise QCageError("build graph missing assembly source digest set")
    if not value.get("tools_python"):
        raise QCageError("build graph missing tool digest set")
    return value


def load_valid_cage_attestation(
    bin_path: Path,
    bundle: Path,
    path: Path,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    observed = wuci_cage.validate_attestation_shape(
        wuci_cage.load_json(path, "CAGE attestation")
    )
    expected = wuci_cage.build_attestation(
        bin_path=bin_path,
        bundle=bundle,
        ticker_mode=ticker_mode,
    )
    if observed != expected:
        raise QCageError("CAGE attestation does not match bundle state")
    if observed["cage_decision"] != "allow-publish":
        raise QCageError("QCAGE requires an allow-publish CAGE attestation")
    return observed


def public_evidence_digest_vectors(
    bundle: Path,
    ticker_mode: str = "auto",
) -> dict[str, dict[str, str]]:
    vectors: dict[str, dict[str, str]] = {}
    for label, filename in PUBLIC_EVIDENCE_FILES.items():
        path = bundle / filename
        if not path.is_file():
            raise QCageError(f"missing public evidence file: {filename}")
        vectors[label] = digest_vector_for_file(path, ticker_mode)
    return vectors


def validate_mode(mode: str) -> None:
    if mode not in MODES:
        raise QCageError(f"unsupported QCAGE mode: {mode}")
    if mode == "hybrid-required":
        raise QCageError("hybrid-required mode fails closed without real PQ verification")
    if mode == "pq-required":
        raise QCageError("pq-required mode fails closed without real PQ verification")


def min_bits_from_vectors(vectors: dict[str, dict[str, str]], kind: str) -> int:
    if kind == "preimage":
        values = (quantum_preimage_bits(256), quantum_preimage_bits(384), quantum_preimage_bits(512))
    else:
        values = (quantum_collision_bits(256), quantum_collision_bits(384), quantum_collision_bits(512))
    _ = vectors
    return min(values)


def build_attestation(
    *,
    bin_path: Path,
    cage_attestation_path: Path,
    bundle: Path,
    crypto_inventory_path: Path,
    build_graph_path: Path,
    mode: str,
    t_migrate: int,
    t_trust: int,
    t_crqc: int,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    load_policy()
    validate_mode(mode)
    cage_attestation = load_valid_cage_attestation(
        bin_path,
        bundle,
        cage_attestation_path,
        ticker_mode,
    )
    validate_crypto_inventory(
        load_json(crypto_inventory_path, "QCAGE crypto inventory")
    )
    graph = validate_build_graph(
        load_json(build_graph_path, "QCAGE build graph"),
        ticker_mode=ticker_mode,
    )
    evidence_vectors = public_evidence_digest_vectors(bundle, ticker_mode)
    cage_vector = digest_vector_for_file(cage_attestation_path, ticker_mode)
    inventory_vector = digest_vector_for_file(crypto_inventory_path, ticker_mode)
    build_graph_vector = digest_vector_for_file(build_graph_path, ticker_mode)
    qmd = quantum_migration_debt(t_migrate, t_trust, t_crqc)

    return {
        "schema": ATTESTATION_SCHEMA,
        "profile": PROFILE,
        "cage_attestation_sha256": cage_vector["sha256"],
        "artifact_sha256": evidence_vectors["artifact"]["sha256"],
        "artifact_sha384": evidence_vectors["artifact"]["sha384"],
        "artifact_sha512": evidence_vectors["artifact"]["sha512"],
        "manifest_sha256": evidence_vectors["manifest"]["sha256"],
        "manifest_sha384": evidence_vectors["manifest"]["sha384"],
        "manifest_sha512": evidence_vectors["manifest"]["sha512"],
        "public_evidence_digest_vectors": evidence_vectors,
        "cage_attestation_digest_vector": cage_vector,
        "crypto_inventory_digest_vector": inventory_vector,
        "build_graph_digest_vector": build_graph_vector,
        "crypto_inventory_sha512": inventory_vector["sha512"],
        "build_graph_sha512": build_graph_vector["sha512"],
        "toolchain_manifest_sha512": build_graph_vector["sha512"],
        "classic_authority_profile": CLASSIC_AUTHORITY_PROFILE,
        "classic_authority_quantum_status": CLASSIC_QUANTUM_STATUS,
        "pq_authority_profile": "absent",
        "pq_authority_verified": False,
        "quantum_safe": False,
        "qcage_mode": mode,
        "min_quantum_preimage_bits": min_bits_from_vectors(evidence_vectors, "preimage"),
        "min_quantum_collision_bits": min_bits_from_vectors(evidence_vectors, "collision"),
        "quantum_migration_debt": qmd,
        "qmd_inputs": {
            "T_CRQC": t_crqc,
            "T_migrate": t_migrate,
            "T_trust": t_trust,
        },
        "downgrade_checks": {
            "digest_vector_present": True,
            "hybrid_acceptance_is_conjunctive": True,
            "no_false_quantum_safe_claim": True,
            "no_pq_stub_marked_real": True,
            "no_sha256_only_public_evidence": True,
        },
        "toolchain_checks": {
            "build_graph_present": True,
            "crypto_inventory_present": True,
            "source_digest_set_present": bool(graph["src_asm"]),
            "toolchain_manifest_present": True,
        },
        "cage_decision": cage_attestation["cage_decision"],
        "qcage_decision": "allow-classic-cage-with-quantum-warning",
        "boundary_statement": BOUNDARY_STATEMENT,
    }


def validate_hex(value: Any, length: int, field: str) -> None:
    if not isinstance(value, str) or len(value) != length:
        raise QCageError(f"{field} must be {length} lowercase hex characters")
    if value.lower() != value:
        raise QCageError(f"{field} must be lowercase hex")
    try:
        int(value, 16)
    except ValueError as exc:
        raise QCageError(f"{field} must be hex") from exc


def validate_digest_vector(value: Any, context: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise QCageError(f"{context} digest vector must be an object")
    if set(value) != {"sha256", "sha384", "sha512"}:
        raise QCageError(f"{context} digest vector must include sha256, sha384, sha512")
    validate_hex(value["sha256"], 64, f"{context}.sha256")
    validate_hex(value["sha384"], 96, f"{context}.sha384")
    validate_hex(value["sha512"], 128, f"{context}.sha512")
    return value


def validate_attestation_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QCageError("QCAGE attestation must be a JSON object")
    required = {
        "schema",
        "profile",
        "cage_attestation_sha256",
        "artifact_sha256",
        "artifact_sha384",
        "artifact_sha512",
        "manifest_sha256",
        "manifest_sha384",
        "manifest_sha512",
        "public_evidence_digest_vectors",
        "cage_attestation_digest_vector",
        "crypto_inventory_digest_vector",
        "build_graph_digest_vector",
        "crypto_inventory_sha512",
        "build_graph_sha512",
        "toolchain_manifest_sha512",
        "classic_authority_profile",
        "classic_authority_quantum_status",
        "pq_authority_profile",
        "pq_authority_verified",
        "quantum_safe",
        "qcage_mode",
        "min_quantum_preimage_bits",
        "min_quantum_collision_bits",
        "quantum_migration_debt",
        "qmd_inputs",
        "downgrade_checks",
        "toolchain_checks",
        "cage_decision",
        "qcage_decision",
        "boundary_statement",
    }
    if set(value) != required:
        raise QCageError("QCAGE attestation fields are not canonical")
    if value["schema"] != ATTESTATION_SCHEMA:
        raise QCageError("QCAGE attestation has unsupported schema")
    if value["profile"] != PROFILE:
        raise QCageError("QCAGE attestation has unsupported profile")
    for field, length in (
        ("cage_attestation_sha256", 64),
        ("artifact_sha256", 64),
        ("artifact_sha384", 96),
        ("artifact_sha512", 128),
        ("manifest_sha256", 64),
        ("manifest_sha384", 96),
        ("manifest_sha512", 128),
        ("crypto_inventory_sha512", 128),
        ("build_graph_sha512", 128),
        ("toolchain_manifest_sha512", 128),
    ):
        validate_hex(value[field], length, field)
    for context in (
        "cage_attestation",
        "crypto_inventory",
        "build_graph",
    ):
        validate_digest_vector(value[f"{context}_digest_vector"], context)
    evidence = value["public_evidence_digest_vectors"]
    if not isinstance(evidence, dict) or set(evidence) != set(PUBLIC_EVIDENCE_FILES):
        raise QCageError("public evidence digest vectors are not canonical")
    for label in PUBLIC_EVIDENCE_FILES:
        validate_digest_vector(evidence[label], f"public_evidence.{label}")
    if value["artifact_sha256"] != evidence["artifact"]["sha256"]:
        raise QCageError("artifact sha256 does not match public evidence vector")
    if value["artifact_sha384"] != evidence["artifact"]["sha384"]:
        raise QCageError("artifact sha384 does not match public evidence vector")
    if value["artifact_sha512"] != evidence["artifact"]["sha512"]:
        raise QCageError("artifact sha512 does not match public evidence vector")
    if value["manifest_sha256"] != evidence["manifest"]["sha256"]:
        raise QCageError("manifest sha256 does not match public evidence vector")
    if value["manifest_sha384"] != evidence["manifest"]["sha384"]:
        raise QCageError("manifest sha384 does not match public evidence vector")
    if value["manifest_sha512"] != evidence["manifest"]["sha512"]:
        raise QCageError("manifest sha512 does not match public evidence vector")
    if value["crypto_inventory_sha512"] != value["crypto_inventory_digest_vector"]["sha512"]:
        raise QCageError("crypto inventory sha512 does not match digest vector")
    if value["build_graph_sha512"] != value["build_graph_digest_vector"]["sha512"]:
        raise QCageError("build graph sha512 does not match digest vector")
    if value["toolchain_manifest_sha512"] != value["build_graph_sha512"]:
        raise QCageError("toolchain manifest digest must match build graph in v1")
    if value["classic_authority_profile"] != CLASSIC_AUTHORITY_PROFILE:
        raise QCageError("QCAGE classic authority profile is not canonical")
    if value["classic_authority_quantum_status"] != CLASSIC_QUANTUM_STATUS:
        raise QCageError("classic authority must be marked quantum-vulnerable")
    if value["pq_authority_profile"] not in {"absent", "external-verified", "future"}:
        raise QCageError("unsupported PQ authority profile")
    if value["pq_authority_profile"] == "external-verified":
        raise QCageError("external PQ verifier metadata is not pinned in v1")
    if value["pq_authority_verified"] is not False:
        raise QCageError("QCAGE v1 has no real PQ verifier")
    if value["quantum_safe"] is not False:
        raise QCageError("quantum_safe:true requires real PQ verification")
    if value["qcage_mode"] not in MODES:
        raise QCageError("unsupported QCAGE mode")
    if value["qcage_mode"] in {"hybrid-required", "pq-required"}:
        raise QCageError("PQ-required QCAGE modes fail closed in v1")
    if not isinstance(value["qmd_inputs"], dict):
        raise QCageError("qmd_inputs must be an object")
    qmd_inputs = value["qmd_inputs"]
    if set(qmd_inputs) != {"T_CRQC", "T_migrate", "T_trust"}:
        raise QCageError("qmd_inputs fields are not canonical")
    for name in qmd_inputs:
        if not isinstance(qmd_inputs[name], int) or qmd_inputs[name] < 0:
            raise QCageError(f"qmd_inputs {name} must be a nonnegative integer")
    if value["quantum_migration_debt"] != quantum_migration_debt(
        qmd_inputs["T_migrate"],
        qmd_inputs["T_trust"],
        qmd_inputs["T_CRQC"],
    ):
        raise QCageError("quantum migration debt does not match inputs")
    if value["min_quantum_preimage_bits"] != 128:
        raise QCageError("minimum quantum preimage bits must be 128 in v1")
    if value["min_quantum_collision_bits"] != 85:
        raise QCageError("minimum quantum collision bits must be 85 in v1")
    if value["cage_decision"] != "allow-publish":
        raise QCageError("QCAGE requires a CAGE allow-publish decision")
    if value["qcage_decision"] != "allow-classic-cage-with-quantum-warning":
        raise QCageError("compat QCAGE decision must retain the quantum warning")
    if value["boundary_statement"] != BOUNDARY_STATEMENT:
        raise QCageError("QCAGE boundary statement is not canonical")
    for check_group in ("downgrade_checks", "toolchain_checks"):
        checks = value[check_group]
        if not isinstance(checks, dict) or not checks:
            raise QCageError(f"{check_group} must be a nonempty object")
        if any(check is not True for check in checks.values()):
            raise QCageError(f"{check_group} must all be true in an allow attestation")
    return value


def run_policy(args: argparse.Namespace) -> int:
    policy = load_policy()
    if not args.print_policy:
        raise QCageError("policy command requires --print")
    sys.stdout.write(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    return 0


def run_digest_vector(args: argparse.Namespace) -> int:
    ticker_mode = getattr(args, "ticker", "auto")
    path = Path(args.file)
    if not path.is_file():
        raise QCageError(f"digest-vector input is not a file: {path}")
    write_json(Path(args.out), digest_vector_document(path, ticker_mode), "QCAGE digest vector")
    print(f"wrote QCAGE digest vector: {display_path(Path(args.out))}")
    return 0


def run_crypto_inventory(args: argparse.Namespace) -> int:
    _ = Path(args.repo)
    write_json(Path(args.out), crypto_inventory(), "QCAGE crypto inventory")
    print(f"wrote QCAGE crypto inventory: {display_path(Path(args.out))}")
    return 0


def run_build_graph(args: argparse.Namespace) -> int:
    ticker_mode = getattr(args, "ticker", "auto")
    repo = Path(args.repo)
    if not repo.is_dir():
        raise QCageError(f"build graph repo is not a directory: {repo}")
    write_json(Path(args.out), build_graph(repo, ticker_mode), "QCAGE build graph")
    print(f"wrote QCAGE build graph: {display_path(Path(args.out))}")
    return 0


def run_attest(args: argparse.Namespace) -> int:
    ticker_mode = getattr(args, "ticker", "auto")
    attestation = build_attestation(
        bin_path=Path(args.bin),
        cage_attestation_path=Path(args.cage_attestation),
        bundle=Path(args.witness_bundle),
        crypto_inventory_path=Path(args.crypto_inventory),
        build_graph_path=Path(args.build_graph),
        mode=args.mode,
        t_migrate=args.t_migrate,
        t_trust=args.t_trust,
        t_crqc=args.t_crqc,
        ticker_mode=ticker_mode,
    )
    write_json(Path(args.out), attestation, "QCAGE attestation")
    print(f"wrote QCAGE attestation: {display_path(Path(args.out))}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    ticker_mode = getattr(args, "ticker", "auto")
    observed = validate_attestation_shape(
        load_json(Path(args.attestation), "QCAGE attestation")
    )
    expected = build_attestation(
        bin_path=Path(args.bin),
        cage_attestation_path=Path(args.cage_attestation)
        if args.cage_attestation
        else Path(args.attestation).with_name("wuci-cage-attestation.json"),
        bundle=Path(args.witness_bundle),
        crypto_inventory_path=Path(args.crypto_inventory),
        build_graph_path=Path(args.build_graph),
        mode=observed["qcage_mode"],
        t_migrate=observed["qmd_inputs"]["T_migrate"],
        t_trust=observed["qmd_inputs"]["T_trust"],
        t_crqc=observed["qmd_inputs"]["T_CRQC"],
        ticker_mode=ticker_mode,
    )
    if observed != expected:
        raise QCageError("QCAGE attestation does not match current evidence")
    print(f"valid QCAGE attestation: {display_path(Path(args.attestation))}")
    return 0


def run_risk(args: argparse.Namespace) -> int:
    qmd = quantum_migration_debt(args.t_migrate, args.t_trust, args.t_crqc)
    value = (
        f"schema: {RISK_SCHEMA}\n"
        f"T_migrate: {args.t_migrate}\n"
        f"T_trust: {args.t_trust}\n"
        f"T_CRQC: {args.t_crqc}\n"
        f"quantum_migration_debt: {qmd}\n"
        f"recommendation: {risk_recommendation(args.t_migrate, args.t_trust, args.t_crqc)}\n"
    )
    sys.stdout.write(value)
    return 0


def add_bin_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to wuci-ji; defaults to WUCI_JI_BIN or build/wuci-ji",
    )


def add_qmd_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--T-migrate", dest="t_migrate", type=int, required=True)
    parser.add_argument("--T-trust", dest="t_trust", type=int, required=True)
    parser.add_argument("--T-CRQC", dest="t_crqc", type=int, required=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WUCI-QCAGE v1 quantum-aware artifact airlock."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy_parser = subparsers.add_parser("policy", help="print QCAGE policy")
    policy_parser.add_argument("--print", dest="print_policy", action="store_true")
    policy_parser.set_defaults(func=run_policy)

    digest_parser = subparsers.add_parser("digest-vector", help="write digest vector")
    digest_parser.add_argument("--file", required=True)
    digest_parser.add_argument("--out", required=True)
    wuci_progress.add_ticker_arg(digest_parser)
    digest_parser.set_defaults(func=run_digest_vector)

    inventory_parser = subparsers.add_parser(
        "crypto-inventory",
        help="write declared crypto inventory",
    )
    inventory_parser.add_argument("--repo", default=".")
    inventory_parser.add_argument("--out", required=True)
    inventory_parser.set_defaults(func=run_crypto_inventory)

    graph_parser = subparsers.add_parser("build-graph", help="write build graph evidence")
    graph_parser.add_argument("--repo", default=".")
    graph_parser.add_argument("--out", required=True)
    wuci_progress.add_ticker_arg(graph_parser)
    graph_parser.set_defaults(func=run_build_graph)

    attest_parser = subparsers.add_parser("attest", help="write QCAGE attestation")
    add_bin_arg(attest_parser)
    attest_parser.add_argument("--cage-attestation", required=True)
    attest_parser.add_argument("--witness-bundle", default=str(DEFAULT_BUNDLE_DIR))
    attest_parser.add_argument("--crypto-inventory", required=True)
    attest_parser.add_argument("--build-graph", required=True)
    attest_parser.add_argument("--mode", choices=sorted(MODES), required=True)
    add_qmd_args(attest_parser)
    attest_parser.add_argument("--out", required=True)
    wuci_progress.add_ticker_arg(attest_parser)
    attest_parser.set_defaults(func=run_attest)

    verify_parser = subparsers.add_parser("verify", help="verify QCAGE attestation")
    add_bin_arg(verify_parser)
    verify_parser.add_argument("--attestation", required=True)
    verify_parser.add_argument("--cage-attestation")
    verify_parser.add_argument("--witness-bundle", default=str(DEFAULT_BUNDLE_DIR))
    verify_parser.add_argument("--crypto-inventory", required=True)
    verify_parser.add_argument("--build-graph", required=True)
    wuci_progress.add_ticker_arg(verify_parser)
    verify_parser.set_defaults(func=run_verify)

    risk_parser = subparsers.add_parser("risk", help="print QCAGE migration risk")
    add_qmd_args(risk_parser)
    risk_parser.set_defaults(func=run_risk)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (QCageError, wuci_cage.CageError, ValueError) as exc:
        print(f"wuci qcage: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
