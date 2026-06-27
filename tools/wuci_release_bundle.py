#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))
import wuci_install  # noqa: E402
import wuci_external_audit  # noqa: E402
import wuci_pq_verifier  # noqa: E402
import wuci_production_authority  # noqa: E402


class ReleaseBundleError(RuntimeError):
    pass


def sha_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_regular(path: Path, context: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ReleaseBundleError(f"{context} must be a regular non-symlink file: {path}")


def load_json(path: Path, context: str) -> dict[str, Any]:
    require_regular(path, context)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseBundleError(f"{context} is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ReleaseBundleError(f"{context} must be a JSON object")
    return value


def run(argv: list[str], context: str, *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        raise ReleaseBundleError(f"{context} failed: {detail}")
    return proc


def hash_tree(path: Path, context: str) -> str:
    if not path.is_dir() or path.is_symlink():
        raise ReleaseBundleError(f"{context} must be a directory: {path}")
    digest = hashlib.sha512()
    for child in sorted(path.rglob("*")):
        rel = child.relative_to(path).as_posix()
        info = os.lstat(child)
        if child.is_symlink():
            raise ReleaseBundleError(f"{context} must not contain symlink: {child}")
        if child.is_dir():
            continue
        if not child.is_file():
            raise ReleaseBundleError(f"{context} must contain regular files only: {child}")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(child.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_json_evidence(args: argparse.Namespace) -> dict[str, Any]:
    sbom = load_json(Path(args.sbom), "SBOM")
    provenance = load_json(Path(args.provenance), "provenance")
    carrot = load_json(Path(args.carrot), "CARROT attestation")
    pq = load_json(Path(args.pq), "PQ verifier evidence")
    crypto_audit = load_json(Path(args.crypto_audit), "crypto self-audit")
    parser_replay = load_json(Path(args.parser_replay), "parser corpus replay")
    production_authority = load_json(
        Path(args.production_authority_policy), "production authority policy"
    )

    if sbom.get("schema") != "wuci-sbom-v1" or sbom.get("network_required") is not False:
        raise ReleaseBundleError("SBOM must be offline wuci-sbom-v1 evidence")
    if sbom.get("license") != "Apache-2.0":
        raise ReleaseBundleError("SBOM must record Apache-2.0")
    if provenance.get("schema") != "wuci-provenance-v1":
        raise ReleaseBundleError("provenance must be wuci-provenance-v1")
    if provenance.get("production_readiness", {}).get("claim") != "not-production-ready":
        raise ReleaseBundleError("provenance must not claim production readiness")
    if carrot.get("schema") != "wuci-carrot-runtime-attestation-v1":
        raise ReleaseBundleError("CARROT attestation schema mismatch")
    if carrot.get("allow_network") is not False:
        raise ReleaseBundleError("CARROT must not allow network")
    if carrot.get("kernel_probe", {}).get("socket_probe_denied") is not True:
        raise ReleaseBundleError("CARROT kernel probe must deny socket creation")
    if pq.get("schema") != "wuci-pq-verifier-detection-v1":
        raise ReleaseBundleError("PQ verifier evidence schema mismatch")
    if pq.get("quantum_safe_claim_allowed") is not False:
        raise ReleaseBundleError("release verifier refuses quantum-safe overclaim")
    if crypto_audit.get("schema") != "wuci-crypto-self-audit-v1":
        raise ReleaseBundleError("crypto self-audit schema mismatch")
    if crypto_audit.get("external_audit") is not False:
        raise ReleaseBundleError("internal crypto audit must not claim external audit")
    if crypto_audit.get("production_sufficient") is not False:
        raise ReleaseBundleError("internal crypto audit must not claim production sufficiency")
    if parser_replay.get("schema") != "wuci-parser-corpus-replay-v2":
        raise ReleaseBundleError("parser corpus replay schema mismatch")
    if parser_replay.get("offensive_fuzzing") is not False:
        raise ReleaseBundleError("parser corpus replay must not be offensive fuzzing")
    if parser_replay.get("network_required") is not False:
        raise ReleaseBundleError("parser corpus replay must not require network")
    if parser_replay.get("runtime_sandbox_claim") is not False:
        raise ReleaseBundleError("parser corpus replay must not claim runtime sandboxing")
    if parser_replay.get("deterministic_mutation_mode") is not True:
        raise ReleaseBundleError("parser corpus replay must be deterministic")
    if parser_replay.get("fail_closed") is not True:
        raise ReleaseBundleError("parser corpus replay must fail closed")
    if parser_replay.get("timeouts") != 0 or parser_replay.get("signals") != 0:
        raise ReleaseBundleError("parser corpus replay must not time out or terminate by signal")
    required_parser_surfaces = {
        "armor",
        "authority-root",
        "envelope",
        "gate-contract",
        "ledger-entry",
        "ledger-head",
        "ledger-proof",
        "wjnext-model",
        "wjstar-model",
    }
    parser_surfaces = parser_replay.get("surfaces")
    if not isinstance(parser_surfaces, dict):
        raise ReleaseBundleError("parser corpus replay must record surface coverage")
    missing_parser_surfaces = sorted(required_parser_surfaces.difference(parser_surfaces))
    if missing_parser_surfaces:
        raise ReleaseBundleError(
            "parser corpus replay missing surfaces: " + ", ".join(missing_parser_surfaces)
        )
    if parser_replay.get("wjstar_model_covered") is not True:
        raise ReleaseBundleError("parser corpus replay must cover WJ* model inputs")
    if parser_replay.get("wjnext_model_covered") is not True:
        raise ReleaseBundleError("parser corpus replay must cover WJ-next model inputs")
    if production_authority.get("schema") != "wuci-production-authority-policy-v1":
        raise ReleaseBundleError("production authority policy schema mismatch")
    if production_authority.get("fixture_authority_allowed_for_production") is not False:
        raise ReleaseBundleError("fixture authority must not be allowed for production")
    required_authority = production_authority.get("required_for_production", {})
    if required_authority.get("key_ceremony_document_required") is not True:
        raise ReleaseBundleError("production authority must require ceremony evidence")
    if required_authority.get("ceremony_threshold_minimum") != 4:
        raise ReleaseBundleError("production authority must require Golden Lock ceremony threshold")
    if required_authority.get("ceremony_signer_count_minimum") != 5:
        raise ReleaseBundleError("production authority must require Golden Lock signer count")
    if required_authority.get("publish_or_trust_requires_assembly_gate") is not True:
        raise ReleaseBundleError("production authority must require assembly Gate publish/trust")
    golden_lock = production_authority.get("golden_lock", {})
    if golden_lock.get("schema") != "wuci-golden-lock-v1":
        raise ReleaseBundleError("production authority policy must name Golden Lock v1")
    if golden_lock.get("normal_open_release_threshold") != {"n": 5, "t": 3}:
        raise ReleaseBundleError("production authority policy must require 3-of-5 open/release")
    if golden_lock.get("root_authority_audit_ceremony_threshold") != {"n": 5, "t": 4}:
        raise ReleaseBundleError("production authority policy must require 4-of-5 ceremonies")

    return {
        "sbom_sha256": sha_file(Path(args.sbom), "sha256"),
        "provenance_sha256": sha_file(Path(args.provenance), "sha256"),
        "carrot_attestation_sha256": sha_file(Path(args.carrot), "sha256"),
        "pq_verifier_evidence_sha256": sha_file(Path(args.pq), "sha256"),
        "crypto_self_audit_sha256": sha_file(Path(args.crypto_audit), "sha256"),
        "crypto_external_audit": crypto_audit.get("external_audit") is True,
        "crypto_production_sufficient": crypto_audit.get("production_sufficient") is True,
        "parser_corpus_replay_sha256": sha_file(Path(args.parser_replay), "sha256"),
        "parser_corpus_replay_cases": parser_replay.get("cases"),
        "parser_corpus_replay_surfaces": sorted(parser_replay.get("surfaces", {}).keys()),
        "production_authority_policy_sha256": sha_file(
            Path(args.production_authority_policy), "sha256"
        ),
        "fixture_authority_allowed_for_production": production_authority.get(
            "fixture_authority_allowed_for_production"
        ),
        "pq_real_signature_verifier_available": pq.get("real_pq_signature_verifier_available")
        is True,
    }


def verify_real_pq(args: argparse.Namespace) -> dict[str, Any]:
    if not args.real_pq_evidence:
        return {
            "provided": False,
            "verified": False,
            "reason": "no real PQ verifier evidence supplied",
        }
    evidence_path = Path(args.real_pq_evidence)
    pins_path = Path(args.pq_pins)
    try:
        summary = wuci_pq_verifier.verify_real_evidence(
            evidence_path=evidence_path,
            pins_path=pins_path,
            rerun=args.real_pq_rerun,
        )
    except wuci_pq_verifier.PQVerifierError as exc:
        raise ReleaseBundleError(f"real PQ verifier evidence failed: {exc}") from exc
    return {
        "provided": True,
        "verified": True,
        "evidence_sha256": sha_file(evidence_path, "sha256"),
        "pins_sha256": sha_file(pins_path, "sha256"),
        **summary,
    }


def verify_production_authority(args: argparse.Namespace) -> dict[str, Any]:
    values = (
        args.production_authority,
        args.production_authority_ceremony,
        args.production_authority_ceremony_root_key,
        args.production_authority_ceremony_signature,
    )
    if not any(values):
        return {
            "provided": False,
            "verified": False,
            "reason": "no signed non-fixture production authority ceremony supplied",
        }
    if not all(values):
        raise ReleaseBundleError(
            "production authority release evidence requires authority, ceremony, root key, and signature"
        )
    try:
        summary = wuci_production_authority.verify_authority(
            authority_path=Path(args.production_authority),
            ceremony_path=Path(args.production_authority_ceremony),
            ceremony_root_key=Path(args.production_authority_ceremony_root_key),
            ceremony_signature=Path(args.production_authority_ceremony_signature),
            policy_path=Path(args.production_authority_policy),
            ssh_keygen=args.ssh_keygen,
            allow_unsigned_ceremony=False,
        )
    except wuci_production_authority.ProductionAuthorityError as exc:
        raise ReleaseBundleError(f"production authority evidence failed: {exc}") from exc
    return {
        "provided": True,
        "verified": True,
        "ceremony_root_key_sha256": sha_file(
            Path(args.production_authority_ceremony_root_key), "sha256"
        ),
        "ceremony_signature_sha256": sha_file(
            Path(args.production_authority_ceremony_signature), "sha256"
        ),
        **summary,
    }


def verify_external_audit(args: argparse.Namespace, repo: Path) -> dict[str, Any]:
    values = (
        args.external_audit_evidence,
        args.external_audit_report,
        args.external_audit_root_key,
        args.external_audit_signature,
    )
    if not any(values):
        return {
            "provided": False,
            "verified": False,
            "reason": "no independent external crypto/security audit evidence supplied",
        }
    if not all(values):
        raise ReleaseBundleError(
            "external audit release evidence requires evidence, report, root key, and signature"
        )
    try:
        summary = wuci_external_audit.verify_external_audit(
            evidence_path=Path(args.external_audit_evidence),
            report_path=Path(args.external_audit_report),
            audit_root_key=Path(args.external_audit_root_key),
            audit_signature=Path(args.external_audit_signature),
            repo=repo,
            ssh_keygen=args.ssh_keygen,
            allow_unsigned_audit=False,
        )
    except wuci_external_audit.ExternalAuditError as exc:
        raise ReleaseBundleError(f"external audit evidence failed: {exc}") from exc
    return {
        "provided": True,
        "verified": True,
        "audit_root_key_sha256": sha_file(Path(args.external_audit_root_key), "sha256"),
        "audit_signature_sha256": sha_file(Path(args.external_audit_signature), "sha256"),
        **summary,
    }


def verify_install_manifest(args: argparse.Namespace, binary_hashes: dict[str, str]) -> dict[str, Any]:
    manifest_path = Path(args.install_manifest)
    manifest = wuci_install.verify_manifest_signature(
        install_root_key=Path(args.install_root_key),
        manifest_path=manifest_path,
        signature_path=Path(args.install_signature),
        ssh_keygen=args.ssh_keygen,
        quiet=True,
    )
    current_match = (
        manifest["binary-sha256"] == binary_hashes["sha256"]
        and manifest["binary-sha384"] == binary_hashes["sha384"]
        and manifest["binary-sha512"] == binary_hashes["sha512"]
    )
    return {
        "install_manifest_sha256": sha_file(manifest_path, "sha256"),
        "install_signature_verified": True,
        "install_root_key_sha256": sha_file(Path(args.install_root_key), "sha256"),
        "install_manifest_matches_current_binary": current_match,
    }


def verify_witness_and_ledger(args: argparse.Namespace, repo: Path) -> dict[str, Any]:
    witness = Path(args.witness_bundle)
    ledger = Path(args.ledger)
    for rel in (
        "wuci-ji.self.wj",
        "manifest.txt",
        "warrant-message.txt",
        "release-receipt.json",
        "receipt-contract.txt",
        "authority-root.txt",
        "release-decision.txt",
        "publish-index.txt",
        "attestation.json",
    ):
        require_regular(witness / rel, f"witness bundle {rel}")

    run(
        [
            sys.executable,
            str(repo / "tools" / "wuci_witness.py"),
            "verify",
            "--bin",
            str(Path(args.bin)),
            "--bundle",
            str(witness),
        ],
        "Python witness verification",
        cwd=repo,
    )
    if Path(args.zig_witness).exists():
        run(
            [str(Path(args.zig_witness)), "verify", str(witness), "--bin", str(Path(args.bin))],
            "Zig witness verification",
            cwd=repo,
        )

    for rel in (
        "ledger-entry.txt",
        "ledger-head.txt",
        "previous-ledger-head.txt",
        "inclusion-proof.txt",
        "consistency-proof.txt",
    ):
        require_regular(ledger / rel, f"ledger {rel}")
    if Path(args.zig_ledger).exists():
        run(
            [str(Path(args.zig_ledger)), "verify-history", "--ledger", str(ledger)],
            "Zig ledger history verification",
            cwd=repo,
        )
    return {
        "witness_bundle_sha512": hash_tree(witness, "witness bundle"),
        "ledger_history_sha512": hash_tree(ledger, "ledger history"),
    }


def verify_runtime(args: argparse.Namespace, repo: Path) -> dict[str, Any]:
    run([str(Path(args.bin)), "selftest"], "wuci-ji selftest", cwd=repo)
    run([str(Path(args.rust_sandbox)), "--selftest"], "Rust sandbox selftest", cwd=repo)
    run(
        [str(Path(args.rust_sandbox)), "--no-network", "--", str(Path(args.bin)), "selftest"],
        "wuci-ji selftest under Rust sandbox",
        cwd=repo,
    )
    return {
        "binary_selftest": True,
        "rust_sandbox_selftest": True,
        "rust_sandbox_binary_sha256": sha_file(Path(args.rust_sandbox), "sha256"),
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo).resolve()
    bin_path = Path(args.bin)
    require_regular(bin_path, "release binary")
    binary_hashes = {
        "sha256": sha_file(bin_path, "sha256"),
        "sha384": sha_file(bin_path, "sha384"),
        "sha512": sha_file(bin_path, "sha512"),
    }

    result: dict[str, Any] = {
        "schema": "wuci-release-bundle-verification-v1",
        "evidence_candidate": True,
        "production_ready": False,
        "host": {
            "observed_logical_cpus": os.cpu_count(),
            "dual_core_assumption": False,
            "parallel_make_supported": True,
            "shared_evidence_paths_serialized": True,
            "parallel_make_guidance": "use make -jN for independent proof targets; shared evidence bundle targets remain serialized by Make dependencies",
        },
        "non_claims": [
            "release verifier does not create production authority",
            "fixture authority remains test-only",
            "internal crypto self-audit is not external cryptographic assurance",
            "PQ detector does not claim quantum safety without separate pinned real verifier evidence",
            "external audit evidence does not by itself create production authority",
        ],
        "binary": {
            "path": str(bin_path),
            **binary_hashes,
        },
        "json_evidence": verify_json_evidence(args),
        "real_pq_evidence": verify_real_pq(args),
        "production_authority": verify_production_authority(args),
        "external_audit": verify_external_audit(args, repo),
        "install": verify_install_manifest(args, binary_hashes),
        "public_evidence": verify_witness_and_ledger(args, repo),
        "runtime_evidence": verify_runtime(args, repo),
    }
    blockers: list[str] = []
    if result["install"]["install_manifest_matches_current_binary"] is not True:
        blockers.append("install manifest signature is valid but not for current binary")
    if result["real_pq_evidence"]["verified"] is not True:
        blockers.append("no real pinned PQ signature verifier evidence supplied")
    if result["production_authority"]["verified"] is not True:
        blockers.append("no signed non-fixture production authority ceremony supplied")
    if result["external_audit"]["verified"] is not True:
        blockers.append("no independent external crypto/security audit evidence supplied")
    if blockers:
        result["blockers"] = blockers
    return result


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify WUCI release evidence bundle.")
    parser.add_argument("verify", choices=("verify",))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--bin", default="build/wuci-ji")
    parser.add_argument("--sbom", default="build/wuci-sbom.json")
    parser.add_argument("--provenance", default="build/wuci-provenance.json")
    parser.add_argument("--carrot", default="build/wuci-carrot-attestation.json")
    parser.add_argument("--pq", default="build/wuci-pq-verifier.json")
    parser.add_argument("--real-pq-evidence")
    parser.add_argument("--pq-pins", default="docs/wuci_pq_verifier_pins.json")
    parser.add_argument("--real-pq-rerun", action="store_true")
    parser.add_argument("--crypto-audit", default="build/wuci-crypto-self-audit.json")
    parser.add_argument("--parser-replay", default="build/wuci-parser-corpus-replay.json")
    parser.add_argument(
        "--production-authority-policy",
        default="docs/wuci_production_authority_policy.json",
    )
    parser.add_argument("--production-authority")
    parser.add_argument("--production-authority-ceremony")
    parser.add_argument("--production-authority-ceremony-root-key")
    parser.add_argument("--production-authority-ceremony-signature")
    parser.add_argument("--external-audit-evidence")
    parser.add_argument("--external-audit-report")
    parser.add_argument("--external-audit-root-key")
    parser.add_argument("--external-audit-signature")
    parser.add_argument("--witness-bundle", default="build/wuci-witness-bundle")
    parser.add_argument("--ledger", default="build/wuci-ledger")
    parser.add_argument("--install-manifest", default="install/wuci-install-manifest.v1")
    parser.add_argument("--install-signature", default="install/wuci-install-manifest.v1.sig")
    parser.add_argument("--install-root-key", default="install/wuci-install-root.v1.pub")
    parser.add_argument("--rust-sandbox", default="build/wuci-sandbox")
    parser.add_argument("--zig-witness", default="build/wuci-witness")
    parser.add_argument("--zig-ledger", default="build/wuci-ledger-tool")
    parser.add_argument("--ssh-keygen")
    parser.add_argument("--out", required=True)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(args)
        write_json(Path(args.out), result)
        if not args.quiet:
            print(f"wrote release bundle verification: {args.out}")
        return 0
    except (OSError, UnicodeDecodeError, wuci_install.InstallError, ReleaseBundleError) as exc:
        print(f"wuci release bundle: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
