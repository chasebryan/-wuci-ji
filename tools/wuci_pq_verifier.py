#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


CONTRACT = Path("docs/wuci_pq_verifier_contract.json")
PINS = Path("docs/wuci_pq_verifier_pins.json")
SIGNATURE_TARGETS = {"ML-DSA", "SLH-DSA", "LMS", "XMSS"}
KEM_TARGETS = {"ML-KEM", "HQC"}
REAL_EVIDENCE_SCHEMAS = {
    "wuci-real-pq-verifier-evidence-v2",
}
EXTERNAL_VERIFY_PROTOCOL = "wuci-pq-external-verify-v1"
STANDARD_REFERENCES = {
    "ML-DSA": "NIST FIPS 204",
    "SLH-DSA": "NIST FIPS 205",
    "LMS": "NIST SP 800-208",
    "XMSS": "NIST SP 800-208",
}


class PQVerifierError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_regular(path: Path, context: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise PQVerifierError(f"{context} must be a regular non-symlink file: {path}")


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def run_external_verifier(
    *,
    verifier: Path,
    algorithm: str,
    public_key: Path,
    message: Path,
    signature: Path,
) -> None:
    require_regular(verifier, "PQ verifier binary")
    for path, context in (
        (public_key, "PQ KAT public key"),
        (message, "PQ KAT message"),
        (signature, "PQ KAT signature"),
    ):
        require_regular(path, context)
    proc = subprocess.run(
        [
            str(verifier),
            "verify",
            "--algorithm",
            algorithm,
            "--public-key",
            str(public_key),
            "--message",
            str(message),
            "--signature",
            str(signature),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise PQVerifierError(f"external PQ verifier KAT failed: {detail}")


def openssl_list(kind: str) -> list[str]:
    exe = shutil.which("openssl")
    if exe is None:
        return []
    proc = run([exe, "list", f"-{kind}-algorithms"])
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def detect() -> dict[str, Any]:
    openssl = shutil.which("openssl")
    signatures = openssl_list("signature")
    kems = openssl_list("kem")
    joined = "\n".join(signatures + kems).upper()
    found_signatures = sorted(name for name in SIGNATURE_TARGETS if name in joined)
    found_kems = sorted(name for name in KEM_TARGETS if name in joined)
    return {
        "schema": "wuci-pq-verifier-detection-v1",
        "contract_sha256": sha256_file(CONTRACT),
        "openssl_path": openssl,
        "openssl_version": run([openssl, "version"]).stdout.strip() if openssl else None,
        "signature_algorithms_seen": signatures,
        "kem_algorithms_seen": kems,
        "found_signature_targets": found_signatures,
        "found_kem_targets": found_kems,
        "real_pq_signature_verifier_available": bool(found_signatures),
        "real_pq_kem_available": bool(found_kems),
        "quantum_safe_claim_allowed": False,
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def run_detect(args: argparse.Namespace) -> int:
    value = detect()
    write_json(Path(args.out), value)
    if args.require_real and not value["real_pq_signature_verifier_available"]:
        raise PQVerifierError("no real pinned PQ signature verifier is available")
    if not args.quiet:
        print(f"wrote PQ verifier detection: {args.out}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    value = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    expected = detect()
    if value != expected:
        raise PQVerifierError("PQ verifier detection evidence does not match local state")
    if args.require_real and not value["real_pq_signature_verifier_available"]:
        raise PQVerifierError("no real pinned PQ signature verifier is available")
    if not args.quiet:
        print("wuci pq verifier detection: PASS")
    return 0


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PQVerifierError(f"could not read JSON evidence: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PQVerifierError(f"JSON evidence is invalid: {exc.msg}") from exc


def non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise PQVerifierError(f"{context} is required")
    return value


def require_boolean(value: Any, context: str, expected: bool) -> None:
    if value is not expected:
        raise PQVerifierError(f"{context} must be {expected}")


def validate_kat(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PQVerifierError("real PQ evidence KAT must be a JSON object")
    for label in ("public_key_path", "message_path", "signature_path"):
        non_empty_string(value.get(label), f"KAT {label}")
    for label in ("public_key_sha256", "message_sha256", "signature_sha256"):
        digest = non_empty_string(value.get(label), f"KAT {label}")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise PQVerifierError(f"KAT {label} must be SHA-256 lowercase hex")
    require_boolean(value.get("verified"), "KAT verified", True)
    paths = (
        (Path(value["public_key_path"]), "PQ KAT public key", value["public_key_sha256"]),
        (Path(value["message_path"]), "PQ KAT message", value["message_sha256"]),
        (Path(value["signature_path"]), "PQ KAT signature", value["signature_sha256"]),
    )
    for path, context, expected in paths:
        require_regular(path, context)
        observed = sha256_file(path)
        if observed != expected:
            raise PQVerifierError(f"{context} digest mismatch")
    return value


def pin_matches(pin: Any, *, evidence: dict[str, Any], binary_sha256: str) -> bool:
    if not isinstance(pin, dict):
        return False
    keys = (
        "algorithm",
        "binary_sha256",
        "implementation_name",
        "implementation_version",
        "verifier_protocol",
    )
    expected = {
        "algorithm": evidence.get("algorithm"),
        "binary_sha256": binary_sha256,
        "implementation_name": evidence.get("implementation_name"),
        "implementation_version": evidence.get("implementation_version"),
        "verifier_protocol": evidence.get("verifier_protocol", EXTERNAL_VERIFY_PROTOCOL),
    }
    return all(pin.get(key) == expected[key] for key in keys)


def verify_real_evidence(
    *,
    evidence_path: Path,
    pins_path: Path,
    rerun: bool = False,
) -> dict[str, Any]:
    evidence = load_json(evidence_path)
    pins = load_json(pins_path)
    if not isinstance(evidence, dict):
        raise PQVerifierError("real PQ verifier evidence must be a JSON object")
    if pins.get("schema") != "wuci-pq-verifier-pins-v1":
        raise PQVerifierError("unsupported PQ verifier pins schema")
    if evidence.get("schema") not in REAL_EVIDENCE_SCHEMAS:
        raise PQVerifierError("unsupported real PQ verifier evidence schema")
    algorithm = evidence.get("algorithm")
    if algorithm not in SIGNATURE_TARGETS:
        raise PQVerifierError("real PQ evidence must name an accepted PQ signature algorithm")
    non_empty_string(evidence.get("implementation_name"), "implementation_name")
    non_empty_string(evidence.get("implementation_version"), "implementation_version")
    require_boolean(evidence.get("known_answer_test"), "known_answer_test", True)
    require_boolean(evidence.get("no_stub_mode"), "no_stub_mode", True)
    require_boolean(evidence.get("offline_verification"), "offline_verification", True)
    if evidence.get("network_required") is not None:
        require_boolean(evidence.get("network_required"), "network_required", False)
    if evidence.get("verifier_protocol") not in (None, EXTERNAL_VERIFY_PROTOCOL):
        raise PQVerifierError("unsupported external PQ verifier protocol")
    binary_path = Path(str(evidence.get("binary_path", "")))
    require_regular(binary_path, "real PQ verifier binary")
    observed_sha256 = sha256_file(binary_path)
    if evidence.get("binary_sha256") != observed_sha256:
        raise PQVerifierError("real PQ verifier binary digest mismatch")
    kat = evidence.get("kat")
    if evidence.get("schema") == "wuci-real-pq-verifier-evidence-v2":
        kat = validate_kat(kat)
    allowed = pins.get("allowed_verifiers")
    if not isinstance(allowed, list):
        raise PQVerifierError("PQ verifier pins must contain allowed_verifiers")
    for pin in allowed:
        if pin_matches(pin, evidence=evidence, binary_sha256=observed_sha256):
            if rerun:
                if not isinstance(kat, dict):
                    raise PQVerifierError("rerun requires v2 KAT evidence")
                run_external_verifier(
                    verifier=binary_path,
                    algorithm=str(algorithm),
                    public_key=Path(kat["public_key_path"]),
                    message=Path(kat["message_path"]),
                    signature=Path(kat["signature_path"]),
                )
            return {
                "schema": "wuci-real-pq-verifier-summary-v1",
                "algorithm": algorithm,
                "binary_sha256": observed_sha256,
                "implementation_name": evidence.get("implementation_name"),
                "implementation_version": evidence.get("implementation_version"),
                "kat_verified": evidence.get("known_answer_test") is True,
                "pinned": True,
                "rerun": rerun,
                "standard_reference": evidence.get(
                    "standard_reference", STANDARD_REFERENCES.get(str(algorithm))
                ),
            }
    raise PQVerifierError("real PQ verifier evidence is not pinned as reviewed")


def run_verify_real(args: argparse.Namespace) -> int:
    verify_real_evidence(
        evidence_path=Path(args.evidence),
        pins_path=Path(args.pins),
        rerun=args.rerun,
    )
    if not args.quiet:
        print("wuci real PQ verifier evidence: PASS")
    return 0


def run_attest_real(args: argparse.Namespace) -> int:
    algorithm = args.algorithm
    if algorithm not in SIGNATURE_TARGETS:
        raise PQVerifierError("real PQ evidence must name an accepted PQ signature algorithm")
    verifier = Path(args.verifier).resolve(strict=True)
    public_key = Path(args.public_key).resolve(strict=True)
    message = Path(args.message).resolve(strict=True)
    signature = Path(args.signature).resolve(strict=True)
    run_external_verifier(
        verifier=verifier,
        algorithm=algorithm,
        public_key=public_key,
        message=message,
        signature=signature,
    )
    evidence = {
        "schema": "wuci-real-pq-verifier-evidence-v2",
        "algorithm": algorithm,
        "binary_path": str(verifier),
        "binary_sha256": sha256_file(verifier),
        "implementation_name": args.implementation_name,
        "implementation_version": args.implementation_version,
        "verifier_protocol": EXTERNAL_VERIFY_PROTOCOL,
        "standard_reference": STANDARD_REFERENCES.get(algorithm),
        "known_answer_test": True,
        "no_stub_mode": True,
        "offline_verification": True,
        "network_required": False,
        "kat": {
            "public_key_path": str(public_key),
            "public_key_sha256": sha256_file(public_key),
            "message_path": str(message),
            "message_sha256": sha256_file(message),
            "signature_path": str(signature),
            "signature_sha256": sha256_file(signature),
            "verified": True,
        },
        "quantum_safe_system_claim_allowed": False,
        "non_claims": [
            "passing one PQ KAT does not make WUCI-JI quantum-safe",
            "the external verifier must remain pinned and reviewed before release use",
            "this evidence does not replace an independent cryptographic audit",
        ],
    }
    write_json(Path(args.out), evidence)
    if args.require_pin:
        verify_real_evidence(
            evidence_path=Path(args.out),
            pins_path=Path(args.pins),
            rerun=False,
        )
    if not args.quiet:
        print(f"wrote real PQ verifier evidence: {args.out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect real local PQ verifier availability.")
    sub = parser.add_subparsers(dest="command", required=True)
    detect_parser = sub.add_parser("detect")
    detect_parser.add_argument("--out", required=True)
    detect_parser.add_argument("--require-real", action="store_true")
    detect_parser.add_argument("--quiet", action="store_true")
    detect_parser.set_defaults(func=run_detect)

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--evidence", required=True)
    verify_parser.add_argument("--require-real", action="store_true")
    verify_parser.add_argument("--quiet", action="store_true")
    verify_parser.set_defaults(func=run_verify)

    real_parser = sub.add_parser("verify-real")
    real_parser.add_argument("--evidence", required=True)
    real_parser.add_argument("--pins", default=str(PINS))
    real_parser.add_argument("--rerun", action="store_true")
    real_parser.add_argument("--quiet", action="store_true")
    real_parser.set_defaults(func=run_verify_real)

    attest_parser = sub.add_parser("attest-real")
    attest_parser.add_argument("--verifier", required=True)
    attest_parser.add_argument("--algorithm", required=True, choices=sorted(SIGNATURE_TARGETS))
    attest_parser.add_argument("--public-key", required=True)
    attest_parser.add_argument("--message", required=True)
    attest_parser.add_argument("--signature", required=True)
    attest_parser.add_argument("--implementation-name", required=True)
    attest_parser.add_argument("--implementation-version", required=True)
    attest_parser.add_argument("--out", required=True)
    attest_parser.add_argument("--pins", default=str(PINS))
    attest_parser.add_argument("--require-pin", action="store_true")
    attest_parser.add_argument("--quiet", action="store_true")
    attest_parser.set_defaults(func=run_attest_real)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, json.JSONDecodeError, PQVerifierError) as exc:
        print(f"wuci pq verifier: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
