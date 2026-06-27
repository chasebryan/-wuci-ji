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


class PQVerifierError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


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


def run_verify_real(args: argparse.Namespace) -> int:
    evidence = load_json(Path(args.evidence))
    pins = load_json(Path(args.pins))
    if not isinstance(evidence, dict):
        raise PQVerifierError("real PQ verifier evidence must be a JSON object")
    if pins.get("schema") != "wuci-pq-verifier-pins-v1":
        raise PQVerifierError("unsupported PQ verifier pins schema")
    if evidence.get("schema") != "wuci-real-pq-verifier-evidence-v1":
        raise PQVerifierError("unsupported real PQ verifier evidence schema")
    algorithm = evidence.get("algorithm")
    if algorithm not in SIGNATURE_TARGETS:
        raise PQVerifierError("real PQ evidence must name an accepted PQ signature algorithm")
    if evidence.get("known_answer_test") is not True:
        raise PQVerifierError("real PQ evidence must include a passing KAT")
    if evidence.get("no_stub_mode") is not True:
        raise PQVerifierError("real PQ evidence must reject stub mode")
    if evidence.get("offline_verification") is not True:
        raise PQVerifierError("real PQ evidence must be offline")
    binary_path = Path(str(evidence.get("binary_path", "")))
    if not binary_path.is_file():
        raise PQVerifierError("real PQ verifier binary is missing")
    observed_sha256 = sha256_file(binary_path)
    if evidence.get("binary_sha256") != observed_sha256:
        raise PQVerifierError("real PQ verifier binary digest mismatch")
    allowed = pins.get("allowed_verifiers")
    if not isinstance(allowed, list):
        raise PQVerifierError("PQ verifier pins must contain allowed_verifiers")
    for pin in allowed:
        if not isinstance(pin, dict):
            continue
        if pin.get("binary_sha256") == observed_sha256 and pin.get("algorithm") == algorithm:
            if not args.quiet:
                print("wuci real PQ verifier evidence: PASS")
            return 0
    raise PQVerifierError("real PQ verifier evidence is not pinned as reviewed")


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
    real_parser.add_argument("--quiet", action="store_true")
    real_parser.set_defaults(func=run_verify_real)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, json.JSONDecodeError, PQVerifierError) as exc:
        print(f"wuci pq verifier: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
