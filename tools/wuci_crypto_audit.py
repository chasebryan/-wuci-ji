#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import wuci_safeio


CRYPTO_SOURCES = (
    "src/sha256.s",
    "src/hmac_hkdf.s",
    "src/secp256k1_field.s",
    "src/secp256k1_scalar.s",
    "src/secp256k1_point.s",
    "src/frost.s",
    "src/x25519.s",
    "src/wuci-ji.s",
    "src/gate_contract.s",
    "src/regression.s",
    "src/sandbox.s",
)
REQUIRED_TARGETS = (
    "asm-smoke",
    "asm-regression",
    "check-asm-immediates",
    "test-linux",
    "qcage-policy-matrix",
    "pq-verifier-test",
    "kernel-sandbox-proof",
    "rust-sandbox-test",
)


class CryptoAuditError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(wuci_safeio.read_regular_bytes(path, "crypto audit source", reject_symlink=True, reject_hardlink=True))
    return h.hexdigest()


def file_record(repo: Path, rel: str) -> dict[str, Any]:
    path = repo / rel
    if not path.is_file():
        raise CryptoAuditError(f"missing crypto source: {rel}")
    return {"path": rel, "sha256": sha256_file(path), "size": path.stat().st_size}


def build_audit(repo: Path) -> dict[str, Any]:
    return {
        "schema": "wuci-crypto-self-audit-v1",
        "status": "internal-self-audit-evidence-not-external-certification",
        "external_audit": False,
        "production_sufficient": False,
        "source_files": [file_record(repo, rel) for rel in CRYPTO_SOURCES],
        "required_targets": list(REQUIRED_TARGETS),
        "non_claims": [
            "self-audit is not an independent cryptographic audit",
            "known-answer tests are not constant-time certification",
            "classical crypto evidence is not quantum-safe evidence",
        ],
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    wuci_safeio.atomic_replace_text(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        "crypto self-audit evidence",
        mode=0o644,
    )


def run_emit(args: argparse.Namespace) -> int:
    write_json(Path(args.out), build_audit(Path(args.repo)))
    if not args.quiet:
        print(f"wrote crypto self-audit: {args.out}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    observed = json.loads(
        wuci_safeio.read_regular_bytes(
            Path(args.audit),
            "crypto self-audit evidence",
            reject_symlink=True,
            reject_hardlink=True,
        ).decode("utf-8")
    )
    expected = build_audit(Path(args.repo))
    if observed != expected:
        raise CryptoAuditError("crypto self-audit evidence does not match repository state")
    if observed["external_audit"] is not False or observed["production_sufficient"] is not False:
        raise CryptoAuditError("self-audit must not claim production sufficiency")
    if not args.quiet:
        print("wuci crypto self-audit: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit and verify WUCI crypto self-audit evidence.")
    sub = parser.add_subparsers(dest="command", required=True)
    emit = sub.add_parser("emit")
    emit.add_argument("--repo", default=".")
    emit.add_argument("--out", required=True)
    emit.add_argument("--quiet", action="store_true")
    emit.set_defaults(func=run_emit)

    verify = sub.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--audit", required=True)
    verify.add_argument("--quiet", action="store_true")
    verify.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, json.JSONDecodeError, CryptoAuditError) as exc:
        print(f"wuci crypto audit: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
