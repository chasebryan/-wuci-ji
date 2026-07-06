#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import sys
from pathlib import Path

import wuci_safeio


ALLOWED_RUNNERS = ("", "qemu-x86_64")
IDENTITY_SCHEMA = "wuci-verifier-identity-v1"


class VerifierIdentityError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    try:
        return wuci_safeio.sha256_file(path)
    except wuci_safeio.SafeIOError as exc:
        raise VerifierIdentityError(str(exc)) from exc


def canonical_bin_path(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise VerifierIdentityError(f"verifier binary does not exist: {path}") from exc


def runner_string(runner: str | None = None) -> str:
    if runner is not None:
        return runner.strip()
    return os.environ.get("WUCI_JI_RUNNER", "").strip()


def validate_runner(
    runner: str | None,
    *,
    strict: bool = False,
    allowed_extra: tuple[str, ...] = (),
) -> str:
    value = runner_string(runner)
    parts = shlex.split(value)
    normalized = " ".join(parts)
    if normalized == "":
        return ""
    if normalized in ALLOWED_RUNNERS or normalized in allowed_extra:
        return normalized
    if (
        len(parts) == 3
        and parts[0] == "qemu-x86_64"
        and parts[1] == "-cpu"
        and re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", parts[2])
    ):
        return normalized
    mode = "strict mode" if strict else "proof mode"
    raise VerifierIdentityError(f"runner is not approved in {mode}: {normalized}")


def require_trusted_verifier(
    bin_path: Path,
    trusted_sha256: str | None,
    runner: str | None,
    *,
    strict: bool,
) -> str:
    actual = sha256_file(canonical_bin_path(bin_path))
    validate_runner(runner, strict=strict)
    if strict:
        if not trusted_sha256:
            raise VerifierIdentityError("strict proof requires --trusted-bin-sha256")
        if trusted_sha256 != actual:
            raise VerifierIdentityError("verifier binary SHA-256 does not match trusted pin")
    return actual


def is_strict(flag: bool = False) -> bool:
    return flag or os.environ.get("WUCI_STRICT") == "1"


def add_strict_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--strict-proof",
        action="store_true",
        help="enforce strict proof-chain verifier identity checks",
    )
    parser.add_argument(
        "--trusted-bin-sha256",
        help="trusted SHA-256 of the verifier binary required in strict mode",
    )


def enforce_args(args: argparse.Namespace, bin_path: Path) -> str:
    return require_trusted_verifier(
        bin_path,
        getattr(args, "trusted_bin_sha256", None),
        os.environ.get("WUCI_JI_RUNNER", ""),
        strict=is_strict(getattr(args, "strict_proof", False)),
    )


def run_identity(args: argparse.Namespace) -> int:
    path = canonical_bin_path(Path(args.bin))
    runner = validate_runner(args.runner, strict=False)
    print(f"schema: {IDENTITY_SCHEMA}")
    print(f"bin-path: {path}")
    print(f"bin-sha256: {sha256_file(path)}")
    print(f"runner: {runner}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    require_trusted_verifier(
        Path(args.bin),
        args.trusted_bin_sha256,
        args.runner,
        strict=True,
    )
    print("valid")
    return 0


def run_check_runner(args: argparse.Namespace) -> int:
    runner = validate_runner(
        args.runner,
        strict=True,
        allowed_extra=tuple(args.allow_runner or ()),
    )
    print(f"runner: {runner}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify wuci-ji binary identity.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity", help="print verifier identity")
    identity.add_argument("--bin", required=True)
    identity.add_argument("--runner", default=os.environ.get("WUCI_JI_RUNNER", ""))
    identity.set_defaults(func=run_identity)

    verify = subparsers.add_parser("verify", help="verify a pinned verifier hash")
    verify.add_argument("--bin", required=True)
    verify.add_argument("--trusted-bin-sha256", required=True)
    verify.add_argument("--runner", default=os.environ.get("WUCI_JI_RUNNER", ""))
    verify.set_defaults(func=run_verify)

    check_runner = subparsers.add_parser("check-runner", help="validate proof runner")
    check_runner.add_argument("--runner", default=os.environ.get("WUCI_JI_RUNNER", ""))
    check_runner.add_argument(
        "--allow-runner",
        action="append",
        help="explicitly allow an additional runner string for this check",
    )
    check_runner.set_defaults(func=run_check_runner)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (VerifierIdentityError, wuci_safeio.SafeIOError) as exc:
        print(f"wuci verifier identity: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
