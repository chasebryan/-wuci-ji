#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import wuci_authority_root as authority_root
import wuci_receipt_contract as receipt_contract
import wuci_safeio


REPO_ROOT = Path(__file__).resolve().parents[1]
ANCHOR_RELATIVE_PATH = Path("authority/wuci-root.fixture.txt")
ANCHOR_SHA256_RELATIVE_PATH = Path("authority/wuci-root.fixture.sha256")
RELEASE_ANCHOR_RELATIVE_PATH = Path("authority/wuci-release-root.fixture.txt")
RELEASE_ANCHOR_SHA256_RELATIVE_PATH = Path("authority/wuci-release-root.fixture.sha256")
FIXTURE_GROUP_PUBLIC_KEY = (
    "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
)
FIXTURE_AUTHORITY_SHA256 = "64bbc230cc15f770b457b779e3c7002128fd27ae4bed0afbaa8375d62960d1d3"
FIXTURE_RELEASE_AUTHORITY_SHA256 = "d50c0be237fadddc4f22c69d912567b318cd235b2b4bd0aeff851b54d126ae1f"


class AuthorityAnchorError(RuntimeError):
    pass


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    try:
        return wuci_safeio.sha256_file(path)
    except wuci_safeio.SafeIOError as exc:
        raise AuthorityAnchorError(str(exc)) from exc


def anchor_paths(action: str) -> tuple[Path, Path, str]:
    if action == "open":
        return ANCHOR_RELATIVE_PATH, ANCHOR_SHA256_RELATIVE_PATH, FIXTURE_AUTHORITY_SHA256
    if action == "release":
        return (
            RELEASE_ANCHOR_RELATIVE_PATH,
            RELEASE_ANCHOR_SHA256_RELATIVE_PATH,
            FIXTURE_RELEASE_AUTHORITY_SHA256,
        )
    raise AuthorityAnchorError(f"unsupported anchor action: {action}")


def require_repo_fixture_path(path: Path, expected_relative: Path) -> None:
    try:
        relative = path.resolve().relative_to(REPO_ROOT)
    except ValueError as exc:
        raise AuthorityAnchorError(
            f"authority anchor must be {expected_relative}"
        ) from exc
    if relative != expected_relative:
        raise AuthorityAnchorError(
            f"authority anchor must be {expected_relative}"
        )


def verify_sha256_sidecar(
    authority_path: Path,
    sha256_path: Path,
    expected_relative: Path,
    expected_digest: str,
) -> str:
    try:
        sidecar = wuci_safeio.read_regular_ascii(
            sha256_path,
            "authority root SHA-256",
            reject_symlink=True,
        )
    except wuci_safeio.SafeIOError as exc:
        raise AuthorityAnchorError(str(exc)) from exc
    actual_digest = sha256_file(authority_path)
    if actual_digest != expected_digest:
        raise AuthorityAnchorError("authority root bytes do not match the fixture digest")
    expected = f"{expected_digest}  {expected_relative}\n"
    if sidecar != expected:
        raise AuthorityAnchorError("authority root SHA-256 sidecar does not match anchor")
    return expected.split(" ", 1)[0]


def parse_authority(path: Path) -> dict[str, str]:
    try:
        return authority_root.parse_root(
            authority_root.read_ascii(path, "authority root")
        )
    except authority_root.AuthorityRootError as exc:
        raise AuthorityAnchorError(str(exc)) from exc


def parse_contract(path: Path) -> dict[str, str]:
    try:
        return receipt_contract.parse_contract(
            receipt_contract.read_ascii(path, "receipt contract")
        )
    except receipt_contract.ContractError as exc:
        raise AuthorityAnchorError(str(exc)) from exc


def verify_anchor(
    *,
    authority_path: Path,
    contract_path: Path | None,
    strict_fixture_path: bool,
    sha256_path: Path,
    action: str,
) -> dict[str, str]:
    expected_authority_path, expected_sha256_path, expected_digest = anchor_paths(action)
    if strict_fixture_path:
        require_repo_fixture_path(authority_path, expected_authority_path)
        require_repo_fixture_path(REPO_ROOT / expected_authority_path, expected_authority_path)
        if sha256_path.resolve() != (REPO_ROOT / expected_sha256_path).resolve():
            raise AuthorityAnchorError(
                f"authority root SHA-256 must be {expected_sha256_path}"
            )
        verify_sha256_sidecar(
            authority_path,
            sha256_path,
            expected_authority_path,
            expected_digest,
        )

    fields = parse_authority(authority_path)
    if fields["group-public-key"] != FIXTURE_GROUP_PUBLIC_KEY:
        raise AuthorityAnchorError("authority anchor group key is not the fixture key")
    if action == "open" and fields["allow-open"] != "true":
        raise AuthorityAnchorError("authority anchor must allow open")
    if action == "release" and fields["allow-open"] != "false":
        raise AuthorityAnchorError("release authority anchor must not allow open")
    if action == "open" and fields["allow-release"] != "false":
        raise AuthorityAnchorError("authority anchor must not allow release")
    if action == "release" and fields["allow-release"] != "true":
        raise AuthorityAnchorError("release authority anchor must allow release")
    if fields["allow-trust"] != "false":
        raise AuthorityAnchorError("authority anchor must not allow trust")
    if fields["allow-publish"] != "false":
        raise AuthorityAnchorError("authority anchor must not allow publish")

    if contract_path is not None:
        contract = parse_contract(contract_path)
        if contract["action"] != action:
            raise AuthorityAnchorError("receipt contract action does not match anchor action")
        if contract["group-public-key"] != fields["group-public-key"]:
            raise AuthorityAnchorError(
                "receipt contract group key does not match authority anchor"
            )
    return fields


def run_check(args: argparse.Namespace) -> int:
    authority_path = Path(args.authority)
    fields = verify_anchor(
        authority_path=authority_path,
        contract_path=Path(args.contract) if args.contract else None,
        strict_fixture_path=args.strict_fixture_path,
        sha256_path=Path(args.sha256),
        action=args.action,
    )
    if not args.quiet:
        print("valid")
        print(f"authority-root: {display_path(authority_path)}")
        print(f"authority-id: {fields['authority-id']}")
        print(f"group-public-key: {fields['group-public-key']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the committed WUCI-ANCHOR authority root."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="verify an authority anchor")
    check.add_argument(
        "--authority",
        default=str(REPO_ROOT / ANCHOR_RELATIVE_PATH),
        help="authority root path",
    )
    check.add_argument(
        "--sha256",
        default=str(REPO_ROOT / ANCHOR_SHA256_RELATIVE_PATH),
        help="authority root SHA-256 sidecar",
    )
    check.add_argument(
        "--action",
        choices=("open", "release"),
        default="open",
        help="anchored action policy to require; defaults to open",
    )
    check.add_argument(
        "--contract",
        help="optional receipt contract that must answer to the anchor",
    )
    check.add_argument(
        "--strict-fixture-path",
        action="store_true",
        help="require the committed fixture path and SHA-256 sidecar",
    )
    check.add_argument("--quiet", action="store_true", help="suppress success output")

    args = parser.parse_args()
    try:
        if args.command == "check":
            return run_check(args)
        raise AuthorityAnchorError(f"unsupported command: {args.command}")
    except AuthorityAnchorError as exc:
        print(f"wuci authority anchor: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
