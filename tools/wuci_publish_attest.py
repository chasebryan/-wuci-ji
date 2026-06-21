#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import wuci_authority_root as authority_root
import wuci_frost_authorize as warrant
import wuci_receipt_contract as receipt_contract


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "build" / "wuci-publish-bundle"
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))
ATTESTATION_SCHEMA = "wuci-publish-bundle-attestation-v1"
ACTION = "release"

BUNDLE_FILES = {
    "artifact_key": "artifact.key",
    "sealed_artifact": "wuci-ji.self.wj",
    "manifest": "manifest.txt",
    "warrant_message": "warrant-message.txt",
    "release_receipt": "release-receipt.json",
    "receipt_contract": "receipt-contract.txt",
    "authority_root": "authority-root.txt",
    "release_decision": "release-decision.txt",
}

BOUNDARY = {
    "gate_enforcement": "assembly-rooted-release-contract",
    "authority_schema": authority_root.ROOT_SCHEMA,
    "contract_schema": receipt_contract.CONTRACT_SCHEMA,
    "assembly_owned_surfaces": [
        "manifest-file",
        "warrant-message-file",
        "frost-secp256k1-challenge",
        "frost-secp256k1-verify",
        "authority-root-verify",
        "release-authorized-rooted",
    ],
    "non_goals": [
        "Do not parse receipt JSON in assembly.",
        "Do not accept arbitrary signer material.",
        "Do not accept non-release actions through release-authorized-rooted.",
        "Do not accept trust or publish authority bits yet.",
    ],
}


class PublishAttestationError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise PublishAttestationError(f"could not read {path}") from exc
    return digest.hexdigest()


def read_bytes(path: Path, context: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PublishAttestationError(f"could not read {context} {path}") from exc


def load_json_file(path: Path, context: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise PublishAttestationError(f"could not read {context} {path}") from exc
    except json.JSONDecodeError as exc:
        raise PublishAttestationError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_json_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise PublishAttestationError(f"refusing to overwrite existing attestation {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    try:
        tmp_path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def require_file(path: Path, context: str) -> None:
    if not path.is_file():
        raise PublishAttestationError(f"missing {context}: {path}")


def bundle_paths(bundle_dir: Path) -> dict[str, Path]:
    return {name: bundle_dir / rel for name, rel in BUNDLE_FILES.items()}


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def run_wuci(bin_path: Path, args: list[str]) -> bytes:
    try:
        proc = subprocess.run(
            [*RUNNER, str(bin_path), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise PublishAttestationError(f"could not execute {bin_path}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        detail = stderr or stdout or f"exit status {proc.returncode}"
        raise PublishAttestationError(f"{args[0]} failed: {detail}")
    return proc.stdout


def parse_decision(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ": " not in line:
            raise PublishAttestationError(f"release decision has unexpected line: {line!r}")
        label, value = line.split(": ", 1)
        if label in fields:
            raise PublishAttestationError(f"release decision duplicates label: {label}")
        fields[label] = value
    expected = (
        "authorized",
        "action",
        "artifact-sha256",
    )
    if tuple(fields) != expected:
        raise PublishAttestationError("release decision fields are not canonical")
    if fields["authorized"] != "true":
        raise PublishAttestationError("release decision is not authorized")
    if fields["action"] != ACTION:
        raise PublishAttestationError("release decision action is not release")
    return fields


def assert_current_manifest_and_warrant(
    *,
    bin_path: Path,
    artifact_path: Path,
    manifest_path: Path,
    warrant_message_path: Path,
) -> None:
    try:
        cli = warrant.WuciJi(bin_path)
        manifest_bytes = cli.run(["manifest-file", str(artifact_path)]).encode("ascii")
        warrant_bytes = cli.run(
            ["warrant-message-file", ACTION, str(artifact_path)]
        ).encode("ascii")
    except warrant.AuthorizationError as exc:
        raise PublishAttestationError(str(exc)) from exc
    if read_bytes(manifest_path, "manifest") != manifest_bytes:
        raise PublishAttestationError("manifest.txt does not match manifest-file output")
    if read_bytes(warrant_message_path, "warrant message") != warrant_bytes:
        raise PublishAttestationError(
            "warrant-message.txt does not match release warrant-message-file output"
        )


def assert_current_contract(
    *,
    bin_path: Path,
    artifact_path: Path,
    receipt_path: Path,
    contract_path: Path,
) -> dict[str, str]:
    try:
        actual_text = receipt_contract.read_ascii(contract_path, "receipt contract")
        actual_fields = receipt_contract.parse_contract(actual_text)
        expected_fields = receipt_contract.derive_contract(
            bin_path=bin_path,
            artifact_path=artifact_path,
            action=ACTION,
            receipt_path=receipt_path,
        )
        expected_text = receipt_contract.format_contract(expected_fields)
    except receipt_contract.ContractError as exc:
        raise PublishAttestationError(str(exc)) from exc
    for label in receipt_contract.CONTRACT_FIELDS:
        if actual_fields[label] != expected_fields[label]:
            raise PublishAttestationError(
                f"receipt contract field does not match derived value: {label}"
            )
    if actual_text != expected_text:
        raise PublishAttestationError("receipt contract bytes are not canonical")
    if actual_fields["action"] != ACTION:
        raise PublishAttestationError("receipt contract action is not release")
    return actual_fields


def assert_current_authority(
    *,
    authority_path: Path,
    contract_fields: dict[str, str],
) -> dict[str, str]:
    try:
        authority_fields = authority_root.parse_root(
            authority_root.read_ascii(authority_path, "authority root")
        )
    except authority_root.AuthorityRootError as exc:
        raise PublishAttestationError(str(exc)) from exc
    if authority_fields["allow-release"] != "true":
        raise PublishAttestationError("authority root does not allow release")
    if authority_fields["allow-trust"] != "false":
        raise PublishAttestationError("authority root must not allow trust")
    if authority_fields["allow-publish"] != "false":
        raise PublishAttestationError("authority root must not allow publish")
    if authority_fields["group-public-key"] != contract_fields["group-public-key"]:
        raise PublishAttestationError("authority root group key does not match receipt contract")
    return authority_fields


def assert_rooted_release_decision(
    *,
    bin_path: Path,
    authority_path: Path,
    artifact_path: Path,
    contract_path: Path,
    decision_path: Path,
) -> dict[str, str]:
    authority_stdout = run_wuci(
        bin_path,
        ["authority-root-verify", str(authority_path)],
    )
    if authority_stdout != b"valid\n":
        raise PublishAttestationError("authority-root-verify did not report valid")
    decision_bytes = run_wuci(
        bin_path,
        [
            "release-authorized-rooted",
            str(authority_path),
            str(artifact_path),
            str(contract_path),
        ],
    )
    recorded = read_bytes(decision_path, "release decision")
    if recorded != decision_bytes:
        raise PublishAttestationError("release-decision.txt does not match assembly output")
    try:
        return parse_decision(decision_bytes.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise PublishAttestationError("release decision is not ASCII") from exc


def build_attestation(*, bin_path: Path, bundle_dir: Path) -> dict[str, Any]:
    paths = bundle_paths(bundle_dir)
    for name, path in paths.items():
        require_file(path, name.replace("_", " "))

    assert_current_manifest_and_warrant(
        bin_path=bin_path,
        artifact_path=paths["sealed_artifact"],
        manifest_path=paths["manifest"],
        warrant_message_path=paths["warrant_message"],
    )
    contract_fields = assert_current_contract(
        bin_path=bin_path,
        artifact_path=paths["sealed_artifact"],
        receipt_path=paths["release_receipt"],
        contract_path=paths["receipt_contract"],
    )
    authority_fields = assert_current_authority(
        authority_path=paths["authority_root"],
        contract_fields=contract_fields,
    )
    decision = assert_rooted_release_decision(
        bin_path=bin_path,
        authority_path=paths["authority_root"],
        artifact_path=paths["sealed_artifact"],
        contract_path=paths["receipt_contract"],
        decision_path=paths["release_decision"],
    )

    hashes = {name: sha256_file(path) for name, path in paths.items()}
    receipt = load_json_file(paths["release_receipt"], "release receipt")
    if not isinstance(receipt, dict):
        raise PublishAttestationError("release receipt must be a JSON object")
    if receipt.get("action") != ACTION:
        raise PublishAttestationError("release receipt action is not release")
    if receipt.get("artifact_manifest_sha256") != hashes["manifest"]:
        raise PublishAttestationError("release receipt manifest hash does not match manifest")
    if receipt.get("authorization_message_sha256") != hashes["warrant_message"]:
        raise PublishAttestationError(
            "release receipt authorization message hash does not match warrant message"
        )
    if contract_fields["artifact-sha256"] != hashes["sealed_artifact"]:
        raise PublishAttestationError("contract artifact hash does not match artifact")
    if contract_fields["artifact-manifest-sha256"] != hashes["manifest"]:
        raise PublishAttestationError("contract manifest hash does not match manifest")
    if contract_fields["authorization-message-sha256"] != hashes["warrant_message"]:
        raise PublishAttestationError("contract message hash does not match warrant")
    if decision["artifact-sha256"] != hashes["sealed_artifact"]:
        raise PublishAttestationError("release decision artifact hash does not match artifact")

    checks = {
        "manifest_matches_assembly": True,
        "release_warrant_message_matches_assembly": True,
        "release_receipt_contract_matches_receipt": True,
        "authority_root_check": True,
        "release_authority_allows_release": True,
        "release_authority_matches_contract": True,
        "rooted_release_check": True,
        "release_decision_matches_assembly": True,
        "publish_bundle_complete": True,
    }

    return {
        "schema": ATTESTATION_SCHEMA,
        "production": False,
        "action": ACTION,
        "summary": (
            "Wuci-ji produced a rooted, assembly-enforced release decision "
            "and sealed it into an independently auditable publish bundle."
        ),
        "paths": {name: display_path(path) for name, path in paths.items()},
        "sha256": hashes,
        "release_decision": decision,
        "release_authority_root_sha256": hashes["authority_root"],
        "release_authority_group_public_key": authority_fields["group-public-key"],
        "release_contract_sha256": hashes["receipt_contract"],
        "release_decision_sha256": hashes["release_decision"],
        "rooted_release_check": True,
        "publish_bundle_complete": True,
        "checks": checks,
        "boundary": BOUNDARY,
    }


def compare_attestations(expected: Any, observed: dict[str, Any]) -> None:
    if not isinstance(expected, dict):
        raise PublishAttestationError("publish attestation must be a JSON object")
    if expected != observed:
        raise PublishAttestationError("publish attestation does not match bundle state")


def run_attest(args: argparse.Namespace) -> int:
    attestation_path = Path(args.attestation)
    attestation = build_attestation(
        bin_path=Path(args.bin),
        bundle_dir=Path(args.bundle_dir),
    )
    write_json_new(attestation_path, attestation)
    print(f"wrote publish attestation: {display_path(attestation_path)}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    attestation_path = Path(args.attestation)
    observed = build_attestation(
        bin_path=Path(args.bin),
        bundle_dir=Path(args.bundle_dir),
    )
    expected = load_json_file(attestation_path, "publish attestation")
    compare_attestations(expected, observed)
    print(f"valid publish attestation: {display_path(attestation_path)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify rooted WUCI publish bundle attestations."
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    parser.add_argument(
        "--bundle-dir",
        default=str(DEFAULT_BUNDLE_DIR),
        help="publish bundle directory",
    )
    parser.add_argument(
        "--attestation",
        default=str(DEFAULT_BUNDLE_DIR / "attestation.json"),
        help="publish bundle attestation JSON path",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("attest", help="write a new publish attestation")
    subparsers.add_parser("verify", help="verify an existing publish attestation")
    args = parser.parse_args()

    try:
        if args.command == "attest":
            return run_attest(args)
        if args.command == "verify":
            return run_verify(args)
        raise PublishAttestationError(f"unsupported command: {args.command}")
    except PublishAttestationError as exc:
        print(f"wuci publish: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
