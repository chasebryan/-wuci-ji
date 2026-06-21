#!/usr/bin/env python3
from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import wuci_frost_authorize as warrant
import wuci_gate


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "build" / "wuci-self-release-demo"
ATTESTATION_SCHEMA = "wuci-self-release-attestation-v1"
ACTION = "open"

BOUNDARY = {
    "gate_enforcement": "python-preview",
    "assembly_owned_surfaces": [
        "manifest-file",
        "warrant-message-file",
        "frost-secp256k1-challenge",
        "frost-secp256k1-verify",
        "open-file-keyfile",
    ],
    "non_goals": [
        "Do not add assembly open-authorized yet.",
        "Do not parse receipt JSON in assembly yet.",
        "Do not accept arbitrary signer material yet.",
    ],
}

BUNDLE_FILES = {
    "artifact_key": "artifact.key",
    "sealed_artifact": "wuci-ji.self.wj",
    "manifest": "manifest.txt",
    "warrant_message": "warrant-message.txt",
    "receipt": "auth-receipt.json",
    "opened_binary": "opened-wuci-ji",
}


class SelfReleaseError(RuntimeError):
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
        raise SelfReleaseError(f"could not read {path}") from exc
    return digest.hexdigest()


def read_bytes(path: Path, context: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SelfReleaseError(f"could not read {context} {path}") from exc


def load_json_file(path: Path, context: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise SelfReleaseError(f"could not read {context} {path}") from exc
    except json.JSONDecodeError as exc:
        raise SelfReleaseError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_json_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise SelfReleaseError(f"refusing to overwrite existing attestation {path}")
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
        raise SelfReleaseError(f"missing {context}: {path}")


def bundle_paths(bundle_dir: Path, original_bin: Path) -> dict[str, Path]:
    paths = {name: bundle_dir / rel for name, rel in BUNDLE_FILES.items()}
    paths["original_binary"] = original_bin
    return paths


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def run_opened_help(opened_binary: Path) -> None:
    try:
        proc = subprocess.run(
            [str(opened_binary), "--help"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise SelfReleaseError(f"opened binary could not execute: {opened_binary}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        detail = stderr or f"exit status {proc.returncode}"
        raise SelfReleaseError(f"opened binary --help failed: {detail}")


def assert_current_manifest_and_warrant(
    *,
    bin_path: Path,
    artifact_path: Path,
    manifest_path: Path,
    warrant_message_path: Path,
) -> None:
    cli = warrant.WuciJi(bin_path)
    try:
        manifest_bytes = cli.run(["manifest-file", str(artifact_path)]).encode("ascii")
        warrant_bytes = cli.run(
            ["warrant-message-file", ACTION, str(artifact_path)]
        ).encode("ascii")
    except warrant.AuthorizationError as exc:
        raise SelfReleaseError(str(exc)) from exc
    if read_bytes(manifest_path, "manifest") != manifest_bytes:
        raise SelfReleaseError("manifest.txt does not match manifest-file output")
    if read_bytes(warrant_message_path, "warrant message") != warrant_bytes:
        raise SelfReleaseError(
            "warrant-message.txt does not match warrant-message-file output"
        )


def reproduce_gate_open(
    *,
    bin_path: Path,
    artifact_path: Path,
    receipt_path: Path,
    keyfile_path: Path,
    opened_binary: Path,
) -> None:
    try:
        wuci_gate.gate_decision(
            bin_path=bin_path,
            artifact_path=artifact_path,
            action=ACTION,
            receipt_path=receipt_path,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            reproduced = Path(temp_dir) / "opened-wuci-ji"
            wuci_gate.validate_output_path(reproduced)
            wuci_gate.run_open_file_keyfile(
                bin_path=bin_path,
                keyfile_path=keyfile_path,
                artifact_path=artifact_path,
                out_path=reproduced,
            )
            if not filecmp.cmp(opened_binary, reproduced, shallow=False):
                raise SelfReleaseError(
                    "gate-opened reproduction does not match opened binary"
                )
    except wuci_gate.GateError as exc:
        raise SelfReleaseError(str(exc)) from exc


def gate_decision(
    *,
    bin_path: Path,
    artifact_path: Path,
    receipt_path: Path,
) -> dict[str, str]:
    try:
        return wuci_gate.gate_decision(
            bin_path=bin_path,
            artifact_path=artifact_path,
            action=ACTION,
            receipt_path=receipt_path,
        )
    except wuci_gate.GateError as exc:
        raise SelfReleaseError(str(exc)) from exc


def build_attestation(
    *,
    bin_path: Path,
    bundle_dir: Path,
) -> dict[str, Any]:
    paths = bundle_paths(bundle_dir, bin_path)
    for name, path in paths.items():
        require_file(path, name.replace("_", " "))

    assert_current_manifest_and_warrant(
        bin_path=bin_path,
        artifact_path=paths["sealed_artifact"],
        manifest_path=paths["manifest"],
        warrant_message_path=paths["warrant_message"],
    )
    decision = gate_decision(
        bin_path=bin_path,
        artifact_path=paths["sealed_artifact"],
        receipt_path=paths["receipt"],
    )
    reproduce_gate_open(
        bin_path=bin_path,
        artifact_path=paths["sealed_artifact"],
        receipt_path=paths["receipt"],
        keyfile_path=paths["artifact_key"],
        opened_binary=paths["opened_binary"],
    )

    original_sha256 = sha256_file(paths["original_binary"])
    opened_sha256 = sha256_file(paths["opened_binary"])
    if original_sha256 != opened_sha256:
        raise SelfReleaseError("opened binary is not byte-identical to original binary")
    run_opened_help(paths["opened_binary"])

    hashes = {
        "artifact_key": sha256_file(paths["artifact_key"]),
        "sealed_artifact": sha256_file(paths["sealed_artifact"]),
        "manifest": sha256_file(paths["manifest"]),
        "warrant_message": sha256_file(paths["warrant_message"]),
        "receipt": sha256_file(paths["receipt"]),
        "original_binary": original_sha256,
        "opened_binary": opened_sha256,
    }

    receipt = load_json_file(paths["receipt"], "authorization receipt")
    if not isinstance(receipt, dict):
        raise SelfReleaseError("authorization receipt must be a JSON object")
    if receipt.get("artifact_manifest_sha256") != hashes["manifest"]:
        raise SelfReleaseError("receipt artifact manifest hash does not match manifest")
    if receipt.get("authorization_message_sha256") != hashes["warrant_message"]:
        raise SelfReleaseError(
            "receipt authorization message hash does not match warrant message"
        )
    if decision["artifact-sha256"] != hashes["sealed_artifact"]:
        raise SelfReleaseError("gate decision artifact hash does not match artifact")
    if decision["authorization-message-sha256"] != hashes["warrant_message"]:
        raise SelfReleaseError("gate decision message hash does not match warrant")
    if decision["receipt-sha256"] != hashes["receipt"]:
        raise SelfReleaseError("gate decision receipt hash does not match receipt")

    return {
        "schema": ATTESTATION_SCHEMA,
        "production": False,
        "action": ACTION,
        "summary": (
            "Wuci-ji sealed itself, warranted itself, passed its own gate, "
            "and opened to a byte-identical executable copy."
        ),
        "paths": {name: display_path(path) for name, path in paths.items()},
        "sha256": hashes,
        "gate_decision": decision,
        "checks": {
            "manifest_matches_assembly": True,
            "warrant_message_matches_assembly": True,
            "gate_check": True,
            "gate_open_reproduced": True,
            "byte_identical": True,
            "opened_executable": True,
        },
        "boundary": BOUNDARY,
    }


def compare_attestations(expected: Any, observed: dict[str, Any]) -> None:
    if not isinstance(expected, dict):
        raise SelfReleaseError("self-release attestation must be a JSON object")
    if expected != observed:
        raise SelfReleaseError("self-release attestation does not match bundle state")


def run_attest(args: argparse.Namespace) -> int:
    attestation_path = Path(args.attestation)
    attestation = build_attestation(
        bin_path=Path(args.bin),
        bundle_dir=Path(args.bundle_dir),
    )
    write_json_new(attestation_path, attestation)
    print(f"wrote self-release attestation: {display_path(attestation_path)}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    attestation_path = Path(args.attestation)
    observed = build_attestation(
        bin_path=Path(args.bin),
        bundle_dir=Path(args.bundle_dir),
    )
    expected = load_json_file(attestation_path, "self-release attestation")
    compare_attestations(expected, observed)
    print(f"valid self-release attestation: {display_path(attestation_path)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify WUCI self-release attestation bundles."
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    parser.add_argument(
        "--bundle-dir",
        default=str(DEFAULT_BUNDLE_DIR),
        help="self-release bundle directory",
    )
    parser.add_argument(
        "--attestation",
        default=str(DEFAULT_BUNDLE_DIR / "attestation.json"),
        help="self-release attestation JSON path",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("attest", help="write a new self-release attestation")
    subparsers.add_parser("verify", help="verify an existing self-release attestation")
    args = parser.parse_args()

    try:
        if args.command == "attest":
            return run_attest(args)
        if args.command == "verify":
            return run_verify(args)
        raise SelfReleaseError(f"unsupported command: {args.command}")
    except SelfReleaseError as exc:
        print(f"wuci self-release: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
