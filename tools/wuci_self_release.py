#!/usr/bin/env python3
from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import wuci_frost_authorize as warrant
import wuci_authority_root as authority_root
import wuci_gate
import wuci_receipt_contract as receipt_contract
import wuci_safeio
import wuci_verifier_identity


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "build" / "wuci-self-release-demo"
DEFAULT_CONTRACT_BIN = REPO_ROOT / "build" / "wuci-gate-contract"
RUNNER = shlex.split(wuci_verifier_identity.validate_runner(os.environ.get("WUCI_JI_RUNNER", ""), strict=False))
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
        "Do not parse receipt JSON in assembly.",
        "Do not accept arbitrary signer material.",
        "Do not make Python the canonical authorization-message owner.",
    ],
}
CONTRACT_BOUNDARY = {
    **BOUNDARY,
    "gate_enforcement": "zig-flat-contract-preview",
    "contract_schema": receipt_contract.CONTRACT_SCHEMA,
    "contract_verifier": "tools/wuci_gate_contract.zig",
}
ASM_CONTRACT_BOUNDARY = {
    **BOUNDARY,
    "gate_enforcement": "assembly-flat-contract",
    "assembly_owned_surfaces": [
        *BOUNDARY["assembly_owned_surfaces"],
        "gate-contract-verify",
        "open-authorized-contract",
    ],
    "contract_schema": receipt_contract.CONTRACT_SCHEMA,
    "contract_verifier": "gate-contract-verify + open-authorized-contract",
    "non_goals": [
        "Do not parse receipt JSON in assembly.",
        "Do not accept arbitrary signer material.",
        "Do not accept non-open actions through open-authorized-contract.",
    ],
}
ROOTED_ASM_CONTRACT_BOUNDARY = {
    **BOUNDARY,
    "gate_enforcement": "assembly-rooted-flat-contract",
    "authority_schema": authority_root.ROOT_SCHEMA,
    "contract_schema": receipt_contract.CONTRACT_SCHEMA,
    "assembly_owned_surfaces": [
        *BOUNDARY["assembly_owned_surfaces"],
        "authority-root-verify",
        "gate-contract-verify-rooted",
        "open-authorized-rooted",
    ],
    "contract_verifier": "authority-root-verify + gate-contract-verify-rooted + open-authorized-rooted",
    "non_goals": [
        "Do not parse receipt JSON in assembly.",
        "Do not accept arbitrary signer material.",
        "Do not accept non-open actions through open-authorized-rooted.",
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
        for chunk in wuci_safeio.iter_regular_chunks(path, str(path), reject_hardlink=True):
            digest.update(chunk)
    except wuci_safeio.SafeIOError as exc:
        raise SelfReleaseError(f"could not read {path}") from exc
    return digest.hexdigest()


def read_bytes(path: Path, context: str) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(path, context, reject_hardlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise SelfReleaseError(f"could not read {context} {path}") from exc


def load_json_file(path: Path, context: str) -> Any:
    try:
        return json.loads(read_bytes(path, context).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise SelfReleaseError(f"{context} is not UTF-8: {path}") from exc
    except wuci_safeio.SafeIOError as exc:
        raise SelfReleaseError(f"could not read {context} {path}") from exc
    except json.JSONDecodeError as exc:
        raise SelfReleaseError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_json_new(path: Path, value: dict[str, Any]) -> None:
    try:
        wuci_safeio.write_new_text(
            path,
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            "self-release attestation",
            mode=0o644,
        )
    except wuci_safeio.SafeIOError as exc:
        raise SelfReleaseError(str(exc)) from exc


def require_file(path: Path, context: str) -> None:
    try:
        wuci_safeio.require_regular_file(path, context, reject_hardlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise SelfReleaseError(str(exc)) from exc


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
            [*RUNNER, str(opened_binary), "--help"],
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


def assert_current_contract(
    *,
    bin_path: Path,
    artifact_path: Path,
    receipt_path: Path,
    contract_path: Path,
) -> None:
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
        raise SelfReleaseError(str(exc)) from exc
    for label in receipt_contract.CONTRACT_FIELDS:
        if actual_fields[label] != expected_fields[label]:
            raise SelfReleaseError(
                f"receipt contract field does not match derived value: {label}"
            )
    if actual_text != expected_text:
        raise SelfReleaseError("receipt contract bytes are not canonical")


def assert_current_authority(
    *,
    authority_path: Path,
    contract_path: Path,
) -> dict[str, str]:
    try:
        authority_fields = authority_root.parse_root(
            authority_root.read_ascii(authority_path, "authority root")
        )
        contract_fields = receipt_contract.parse_contract(
            receipt_contract.read_ascii(contract_path, "receipt contract")
        )
    except authority_root.AuthorityRootError as exc:
        raise SelfReleaseError(str(exc)) from exc
    except receipt_contract.ContractError as exc:
        raise SelfReleaseError(str(exc)) from exc
    if authority_fields["group-public-key"] != contract_fields["group-public-key"]:
        raise SelfReleaseError("authority root group key does not match receipt contract")
    return authority_fields


def run_zig_contract(
    *,
    contract_bin_path: Path,
    command: str,
    bin_path: Path,
    artifact_path: Path,
    receipt_path: Path,
    contract_path: Path,
    keyfile_path: Path | None = None,
    out_path: Path | None = None,
) -> bytes:
    args = [
        str(contract_bin_path),
        command,
        "--bin",
        str(bin_path),
        "--artifact",
        str(artifact_path),
        "--receipt",
        str(receipt_path),
        "--contract",
        str(contract_path),
    ]
    if command == "open":
        if keyfile_path is None or out_path is None:
            raise SelfReleaseError("zig contract open requires keyfile and output path")
        args.extend(["--keyfile", str(keyfile_path), "--out", str(out_path)])
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise SelfReleaseError(
            f"could not execute Zig gate contract verifier: {contract_bin_path}"
        ) from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        detail = stderr or f"exit status {proc.returncode}"
        raise SelfReleaseError(f"zig gate contract {command} failed: {detail}")
    if proc.stdout != b"valid\n":
        raise SelfReleaseError(f"zig gate contract {command} did not report valid")
    return proc.stdout


def reproduce_zig_contract_open(
    *,
    contract_bin_path: Path,
    bin_path: Path,
    artifact_path: Path,
    receipt_path: Path,
    contract_path: Path,
    keyfile_path: Path,
    opened_binary: Path,
) -> None:
    require_file(contract_bin_path, "Zig gate contract verifier")
    run_zig_contract(
        contract_bin_path=contract_bin_path,
        command="verify",
        bin_path=bin_path,
        artifact_path=artifact_path,
        receipt_path=receipt_path,
        contract_path=contract_path,
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        reproduced = Path(temp_dir) / "opened-wuci-ji"
        run_zig_contract(
            contract_bin_path=contract_bin_path,
            command="open",
            bin_path=bin_path,
            artifact_path=artifact_path,
            receipt_path=receipt_path,
            contract_path=contract_path,
            keyfile_path=keyfile_path,
            out_path=reproduced,
        )
        if not filecmp.cmp(opened_binary, reproduced, shallow=False):
            raise SelfReleaseError(
                "zig-contract-opened reproduction does not match opened binary"
            )


def run_asm_contract(
    *,
    command: str,
    bin_path: Path,
    artifact_path: Path,
    contract_path: Path,
    keyfile_path: Path | None = None,
    out_path: Path | None = None,
) -> bytes:
    if command == "verify":
        args = [
            *RUNNER,
            str(bin_path),
            "gate-contract-verify",
            str(artifact_path),
            str(contract_path),
        ]
    elif command == "open":
        if keyfile_path is None or out_path is None:
            raise SelfReleaseError(
                "assembly contract open requires keyfile and output path"
            )
        args = [
            *RUNNER,
            str(bin_path),
            "open-authorized-contract",
            str(keyfile_path),
            str(artifact_path),
            str(contract_path),
            str(out_path),
        ]
    else:
        raise SelfReleaseError(f"unsupported assembly contract command: {command}")

    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise SelfReleaseError(f"could not execute assembly gate command: {bin_path}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        detail = stderr or f"exit status {proc.returncode}"
        raise SelfReleaseError(f"assembly gate contract {command} failed: {detail}")
    if command == "verify" and proc.stdout != b"valid\n":
        raise SelfReleaseError("assembly gate contract verify did not report valid")
    if command == "open" and proc.stdout != b"":
        raise SelfReleaseError("assembly gate contract open wrote unexpected stdout")
    return proc.stdout


def reproduce_asm_contract_open(
    *,
    bin_path: Path,
    artifact_path: Path,
    contract_path: Path,
    keyfile_path: Path,
    opened_binary: Path,
) -> None:
    run_asm_contract(
        command="verify",
        bin_path=bin_path,
        artifact_path=artifact_path,
        contract_path=contract_path,
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        reproduced = Path(temp_dir) / "opened-wuci-ji"
        run_asm_contract(
            command="open",
            bin_path=bin_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            keyfile_path=keyfile_path,
            out_path=reproduced,
        )
        if not filecmp.cmp(opened_binary, reproduced, shallow=False):
            raise SelfReleaseError(
                "assembly-contract-opened reproduction does not match opened binary"
            )


def run_rooted_asm_contract(
    *,
    command: str,
    bin_path: Path,
    authority_path: Path,
    artifact_path: Path,
    contract_path: Path,
    keyfile_path: Path | None = None,
    out_path: Path | None = None,
) -> bytes:
    if command == "verify":
        args = [
            *RUNNER,
            str(bin_path),
            "gate-contract-verify-rooted",
            str(authority_path),
            str(artifact_path),
            str(contract_path),
        ]
    elif command == "open":
        if keyfile_path is None or out_path is None:
            raise SelfReleaseError(
                "rooted assembly contract open requires keyfile and output path"
            )
        args = [
            *RUNNER,
            str(bin_path),
            "open-authorized-rooted",
            str(authority_path),
            str(keyfile_path),
            str(artifact_path),
            str(contract_path),
            str(out_path),
        ]
    elif command == "authority":
        args = [
            *RUNNER,
            str(bin_path),
            "authority-root-verify",
            str(authority_path),
        ]
    else:
        raise SelfReleaseError(f"unsupported rooted assembly command: {command}")

    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise SelfReleaseError(f"could not execute rooted assembly gate command: {bin_path}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        detail = stderr or f"exit status {proc.returncode}"
        raise SelfReleaseError(f"rooted assembly gate contract {command} failed: {detail}")
    if command in {"verify", "authority"} and proc.stdout != b"valid\n":
        raise SelfReleaseError(f"rooted assembly gate contract {command} did not report valid")
    if command == "open" and proc.stdout != b"":
        raise SelfReleaseError("rooted assembly gate contract open wrote unexpected stdout")
    return proc.stdout


def reproduce_rooted_asm_contract_open(
    *,
    bin_path: Path,
    authority_path: Path,
    artifact_path: Path,
    contract_path: Path,
    keyfile_path: Path,
    opened_binary: Path,
) -> None:
    run_rooted_asm_contract(
        command="authority",
        bin_path=bin_path,
        authority_path=authority_path,
        artifact_path=artifact_path,
        contract_path=contract_path,
    )
    run_rooted_asm_contract(
        command="verify",
        bin_path=bin_path,
        authority_path=authority_path,
        artifact_path=artifact_path,
        contract_path=contract_path,
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        reproduced = Path(temp_dir) / "opened-wuci-ji"
        run_rooted_asm_contract(
            command="open",
            bin_path=bin_path,
            authority_path=authority_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            keyfile_path=keyfile_path,
            out_path=reproduced,
        )
        if not filecmp.cmp(opened_binary, reproduced, shallow=False):
            raise SelfReleaseError(
                "rooted-assembly-contract-opened reproduction does not match opened binary"
            )


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
    contract_path: Path | None = None,
    contract_bin_path: Path | None = None,
    contract_mode: str = "zig",
    authority_path: Path | None = None,
) -> dict[str, Any]:
    paths = bundle_paths(bundle_dir, bin_path)
    if contract_path is not None:
        paths["receipt_contract"] = contract_path
    if authority_path is not None:
        paths["authority_root"] = authority_path
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
    contract_enabled = contract_path is not None
    authority_fields: dict[str, str] | None = None
    if contract_enabled:
        assert_current_contract(
            bin_path=bin_path,
            artifact_path=paths["sealed_artifact"],
            receipt_path=paths["receipt"],
            contract_path=paths["receipt_contract"],
        )
        if contract_mode == "zig":
            if contract_bin_path is None:
                contract_bin_path = DEFAULT_CONTRACT_BIN
            reproduce_zig_contract_open(
                contract_bin_path=contract_bin_path,
                bin_path=bin_path,
                artifact_path=paths["sealed_artifact"],
                receipt_path=paths["receipt"],
                contract_path=paths["receipt_contract"],
                keyfile_path=paths["artifact_key"],
                opened_binary=paths["opened_binary"],
            )
        elif contract_mode == "asm":
            reproduce_asm_contract_open(
                bin_path=bin_path,
                artifact_path=paths["sealed_artifact"],
                contract_path=paths["receipt_contract"],
                keyfile_path=paths["artifact_key"],
                opened_binary=paths["opened_binary"],
            )
        elif contract_mode == "rooted-asm":
            if authority_path is None:
                raise SelfReleaseError("rooted assembly contract mode requires --authority")
            authority_fields = assert_current_authority(
                authority_path=paths["authority_root"],
                contract_path=paths["receipt_contract"],
            )
            reproduce_rooted_asm_contract_open(
                bin_path=bin_path,
                authority_path=paths["authority_root"],
                artifact_path=paths["sealed_artifact"],
                contract_path=paths["receipt_contract"],
                keyfile_path=paths["artifact_key"],
                opened_binary=paths["opened_binary"],
            )
        else:
            raise SelfReleaseError(f"unsupported contract mode: {contract_mode}")
    elif authority_path is not None:
        raise SelfReleaseError("--authority requires --contract")
    else:
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
    if contract_enabled:
        hashes["receipt_contract"] = sha256_file(paths["receipt_contract"])
    if authority_path is not None:
        hashes["authority_root"] = sha256_file(paths["authority_root"])

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

    checks = {
        "manifest_matches_assembly": True,
        "warrant_message_matches_assembly": True,
        "gate_check": True,
        "byte_identical": True,
        "opened_executable": True,
    }
    if contract_enabled:
        checks["receipt_contract_matches_receipt"] = True
        if contract_mode == "zig":
            checks["zig_contract_check"] = True
            checks["zig_contract_open_reproduced"] = True
        else:
            checks["assembly_contract_check"] = True
            checks["assembly_contract_open_reproduced"] = True
        if contract_mode == "rooted-asm":
            checks.pop("assembly_contract_check", None)
            checks.pop("assembly_contract_open_reproduced", None)
            checks["authority_root_check"] = True
            checks["authority_root_matches_contract"] = True
            checks["rooted_gate_check"] = True
            checks["rooted_gate_open"] = True
    else:
        checks["gate_open_reproduced"] = True

    boundary = BOUNDARY
    if contract_enabled:
        if contract_mode == "asm":
            boundary = ASM_CONTRACT_BOUNDARY
        elif contract_mode == "rooted-asm":
            boundary = ROOTED_ASM_CONTRACT_BOUNDARY
        else:
            boundary = CONTRACT_BOUNDARY

    attestation = {
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
        "checks": checks,
        "boundary": boundary,
    }
    if authority_fields is not None:
        attestation["authority_root_sha256"] = hashes["authority_root"]
        attestation["authority_group_public_key"] = authority_fields["group-public-key"]
    return attestation


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
        contract_path=Path(args.contract) if args.contract else None,
        contract_bin_path=Path(args.contract_bin) if args.contract_bin else None,
        contract_mode=args.contract_mode,
        authority_path=Path(args.authority) if args.authority else None,
    )
    write_json_new(attestation_path, attestation)
    print(f"wrote self-release attestation: {display_path(attestation_path)}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    attestation_path = Path(args.attestation)
    observed = build_attestation(
        bin_path=Path(args.bin),
        bundle_dir=Path(args.bundle_dir),
        contract_path=Path(args.contract) if args.contract else None,
        contract_bin_path=Path(args.contract_bin) if args.contract_bin else None,
        contract_mode=args.contract_mode,
        authority_path=Path(args.authority) if args.authority else None,
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
    parser.add_argument(
        "--contract",
        help="optional flat WUCI-GATE receipt contract path to bind into the attestation",
    )
    parser.add_argument(
        "--contract-bin",
        default=os.environ.get("WUCI_GATE_CONTRACT_BIN", str(DEFAULT_CONTRACT_BIN)),
        help="Zig gate contract verifier; defaults to WUCI_GATE_CONTRACT_BIN or build/wuci-gate-contract",
    )
    parser.add_argument(
        "--contract-mode",
        choices=("zig", "asm", "rooted-asm"),
        default=os.environ.get("WUCI_GATE_CONTRACT_MODE", "zig"),
        help="contract enforcement reproduction mode; defaults to zig",
    )
    parser.add_argument(
        "--authority",
        help="optional flat WUCI-ROOT authority file for rooted assembly mode",
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
