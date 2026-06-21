#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import wuci_authority_anchor as authority_anchor
import wuci_authority_root as authority_root
import wuci_frost_authorize as warrant
import wuci_receipt_contract as receipt_contract


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "build" / "wuci-witness-bundle"
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))
ACTION = "release"
BUNDLE_SCHEMA = "wuci-publish-bundle-v1"
INDEX_SCHEMA = "wuci-publish-index-v1"
ATTESTATION_SCHEMA = "wuci-witness-attestation-v1"

PUBLIC_FILES = {
    "sealed_artifact": "wuci-ji.self.wj",
    "manifest": "manifest.txt",
    "warrant_message": "warrant-message.txt",
    "release_receipt": "release-receipt.json",
    "receipt_contract": "receipt-contract.txt",
    "authority_root": "authority-root.txt",
    "release_decision": "release-decision.txt",
    "publish_index": "publish-index.txt",
    "attestation": "attestation.json",
}
CORE_FILES = (
    "sealed_artifact",
    "manifest",
    "warrant_message",
    "release_receipt",
    "receipt_contract",
    "authority_root",
    "release_decision",
)
FORBIDDEN_PUBLIC_FILES = {
    "artifact.key",
    "opened-wuci-ji",
    "auth-transcript.json",
    "release-transcript.json",
}
INDEX_FIELDS = (
    "schema",
    "artifact-sha256",
    "manifest-sha256",
    "warrant-message-sha256",
    "release-receipt-sha256",
    "receipt-contract-sha256",
    "authority-root-sha256",
    "release-decision-sha256",
    "release-authority-group-public-key",
)
HEX64_INDEX_FIELDS = {
    "artifact-sha256",
    "manifest-sha256",
    "warrant-message-sha256",
    "release-receipt-sha256",
    "receipt-contract-sha256",
    "authority-root-sha256",
    "release-decision-sha256",
}
HEX_RE = re.compile(r"^[0-9a-f]+$")

BOUNDARY = {
    "bundle_schema": BUNDLE_SCHEMA,
    "index_schema": INDEX_SCHEMA,
    "gate_enforcement": "assembly-rooted-release-contract",
    "authority_anchor": "authority/wuci-release-root.fixture.txt",
    "authority_anchor_sha256": authority_anchor.FIXTURE_RELEASE_AUTHORITY_SHA256,
    "authority_schema": authority_root.ROOT_SCHEMA,
    "contract_schema": receipt_contract.CONTRACT_SCHEMA,
    "assembly_owned_surfaces": [
        "manifest-file",
        "warrant-message-file",
        "authority-root-verify",
        "release-authorized-rooted",
    ],
    "public_profile_excludes": sorted(FORBIDDEN_PUBLIC_FILES),
    "non_goals": [
        "Do not require or accept a decryption key in the public witness bundle.",
        "Do not open the sealed artifact.",
        "Do not parse receipt JSON in assembly.",
        "Do not accept arbitrary signer material.",
        "Do not accept trust or publish authority bits yet.",
    ],
}


class WitnessError(RuntimeError):
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
        raise WitnessError(f"could not read {path}") from exc
    return digest.hexdigest()


def read_bytes(path: Path, context: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise WitnessError(f"could not read {context} {path}") from exc


def read_ascii(path: Path, context: str) -> str:
    try:
        return path.read_bytes().decode("ascii")
    except OSError as exc:
        raise WitnessError(f"could not read {context} {path}") from exc
    except UnicodeDecodeError as exc:
        raise WitnessError(f"{context} is not ASCII") from exc


def load_json_file(path: Path, context: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise WitnessError(f"could not read {context} {path}") from exc
    except json.JSONDecodeError as exc:
        raise WitnessError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_new_ascii(path: Path, value: str, context: str) -> None:
    if path.exists():
        raise WitnessError(f"refusing to overwrite existing {context} {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise WitnessError(f"could not write {context} {path}") from exc


def write_json_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise WitnessError(f"refusing to overwrite existing witness attestation {path}")
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


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def bundle_paths(bundle_dir: Path) -> dict[str, Path]:
    return {name: bundle_dir / rel for name, rel in PUBLIC_FILES.items()}


def require_file(path: Path, context: str) -> None:
    if not path.is_file():
        raise WitnessError(f"missing {context}: {path}")


def assert_public_profile(
    *,
    bundle_dir: Path,
    paths: dict[str, Path],
    require_index: bool,
    require_attestation: bool,
) -> None:
    if not bundle_dir.is_dir():
        raise WitnessError(f"missing public witness bundle directory: {bundle_dir}")

    allowed_names = set(PUBLIC_FILES.values())
    for child in bundle_dir.iterdir():
        if child.name in FORBIDDEN_PUBLIC_FILES:
            raise WitnessError(f"private file must not be present: {child.name}")
        if child.name not in allowed_names:
            raise WitnessError(f"unexpected file in public witness bundle: {child.name}")
        if child.is_dir():
            raise WitnessError(f"public witness bundle entry must be a file: {child.name}")

    required = list(CORE_FILES)
    if require_index:
        required.append("publish_index")
    if require_attestation:
        required.append("attestation")
    for name in required:
        require_file(paths[name], name.replace("_", " "))


def require_hex(value: str, chars: int, context: str) -> None:
    if len(value) != chars or HEX_RE.fullmatch(value) is None:
        raise WitnessError(f"{context} must be {chars} lowercase hex characters")


def validate_index_fields(fields: dict[str, str]) -> None:
    if tuple(fields) != INDEX_FIELDS:
        raise WitnessError("publish index fields are not in canonical order")
    if fields["schema"] != INDEX_SCHEMA:
        raise WitnessError("publish index has unsupported schema")
    for label in HEX64_INDEX_FIELDS:
        require_hex(fields[label], 64, label)
    group_key = fields["release-authority-group-public-key"]
    require_hex(group_key, 66, "release-authority-group-public-key")
    if group_key[:2] not in {"02", "03"}:
        raise WitnessError("release-authority-group-public-key must be a compressed SEC1 point")


def format_index(fields: dict[str, str]) -> str:
    validate_index_fields(fields)
    return "".join(f"{label}: {fields[label]}\n" for label in INDEX_FIELDS)


def parse_index(text: str) -> dict[str, str]:
    if "\r" in text:
        raise WitnessError("publish index must not contain CRLF")
    if not text.endswith("\n"):
        raise WitnessError("publish index must end with one trailing newline")
    if text.endswith("\n\n"):
        raise WitnessError("publish index must end with exactly one trailing newline")

    lines = text[:-1].split("\n")
    if len(lines) != len(INDEX_FIELDS):
        raise WitnessError("publish index has unexpected field count")

    fields: dict[str, str] = {}
    for index, (line, expected_label) in enumerate(zip(lines, INDEX_FIELDS), start=1):
        if ": " not in line:
            raise WitnessError(f"publish index line {index} is not label: value")
        label, value = line.split(": ", 1)
        if label != expected_label:
            raise WitnessError(f"publish index line {index} expected label {expected_label}")
        if label in fields:
            raise WitnessError(f"publish index duplicates label {label}")
        if value == "":
            raise WitnessError(f"publish index field {label} is empty")
        fields[label] = value

    validate_index_fields(fields)
    return fields


def run_wuci(bin_path: Path, args: list[str]) -> bytes:
    try:
        proc = subprocess.run(
            [*RUNNER, str(bin_path), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise WitnessError(f"could not execute {bin_path}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        detail = stderr or stdout or f"exit status {proc.returncode}"
        raise WitnessError(f"{args[0]} failed: {detail}")
    return proc.stdout


def parse_decision(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ": " not in line:
            raise WitnessError(f"release decision has unexpected line: {line!r}")
        label, value = line.split(": ", 1)
        if label in fields:
            raise WitnessError(f"release decision duplicates label: {label}")
        fields[label] = value
    expected = ("authorized", "action", "artifact-sha256")
    if tuple(fields) != expected:
        raise WitnessError("release decision fields are not canonical")
    if fields["authorized"] != "true":
        raise WitnessError("release decision is not authorized")
    if fields["action"] != ACTION:
        raise WitnessError("release decision action is not release")
    return fields


def assert_current_manifest_and_warrant(
    *,
    bin_path: Path,
    artifact_path: Path,
    manifest_path: Path,
    warrant_message_path: Path,
) -> None:
    manifest_bytes = run_wuci(bin_path, ["manifest-file", str(artifact_path)])
    warrant_bytes = run_wuci(
        bin_path,
        ["warrant-message-file", ACTION, str(artifact_path)],
    )
    if read_bytes(manifest_path, "manifest") != manifest_bytes:
        raise WitnessError("manifest.txt does not match manifest-file output")
    if read_bytes(warrant_message_path, "warrant message") != warrant_bytes:
        raise WitnessError(
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
        raise WitnessError(str(exc)) from exc
    except warrant.AuthorizationError as exc:
        raise WitnessError(str(exc)) from exc

    for label in receipt_contract.CONTRACT_FIELDS:
        if actual_fields[label] != expected_fields[label]:
            raise WitnessError(
                f"receipt contract field does not match derived value: {label}"
            )
    if actual_text != expected_text:
        raise WitnessError("receipt contract bytes are not canonical")
    if actual_fields["action"] != ACTION:
        raise WitnessError("receipt contract action is not release")
    return actual_fields


def assert_current_authority(
    *,
    authority_path: Path,
    contract_fields: dict[str, str],
    authority_sha256: str,
) -> dict[str, str]:
    try:
        authority_text = authority_root.read_ascii(authority_path, "authority root")
        authority_fields = authority_root.parse_root(authority_text)
        expected_text = authority_root.format_root(
            authority_fields["group-public-key"],
            allow_open=authority_fields["allow-open"],
            allow_release=authority_fields["allow-release"],
        )
    except authority_root.AuthorityRootError as exc:
        raise WitnessError(str(exc)) from exc
    if authority_text != expected_text:
        raise WitnessError("authority root bytes are not canonical")
    if authority_sha256 != authority_anchor.FIXTURE_RELEASE_AUTHORITY_SHA256:
        raise WitnessError("authority root is not the committed release anchor")
    if authority_fields["group-public-key"] != authority_anchor.FIXTURE_GROUP_PUBLIC_KEY:
        raise WitnessError("authority root group key is not the fixture key")
    if authority_fields["allow-open"] != "false":
        raise WitnessError("release authority root must not allow open")
    if authority_fields["allow-release"] != "true":
        raise WitnessError("authority root does not allow release")
    if authority_fields["allow-trust"] != "false":
        raise WitnessError("authority root must not allow trust")
    if authority_fields["allow-publish"] != "false":
        raise WitnessError("authority root must not allow publish")
    if authority_fields["group-public-key"] != contract_fields["group-public-key"]:
        raise WitnessError("authority root group key does not match receipt contract")
    return authority_fields


def assert_rooted_release_decision(
    *,
    bin_path: Path,
    authority_path: Path,
    artifact_path: Path,
    contract_path: Path,
    decision_path: Path,
) -> dict[str, str]:
    authority_stdout = run_wuci(bin_path, ["authority-root-verify", str(authority_path)])
    if authority_stdout != b"valid\n":
        raise WitnessError("authority-root-verify did not report valid")
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
        raise WitnessError("release-decision.txt does not match assembly output")
    try:
        return parse_decision(decision_bytes.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise WitnessError("release decision is not ASCII") from exc


def expected_index_fields(
    *,
    hashes: dict[str, str],
    authority_fields: dict[str, str],
) -> dict[str, str]:
    return {
        "schema": INDEX_SCHEMA,
        "artifact-sha256": hashes["sealed_artifact"],
        "manifest-sha256": hashes["manifest"],
        "warrant-message-sha256": hashes["warrant_message"],
        "release-receipt-sha256": hashes["release_receipt"],
        "receipt-contract-sha256": hashes["receipt_contract"],
        "authority-root-sha256": hashes["authority_root"],
        "release-decision-sha256": hashes["release_decision"],
        "release-authority-group-public-key": authority_fields["group-public-key"],
    }


def assert_publish_index(
    *,
    index_path: Path,
    expected_fields: dict[str, str],
) -> dict[str, str]:
    actual_text = read_ascii(index_path, "publish index")
    actual_fields = parse_index(actual_text)
    expected_text = format_index(expected_fields)
    if actual_text != expected_text:
        raise WitnessError("publish-index.txt does not match bundle state")
    return actual_fields


def build_witness_attestation(
    *,
    bin_path: Path,
    bundle_dir: Path,
    require_index: bool,
    require_attestation: bool,
) -> tuple[dict[str, Any], str]:
    paths = bundle_paths(bundle_dir)
    assert_public_profile(
        bundle_dir=bundle_dir,
        paths=paths,
        require_index=require_index,
        require_attestation=require_attestation,
    )

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

    hash_names = list(CORE_FILES)
    if require_index:
        hash_names.append("publish_index")
    hashes = {name: sha256_file(paths[name]) for name in hash_names}

    authority_fields = assert_current_authority(
        authority_path=paths["authority_root"],
        contract_fields=contract_fields,
        authority_sha256=hashes["authority_root"],
    )
    decision = assert_rooted_release_decision(
        bin_path=bin_path,
        authority_path=paths["authority_root"],
        artifact_path=paths["sealed_artifact"],
        contract_path=paths["receipt_contract"],
        decision_path=paths["release_decision"],
    )

    receipt = load_json_file(paths["release_receipt"], "release receipt")
    if not isinstance(receipt, dict):
        raise WitnessError("release receipt must be a JSON object")
    if receipt.get("action") != ACTION:
        raise WitnessError("release receipt action is not release")
    if receipt.get("artifact_manifest_sha256") != hashes["manifest"]:
        raise WitnessError("release receipt manifest hash does not match manifest")
    if receipt.get("authorization_message_sha256") != hashes["warrant_message"]:
        raise WitnessError(
            "release receipt authorization message hash does not match warrant message"
        )
    if contract_fields["artifact-sha256"] != hashes["sealed_artifact"]:
        raise WitnessError("contract artifact hash does not match artifact")
    if contract_fields["artifact-manifest-sha256"] != hashes["manifest"]:
        raise WitnessError("contract manifest hash does not match manifest")
    if contract_fields["authorization-message-sha256"] != hashes["warrant_message"]:
        raise WitnessError("contract message hash does not match warrant")
    if decision["artifact-sha256"] != hashes["sealed_artifact"]:
        raise WitnessError("release decision artifact hash does not match artifact")

    index_fields = expected_index_fields(
        hashes=hashes,
        authority_fields=authority_fields,
    )
    index_text = format_index(index_fields)
    if require_index:
        observed_index_fields = assert_publish_index(
            index_path=paths["publish_index"],
            expected_fields=index_fields,
        )
        if observed_index_fields != index_fields:
            raise WitnessError("publish index fields do not match bundle state")

    checks = {
        "public_bundle_profile": True,
        "forbidden_private_files_absent": True,
        "manifest_matches_assembly": True,
        "release_warrant_message_matches_assembly": True,
        "release_receipt_contract_matches_receipt": True,
        "release_authority_is_committed_anchor": True,
        "release_authority_allows_release": True,
        "release_authority_matches_contract": True,
        "rooted_release_check": True,
        "release_decision_matches_assembly": True,
        "publish_index_matches_bundle": require_index,
        "witness_bundle_complete": True,
    }

    path_names = list(CORE_FILES) + ["publish_index", "attestation"]
    attestation = {
        "schema": ATTESTATION_SCHEMA,
        "bundle_schema": BUNDLE_SCHEMA,
        "production": False,
        "action": ACTION,
        "summary": (
            "Wuci-ji publish bundle was verified from the public files only: "
            "the release authority root is pinned, the assembly rooted release "
            "decision is reproducible, and no key or opened binary is present."
        ),
        "paths": {name: PUBLIC_FILES[name] for name in path_names},
        "sha256": hashes,
        "publish_index": index_fields,
        "release_decision": decision,
        "release_authority_root_sha256": hashes["authority_root"],
        "release_authority_group_public_key": authority_fields["group-public-key"],
        "release_contract_sha256": hashes["receipt_contract"],
        "release_decision_sha256": hashes["release_decision"],
        "rooted_release_check": True,
        "publish_index_matches_bundle": require_index,
        "witness_bundle_complete": True,
        "checks": checks,
        "boundary": BOUNDARY,
    }
    return attestation, index_text


def compare_attestations(expected: Any, observed: dict[str, Any]) -> None:
    if not isinstance(expected, dict):
        raise WitnessError("witness attestation must be a JSON object")
    if expected != observed:
        raise WitnessError("witness attestation does not match bundle state")


def run_index(args: argparse.Namespace) -> int:
    bundle_dir = Path(args.bundle)
    paths = bundle_paths(bundle_dir)
    _, index_text = build_witness_attestation(
        bin_path=Path(args.bin),
        bundle_dir=bundle_dir,
        require_index=False,
        require_attestation=False,
    )
    write_new_ascii(paths["publish_index"], index_text, "publish index")
    print(f"wrote publish index: {display_path(paths['publish_index'])}")
    return 0


def run_attest(args: argparse.Namespace) -> int:
    bundle_dir = Path(args.bundle)
    paths = bundle_paths(bundle_dir)
    attestation, _ = build_witness_attestation(
        bin_path=Path(args.bin),
        bundle_dir=bundle_dir,
        require_index=True,
        require_attestation=False,
    )
    write_json_new(paths["attestation"], attestation)
    print(f"wrote witness attestation: {display_path(paths['attestation'])}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    bundle_dir = Path(args.bundle)
    paths = bundle_paths(bundle_dir)
    observed, _ = build_witness_attestation(
        bin_path=Path(args.bin),
        bundle_dir=bundle_dir,
        require_index=True,
        require_attestation=True,
    )
    expected = load_json_file(paths["attestation"], "witness attestation")
    compare_attestations(expected, observed)
    print(f"valid witness bundle: {display_path(bundle_dir)}")
    return 0


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    parser.add_argument(
        "--bundle",
        default=str(DEFAULT_BUNDLE_DIR),
        help="public witness bundle directory",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify public WUCI-WITNESS publish bundles."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    index_parser = subparsers.add_parser("index", help="write publish-index.txt")
    add_common_args(index_parser)
    index_parser.set_defaults(func=run_index)

    attest_parser = subparsers.add_parser("attest", help="write attestation.json")
    add_common_args(attest_parser)
    attest_parser.set_defaults(func=run_attest)

    verify_parser = subparsers.add_parser("verify", help="verify a public witness bundle")
    add_common_args(verify_parser)
    verify_parser.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except WitnessError as exc:
        print(f"wuci witness: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
