#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import wuci_witness


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "docs" / "wuci_cage_policy.json"
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "build" / "wuci-witness-bundle"

POLICY_SCHEMA = "wuci-cage-policy-v1"
ATTESTATION_SCHEMA = "wuci-cage-attestation-v1"
PROFILE = "WUCI-CAGE-v1"
LEDGER_ENTRY_SCHEMA = "wuci-cage-ledger-entry-v1"
RUN_DECISION_SCHEMA = "wuci-cage-run-decision-v1"
CHECKED_AT = "deterministic-fixture"
BOUNDARY_STATEMENT = (
    "WUCI-CAGE v1 verifies artifact legitimacy; it does not claim OS sandbox "
    "enforcement."
)
RUN_DENIAL_REASON = (
    "runtime sandbox enforcement is not implemented in WUCI-CAGE v1"
)

PUBLIC_FILES = (
    "wuci-ji.self.wj",
    "manifest.txt",
    "warrant-message.txt",
    "release-receipt.json",
    "receipt-contract.txt",
    "authority-root.txt",
    "release-decision.txt",
    "publish-index.txt",
    "attestation.json",
)
TEXT_PUBLIC_FILES = tuple(name for name in PUBLIC_FILES if name != "wuci-ji.self.wj")
FORBIDDEN_PUBLIC_FILES = {
    "artifact.key",
    "opened-wuci-ji",
    "auth-transcript.json",
    "release-transcript.json",
}
PRIVATE_MARKERS = (
    "group_secret",
    "share",
    "hiding",
    "binding",
    "hiding_nonce",
    "binding_nonce",
    "signature_share",
)
HASH_FIELDS = {
    "artifact_sha256": "wuci-ji.self.wj",
    "manifest_sha256": "manifest.txt",
    "warrant_message_sha256": "warrant-message.txt",
    "receipt_sha256": "release-receipt.json",
    "contract_sha256": "receipt-contract.txt",
    "authority_root_sha256": "authority-root.txt",
    "release_decision_sha256": "release-decision.txt",
    "publish_index_sha256": "publish-index.txt",
}
INDEX_HASH_FIELDS = {
    "artifact-sha256": "artifact_sha256",
    "manifest-sha256": "manifest_sha256",
    "warrant-message-sha256": "warrant_message_sha256",
    "release-receipt-sha256": "receipt_sha256",
    "receipt-contract-sha256": "contract_sha256",
    "authority-root-sha256": "authority_root_sha256",
    "release-decision-sha256": "release_decision_sha256",
}


class CageError(RuntimeError):
    pass


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
        raise CageError(f"could not read {path}") from exc
    return digest.hexdigest()


def read_bytes(path: Path, context: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CageError(f"could not read {context}: {path}") from exc


def read_text(path: Path, context: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CageError(f"could not read {context}: {path}") from exc
    except UnicodeDecodeError as exc:
        raise CageError(f"{context} is not UTF-8 text") from exc


def load_json(path: Path, context: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise CageError(f"could not read {context}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CageError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_new_text(path: Path, value: str, context: str) -> None:
    if path.exists():
        raise CageError(f"refusing to overwrite existing {context}: {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    except OSError as exc:
        raise CageError(f"could not write {context}: {path}") from exc


def write_new_json(path: Path, value: dict[str, Any], context: str) -> None:
    write_new_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", context)


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise CageError("CAGE policy must be a JSON object")
    if policy.get("schema") != POLICY_SCHEMA:
        raise CageError("CAGE policy has unsupported schema")
    if policy.get("status") != "defensive-artifact-airlock-v1":
        raise CageError("CAGE policy has unsupported status")
    actions = policy.get("canonical_actions")
    if not isinstance(actions, dict):
        raise CageError("CAGE policy canonical_actions must be an object")
    if actions.get("stage", {}).get("wuci_action") != "open":
        raise CageError("CAGE policy stage action must map to open")
    if actions.get("publish", {}).get("wuci_action") != "release":
        raise CageError("CAGE policy publish action must map to release")
    if actions.get("run", {}).get("status") != "unsupported-in-v1":
        raise CageError("CAGE policy run action must be unsupported in v1")
    runtime = policy.get("runtime_claims")
    if not isinstance(runtime, dict):
        raise CageError("CAGE policy runtime_claims must be an object")
    if runtime.get("no_network_enforced_v1") is not False:
        raise CageError("CAGE v1 must not claim no-network enforcement")
    if runtime.get("public_witness_secret_free_v1") is not True:
        raise CageError("CAGE v1 must require secret-free public witnesses")
    required_files = policy.get("required_public_witness_files")
    if required_files != list(PUBLIC_FILES):
        raise CageError("CAGE policy public witness file order is not canonical")
    forbidden = set(policy.get("forbidden_public_witness_files", []))
    for name in FORBIDDEN_PUBLIC_FILES:
        if name not in forbidden:
            raise CageError(f"CAGE policy does not forbid {name}")
    rejections = set(policy.get("rejection_classes", []))
    if "runtime_sandbox_claim_without_enforcement" not in rejections:
        raise CageError("CAGE policy must reject runtime sandbox overclaims")
    return policy


def load_policy() -> dict[str, Any]:
    return validate_policy(load_json(POLICY_PATH, "CAGE policy"))


def bundle_file(bundle: Path, filename: str) -> Path:
    return bundle / filename


def assert_public_bundle_shape(bundle: Path) -> None:
    if not bundle.is_dir():
        raise CageError(f"missing public witness bundle directory: {bundle}")
    expected = set(PUBLIC_FILES)
    observed: set[str] = set()
    for child in bundle.iterdir():
        if child.is_dir():
            raise CageError(f"public witness bundle entry must be a file: {child.name}")
        if child.name in FORBIDDEN_PUBLIC_FILES:
            raise CageError(f"forbidden public witness file present: {child.name}")
        if child.name not in expected:
            raise CageError(f"unexpected public witness file: {child.name}")
        observed.add(child.name)
    missing = sorted(expected - observed)
    if missing:
        raise CageError(f"missing public witness file: {missing[0]}")


def reject_private_material(bundle: Path) -> None:
    for filename in TEXT_PUBLIC_FILES:
        path = bundle_file(bundle, filename)
        text = read_text(path, filename)
        for marker in PRIVATE_MARKERS:
            if marker in text:
                raise CageError(
                    f"public witness file contains private material marker: {filename}"
                )


def parse_label_values(text: str, context: str) -> dict[str, str]:
    if "\r" in text:
        raise CageError(f"{context} must not contain CRLF")
    if not text.endswith("\n"):
        raise CageError(f"{context} must end with one trailing newline")
    if text.endswith("\n\n"):
        raise CageError(f"{context} must end with exactly one trailing newline")
    fields: dict[str, str] = {}
    for line_no, line in enumerate(text[:-1].split("\n"), start=1):
        if ": " not in line:
            raise CageError(f"{context} line {line_no} is not label: value")
        label, value = line.split(": ", 1)
        if label in fields:
            raise CageError(f"{context} duplicates label: {label}")
        if value == "":
            raise CageError(f"{context} field {label} is empty")
        fields[label] = value
    return fields


def parse_release_decision(path: Path) -> dict[str, str]:
    fields = parse_label_values(read_text(path, "release decision"), "release decision")
    expected = ("authorized", "action", "artifact-sha256")
    if tuple(fields) != expected:
        raise CageError("release-decision.txt fields are not canonical")
    if fields["authorized"] != "true":
        raise CageError("release-decision.txt does not authorize release")
    if fields["action"] != "release":
        raise CageError("release-decision.txt action is not release")
    return fields


def bundle_hashes(bundle: Path) -> dict[str, str]:
    return {
        field: sha256_file(bundle_file(bundle, filename))
        for field, filename in HASH_FIELDS.items()
    }


def verify_publish_index(bundle: Path, hashes: dict[str, str]) -> None:
    try:
        index_text = wuci_witness.read_ascii(
            bundle_file(bundle, "publish-index.txt"),
            "publish index",
        )
        index_fields = wuci_witness.parse_index(index_text)
    except wuci_witness.WitnessError as exc:
        raise CageError(str(exc)) from exc
    for index_label, cage_field in INDEX_HASH_FIELDS.items():
        if index_fields[index_label] != hashes[cage_field]:
            raise CageError(f"publish-index.txt does not match {HASH_FIELDS[cage_field]}")


def verify_witness_bundle(bin_path: Path, bundle: Path) -> None:
    try:
        observed, _ = wuci_witness.build_witness_attestation(
            bin_path=bin_path,
            bundle_dir=bundle,
            require_index=True,
            require_attestation=True,
        )
        expected = wuci_witness.load_json_file(
            bundle_file(bundle, "attestation.json"),
            "witness attestation",
        )
        wuci_witness.compare_attestations(expected, observed)
    except wuci_witness.WitnessError as exc:
        raise CageError(f"witness verification failed: {exc}") from exc


def build_attestation(*, bin_path: Path, bundle: Path) -> dict[str, Any]:
    load_policy()
    assert_public_bundle_shape(bundle)
    reject_private_material(bundle)
    hashes = bundle_hashes(bundle)
    decision = parse_release_decision(bundle_file(bundle, "release-decision.txt"))
    if decision["artifact-sha256"] != hashes["artifact_sha256"]:
        raise CageError("release-decision.txt artifact hash does not match artifact")
    verify_publish_index(bundle, hashes)
    verify_witness_bundle(bin_path, bundle)
    return {
        "schema": ATTESTATION_SCHEMA,
        "profile": PROFILE,
        **hashes,
        "cage_decision": "allow-publish",
        "runtime_sandbox_enforced": False,
        "runtime_execution_allowed": False,
        "public_witness_secret_free": True,
        "checked_at": CHECKED_AT,
        "boundary_statement": BOUNDARY_STATEMENT,
    }


def validate_attestation_shape(attestation: Any) -> dict[str, Any]:
    if not isinstance(attestation, dict):
        raise CageError("CAGE attestation must be a JSON object")
    required = {
        "schema",
        "profile",
        *HASH_FIELDS,
        "cage_decision",
        "runtime_sandbox_enforced",
        "runtime_execution_allowed",
        "public_witness_secret_free",
        "checked_at",
        "boundary_statement",
    }
    observed = set(attestation)
    if observed != required:
        raise CageError("CAGE attestation fields are not canonical")
    if attestation["schema"] != ATTESTATION_SCHEMA:
        raise CageError("CAGE attestation has unsupported schema")
    if attestation["profile"] != PROFILE:
        raise CageError("CAGE attestation has unsupported profile")
    if attestation["cage_decision"] not in {"allow-publish", "deny"}:
        raise CageError("CAGE attestation has unsupported decision")
    if attestation["runtime_sandbox_enforced"] is not False:
        raise CageError("CAGE v1 must not claim runtime sandbox enforcement")
    if attestation["runtime_execution_allowed"] is not False:
        raise CageError("CAGE v1 must deny general runtime execution")
    if attestation["public_witness_secret_free"] is not True:
        raise CageError("CAGE attestation must assert a secret-free public witness")
    if attestation["checked_at"] != CHECKED_AT:
        raise CageError("CAGE attestation checked_at is not deterministic")
    if attestation["boundary_statement"] != BOUNDARY_STATEMENT:
        raise CageError("CAGE attestation boundary statement is not canonical")
    for field in HASH_FIELDS:
        value = attestation[field]
        if not isinstance(value, str) or len(value) != 64:
            raise CageError(f"CAGE attestation {field} must be 64 hex characters")
        int(value, 16)
    return attestation


def run_policy(args: argparse.Namespace) -> int:
    load_policy()
    if not args.print_policy:
        raise CageError("policy command requires --print")
    sys.stdout.write(POLICY_PATH.read_text(encoding="utf-8"))
    return 0


def run_attest(args: argparse.Namespace) -> int:
    attestation = build_attestation(bin_path=Path(args.bin), bundle=Path(args.bundle))
    write_new_json(Path(args.out), attestation, "CAGE attestation")
    print(f"wrote CAGE attestation: {display_path(Path(args.out))}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    expected = build_attestation(bin_path=Path(args.bin), bundle=Path(args.bundle))
    observed = validate_attestation_shape(
        load_json(Path(args.attestation), "CAGE attestation")
    )
    if observed != expected:
        raise CageError("CAGE attestation does not match bundle state")
    print(f"valid CAGE attestation: {display_path(Path(args.attestation))}")
    return 0


def run_deny_run(args: argparse.Namespace) -> int:
    _ = args.artifact
    decision = (
        f"schema: {RUN_DECISION_SCHEMA}\n"
        "authorized: false\n"
        "action: run\n"
        f"reason: {RUN_DENIAL_REASON}\n"
    )
    write_new_text(Path(args.out), decision, "CAGE run denial")
    print(f"wrote CAGE run denial: {display_path(Path(args.out))}")
    return 0


def run_ledger_entry(args: argparse.Namespace) -> int:
    attestation_path = Path(args.attestation)
    attestation = validate_attestation_shape(
        load_json(attestation_path, "CAGE attestation")
    )
    if attestation["cage_decision"] != "allow-publish":
        raise CageError("only allow-publish CAGE attestations can enter the ledger")
    entry = (
        f"schema: {LEDGER_ENTRY_SCHEMA}\n"
        f"profile: {PROFILE}\n"
        f"artifact-sha256: {attestation['artifact_sha256']}\n"
        f"cage-attestation-sha256: {sha256_file(attestation_path)}\n"
        f"cage-decision: {attestation['cage_decision']}\n"
        "runtime-sandbox-enforced: false\n"
    )
    write_new_text(Path(args.out), entry, "CAGE ledger entry")
    print(f"wrote CAGE ledger entry: {display_path(Path(args.out))}")
    return 0


def add_bin_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to wuci-ji; defaults to WUCI_JI_BIN or build/wuci-ji",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WUCI-CAGE v1 defensive artifact airlock."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy_parser = subparsers.add_parser("policy", help="print CAGE policy")
    policy_parser.add_argument("--print", dest="print_policy", action="store_true")
    policy_parser.set_defaults(func=run_policy)

    attest_parser = subparsers.add_parser("attest", help="write a CAGE attestation")
    add_bin_arg(attest_parser)
    attest_parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE_DIR))
    attest_parser.add_argument("--out", required=True)
    attest_parser.set_defaults(func=run_attest)

    verify_parser = subparsers.add_parser("verify", help="verify a CAGE attestation")
    add_bin_arg(verify_parser)
    verify_parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE_DIR))
    verify_parser.add_argument("--attestation", required=True)
    verify_parser.set_defaults(func=run_verify)

    deny_parser = subparsers.add_parser("deny-run", help="deny general runtime execution")
    deny_parser.add_argument("--artifact", required=True)
    deny_parser.add_argument("--out", required=True)
    deny_parser.set_defaults(func=run_deny_run)

    ledger_parser = subparsers.add_parser(
        "ledger-entry",
        help="write a ledger-ready CAGE entry",
    )
    ledger_parser.add_argument("--attestation", required=True)
    ledger_parser.add_argument("--out", required=True)
    ledger_parser.set_defaults(func=run_ledger_entry)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (CageError, ValueError) as exc:
        print(f"wuci cage: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
