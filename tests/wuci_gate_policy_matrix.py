#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
BOUNDARY = REPO_ROOT / "docs" / "wuci_gate_boundary.json"
GATE = REPO_ROOT / "tools" / "wuci_gate.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))


@dataclass
class GateCase:
    rejection_class: str
    name: str
    artifact_path: Path
    action: str
    receipt_path: Path
    keyfile_path: Path
    out_path: Path
    expected_stderr: bytes
    existing_output: bytes | None = None
    existing_directory: bool = False
    existing_dangling_symlink: bool = False
    existing_parent_file: bytes | None = None


def run_wuci(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_authorize(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(AUTHORIZE), "--bin", str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_gate_open(case: GateCase) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            str(GATE),
            "open",
            "--bin",
            str(BIN),
            "--artifact",
            str(case.artifact_path),
            "--action",
            case.action,
            "--receipt",
            str(case.receipt_path),
            "--keyfile",
            str(case.keyfile_path),
            "--out",
            str(case.out_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def clone_json(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def write_json(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_bytes(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    return path


def make_receipt(tmp: Path, artifact_path: Path, action: str) -> Path:
    transcript_path = tmp / f"{action}-transcript.json"
    receipt_path = tmp / f"{action}-receipt.json"
    transcript_proc = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--print-transcript-manifest",
        ]
    )
    assert transcript_proc.returncode == 0, transcript_proc.stderr.decode(
        "utf-8", "replace"
    )
    transcript_path.write_bytes(transcript_proc.stdout)

    receipt_proc = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--transcript-manifest",
            str(transcript_path),
            "--update-transcript-manifest",
            "--receipt",
            str(receipt_path),
        ]
    )
    assert receipt_proc.returncode == 0, receipt_proc.stderr.decode("utf-8", "replace")
    assert receipt_proc.stdout == b""
    return receipt_path


def mutated_receipt(
    tmp: Path,
    base_receipt: dict[str, Any],
    name: str,
    mutation: dict[str, Any],
) -> Path:
    receipt = clone_json(base_receipt)
    for path, value in mutation.items():
        parts = path.split(".")
        target: Any = receipt
        for part in parts[:-1]:
            target = target[part]
        if value is _DELETE:
            del target[parts[-1]]
        else:
            target[parts[-1]] = value
    return write_json(tmp / f"{name}.json", receipt)


class DeleteMarker:
    pass


_DELETE = DeleteMarker()


def assert_gate_case(case: GateCase) -> None:
    if case.existing_output is not None:
        case.out_path.write_bytes(case.existing_output)
    if case.existing_directory:
        case.out_path.mkdir()
    if case.existing_dangling_symlink:
        case.out_path.symlink_to(
            case.out_path.with_name(f"{case.out_path.name}.missing-target")
        )
    if case.existing_parent_file is not None:
        case.out_path.parent.write_bytes(case.existing_parent_file)

    proc = run_gate_open(case)
    assert proc.returncode != 0, case.name
    assert proc.stdout == b"", case.name
    assert case.expected_stderr in proc.stderr, (
        case.name,
        proc.stderr.decode("utf-8", "replace"),
    )
    if case.existing_output is None:
        if case.existing_directory:
            assert case.out_path.is_dir(), case.name
        elif case.existing_dangling_symlink:
            assert case.out_path.is_symlink(), case.name
            assert not case.out_path.exists(), case.name
        elif case.existing_parent_file is not None:
            assert case.out_path.parent.read_bytes() == case.existing_parent_file
            assert not case.out_path.exists(), case.name
        else:
            assert not case.out_path.exists(), case.name
    else:
        assert case.out_path.read_bytes() == case.existing_output, case.name


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check WUCI-GATE policy rejection matrix."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress matrix summary")
    args = parser.parse_args()

    boundary = load_json(BOUNDARY)
    expected_classes = set(boundary["expected_rejection_classes"])
    non_python_gate_open_classes = {
        "malformed_authority_root",
        "unsupported_authority_schema",
        "unsupported_authority_suite",
        "authority_id_mismatch",
        "authority_group_key_mismatch",
        "authority_open_disallowed",
        "authority_release_disallowed",
        "authority_publish_disallowed",
        "authority_trust_disallowed",
        "authority_anchor_path_mismatch",
        "authority_anchor_digest_mismatch",
        "self_derived_authority_rejected",
        "anchored_authority_policy_mismatch",
        "wrong_release_action",
        "wrong_rooted_release_action",
        "publish_bundle_tamper",
        "witness_private_file_present",
        "witness_publish_index_missing",
        "witness_publish_index_mismatch",
        "witness_public_bundle_tamper",
    }
    expected_classes -= non_python_gate_open_classes
    assert "private_material" in expected_classes

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        key_path = tmp / "artifact.key"
        wrong_key_path = tmp / "wrong.key"
        plain_path = tmp / "plain.txt"
        artifact_path = tmp / "sealed.wj"
        key_hex = "11" * 32
        key_id = "2233445566778899aabbccddeeff0011"
        plain_path.write_bytes(b"wuci gate policy matrix plaintext\n")
        key_path.write_text(key_hex + "\n", encoding="ascii")
        wrong_key_path.write_text(("22" * 32) + "\n", encoding="ascii")

        sealed = run_wuci(
            [
                "seal-file-keyfile-v2",
                str(key_path),
                key_id,
                str(plain_path),
                str(artifact_path),
            ]
        )
        assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
        assert sealed.stdout == b""

        open_receipt_path = make_receipt(tmp, artifact_path, "open")
        release_receipt_path = make_receipt(tmp, artifact_path, "release")
        open_receipt = load_json(open_receipt_path)

        malformed_base = clone_json(open_receipt)
        malformed_base["unknown_extra_field"] = "nope"

        private_top = clone_json(open_receipt)
        private_top["group_secret"] = "00"
        private_nested = clone_json(open_receipt)
        private_nested["artifact_manifest"]["share"] = "00"
        private_string = clone_json(open_receipt)
        private_string["warning"] = "contains group_secret marker"

        tampered_artifact_path = tmp / "tampered.wj"
        tampered_artifact = bytearray(artifact_path.read_bytes())
        tampered_artifact[-1] ^= 1
        tampered_artifact_path.write_bytes(tampered_artifact)

        cases = [
            GateCase(
                "malformed_receipt",
                "invalid-json",
                artifact_path,
                "open",
                write_bytes(tmp / "invalid-json.json", b"{not json"),
                key_path,
                tmp / "invalid-json.out",
                b"not valid JSON",
            ),
            GateCase(
                "malformed_receipt",
                "json-array",
                artifact_path,
                "open",
                write_json(tmp / "array.json", []),
                key_path,
                tmp / "array.out",
                b"must be a JSON object",
            ),
            GateCase(
                "malformed_receipt",
                "missing-required-field",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "missing-schema",
                    {"schema": _DELETE},
                ),
                key_path,
                tmp / "missing-schema.out",
                b"missing required field",
            ),
            GateCase(
                "malformed_receipt",
                "unknown-extra-field",
                artifact_path,
                "open",
                write_json(tmp / "unknown-extra-field.json", malformed_base),
                key_path,
                tmp / "unknown-extra-field.out",
                b"unsupported field",
            ),
            GateCase(
                "unsupported_schema",
                "unsupported-schema",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "unsupported-schema",
                    {"schema": "wuci-frost-authorization-v0"},
                ),
                key_path,
                tmp / "unsupported-schema.out",
                b"unsupported schema",
            ),
            GateCase(
                "unsupported_suite",
                "unsupported-suite",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "unsupported-suite",
                    {"suite": "FROST-unknown-SHA256-v1"},
                ),
                key_path,
                tmp / "unsupported-suite.out",
                b"unsupported suite",
            ),
            GateCase(
                "production_receipt",
                "production-receipt",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "production-receipt",
                    {"production": True},
                ),
                key_path,
                tmp / "production-receipt.out",
                b"production to false",
            ),
            GateCase(
                "wrong_action",
                "wrong-action",
                artifact_path,
                "release",
                open_receipt_path,
                key_path,
                tmp / "wrong-action.out",
                b"action does not match",
            ),
            GateCase(
                "artifact_manifest_digest_mismatch",
                "artifact-manifest-digest-mismatch",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "artifact-manifest-digest-mismatch",
                    {"artifact_manifest_sha256": "00" * 32},
                ),
                key_path,
                tmp / "artifact-manifest-digest-mismatch.out",
                b"manifest digest",
            ),
            GateCase(
                "artifact_manifest_field_mismatch",
                "artifact-manifest-field-mismatch",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "artifact-manifest-field-mismatch",
                    {"artifact_manifest.nonce": "00"},
                ),
                key_path,
                tmp / "artifact-manifest-field-mismatch.out",
                b"artifact manifest",
            ),
            GateCase(
                "artifact_manifest_field_mismatch",
                "tampered-artifact",
                tampered_artifact_path,
                "open",
                open_receipt_path,
                key_path,
                tmp / "tampered-artifact.out",
                b"artifact manifest",
            ),
            GateCase(
                "authorization_message_digest_mismatch",
                "authorization-message-digest-mismatch",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "authorization-message-digest-mismatch",
                    {"authorization_message_sha256": "00" * 32},
                ),
                key_path,
                tmp / "authorization-message-digest-mismatch.out",
                b"message digest",
            ),
            GateCase(
                "challenge_mismatch",
                "challenge-mismatch",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "challenge-mismatch",
                    {"challenge": "00" * 32},
                ),
                key_path,
                tmp / "challenge-mismatch.out",
                b"challenge does not match",
            ),
            GateCase(
                "invalid_signature",
                "invalid-signature",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "invalid-signature",
                    {"signature_scalar": "00" * 32},
                ),
                key_path,
                tmp / "invalid-signature.out",
                b"invalid",
            ),
            GateCase(
                "invalid_signature",
                "signature-commitment-mismatch",
                artifact_path,
                "open",
                mutated_receipt(
                    tmp,
                    open_receipt,
                    "signature-commitment-mismatch",
                    {"signature_commitment": open_receipt["group_public_key"]},
                ),
                key_path,
                tmp / "signature-commitment-mismatch.out",
                b"signature commitment does not match challenge commitment",
            ),
            GateCase(
                "wrong_open_action",
                "release-receipt-cannot-open",
                artifact_path,
                "release",
                release_receipt_path,
                key_path,
                tmp / "release-receipt-cannot-open.out",
                b"gate open requires",
            ),
            GateCase(
                "wrong_key_after_authorization",
                "wrong-key-after-authorization",
                artifact_path,
                "open",
                open_receipt_path,
                wrong_key_path,
                tmp / "wrong-key-after-authorization.out",
                b"envelope authentication failed",
            ),
            GateCase(
                "output_exists",
                "output-exists",
                artifact_path,
                "open",
                open_receipt_path,
                key_path,
                tmp / "output-exists.out",
                b"refusing to overwrite",
                existing_output=b"do-not-touch",
            ),
            GateCase(
                "output_exists",
                "output-existing-directory",
                artifact_path,
                "open",
                open_receipt_path,
                key_path,
                tmp / "output-existing-directory.out",
                b"refusing to overwrite",
                existing_directory=True,
            ),
            GateCase(
                "output_exists",
                "output-dangling-symlink",
                artifact_path,
                "open",
                open_receipt_path,
                key_path,
                tmp / "output-dangling-symlink.out",
                b"refusing to overwrite",
                existing_dangling_symlink=True,
            ),
            GateCase(
                "output_parent_missing",
                "output-parent-missing",
                artifact_path,
                "open",
                open_receipt_path,
                key_path,
                tmp / "missing-output-parent" / "opened.out",
                b"output parent directory does not exist",
            ),
            GateCase(
                "output_parent_not_directory",
                "output-parent-not-directory",
                artifact_path,
                "open",
                open_receipt_path,
                key_path,
                tmp / "output-parent-file" / "opened.out",
                b"output parent is not a directory",
                existing_parent_file=b"not-a-directory",
            ),
            GateCase(
                "private_material",
                "private-material-top-level",
                artifact_path,
                "open",
                write_json(tmp / "private-top-level.json", private_top),
                key_path,
                tmp / "private-top-level.out",
                b"private material marker",
            ),
            GateCase(
                "private_material",
                "private-material-nested",
                artifact_path,
                "open",
                write_json(tmp / "private-nested.json", private_nested),
                key_path,
                tmp / "private-nested.out",
                b"private material marker",
            ),
            GateCase(
                "private_material",
                "private-material-string",
                artifact_path,
                "open",
                write_json(tmp / "private-string.json", private_string),
                key_path,
                tmp / "private-string.out",
                b"private material marker",
            ),
        ]

        covered_classes: set[str] = set()
        for case in cases:
            assert_gate_case(case)
            covered_classes.add(case.rejection_class)

        assert expected_classes <= covered_classes, sorted(
            expected_classes - covered_classes
        )

    if args.quiet:
        return
    print(f"covered gate rejection classes: {len(covered_classes)}\n")


if __name__ == "__main__":
    main()
