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
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
CONTRACT_TOOL = REPO_ROOT / "tools" / "wuci_receipt_contract.py"
CONTRACT_SPEC = REPO_ROOT / "docs" / "wuci_gate_receipt_contract.json"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))

CONTRACT_FIELDS = (
    "schema",
    "action",
    "artifact-sha256",
    "authorization-message-sha256",
    "receipt-sha256",
    "artifact-manifest-sha256",
    "group-public-key",
    "group-commitment",
    "challenge",
    "signature-commitment",
    "signature-scalar",
)


@dataclass(frozen=True)
class FailureCase:
    name: str
    mutate: Callable[[Path, Path, Path, Path], None]
    expected_stderr: tuple[bytes, ...]


def run_cmd(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
    )


def run_wuci(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([str(BIN), *args])


def run_authorize(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(AUTHORIZE), "--bin", str(BIN), *args])


def run_contract(command: str, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(CONTRACT_TOOL), command, "--bin", str(BIN), *args])


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stderr.decode("utf-8", "replace"),
    )


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_receipt(tmp: Path, artifact_path: Path, action: str) -> Path:
    transcript_path = tmp / f"{action}-transcript.json"
    receipt_path = tmp / f"{action}-receipt.json"
    transcript = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--print-transcript-manifest",
        ]
    )
    assert_ok(transcript, "write transcript manifest")
    transcript_path.write_bytes(transcript.stdout)

    receipt = run_authorize(
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
    assert_ok(receipt, "write receipt")
    assert receipt.stdout == b""
    return receipt_path


def write_artifact(tmp: Path) -> tuple[Path, Path]:
    key_path = tmp / "artifact.key"
    plain_path = tmp / "plain.txt"
    artifact_path = tmp / "sealed.wj"
    key_path.write_text(("11" * 32) + "\n", encoding="ascii")
    plain_path.write_bytes(b"wuci receipt contract plaintext\n")
    sealed = run_wuci(
        [
            "seal-file-keyfile-v2",
            str(key_path),
            "2233445566778899aabbccddeeff0011",
            str(plain_path),
            str(artifact_path),
        ]
    )
    assert_ok(sealed, "seal artifact")
    assert sealed.stdout == b""
    return key_path, artifact_path


def emit_contract(artifact_path: Path, receipt_path: Path, contract_path: Path) -> None:
    proc = run_contract(
        "emit",
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--receipt",
            str(receipt_path),
            "--contract",
            str(contract_path),
            "--quiet",
        ],
    )
    assert_ok(proc, "emit receipt contract")
    assert contract_path.exists()


def verify_contract(
    artifact_path: Path,
    receipt_path: Path,
    contract_path: Path,
) -> subprocess.CompletedProcess[bytes]:
    return run_contract(
        "verify",
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--receipt",
            str(receipt_path),
            "--contract",
            str(contract_path),
            "--quiet",
        ],
    )


def replace_value(text: str, label: str, value: str) -> str:
    prefix = f"{label}: "
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return "".join(lines)
    raise AssertionError(f"missing label {label}")


def mutate_contract_text(
    contract_path: Path,
    mutator: Callable[[str], str],
) -> None:
    contract_path.write_text(mutator(contract_path.read_text(encoding="ascii")), encoding="ascii")


def mutate_missing_trailing_newline(
    contract_path: Path,
    _receipt_path: Path,
    _artifact_path: Path,
    _tmp: Path,
) -> None:
    contract_path.write_text(contract_path.read_text(encoding="ascii").rstrip("\n"), encoding="ascii")


def mutate_extra_line(
    contract_path: Path,
    _receipt_path: Path,
    _artifact_path: Path,
    _tmp: Path,
) -> None:
    with contract_path.open("a", encoding="ascii") as handle:
        handle.write("unknown: nope\n")


def mutate_reordered_lines(
    contract_path: Path,
    _receipt_path: Path,
    _artifact_path: Path,
    _tmp: Path,
) -> None:
    lines = contract_path.read_text(encoding="ascii").splitlines(keepends=True)
    lines[1], lines[2] = lines[2], lines[1]
    contract_path.write_text("".join(lines), encoding="ascii")


def mutate_bad_schema(
    contract_path: Path,
    _receipt_path: Path,
    _artifact_path: Path,
    _tmp: Path,
) -> None:
    mutate_contract_text(
        contract_path,
        lambda text: replace_value(text, "schema", "wuci-gate-receipt-contract-v0"),
    )


def mutate_unsupported_action(
    contract_path: Path,
    _receipt_path: Path,
    _artifact_path: Path,
    _tmp: Path,
) -> None:
    mutate_contract_text(
        contract_path,
        lambda text: replace_value(text, "action", "burn"),
    )


def mutate_field(label: str, value: str) -> Callable[[Path, Path, Path, Path], None]:
    def mutate(
        contract_path: Path,
        _receipt_path: Path,
        _artifact_path: Path,
        _tmp: Path,
    ) -> None:
        mutate_contract_text(
            contract_path,
            lambda text: replace_value(text, label, value),
        )

    return mutate


def mutate_private_receipt(
    _contract_path: Path,
    receipt_path: Path,
    _artifact_path: Path,
    _tmp: Path,
) -> None:
    receipt = load_json(receipt_path)
    receipt["group_secret"] = "00"
    write_json(receipt_path, receipt)


def mutate_signature_scalar_receipt(
    _contract_path: Path,
    receipt_path: Path,
    _artifact_path: Path,
    _tmp: Path,
) -> None:
    receipt = load_json(receipt_path)
    receipt["signature_scalar"] = "00" * 32
    write_json(receipt_path, receipt)


def mutate_artifact(
    _contract_path: Path,
    _receipt_path: Path,
    artifact_path: Path,
    _tmp: Path,
) -> None:
    data = bytearray(artifact_path.read_bytes())
    data[-1] ^= 1
    artifact_path.write_bytes(data)


def assert_contract_shape(contract_path: Path) -> None:
    text = contract_path.read_text(encoding="ascii")
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    assert "\r" not in text
    labels = [line.split(": ", 1)[0] for line in text.splitlines()]
    assert tuple(labels) == CONTRACT_FIELDS

    spec = load_json(CONTRACT_SPEC)
    assert spec["contract_schema"] == "wuci-gate-receipt-contract-v1"
    assert tuple(spec["field_order"]) == CONTRACT_FIELDS
    assert "Do not add assembly open-authorized yet." in spec["assembly_non_goals"]
    assert "Do not parse receipt JSON in assembly yet." in spec["assembly_non_goals"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check WUCI-GATE flat receipt contract behavior."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        _key_path, artifact_path = write_artifact(tmp)
        receipt_path = make_receipt(tmp, artifact_path, "open")
        contract_path = tmp / "receipt-contract.txt"
        emit_contract(artifact_path, receipt_path, contract_path)
        assert_contract_shape(contract_path)

        valid = verify_contract(artifact_path, receipt_path, contract_path)
        assert_ok(valid, "verify receipt contract")
        assert valid.stdout == b""

        overwrite = run_contract(
            "emit",
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(receipt_path),
                "--contract",
                str(contract_path),
                "--quiet",
            ],
        )
        assert overwrite.returncode != 0
        assert b"refusing to overwrite existing contract" in overwrite.stderr

        cases = [
            FailureCase(
                "missing-trailing-newline",
                mutate_missing_trailing_newline,
                (b"must end with one trailing newline",),
            ),
            FailureCase(
                "extra-line",
                mutate_extra_line,
                (b"unexpected field count",),
            ),
            FailureCase(
                "reordered-lines",
                mutate_reordered_lines,
                (b"expected label action",),
            ),
            FailureCase(
                "bad-schema",
                mutate_bad_schema,
                (b"unsupported schema",),
            ),
            FailureCase(
                "unsupported-action",
                mutate_unsupported_action,
                (b"unsupported action",),
            ),
            FailureCase(
                "artifact-digest-mismatch",
                mutate_field("artifact-sha256", "00" * 32),
                (b"field does not match derived value: artifact-sha256",),
            ),
            FailureCase(
                "authorization-message-digest-mismatch",
                mutate_field("authorization-message-sha256", "00" * 32),
                (b"field does not match derived value: authorization-message-sha256",),
            ),
            FailureCase(
                "receipt-digest-mismatch",
                mutate_field("receipt-sha256", "00" * 32),
                (b"field does not match derived value: receipt-sha256",),
            ),
            FailureCase(
                "manifest-digest-mismatch",
                mutate_field("artifact-manifest-sha256", "00" * 32),
                (b"field does not match derived value: artifact-manifest-sha256",),
            ),
            FailureCase(
                "bad-sec1",
                mutate_field("group-public-key", "00" * 33),
                (b"group-public-key must be a compressed SEC1 point",),
            ),
            FailureCase(
                "signature-commitment-mismatch",
                mutate_field("signature-commitment", "02" + ("01" * 32)),
                (b"signature-commitment must match group-commitment",),
            ),
            FailureCase(
                "bad-challenge",
                mutate_field("challenge", "0" * 63),
                (b"challenge must be 64 lowercase hex characters",),
            ),
            FailureCase(
                "private-receipt-marker",
                mutate_private_receipt,
                (b"contains private material marker: group_secret",),
            ),
            FailureCase(
                "receipt-signature-tamper",
                mutate_signature_scalar_receipt,
                (b"frost-secp256k1-verify failed: invalid",),
            ),
            FailureCase(
                "artifact-tamper",
                mutate_artifact,
                (b"artifact manifest", b"does not match artifact"),
            ),
        ]

        base_contract = contract_path.read_bytes()
        base_receipt = receipt_path.read_bytes()
        base_artifact = artifact_path.read_bytes()
        for case in cases:
            case_contract = tmp / f"{case.name}.txt"
            case_receipt = tmp / f"{case.name}.json"
            case_artifact = tmp / f"{case.name}.wj"
            case_contract.write_bytes(base_contract)
            case_receipt.write_bytes(base_receipt)
            case_artifact.write_bytes(base_artifact)
            case.mutate(case_contract, case_receipt, case_artifact, tmp)
            proc = verify_contract(case_artifact, case_receipt, case_contract)
            assert proc.returncode != 0, case.name
            assert any(fragment in proc.stderr for fragment in case.expected_stderr), (
                case.name,
                proc.stderr.decode("utf-8", "replace"),
            )

    if not args.quiet:
        print("wuci receipt contract tests passed")


if __name__ == "__main__":
    main()
