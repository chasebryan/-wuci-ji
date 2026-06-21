#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
GATE = REPO_ROOT / "tools" / "wuci_gate.py"
SELF_RELEASE = REPO_ROOT / "tools" / "wuci_self_release.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))

KEY_HEX = "11" * 32
KEY_ID = "2233445566778899aabbccddeeff0011"


@dataclass(frozen=True)
class TamperCase:
    name: str
    mutate: Callable[[Path], None]
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


def run_gate(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(GATE), *args])


def run_self_release(bundle_dir: Path, command: str) -> subprocess.CompletedProcess[bytes]:
    return run_cmd(
        [
            sys.executable,
            str(SELF_RELEASE),
            "--bin",
            str(BIN),
            "--bundle-dir",
            str(bundle_dir),
            "--attestation",
            str(bundle_dir / "attestation.json"),
            command,
        ]
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_verify_fails(bundle_dir: Path, expected_stderr: tuple[bytes, ...]) -> None:
    proc = run_self_release(bundle_dir, "verify")
    assert proc.returncode != 0
    assert any(fragment in proc.stderr for fragment in expected_stderr), (
        proc.stderr.decode("utf-8", "replace"),
        expected_stderr,
    )


def write_self_release_bundle(bundle_dir: Path) -> None:
    bundle_dir.mkdir(parents=True)
    key_path = bundle_dir / "artifact.key"
    artifact_path = bundle_dir / "wuci-ji.self.wj"
    manifest_path = bundle_dir / "manifest.txt"
    warrant_message_path = bundle_dir / "warrant-message.txt"
    transcript_path = bundle_dir / "auth-transcript.json"
    receipt_path = bundle_dir / "auth-receipt.json"
    opened_path = bundle_dir / "opened-wuci-ji"

    key_path.write_text(KEY_HEX + "\n", encoding="ascii")
    assert_ok(
        run_wuci(
            [
                "seal-file-keyfile-v2",
                str(key_path),
                KEY_ID,
                str(BIN),
                str(artifact_path),
            ]
        ),
        "seal self binary",
    )

    manifest = run_wuci(["manifest-file", str(artifact_path)])
    assert_ok(manifest, "manifest self artifact")
    manifest_path.write_bytes(manifest.stdout)

    warrant_message = run_wuci(["warrant-message-file", "open", str(artifact_path)])
    assert_ok(warrant_message, "warrant self artifact")
    warrant_message_path.write_bytes(warrant_message.stdout)

    transcript = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--print-transcript-manifest",
        ]
    )
    assert_ok(transcript, "self transcript")
    transcript_path.write_bytes(transcript.stdout)

    receipt = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--transcript-manifest",
            str(transcript_path),
            "--update-transcript-manifest",
            "--receipt",
            str(receipt_path),
        ]
    )
    assert_ok(receipt, "self receipt")

    check = run_gate(
        [
            "check",
            "--bin",
            str(BIN),
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--receipt",
            str(receipt_path),
        ]
    )
    assert_ok(check, "gate check")

    opened = run_gate(
        [
            "open",
            "--bin",
            str(BIN),
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--receipt",
            str(receipt_path),
            "--keyfile",
            str(key_path),
            "--out",
            str(opened_path),
        ]
    )
    assert_ok(opened, "gate open")
    assert opened_path.read_bytes() == BIN.read_bytes()
    opened_path.chmod(opened_path.stat().st_mode | stat.S_IXUSR)

    attest = run_self_release(bundle_dir, "attest")
    assert_ok(attest, "attest self bundle")
    verify = run_self_release(bundle_dir, "verify")
    assert_ok(verify, "verify self bundle")


def fresh_case_bundle(source: Path, tmp: Path, name: str) -> Path:
    case_dir = tmp / name
    shutil.copytree(source, case_dir)
    (case_dir / "attestation.json").unlink()
    assert_ok(run_self_release(case_dir, "attest"), f"attest {name}")
    return case_dir


def mutate_attestation_summary(bundle_dir: Path) -> None:
    path = bundle_dir / "attestation.json"
    attestation = load_json(path)
    attestation["summary"] = "tampered"
    write_json(path, attestation)


def mutate_boundary(bundle_dir: Path) -> None:
    path = bundle_dir / "attestation.json"
    attestation = load_json(path)
    attestation["boundary"]["gate_enforcement"] = "assembly"
    write_json(path, attestation)


def mutate_gate_decision_hash(bundle_dir: Path) -> None:
    path = bundle_dir / "attestation.json"
    attestation = load_json(path)
    attestation["gate_decision"]["artifact-sha256"] = "00" * 32
    write_json(path, attestation)


def mutate_manifest(bundle_dir: Path) -> None:
    with (bundle_dir / "manifest.txt").open("ab") as handle:
        handle.write(b"tamper: manifest\n")


def mutate_warrant_message(bundle_dir: Path) -> None:
    with (bundle_dir / "warrant-message.txt").open("ab") as handle:
        handle.write(b"tamper: warrant\n")


def mutate_receipt(bundle_dir: Path) -> None:
    path = bundle_dir / "auth-receipt.json"
    receipt = load_json(path)
    receipt["signature_scalar"] = "00" * 32
    write_json(path, receipt)


def mutate_artifact(bundle_dir: Path) -> None:
    path = bundle_dir / "wuci-ji.self.wj"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)


def mutate_opened_binary(bundle_dir: Path) -> None:
    with (bundle_dir / "opened-wuci-ji").open("ab") as handle:
        handle.write(b"tamper")


def mutate_artifact_key(bundle_dir: Path) -> None:
    (bundle_dir / "artifact.key").write_text(("22" * 32) + "\n", encoding="ascii")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check WUCI self-release attestation tamper rejection."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    cases = [
        TamperCase(
            "attestation-summary",
            mutate_attestation_summary,
            (b"attestation does not match bundle state",),
        ),
        TamperCase(
            "attestation-boundary",
            mutate_boundary,
            (b"attestation does not match bundle state",),
        ),
        TamperCase(
            "attestation-gate-decision-hash",
            mutate_gate_decision_hash,
            (b"attestation does not match bundle state",),
        ),
        TamperCase(
            "manifest",
            mutate_manifest,
            (b"manifest.txt does not match manifest-file output",),
        ),
        TamperCase(
            "warrant-message",
            mutate_warrant_message,
            (b"warrant-message.txt does not match warrant-message-file output",),
        ),
        TamperCase(
            "receipt",
            mutate_receipt,
            (b"verification failed", b"invalid"),
        ),
        TamperCase(
            "sealed-artifact",
            mutate_artifact,
            (b"manifest.txt does not match manifest-file output", b"artifact manifest"),
        ),
        TamperCase(
            "opened-binary",
            mutate_opened_binary,
            (b"gate-opened reproduction does not match opened binary",),
        ),
        TamperCase(
            "artifact-key",
            mutate_artifact_key,
            (b"envelope authentication failed",),
        ),
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        base_dir = tmp / "base"
        write_self_release_bundle(base_dir)

        for case in cases:
            case_dir = fresh_case_bundle(base_dir, tmp, case.name)
            case.mutate(case_dir)
            assert_verify_fails(case_dir, case.expected_stderr)

    if args.quiet:
        return
    print(f"covered self-release attestation tamper cases: {len(cases)}")


if __name__ == "__main__":
    main()
