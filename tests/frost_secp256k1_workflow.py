#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import test_wuci_ji as wuci_tests


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "frost_secp256k1_workflow.py"
MESSAGE = "wuci-ji frost integration"


def run_tool(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--bin",
            os.environ.get("WUCI_JI_BIN", str(REPO_ROOT / "build" / "wuci-ji")),
            *args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def output_labels(stdout: bytes) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in stdout.decode("ascii").splitlines():
        label, value = line.split(": ", 1)
        labels[label] = value
    return labels


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the user-facing FROST(secp256k1,SHA-256) workflow helper."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress signature field output",
    )
    args = parser.parse_args()

    signature = wuci_tests.assert_frost_end_to_end_cli_flow()
    proc = run_tool(["--message", MESSAGE])
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    labels = output_labels(proc.stdout)
    for name, value in signature.items():
        assert labels[name] == value, (name, labels[name], value)
    assert labels["verification"] == "valid"
    assert labels["production"] == "false"
    assert "NON-PRODUCTION" in labels["fixture_warning"]

    manifest_proc = run_tool(["--print-fixture-manifest"])
    assert manifest_proc.returncode == 0, manifest_proc.stderr.decode("utf-8", "replace")
    manifest = json.loads(manifest_proc.stdout.decode("ascii"))
    assert manifest["production"] is False
    assert "NON-PRODUCTION" in manifest["warning"]

    transcript_proc = run_tool(["--print-transcript-manifest", "--message", MESSAGE])
    assert transcript_proc.returncode == 0, transcript_proc.stderr.decode(
        "utf-8", "replace"
    )
    transcript = json.loads(transcript_proc.stdout.decode("ascii"))
    assert transcript["schema"] == "wuci-frost-transcript-v1"
    assert transcript["production"] is False
    assert transcript["message_hex"] == MESSAGE.encode("utf-8").hex()
    assert transcript["signing_shares_emitted"] is False
    assert transcript["commitment_hash"] == labels["commitment_hash"]
    assert transcript["message_hash"] == labels["message_hash"]
    assert transcript["group_commitment"] == labels["group_commitment"]
    assert transcript["challenge"] == labels["challenge"]
    assert "signature_share" not in transcript["signers"][0]

    with tempfile.TemporaryDirectory() as temp_dir:
        manifest_path = Path(temp_dir) / "frost-fixture.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        transcript_path = Path(temp_dir) / "frost-transcript.json"

        manifest_run = run_tool(
            ["--fixture-manifest", str(manifest_path), "--message", MESSAGE]
        )
        assert manifest_run.returncode == 0, manifest_run.stderr.decode(
            "utf-8", "replace"
        )
        manifest_labels = output_labels(manifest_run.stdout)
        for name, value in signature.items():
            assert manifest_labels[name] == value, (name, manifest_labels[name], value)

        bad_manifest = json.loads(json.dumps(manifest))
        bad_manifest["production"] = True
        manifest_path.write_text(json.dumps(bad_manifest), encoding="utf-8")
        bad_run = run_tool(["--fixture-manifest", str(manifest_path), "--quiet"])
        assert bad_run.returncode != 0
        assert b"production to false" in bad_run.stderr

        bad_manifest = json.loads(json.dumps(manifest))
        bad_manifest["extra"] = "unsupported"
        manifest_path.write_text(json.dumps(bad_manifest), encoding="utf-8")
        bad_run = run_tool(["--fixture-manifest", str(manifest_path), "--quiet"])
        assert bad_run.returncode != 0
        assert b"unsupported field" in bad_run.stderr

        bad_manifest = json.loads(json.dumps(manifest))
        bad_manifest["signers"][0]["share"] = "0" * 63 + "d"
        manifest_path.write_text(json.dumps(bad_manifest), encoding="utf-8")
        bad_run = run_tool(["--fixture-manifest", str(manifest_path), "--quiet"])
        assert bad_run.returncode != 0
        assert b"does not match the built-in fixture" in bad_run.stderr

        transcript_path.write_text(json.dumps(transcript), encoding="utf-8")
        transcript_run = run_tool(
            ["--transcript-manifest", str(transcript_path), "--message", MESSAGE]
        )
        assert transcript_run.returncode == 0, transcript_run.stderr.decode(
            "utf-8", "replace"
        )
        transcript_labels = output_labels(transcript_run.stdout)
        for name, value in signature.items():
            assert transcript_labels[name] == value, (
                name,
                transcript_labels[name],
                value,
            )
        assert transcript_labels["transcript_signing_shares_emitted"] == "true"

        mismatched_message = run_tool(
            [
                "--transcript-manifest",
                str(transcript_path),
                "--message",
                "different message",
                "--quiet",
            ]
        )
        assert mismatched_message.returncode != 0
        assert b"does not match the current transcript" in mismatched_message.stderr

        bad_transcript = json.loads(json.dumps(transcript))
        bad_transcript["commitment_hash"] = "00" * 32
        transcript_path.write_text(json.dumps(bad_transcript), encoding="utf-8")
        bad_transcript_run = run_tool(
            ["--transcript-manifest", str(transcript_path), "--message", MESSAGE, "--quiet"]
        )
        assert bad_transcript_run.returncode != 0
        assert b"commitment_hash" in bad_transcript_run.stderr

        spent_transcript = json.loads(json.dumps(transcript))
        spent_transcript["signing_shares_emitted"] = True
        transcript_path.write_text(json.dumps(spent_transcript), encoding="utf-8")
        spent_run = run_tool(
            ["--transcript-manifest", str(transcript_path), "--message", MESSAGE, "--quiet"]
        )
        assert spent_run.returncode != 0
        assert b"already emitted signing shares" in spent_run.stderr

        transcript_path.write_text(json.dumps(transcript), encoding="utf-8")
        update_run = run_tool(
            [
                "--transcript-manifest",
                str(transcript_path),
                "--update-transcript-manifest",
                "--message",
                MESSAGE,
                "--quiet",
            ]
        )
        assert update_run.returncode == 0, update_run.stderr.decode(
            "utf-8", "replace"
        )
        updated_transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
        assert updated_transcript["signing_shares_emitted"] is True
        reuse_run = run_tool(
            ["--transcript-manifest", str(transcript_path), "--message", MESSAGE, "--quiet"]
        )
        assert reuse_run.returncode != 0
        assert b"already emitted signing shares" in reuse_run.stderr

    help_proc = run_tool(["--help"])
    assert help_proc.returncode == 0
    help_stdout = help_proc.stdout
    assert b"WUCI-FROST / No Such Quorum" in help_proc.stdout
    assert b"manifest-bound artifact actions" in help_proc.stdout
    assert b"not\n  encryption" in help_proc.stdout
    assert b"arbitrary signer material stays blocked" in help_stdout.lower()
    assert b"--print-transcript-manifest" in help_proc.stdout
    assert b"--transcript-manifest" in help_proc.stdout

    if args.quiet:
        return

    print(proc.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    main()
