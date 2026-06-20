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

    with tempfile.TemporaryDirectory() as temp_dir:
        manifest_path = Path(temp_dir) / "frost-fixture.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

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

    help_proc = run_tool(["--help"])
    assert help_proc.returncode == 0
    assert b"WUCI-FROST / No Such Quorum" in help_proc.stdout
    assert b"manifest-bound artifact actions" in help_proc.stdout
    assert b"not\n  encryption" in help_proc.stdout
    assert b"arbitrary signer material stays blocked" in help_proc.stdout

    if args.quiet:
        return

    print(proc.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    main()
