#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CAGE_TOOL = REPO_ROOT / "tools" / "wuci_cage.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


def run_cmd(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    env["WUCI_JI_RUNNER"] = " ".join(RUNNER)
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
        env=env,
    )


def run_wuci(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([*RUNNER, str(BIN), *args])


def run_cage(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(CAGE_TOOL), *args])


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_cage_fails(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode != 0, context
    assert b"wuci cage:" in proc.stderr, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def load_witness_helpers():
    helper_path = REPO_ROOT / "tests" / "wuci_witness.py"
    spec = importlib.util.spec_from_file_location("wuci_witness_test_helpers", helper_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_case(base: Path, tmp: Path, name: str) -> Path:
    case_dir = tmp / name
    shutil.copytree(base, case_dir)
    return case_dir


def replace_value(text: str, label: str, value: str) -> str:
    prefix = f"{label}: "
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return "".join(lines)
    raise AssertionError(f"missing label {label}")


def mutate_label(path: Path, label: str, value: str) -> None:
    path.write_text(
        replace_value(path.read_text(encoding="ascii"), label, value),
        encoding="ascii",
    )


def cage_attest(bundle: Path, out: Path) -> subprocess.CompletedProcess[bytes]:
    return run_cage(["attest", "--bin", str(BIN), "--bundle", str(bundle), "--out", str(out)])


def cage_verify(bundle: Path, attestation: Path) -> subprocess.CompletedProcess[bytes]:
    return run_cage(
        [
            "verify",
            "--bin",
            str(BIN),
            "--bundle",
            str(bundle),
            "--attestation",
            str(attestation),
        ]
    )


def build_cage_attestation(bundle: Path, tmp: Path, name: str) -> Path:
    out = tmp / f"{name}.json"
    assert_ok(cage_attest(bundle, out), f"attest {name}")
    assert_ok(cage_verify(bundle, out), f"verify {name}")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-CAGE bundle behavior.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    helpers = load_witness_helpers()
    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        base = tmp / "witness-bundle"
        helpers.build_public_witness_bundle(base, tmp / "work")

        policy = run_cage(["policy", "--print"])
        assert_ok(policy, "print CAGE policy")
        assert b'"schema": "wuci-cage-policy-v1"' in policy.stdout

        attestation = build_cage_attestation(base, tmp, "cage-attestation")
        ledger_entry = tmp / "cage-ledger-entry.txt"
        assert_ok(
            run_cage(
                [
                    "ledger-entry",
                    "--attestation",
                    str(attestation),
                    "--out",
                    str(ledger_entry),
                ]
            ),
            "write CAGE ledger entry",
        )
        leaf = run_wuci(["ledger-leaf-file", str(ledger_entry)])
        assert_ok(leaf, "hash CAGE ledger entry")
        assert len(leaf.stdout.strip()) == 64

        missing_manifest = copy_case(base, tmp, "missing-manifest")
        (missing_manifest / "manifest.txt").unlink()
        assert_cage_fails(
            cage_attest(missing_manifest, tmp / "missing-manifest.json"),
            "missing manifest rejected",
        )

        symlink_manifest = copy_case(base, tmp, "symlink-manifest")
        symlink_target = tmp / "symlink-manifest-equivalent.txt"
        symlink_target.write_bytes((symlink_manifest / "manifest.txt").read_bytes())
        (symlink_manifest / "manifest.txt").unlink()
        (symlink_manifest / "manifest.txt").symlink_to(symlink_target)
        assert_cage_fails(
            cage_attest(symlink_manifest, tmp / "symlink-manifest.json"),
            "symlink manifest rejected",
        )

        hardlink_manifest = copy_case(base, tmp, "hardlink-manifest")
        hardlink_target = tmp / "hardlink-manifest-equivalent.txt"
        hardlink_target.write_bytes((hardlink_manifest / "manifest.txt").read_bytes())
        (hardlink_manifest / "manifest.txt").unlink()
        os.link(hardlink_target, hardlink_manifest / "manifest.txt")
        assert_cage_fails(
            cage_attest(hardlink_manifest, tmp / "hardlink-manifest.json"),
            "hardlink manifest rejected",
        )

        if hasattr(os, "symlink"):
            symlink_root = tmp / "symlink-bundle-root"
            symlink_root.symlink_to(base, target_is_directory=True)
            assert_cage_fails(
                cage_attest(symlink_root, tmp / "symlink-bundle-root.json"),
                "symlink bundle root rejected",
            )

        tampered_manifest = copy_case(base, tmp, "tampered-manifest")
        with (tampered_manifest / "manifest.txt").open("ab") as handle:
            handle.write(b"# tamper\n")
        assert_cage_fails(
            cage_attest(tampered_manifest, tmp / "tampered-manifest.json"),
            "tampered manifest rejected",
        )

        missing_decision = copy_case(base, tmp, "missing-decision")
        (missing_decision / "release-decision.txt").unlink()
        assert_cage_fails(
            cage_attest(missing_decision, tmp / "missing-decision.json"),
            "missing release decision rejected",
        )

        denied_decision = copy_case(base, tmp, "denied-decision")
        mutate_label(denied_decision / "release-decision.txt", "authorized", "false")
        assert_cage_fails(
            cage_attest(denied_decision, tmp / "denied-decision.json"),
            "denied release decision rejected",
        )

        open_decision = copy_case(base, tmp, "open-decision")
        mutate_label(open_decision / "release-decision.txt", "action", "open")
        assert_cage_fails(
            cage_attest(open_decision, tmp / "open-decision.json"),
            "open release decision rejected",
        )

        artifact_key = copy_case(base, tmp, "artifact-key-present")
        (artifact_key / "artifact.key").write_text(("11" * 32) + "\n", encoding="ascii")
        assert_cage_fails(
            cage_attest(artifact_key, tmp / "artifact-key.json"),
            "artifact key rejected",
        )

        opened_binary = copy_case(base, tmp, "opened-binary-present")
        (opened_binary / "opened-wuci-ji").write_bytes(b"not public evidence\n")
        assert_cage_fails(
            cage_attest(opened_binary, tmp / "opened-binary.json"),
            "opened binary rejected",
        )

        transcript = copy_case(base, tmp, "release-transcript-present")
        (transcript / "release-transcript.json").write_text("{}\n", encoding="ascii")
        assert_cage_fails(
            cage_attest(transcript, tmp / "release-transcript.json"),
            "release transcript rejected",
        )

        private_marker = copy_case(base, tmp, "private-marker")
        with (private_marker / "manifest.txt").open("a", encoding="ascii") as handle:
            handle.write("group_secret: forbidden\n")
        assert_cage_fails(
            cage_attest(private_marker, tmp / "private-marker.json"),
            "private material marker rejected",
        )

        wrong_hash = tmp / "wrong-artifact-hash.json"
        wrong_value = json.loads(attestation.read_text(encoding="utf-8"))
        wrong_value["artifact_sha256"] = "00" * 32
        wrong_hash.write_text(json.dumps(wrong_value, indent=2, sort_keys=True) + "\n")
        assert_cage_fails(
            cage_verify(base, wrong_hash),
            "wrong artifact hash attestation rejected",
        )

        sandbox_claim = tmp / "sandbox-claim.json"
        sandbox_value = json.loads(attestation.read_text(encoding="utf-8"))
        sandbox_value["runtime_sandbox_enforced"] = True
        sandbox_claim.write_text(json.dumps(sandbox_value, indent=2, sort_keys=True) + "\n")
        assert_cage_fails(
            cage_verify(base, sandbox_claim),
            "runtime sandbox overclaim rejected",
        )

        run_marker = tmp / "would-have-run"
        executable_artifact = tmp / "artifact.sh"
        executable_artifact.write_text(
            "#!/bin/sh\n"
            f"touch {run_marker}\n",
            encoding="ascii",
        )
        executable_artifact.chmod(0o755)
        denial = tmp / "run-denied.txt"
        assert_ok(
            run_cage(
                [
                    "deny-run",
                    "--artifact",
                    str(executable_artifact),
                    "--out",
                    str(denial),
                ]
            ),
            "deny run",
        )
        assert not run_marker.exists()
        assert denial.read_text(encoding="ascii") == (
            "schema: wuci-cage-run-decision-v1\n"
            "authorized: false\n"
            "action: run\n"
            "reason: runtime sandbox enforcement is not implemented in WUCI-CAGE v1\n"
        )

    if not args.quiet:
        print("wuci cage bundle: PASS")


if __name__ == "__main__":
    main()
