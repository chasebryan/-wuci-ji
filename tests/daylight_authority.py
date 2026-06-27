#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DAYLIGHT_TOOL = REPO / "tools" / "daylight_authority.py"
WUCI_AUTHORITY_TOOL = REPO / "tools" / "wuci_production_authority.py"
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_daylight(*args: str) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(DAYLIGHT_TOOL), *args])


def run_wuci(*args: str) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(WUCI_AUTHORITY_TOOL), *args])


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def current_commit() -> str:
    proc = run_cmd(["git", "rev-parse", "HEAD"])
    assert_ok(proc, "read current commit")
    return proc.stdout.decode("ascii").strip()


def deterministic_group_key() -> str:
    for x in range(10001, 30000):
        rhs = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
        y = pow(rhs, (SECP256K1_P + 1) // 4, SECP256K1_P)
        if (y * y) % SECP256K1_P == rhs:
            prefix = "03" if y & 1 else "02"
            return prefix + f"{x:064x}"
    raise AssertionError("could not find deterministic secp256k1 point")


def keygen(path: Path) -> None:
    ssh_keygen = shutil.which("ssh-keygen")
    assert ssh_keygen is not None, "ssh-keygen is required for signed authority tests"
    assert_ok(
        run_cmd([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(path)]),
        "generate authority ceremony signing key",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Daylight authority evidence verifier.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="daylight-authority-") as tmp_name:
        tmp = Path(tmp_name)
        authority = tmp / "daylight-prod-authority.txt"
        ceremony = tmp / "daylight-prod-authority-ceremony.json"
        ceremony_key = tmp / "daylight-ceremony-key"
        ceremony_signature = tmp / "daylight-prod-authority-ceremony.json.sig"
        evidence = tmp / "daylight-authority.json"

        assert_ok(
            run_wuci(
                "emit-root",
                "--group-public-key",
                deterministic_group_key(),
                "--allow-open",
                "--allow-release",
                "--out",
                str(authority),
                "--quiet",
            ),
            "emit non-fixture production authority root",
        )
        trust_emit = run_wuci(
            "emit-root",
            "--group-public-key",
            deterministic_group_key(),
            "--allow-open",
            "--allow-release",
            "--allow-trust",
            "--out",
            str(tmp / "trust-authority.txt"),
            "--quiet",
        )
        assert trust_emit.returncode != 0
        assert b"trust/publish authority requires assembly Gate" in trust_emit.stderr

        assert_ok(
            run_wuci(
                "ceremony",
                "--authority",
                str(authority),
                "--operator",
                "external authority operator",
                "--ceremony-id",
                "daylight-authority-test-v1",
                "--threshold",
                "4",
                "--signer-count",
                "5",
                "--created-utc",
                "2026-06-27T00:00:00Z",
                "--out",
                str(ceremony),
                "--quiet",
            ),
            "write authority ceremony",
        )
        keygen(ceremony_key)
        ceremony_root_key = ceremony_key.with_suffix(".pub")
        assert_ok(
            run_wuci(
                "sign-ceremony",
                "--ceremony",
                str(ceremony),
                "--signing-key",
                str(ceremony_key),
                "--ceremony-root-key",
                str(ceremony_root_key),
                "--signature",
                str(ceremony_signature),
                "--quiet",
            ),
            "sign authority ceremony",
        )
        assert_ok(
            run_daylight(
                "emit-candidate",
                "--repo",
                str(REPO),
                "--authority",
                str(authority),
                "--ceremony",
                str(ceremony),
                "--ceremony-root-key",
                str(ceremony_root_key),
                "--ceremony-signature",
                str(ceremony_signature),
                "--reviewed-commit",
                current_commit(),
                "--certificate",
                "--revocation",
                "--transparency-log",
                "--install",
                "--witness",
                "--publish",
                "--trust",
                "--out",
                str(evidence),
                "--quiet",
            ),
            "emit Daylight authority evidence",
        )
        verified = run_daylight("verify", "--repo", str(REPO), "--evidence", str(evidence), "--json")
        assert_ok(verified, "verify Daylight authority candidate")
        summary = json.loads(verified.stdout.decode("utf-8"))
        assert summary["schema"] == "daylight-v06-authority-verification-v1"
        assert summary["signed_wuci_authority_verified"] is True
        assert summary["ceremony_root_key_sha256"] == hashlib.sha256(ceremony_root_key.read_bytes()).hexdigest()
        assert summary["integrated_predicates"] is False
        assert summary["public_authority_proofs"]["certificate"]["status"] == "missing"
        assert summary["predicate_proofs_bound"]["certificate"] is False
        assert summary["authority_supports_public_gate"] is False
        assert summary["integrated_public_authority"] is False
        assert summary["production_authority_for_daylight"] is False
        assert "public authority predicate proof missing: certificate" in summary["remaining_blockers"]
        assert "signed production authority must support trust authority" in summary["remaining_blockers"]
        assert "signed production authority must support publish authority" in summary["remaining_blockers"]

        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["production_authority"]["ceremony_root_key_sha256"] = "0" * 64
        root_key_mismatch = tmp / "daylight-authority-root-key-mismatch.json"
        root_key_mismatch.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        root_key_mismatch_result = run_daylight(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(root_key_mismatch),
            "--quiet",
        )
        assert root_key_mismatch_result.returncode != 0
        assert b"Daylight authority ceremony root key SHA-256 mismatch" in root_key_mismatch_result.stderr

        proof = tmp / "certificate-proof.txt"
        proof.write_text("deterministic certificate proof placeholder\n", encoding="ascii")
        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["public_authority_proofs"]["certificate"] = {
            "status": "verified",
            "evidence": proof.name,
            "evidence_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
            "verification_command": "make daylight-v06-authority-verifier-test",
        }
        proof_bound = tmp / "daylight-authority-certificate-proof.json"
        proof_bound.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        proof_bound_result = run_daylight("verify", "--repo", str(REPO), "--evidence", str(proof_bound), "--json")
        assert_ok(proof_bound_result, "verify proof-bound Daylight authority candidate")
        proof_bound_summary = json.loads(proof_bound_result.stdout.decode("utf-8"))
        assert proof_bound_summary["predicate_proofs_bound"]["certificate"] is True
        assert "public authority predicate proof missing: certificate" not in proof_bound_summary["remaining_blockers"]
        assert "public authority predicate proof missing: revocation" in proof_bound_summary["remaining_blockers"]

        value["public_authority_proofs"]["certificate"]["evidence_sha256"] = "0" * 64
        bad_proof = tmp / "daylight-authority-bad-certificate-proof.json"
        bad_proof.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        bad_proof_result = run_daylight("verify", "--repo", str(REPO), "--evidence", str(bad_proof), "--quiet")
        assert bad_proof_result.returncode != 0
        assert b"certificate public authority proof digest mismatch" in bad_proof_result.stderr

        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["integrated_public_authority"] = True
        self_claiming = tmp / "daylight-authority-self-claiming.json"
        self_claiming.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self_claiming_result = run_daylight(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(self_claiming),
            "--quiet",
        )
        assert self_claiming_result.returncode != 0
        assert b"unexpected Daylight authority evidence fields" in self_claiming_result.stderr

        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["production_authority"]["allow_publish"] = True
        nested_self_claiming = tmp / "daylight-authority-nested-self-claiming.json"
        nested_self_claiming.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        nested_self_claiming_result = run_daylight(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(nested_self_claiming),
            "--quiet",
        )
        assert nested_self_claiming_result.returncode != 0
        assert b"unexpected production_authority fields" in nested_self_claiming_result.stderr

        strict = run_daylight(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(evidence),
            "--require-integrated",
            "--quiet",
        )
        assert strict.returncode != 0
        assert b"Daylight integrated public authority is incomplete" in strict.stderr

        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["public_authority_predicates"]["certificate"] = False
        missing_predicate = tmp / "daylight-authority-missing-predicate.json"
        missing_predicate.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        missing = run_daylight(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(missing_predicate),
            "--require-integrated",
            "--quiet",
        )
        assert missing.returncode != 0
        assert b"certificate" in missing.stderr
        missing_json = run_daylight("verify", "--repo", str(REPO), "--evidence", str(missing_predicate), "--json")
        assert_ok(missing_json, "verify missing-predicate Daylight authority candidate")
        missing_summary = json.loads(missing_json.stdout.decode("utf-8"))
        assert "public authority predicate missing: certificate" in missing_summary["remaining_blockers"]

        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["reviewed_commit"] = hashlib.sha1(b"stale").hexdigest()
        stale = tmp / "daylight-authority-stale.json"
        stale.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        stale_result = run_daylight("verify", "--repo", str(REPO), "--evidence", str(stale), "--quiet")
        assert stale_result.returncode != 0
        assert b"reviewed_commit does not match current HEAD" in stale_result.stderr

    if not args.quiet:
        print("Daylight authority verifier: PASS")


if __name__ == "__main__":
    main()
