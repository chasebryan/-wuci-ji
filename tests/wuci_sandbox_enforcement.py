#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "docs" / "wuci_carrot_runtime_policy.json"
CARROT = REPO_ROOT / "tools" / "wuci_carrot.py"
RUST_WRAPPER = REPO_ROOT / "tools" / "wuci_sandbox.rs"
BIN = REPO_ROOT / "build" / "wuci-ji"


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI kernel sandbox enforcement.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    assert shutil.which("unshare") is not None, "unshare is required for kernel sandbox proof"
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert policy["schema"] == "wuci-carrot-runtime-policy-v1"
    assert policy["allow_network"] is False
    assert policy["probabilistic_enforcement"] is False
    assert policy["fallback_to_host_network"] is False
    assert {"user", "net"} <= set(policy["kernel_enforcement"]["required_namespaces"])
    assert {"PR_SET_NO_NEW_PRIVS", "PR_SET_SECCOMP"} <= set(
        policy["kernel_enforcement"]["required_prctl"]
    )
    assert {"socket", "connect", "bind", "listen", "accept", "accept4"} <= set(
        policy["kernel_enforcement"]["required_seccomp_deny_network_syscalls"]
    )
    assert "share-net" in policy["kernel_enforcement"]["forbidden_modes"]
    assert policy["attestation_role"]["frost_or_gate_enforces_kernel_boundary"] is False

    assert_ok(
        run_cmd([sys.executable, str(CARROT), "validate", "--policy", str(POLICY), "--quiet"]),
        "validate CARROT policy",
    )

    assert_ok(run_cmd(["unshare", "-Urn", "true"]), "enter user+network namespace")
    assert_ok(
        run_cmd([str(BIN), "sandbox-seccomp-net-deny-selftest"]),
        "assembly seccomp socket denial selftest",
    )
    assert_ok(
        run_cmd(["unshare", "-Urn", str(BIN), "selftest"]),
        "assembly selftest inside user+network namespace",
    )

    assert_ok(
        run_cmd(["unshare", "-Urn", str(BIN), "sandbox-seccomp-net-deny-selftest"]),
        "assembly seccomp socket denial selftest inside user+network namespace",
    )

    rust = RUST_WRAPPER.read_text(encoding="utf-8")
    for required in (
        "PR_SET_NO_NEW_PRIVS",
        "PR_SET_SECCOMP",
        "SECCOMP_RET_ERRNO",
        "CLONE_NEWUSER",
        "CLONE_NEWNET",
        "SYS_SOCKET",
        "SYS_CONNECT",
        "SYS_CLOSE_RANGE",
        "unshare(",
        "Command::new",
    ):
        assert required in rust, required
    for forbidden in ("sh -c", "bash", "share-net", "host-network"):
        assert forbidden not in rust, forbidden

    if not args.quiet:
        print("wuci sandbox enforcement: PASS")


if __name__ == "__main__":
    main()
