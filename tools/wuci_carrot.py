#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "wuci-carrot-runtime-policy-v1"
DEFAULT_POLICY = Path("docs/wuci_carrot_runtime_policy.json")
FORBIDDEN_KEY_FRAGMENTS = (
    "probability",
    "chance",
    "share_net",
    "share-net",
    "host_network",
    "host-network",
)


class CarrotError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CarrotError(f"could not read policy: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CarrotError(f"policy is not valid JSON: {exc.msg}") from exc


def walk_keys(value: Any, prefix: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.lower()
            if any(fragment in lowered for fragment in FORBIDDEN_KEY_FRAGMENTS):
                if key not in {"probabilistic_enforcement", "fallback_to_host_network"}:
                    raise CarrotError(f"policy contains forbidden escape key: {prefix}{key}")
            walk_keys(child, f"{prefix}{key}.")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_keys(child, f"{prefix}{index}.")


def validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CarrotError("policy must be a JSON object")
    walk_keys(value)
    if value.get("schema") != SCHEMA:
        raise CarrotError("unsupported CARROT policy schema")
    if value.get("status") != "kernel-enforced-no-network-baseline-v1":
        raise CarrotError("unsupported CARROT policy status")
    if value.get("allow_network") is not False:
        raise CarrotError("CARROT policy must set allow_network false")
    if value.get("probabilistic_enforcement") is not False:
        raise CarrotError("probabilistic network enforcement is forbidden")
    if value.get("fallback_to_host_network") is not False:
        raise CarrotError("host network fallback is forbidden")

    kernel = value.get("kernel_enforcement")
    if not isinstance(kernel, dict):
        raise CarrotError("kernel_enforcement must be an object")
    required = kernel.get("required_namespaces")
    if not isinstance(required, list) or set(required) < {"user", "net"}:
        raise CarrotError("CARROT requires user and net namespaces")
    forbidden = set(kernel.get("forbidden_modes", []))
    for mode in ("share-net", "host-network", "best-effort-network-denial"):
        if mode not in forbidden:
            raise CarrotError(f"CARROT policy must forbid {mode}")
    required_prctl = set(kernel.get("required_prctl", []))
    if {"PR_SET_NO_NEW_PRIVS", "PR_SET_SECCOMP"} - required_prctl:
        raise CarrotError("CARROT requires no_new_privs and seccomp")
    denied = set(kernel.get("required_seccomp_deny_network_syscalls", []))
    for syscall_name in ("socket", "connect", "bind", "listen", "accept", "accept4"):
        if syscall_name not in denied:
            raise CarrotError(f"CARROT seccomp policy must deny {syscall_name}")

    role = value.get("attestation_role")
    if not isinstance(role, dict):
        raise CarrotError("attestation_role must be an object")
    if role.get("frost_or_gate_enforces_kernel_boundary") is not False:
        raise CarrotError("FROST/Gate must not be described as kernel enforcement")
    if role.get("enforcement_requires_kernel_namespace_or_equivalent") is not True:
        raise CarrotError("CARROT must require kernel namespace or equivalent enforcement")
    return value


def run_probe(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def probe_passed(probe: subprocess.CompletedProcess[bytes], marker: bytes) -> bool:
    return probe.returncode == 0 and marker in probe.stdout


def kernel_probe(probe_bin: Path) -> dict[str, Any]:
    userns = Path("/proc/sys/kernel/unprivileged_userns_clone")
    max_userns = Path("/proc/sys/user/max_user_namespaces")
    ambient = run_probe([str(probe_bin), "sandbox-net-deny-probe"])
    seccomp = run_probe([str(probe_bin), "sandbox-seccomp-net-deny-selftest"])
    namespace_selftest = run_probe(["unshare", "-Urn", str(probe_bin), "selftest"])
    namespace_seccomp = run_probe(
        ["unshare", "-Urn", str(probe_bin), "sandbox-seccomp-net-deny-selftest"]
    )
    seccomp_denied = probe_passed(seccomp, b"seccomp net-deny selftest: PASS")
    namespace_seccomp_denied = probe_passed(
        namespace_seccomp, b"seccomp net-deny selftest: PASS"
    )
    return {
        "unshare_user_net_command": "unshare -Urn",
        "probe_kind": "assembly-seccomp-network-deny-filter",
        "ambient_socket_probe_returncode": ambient.returncode,
        "ambient_socket_creation_denied": probe_passed(ambient, b"net-deny probe: PASS"),
        "unprivileged_userns_clone": userns.read_text(encoding="ascii").strip()
        if userns.exists()
        else None,
        "max_user_namespaces": max_userns.read_text(encoding="ascii").strip()
        if max_userns.exists()
        else None,
        "namespace_selftest_returncode": namespace_selftest.returncode,
        "namespace_selftest_passed": namespace_selftest.returncode == 0
        and b"selftest: PASS" in namespace_selftest.stdout,
        "seccomp_probe_returncode": seccomp.returncode,
        "seccomp_socket_probe_denied": seccomp_denied,
        "namespace_seccomp_probe_returncode": namespace_seccomp.returncode,
        "namespace_seccomp_socket_probe_denied": namespace_seccomp_denied,
        "socket_probe_denied": seccomp_denied and namespace_seccomp_denied,
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def run_validate(args: argparse.Namespace) -> int:
    validate_policy(load_json(Path(args.policy)))
    if not args.quiet:
        print("wuci carrot policy: PASS")
    return 0


def run_attest(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy)
    policy = validate_policy(load_json(policy_path))
    probe_bin = Path(args.probe_bin)
    if not probe_bin.is_file():
        raise CarrotError(f"probe binary not found: {probe_bin}")
    probe = kernel_probe(probe_bin)
    if not probe["socket_probe_denied"]:
        raise CarrotError("kernel seccomp no-network probe did not deny socket creation")
    attestation = {
        "schema": "wuci-carrot-runtime-attestation-v1",
        "policy_sha256": sha256_file(policy_path),
        "policy_status": policy["status"],
        "allow_network": False,
        "kernel_probe": probe,
        "boundary_statement": "CARROT attests runtime policy intent; seccomp plus namespace probes supply kernel enforcement evidence.",
    }
    write_json(Path(args.out), attestation)
    if not args.quiet:
        print(f"wrote CARROT attestation: {args.out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and attest WUCI-CARROT runtime policy.")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--policy", default=str(DEFAULT_POLICY))
    validate.add_argument("--quiet", action="store_true")
    validate.set_defaults(func=run_validate)

    attest = sub.add_parser("attest")
    attest.add_argument("--policy", default=str(DEFAULT_POLICY))
    attest.add_argument("--probe-bin", required=True, help="wuci-ji binary with sandbox probes")
    attest.add_argument("--out", required=True)
    attest.add_argument("--quiet", action="store_true")
    attest.set_defaults(func=run_attest)

    args = parser.parse_args()
    try:
        return args.func(args)
    except CarrotError as exc:
        print(f"wuci carrot: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
