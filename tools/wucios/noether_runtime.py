#!/usr/bin/env python3
"""Runtime inventory and fail-closed contract checks for Noether Forge.

This is local defensive verification. It does not claim general runtime
containment, production authority, external validation, or quantum safety.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence


REPORT_SCHEMA = "wucios.noether.runtime.v1"
RELEASE = "2.4.0"
CODENAME = "Noether Forge"
PROFILE = "noether-core"
SUBSTRATE = "alpine-3.24.1"
ARCH = "x86_64"
PASS_MARKER = (
    "NOETHER_FORGE_RUNTIME_PASS "
    f"schema={REPORT_SCHEMA} release={RELEASE} profile={PROFILE} "
    f"substrate={SUBSTRATE} arch={ARCH}"
)
FAIL_MARKER = "NOETHER_FORGE_RUNTIME_FAIL"

EXPECTED_RUNLEVELS = {
    "sysinit": ["devfs", "dmesg", "hwdrivers", "mdev", "modloop"],
    "boot": [
        "bootmisc",
        "hostname",
        "hwclock",
        "localmount",
        "modules",
        "nftables",
        "sysctl",
        "syslog",
        "wuci-loopback",
    ],
    "default": ["wuci-runtime-contract"],
    "shutdown": ["killprocs", "mount-ro", "savecache"],
}

REQUIRED_COMMANDS = [
    "apk",
    "daylight-claim-scan",
    "doas",
    "nft",
    "openssl",
    "python3",
    "rc-status",
    "wuci-ji",
    "wuci-prism",
    "wuci-runtime-contract",
    "wuci-status",
    "wuci-surface-audit",
]

DENIED_PACKAGE_SET_PATH = "/usr/share/wucios/cantor-denied-noether-packages.txt"

EXPECTED_DOAS_POLICY = (
    "permit nopass wj as root cmd /usr/sbin/nft args list ruleset\n"
    "permit nopass wj as root cmd /sbin/poweroff args\n"
    "permit nopass wj as wj_low cmd /bin/ash args -l\n"
)

DENIED_SERVICE_NAMES = {
    "apache2",
    "avahi-daemon",
    "bluetooth",
    "chronyd",
    "cupsd",
    "dhcpcd",
    "docker",
    "httpd",
    "networking",
    "nginx",
    "ntpd",
    "openntpd",
    "sshd",
    "tiny-cloud-boot",
    "tiny-cloud-early",
    "tiny-cloud-final",
    "tiny-cloud-main",
}

DENIED_COMMANDS = [
    "Xorg",
    "chromium",
    "clang",
    "cmake",
    "dwm",
    "firefox",
    "gcc",
    "make",
    "ratpoison",
    "startx",
    "xbps-install",
]

NON_CLAIMS = [
    "The loaded nftables policy is not a general runtime sandbox or OS containment claim.",
    "The live-console trust model is not an installed-system credential model.",
    "Classical signatures and hashes do not establish quantum safety.",
    "This report grants no publish, trust, certification, or production authority.",
]


class RuntimeContractError(RuntimeError):
    pass


def root_path(root: Path, guest_path: str) -> Path:
    if not guest_path.startswith("/"):
        raise RuntimeContractError(f"guest path must be absolute: {guest_path}")
    return root / guest_path.lstrip("/")


def read_regular_text(path: Path, *, limit: int = 4 * 1024 * 1024) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeContractError(f"not a regular file: {path}")
    if info.st_nlink != 1:
        raise RuntimeContractError(f"hardlinked evidence file rejected: {path}")
    if info.st_size > limit:
        raise RuntimeContractError(f"evidence file exceeds {limit} bytes: {path}")
    return path.read_text(encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def parse_colon_records(path: Path) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    for line in read_regular_text(path).splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if fields[0] in records:
            raise RuntimeContractError(f"duplicate record {fields[0]} in {path}")
        records[fields[0]] = fields
    return records


def parse_os_release(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in read_regular_text(path).splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key] = value
    return result


def parse_apk_installed(path: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key_names = {"P": "name", "V": "version", "A": "architecture", "L": "license", "o": "origin"}
    for line in read_regular_text(path, limit=16 * 1024 * 1024).splitlines() + [""]:
        if not line:
            if current.get("name") and current.get("version"):
                packages.append(current)
            current = {}
            continue
        if len(line) >= 3 and line[1] == ":" and line[0] in key_names:
            current[key_names[line[0]]] = line[2:]
    return sorted(packages, key=lambda item: (item["name"], item["version"]))


def parse_denied_package_set(path: Path) -> list[str]:
    values = [
        line.strip()
        for line in read_regular_text(path).splitlines()
        if line.strip() and not line.startswith("#")
    ]
    malformed = any(
        "/" in value or any(character.isspace() for character in value)
        for value in values
    )
    if not values or len(values) != len(set(values)) or malformed:
        raise RuntimeContractError("canonical denied-package set is empty, duplicated, or malformed")
    return sorted(values)


def parse_runtime_package_contract(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_regular_text(path))
    except json.JSONDecodeError as exc:
        raise RuntimeContractError(f"runtime package contract is invalid JSON: {exc}") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "release", "package_count", "packages"}
        or value.get("schema") != "wucios.noether_forge.runtime_package_contract.v1"
        or value.get("release") != "noether-forge-v2.4.0"
    ):
        raise RuntimeContractError("runtime package contract schema mismatch")
    packages = value.get("packages")
    if not isinstance(packages, list) or value.get("package_count") != 52 or len(packages) != 52:
        raise RuntimeContractError("runtime package contract must list exactly 52 packages")
    identities: list[tuple[str, str, str]] = []
    for package in packages:
        if (
            not isinstance(package, dict)
            or set(package) != {"name", "version", "package_architecture", "installed_architecture", "apk_sha256"}
            or any(
                not isinstance(package.get(key), str) or not package.get(key)
                for key in ("name", "version", "package_architecture", "installed_architecture")
            )
            or not isinstance(package.get("apk_sha256"), str)
            or len(package["apk_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in package["apk_sha256"])
        ):
            raise RuntimeContractError("runtime package contract contains an invalid package record")
        identities.append((package["name"], package["version"], package["installed_architecture"]))
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise RuntimeContractError("runtime package contract identities must be unique and sorted")
    return value


def inventory_runlevels(root: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    base = root_path(root, "/etc/runlevels")
    for runlevel in EXPECTED_RUNLEVELS:
        directory = base / runlevel
        if not directory.is_dir():
            result[runlevel] = []
            continue
        result[runlevel] = sorted(entry.name for entry in directory.iterdir())
    return result


def inventory_openrc_health(root: Path) -> dict[str, Any]:
    state_root = root_path(root, "/run/openrc")
    failed = state_root / "failed"
    return {
        "state_directory_present": state_root.is_dir(),
        "failed_directory_present": failed.is_dir(),
        "failed_services": sorted(entry.name for entry in failed.iterdir()) if failed.is_dir() else [],
    }


def parse_proc_sockets(root: Path) -> list[dict[str, Any]]:
    sockets: list[dict[str, Any]] = []
    for protocol, guest_path in (
        ("tcp", "/proc/net/tcp"),
        ("tcp6", "/proc/net/tcp6"),
        ("udp", "/proc/net/udp"),
        ("udp6", "/proc/net/udp6"),
    ):
        path = root_path(root, guest_path)
        if not path.is_file():
            continue
        lines = path.read_text(encoding="ascii", errors="strict").splitlines()[1:]
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or ":" not in fields[1]:
                continue
            address, port_hex = fields[1].rsplit(":", 1)
            port = int(port_hex, 16)
            state = fields[3]
            if protocol.startswith("tcp") and state != "0A":
                continue
            if protocol.startswith("udp") and port == 0:
                continue
            sockets.append({"protocol": protocol, "address_hex": address, "port": port, "state": state})
    return sorted(sockets, key=lambda item: (item["protocol"], item["port"], item["address_hex"]))


def inventory_default_routes(root: Path) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []
    ipv4 = root_path(root, "/proc/net/route")
    if ipv4.is_file():
        for line in ipv4.read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3 and fields[1] == "00000000" and fields[0] != "lo":
                routes.append({"family": "ipv4", "interface": fields[0], "gateway_hex": fields[2]})
    ipv6 = root_path(root, "/proc/net/ipv6_route")
    if ipv6.is_file():
        for line in ipv6.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == "0" * 32 and fields[1] == "00" and fields[-1] != "lo":
                routes.append({"family": "ipv6", "interface": fields[-1], "gateway_hex": fields[4]})
    return routes


def inventory_interfaces(root: Path) -> list[str]:
    base = root_path(root, "/sys/class/net")
    return sorted(entry.name for entry in base.iterdir()) if base.is_dir() else []


def inventory_privileged_files(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    excluded_top_level = {"dev", "media", "mnt", "proc", "run", "sys", "tmp"}
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if current_path == root:
            dirs[:] = [name for name in sorted(dirs) if name not in excluded_top_level]
        else:
            dirs[:] = sorted(name for name in dirs if not (current_path / name).is_symlink())
        files.sort()
        for name in files:
            path = current_path / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                guest = "/" + str(path.relative_to(root))
                records.append({
                    "path": guest,
                    "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                })
    return sorted(records, key=lambda item: item["path"])


def inventory_modules(root: Path) -> list[str]:
    path = root_path(root, "/proc/modules")
    if not path.is_file():
        return []
    return sorted(line.split()[0] for line in path.read_text(encoding="ascii").splitlines() if line.split())


def inventory_home_directories(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, guest_path in (("wj", "/home/wj"), ("wj_low", "/home/wj_low")):
        path = root_path(root, guest_path)
        try:
            info = path.lstat()
        except OSError as exc:
            result[name] = {"path": guest_path, "error": str(exc)}
            continue
        result[name] = {
            "path": guest_path,
            "type": "directory" if stat.S_ISDIR(info.st_mode) else "other",
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "uid": info.st_uid,
            "gid": info.st_gid,
        }
    return result


def command_path(name: str, root: Path) -> str | None:
    if root == Path("/"):
        return shutil.which(name)
    for prefix in ("usr/local/bin", "usr/local/sbin", "usr/bin", "usr/sbin", "bin", "sbin"):
        candidate = root / prefix / name
        if candidate.exists() or candidate.is_symlink():
            return "/" + str(candidate.relative_to(root))
    return None


def run_command(argv: Sequence[str], *, cwd: Path | None = None, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=timeout,
        env={**os.environ, "PYTHONPATH": "/usr/local/lib/wucios"},
    )


def nft_inventory() -> dict[str, Any]:
    text_result = run_command(["nft", "list", "ruleset"])
    json_result = run_command(["nft", "-j", "list", "ruleset"])
    parsed: dict[str, Any] | None = None
    if json_result.returncode == 0:
        try:
            parsed = json.loads(json_result.stdout)
        except json.JSONDecodeError:
            parsed = None
    return {
        "text_exit": text_result.returncode,
        "text": text_result.stdout,
        "text_stderr": text_result.stderr,
        "json_exit": json_result.returncode,
        "json": parsed,
        "json_stderr": json_result.stderr,
    }


def collect_inventory(root: Path = Path("/"), *, include_firewall: bool = True) -> dict[str, Any]:
    os_release = parse_os_release(root_path(root, "/etc/os-release"))
    packages = parse_apk_installed(root_path(root, "/lib/apk/db/installed"))
    release_path = root_path(root, "/usr/share/wucios/release.json")
    package_lock_path = root_path(root, "/usr/share/wucios/package-lock.json")
    runtime_package_contract = parse_runtime_package_contract(root_path(root, "/usr/share/wucios/runtime-package-contract.json"))
    inventory: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "release": RELEASE,
        "codename": CODENAME,
        "profile": PROFILE,
        "substrate": SUBSTRATE,
        "architecture": ARCH,
        "os_release": os_release,
        "alpine_release": read_regular_text(root_path(root, "/etc/alpine-release")).strip(),
        "kernel": os.uname().release if root == Path("/") else "fixture-root",
        "accounts": parse_colon_records(root_path(root, "/etc/passwd")),
        "groups": parse_colon_records(root_path(root, "/etc/group")),
        "shadow": parse_colon_records(root_path(root, "/etc/shadow")),
        "home_directories": inventory_home_directories(root),
        "doas_policy": read_regular_text(root_path(root, "/etc/doas.conf")),
        "denied_package_names": parse_denied_package_set(root_path(root, DENIED_PACKAGE_SET_PATH)),
        "packages": packages,
        "runtime_package_contract": runtime_package_contract,
        "package_count": len(packages),
        "runlevels": inventory_runlevels(root),
        "openrc_health": inventory_openrc_health(root),
        "listeners": parse_proc_sockets(root),
        "interfaces": inventory_interfaces(root),
        "default_routes": inventory_default_routes(root),
        "privileged_files": inventory_privileged_files(root),
        "kernel_modules": inventory_modules(root),
        "required_commands": {name: command_path(name, root) for name in REQUIRED_COMMANDS},
        "denied_commands_present": {name: command_path(name, root) for name in DENIED_COMMANDS if command_path(name, root)},
        "release_manifest_sha256": sha256_file(release_path),
        "package_lock_sha256": sha256_file(package_lock_path),
        "non_claims": list(NON_CLAIMS),
    }
    if include_firewall and root == Path("/"):
        inventory["firewall"] = nft_inventory()
    else:
        inventory["firewall"] = {"status": "not-executed-for-fixture-root"}
    return inventory


def add_check(checks: list[dict[str, Any]], check_id: str, passed: bool, detail: Any) -> None:
    checks.append({"id": check_id, "status": "pass" if passed else "fail", "detail": detail})


def account_checks(inventory: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    accounts = inventory["accounts"]
    shadow = inventory["shadow"]
    groups = inventory["groups"]
    expected = {
        "root": ("0", "0", "/root", "/bin/ash"),
        "wj": ("1000", "1000", "/home/wj", "/bin/ash"),
        "wj_low": ("1001", "1001", "/home/wj_low", "/bin/ash"),
    }
    for name, (uid, gid, home, shell) in expected.items():
        fields = accounts.get(name, [])
        passed = len(fields) >= 7 and (fields[2], fields[3], fields[5], fields[6]) == (uid, gid, home, shell)
        add_check(checks, f"account-{name}", passed, fields)
        shadow_fields = shadow.get(name, [])
        locked = len(shadow_fields) >= 2 and shadow_fields[1].startswith("!")
        add_check(checks, f"password-locked-{name}", locked, shadow_fields[1] if len(shadow_fields) >= 2 else "missing")
    add_check(checks, "legacy-anon-account-absent", "anon" not in accounts, sorted(accounts))
    uid_zero_accounts = sorted(name for name, fields in accounts.items() if len(fields) >= 3 and fields[2] == "0")
    add_check(checks, "unique-root-uid", uid_zero_accounts == ["root"], uid_zero_accounts)
    unlocked = sorted(
        name for name in accounts
        if name not in shadow or len(shadow[name]) < 2 or not shadow[name][1] or shadow[name][1][0] not in "!*"
    )
    add_check(checks, "all-local-passwords-locked", not unlocked and set(shadow) == set(accounts), {
        "unlocked_or_missing": unlocked,
        "extra_shadow_records": sorted(set(shadow) - set(accounts)),
    })
    wheel_members = sorted(member for member in groups.get("wheel", ["", "", "", ""])[3].split(",") if member)
    add_check(checks, "wheel-membership", wheel_members == ["root"], wheel_members)
    expected_homes = {
        "wj": {"path": "/home/wj", "type": "directory", "mode": "0700", "uid": 1000, "gid": 1000},
        "wj_low": {"path": "/home/wj_low", "type": "directory", "mode": "0700", "uid": 1001, "gid": 1001},
    }
    add_check(checks, "home-directory-contract", inventory["home_directories"] == expected_homes, inventory["home_directories"])


def static_inventory_checks(inventory: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    os_release = inventory["os_release"]
    add_check(
        checks,
        "release-identity",
        os_release.get("ID") == "wucios"
        and os_release.get("ID_LIKE") == "alpine"
        and os_release.get("VERSION_ID") == RELEASE
        and os_release.get("VERSION_CODENAME") == "noether-forge",
        os_release,
    )
    add_check(checks, "alpine-release", inventory["alpine_release"] == "3.24.1", inventory["alpine_release"])
    if inventory["kernel"] != "fixture-root":
        add_check(checks, "kernel-release", inventory["kernel"] == "6.18.35-0-lts", inventory["kernel"])
    account_checks(inventory, checks)

    missing = sorted(name for name, path in inventory["required_commands"].items() if path is None)
    add_check(checks, "required-commands", not missing, missing)
    add_check(checks, "denied-commands", not inventory["denied_commands_present"], inventory["denied_commands_present"])

    package_names = [item["name"] for item in inventory["packages"]]
    observed_package_identities = [
        {key: item.get(key) for key in ("name", "version", "architecture")}
        for item in inventory["packages"]
    ]
    expected_package_identities = [
        {"name": item["name"], "version": item["version"], "architecture": item["installed_architecture"]}
        for item in inventory["runtime_package_contract"]["packages"]
    ]
    add_check(
        checks,
        "exact-installed-package-closure",
        observed_package_identities == expected_package_identities,
        {"expected": expected_package_identities, "observed": observed_package_identities},
    )
    denied_names = inventory["denied_package_names"]
    denied_packages = sorted(
        name for name in package_names
        if any(name == denied or name.startswith(denied + "-") for denied in denied_names)
    )
    add_check(checks, "denied-packages", not denied_packages, denied_packages)
    add_check(checks, "doas-command-policy", inventory["doas_policy"] == EXPECTED_DOAS_POLICY, inventory["doas_policy"])

    add_check(checks, "runlevel-contract", inventory["runlevels"] == EXPECTED_RUNLEVELS, inventory["runlevels"])
    openrc_health = inventory["openrc_health"]
    add_check(
        checks,
        "openrc-failed-services",
        openrc_health["state_directory_present"] and openrc_health["failed_directory_present"] and not openrc_health["failed_services"],
        openrc_health,
    )
    enabled = {name for services in inventory["runlevels"].values() for name in services}
    denied_services = sorted(enabled & DENIED_SERVICE_NAMES)
    add_check(checks, "denied-services", not denied_services, denied_services)
    add_check(checks, "listening-ports", not inventory["listeners"], inventory["listeners"])
    add_check(checks, "default-routes", not inventory["default_routes"], inventory["default_routes"])
    add_check(checks, "loopback-interface", "lo" in inventory["interfaces"], inventory["interfaces"])

    allowed_privileged = [{"path": "/usr/bin/doas", "mode": "4755", "uid": 0, "gid": 0}]
    add_check(checks, "privileged-file-allowlist", inventory["privileged_files"] == allowed_privileged, inventory["privileged_files"])


def normalized_nft_policy(value: Any) -> dict[str, Any]:
    entries = value.get("nftables", []) if isinstance(value, dict) else []
    objects = [entry for entry in entries if isinstance(entry, dict) and "metainfo" not in entry]
    tables = [entry["table"] for entry in objects if set(entry) == {"table"} and isinstance(entry["table"], dict)]
    chains = [entry["chain"] for entry in objects if set(entry) == {"chain"} and isinstance(entry["chain"], dict)]
    rules = [entry["rule"] for entry in objects if set(entry) == {"rule"} and isinstance(entry["rule"], dict)]
    return {
        "object_count": len(objects),
        "tables": sorted(
            ({key: item.get(key) for key in ("family", "name")} for item in tables),
            key=lambda item: (str(item["family"]), str(item["name"])),
        ),
        "chains": sorted(
            ({key: item.get(key) for key in ("family", "table", "name", "type", "hook", "prio", "policy")} for item in chains),
            key=lambda item: str(item["name"]),
        ),
        "rules": sorted(
            ({key: item.get(key) for key in ("family", "table", "chain", "comment", "expr")} for item in rules),
            key=lambda item: str(item["chain"]),
        ),
    }


def firewall_checks(inventory: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    firewall = inventory.get("firewall", {})
    text = str(firewall.get("text", ""))
    required_fragments = [
        "table inet wuci_noether",
        "hook input priority filter; policy drop;",
        "hook forward priority filter; policy drop;",
        "hook output priority filter; policy drop;",
        'iifname "lo" accept',
        'oifname "lo" accept',
    ]
    expected = {
        "object_count": 6,
        "tables": [{"family": "inet", "name": "wuci_noether"}],
        "chains": [
            {"family": "inet", "table": "wuci_noether", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"},
            {"family": "inet", "table": "wuci_noether", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"},
            {"family": "inet", "table": "wuci_noether", "name": "output", "type": "filter", "hook": "output", "prio": 0, "policy": "drop"},
        ],
        "rules": [
            {
                "family": "inet", "table": "wuci_noether", "chain": "input", "comment": "Noether loopback input",
                "expr": [{"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": "lo"}}, {"accept": None}],
            },
            {
                "family": "inet", "table": "wuci_noether", "chain": "output", "comment": "Noether loopback output",
                "expr": [{"match": {"left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo"}}, {"accept": None}],
            },
        ],
    }
    observed = normalized_nft_policy(firewall.get("json"))
    passed = (
        firewall.get("text_exit") == 0
        and firewall.get("json_exit") == 0
        and all(part in text for part in required_fragments)
        and observed == expected
    )
    add_check(checks, "nftables-default-drop", passed, {
        "text_exit": firewall.get("text_exit"),
        "json_exit": firewall.get("json_exit"),
        "normalized_policy": observed,
        "ruleset": text,
    })


def functional_checks(checks: list[dict[str, Any]]) -> None:
    for check_id, argv, expected in (
        ("wuci-ji-selftest", ["wuci-ji", "selftest"], "wuci-ji selftest: PASS"),
        ("wuci-ji-asm-regression", ["wuci-ji", "asm-regression"], "wuci-ji asm-regression: PASS"),
    ):
        result = run_command(argv)
        add_check(checks, check_id, result.returncode == 0 and expected in result.stdout, {
            "exit": result.returncode,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
        })

    fixture_root = Path("/usr/share/wucios/fixtures")
    prism = run_command(["wuci-prism", "inspect", str(fixture_root / "public-fixture.wj"), "--json", "--ticker", "never"])
    prism_schema = ""
    try:
        prism_schema = json.loads(prism.stdout).get("schema", "")
    except (json.JSONDecodeError, AttributeError):
        pass
    add_check(checks, "wuci-prism-positive", prism.returncode == 0 and prism_schema == "wuci-prism-report-v1", {
        "exit": prism.returncode,
        "schema": prism_schema,
        "stderr": prism.stderr[-1000:],
    })
    prism_negative = run_command(["wuci-prism", "inspect", str(fixture_root / "malformed.wj"), "--json", "--ticker", "never"])
    add_check(checks, "wuci-prism-negative", prism_negative.returncode != 0, {
        "exit": prism_negative.returncode,
        "stderr": prism_negative.stderr[-1000:],
    })

    daylight = run_command(["daylight-claim-scan", "--path", "bounded-claims.txt", "--out", "-"], cwd=fixture_root)
    daylight_status = ""
    try:
        daylight_status = json.loads(daylight.stdout).get("status", "")
    except (json.JSONDecodeError, AttributeError):
        pass
    add_check(checks, "daylight-claim-positive", daylight.returncode == 0 and daylight_status == "pass", {
        "exit": daylight.returncode,
        "status": daylight_status,
        "stderr": daylight.stderr[-1000:],
    })
    daylight_negative = run_command(["daylight-claim-scan", "--path", "forbidden-claims.txt", "--out", "-"], cwd=fixture_root)
    negative_status = ""
    try:
        negative_status = json.loads(daylight_negative.stdout).get("status", "")
    except (json.JSONDecodeError, AttributeError):
        pass
    add_check(checks, "daylight-claim-negative", daylight_negative.returncode == 1 and negative_status == "fail", {
        "exit": daylight_negative.returncode,
        "status": negative_status,
        "stderr": daylight_negative.stderr[-1000:],
    })


def boot_media_digest() -> tuple[str, str]:
    for path in (Path("/dev/sr0"), Path("/dev/cdrom")):
        if path.exists():
            return str(path), sha256_file(path)
    raise RuntimeContractError("boot media device not found")


def contract_report(*, root: Path = Path("/"), include_functional: bool = True) -> dict[str, Any]:
    inventory = collect_inventory(root)
    checks: list[dict[str, Any]] = []
    static_inventory_checks(inventory, checks)
    if root == Path("/"):
        firewall_checks(inventory, checks)
        if include_functional:
            functional_checks(checks)
        try:
            media_path, media_sha256 = boot_media_digest()
            inventory["boot_media"] = {"path": media_path, "sha256": media_sha256}
            add_check(checks, "boot-media-digest", len(media_sha256) == 64, inventory["boot_media"])
        except (OSError, RuntimeContractError) as exc:
            inventory["boot_media"] = {"error": str(exc)}
            add_check(checks, "boot-media-digest", False, str(exc))
    status_value = "pass" if all(item["status"] == "pass" for item in checks) else "fail"
    return {
        "schema": REPORT_SCHEMA,
        "status": status_value,
        "identity": {
            "release": RELEASE,
            "codename": CODENAME,
            "profile": PROFILE,
            "substrate": SUBSTRATE,
            "architecture": ARCH,
        },
        "checks": checks,
        "inventory": inventory,
        "non_claims": list(NON_CLAIMS),
    }


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise RuntimeContractError(f"refusing symlink output: {path}")
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def print_contract_markers(report: dict[str, Any]) -> None:
    for check in report["checks"]:
        print(f"NOETHER_FORGE_CHECK id={check['id']} status={check['status']}")
    if report["status"] == "pass":
        media = report["inventory"].get("boot_media", {})
        if media.get("sha256"):
            print(f"NOETHER_FORGE_BOOT_MEDIA_SHA256 {media['sha256']}")
        print(PASS_MARKER)
    else:
        for check in report["checks"]:
            if check["status"] != "pass":
                print(f"{FAIL_MARKER} check={check['id']}")


def human_status(report: dict[str, Any]) -> str:
    inventory = report.get("inventory", report)
    firewall = inventory.get("firewall", {})
    firewall_loaded = firewall.get("text_exit") == 0 and "table inet wuci_noether" in firewall.get("text", "")
    lines = [
        f"WuciOS {RELEASE} - {CODENAME}",
        f"profile: {PROFILE}",
        f"substrate: {SUBSTRATE}",
        f"kernel: {inventory.get('kernel', 'not-measured')}",
        f"packages: {inventory.get('package_count', 'not-measured')}",
        f"listeners: {len(inventory.get('listeners', []))}",
        f"default routes: {len(inventory.get('default_routes', []))}",
        f"nftables default-drop policy loaded: {'yes' if firewall_loaded else 'no'}",
        "boundary: network policy is not a general runtime sandbox claim",
    ]
    return "\n".join(lines) + "\n"


def command_status(args: argparse.Namespace) -> int:
    cached = Path("/run/wucios/runtime-contract.json")
    if cached.is_file():
        report = json.loads(read_regular_text(cached))
    else:
        report = {"inventory": collect_inventory(Path("/"))}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(human_status(report), end="")
    return 0


def command_audit(args: argparse.Namespace) -> int:
    report = collect_inventory(Path("/"))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(human_status(report), end="")
    return 0


def command_contract(args: argparse.Namespace) -> int:
    report = contract_report()
    if args.write:
        write_json_atomic(Path(args.write), report)
    print_contract_markers(report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="show cached contract status or live inventory")
    status_parser.add_argument("--json", action="store_true")
    status_parser.set_defaults(func=command_status)

    audit_parser = subparsers.add_parser("audit", help="inventory the current live surface")
    audit_parser.add_argument("--json", action="store_true")
    audit_parser.set_defaults(func=command_audit)

    contract_parser = subparsers.add_parser("contract", help="run the fail-closed Noether runtime contract")
    contract_parser.add_argument("--json", action="store_true")
    contract_parser.add_argument("--write", help="atomically write the JSON report")
    contract_parser.set_defaults(func=command_contract)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, RuntimeContractError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"{FAIL_MARKER} check=runtime-exception detail={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
