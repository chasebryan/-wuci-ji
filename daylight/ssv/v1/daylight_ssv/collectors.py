"""Read-only local fact collectors for DaylightSSV v1."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

EXCLUDED_DIRS = {".git", "build", "dist", "node_modules", "__pycache__", ".tools", "target"}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".cff",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".py",
    ".rs",
    ".s",
    ".sh",
    ".svg",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
MAX_SCAN_BYTES = 1_000_000

SECRET_PATTERNS = (
    ("private_key_marker", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{40,}?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
DIGEST_PATTERN = re.compile(r"\b(?:sha256|sha3[-_]?512)\s*[:=]\s*[0-9A-Za-z]{32,160}\b", re.IGNORECASE)
UNSAFE_PIPELINE_PATTERN = re.compile(r"\b(?:curl|wget)\b[^\n|;]{0,160}\|\s*(?:sh|bash)\b", re.IGNORECASE)
NEGATED_EXAMPLE_PATTERN = re.compile(r"\b(?:not|no|never|without|does not|do not|must not)\b", re.IGNORECASE)
DEBUG_MARKER_PATTERN = re.compile(r"\b(?:DEBUG\s*=\s*true|FLASK_ENV\s*=\s*development|NODE_ENV\s*=\s*development)\b", re.IGNORECASE)
_PLACEHOLDER_CRYPTO_TERMS = (
    ("placeholder", "crypto"),
    ("fake", "verifier"),
    ("toy", "crypto"),
    ("stub", "verifier"),
)
PLACEHOLDER_CRYPTO_PATTERN = re.compile(
    r"\b(?:"
    + "|".join(f"{left}\\s+{right}" for left, right in _PLACEHOLDER_CRYPTO_TERMS)
    + r")\b",
    re.IGNORECASE,
)

ADMIN_PORTS = {22, 3389, 5900, 5985, 5986, 2375, 2376}
BACKUP_EVIDENCE_SCHEMA = "wuci.backup_evidence.v1"


def _repo_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _safe_read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _safe_load_json_object(path: Path) -> dict[str, Any] | None:
    text = _safe_read_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _safe_relative_path(rel: str) -> bool:
    parts = Path(rel).parts
    return bool(rel) and not Path(rel).is_absolute() and ".." not in parts


def _backup_evidence_status(root: Path, evidence_path: Path) -> dict[str, Any]:
    data = _safe_load_json_object(evidence_path)
    if data is None:
        return {"valid": False, "summary": "backup evidence unavailable or invalid JSON"}
    archive = data.get("archive")
    restore = data.get("restore")
    archive_rel = archive.get("path") if isinstance(archive, dict) else None
    archive_sha = archive.get("sha256") if isinstance(archive, dict) else None
    archive_path = root / archive_rel if isinstance(archive_rel, str) and _safe_relative_path(archive_rel) else None
    observed_archive_sha = _sha256_file(archive_path) if archive_path and archive_path.is_file() else None
    files_total = data.get("files_total")
    restore_checked = bool(isinstance(restore, dict) and restore.get("checked") is True)
    restore_failures = restore.get("failures") if isinstance(restore, dict) else None
    valid = (
        data.get("schema") == BACKUP_EVIDENCE_SCHEMA
        and data.get("result") == "pass"
        and isinstance(files_total, int)
        and files_total > 0
        and restore_checked
        and restore_failures == 0
        and isinstance(archive_sha, str)
        and observed_archive_sha == archive_sha
    )
    return {
        "valid": valid,
        "files_total": files_total if isinstance(files_total, int) else None,
        "archive_exists": bool(archive_path and archive_path.is_file()),
        "archive_sha256": observed_archive_sha,
        "restore_checked": restore_checked,
        "summary": (
            f"valid={valid}; files_total={files_total if isinstance(files_total, int) else 'unknown'}; "
            f"restore_checked={restore_checked}; archive_exists={bool(archive_path and archive_path.is_file())}"
        ),
    }


def _tracked_files(root: Path) -> list[Path]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        proc = None
    if proc is not None and proc.returncode == 0:
        return [root / line for line in proc.stdout.splitlines() if line]

    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def _is_negative_fixture(rel: str) -> bool:
    return rel.startswith("daylight/npt/v1/examples/negative/")


def _has_unsafe_pipeline_marker(text: str) -> bool:
    for line in text.splitlines():
        if UNSAFE_PIPELINE_PATTERN.search(line) and not NEGATED_EXAMPLE_PATTERN.search(line):
            return True
    return False


def collect_platform() -> dict[str, Any]:
    return {
        "is_linux": os.name == "posix" and Path("/proc").is_dir(),
        "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        "errors": [],
    }


def _mode_summary(path: Path) -> dict[str, Any]:
    try:
        mode = path.stat().st_mode
        return {
            "exists": True,
            "readable": os.access(path, os.R_OK),
            "world_writable": bool(mode & stat.S_IWOTH),
            "mode": oct(stat.S_IMODE(mode)),
        }
    except OSError as exc:
        return {
            "exists": False,
            "readable": False,
            "world_writable": False,
            "mode": None,
            "error": exc.__class__.__name__,
        }


def collect_filesystem_facts() -> dict[str, Any]:
    common_paths = {
        "etc_passwd": Path("/etc/passwd"),
        "etc_shadow": Path("/etc/shadow"),
        "etc_sudoers": Path("/etc/sudoers"),
        "ssh_config": Path("/etc/ssh/sshd_config"),
        "usr_local_bin": Path("/usr/local/bin"),
        "usr_bin": Path("/usr/bin"),
        "bin": Path("/bin"),
        "sbin": Path("/sbin"),
    }
    facts: dict[str, Any] = {
        "paths": {name: _mode_summary(path) for name, path in common_paths.items()},
        "sudoers_has_nopasswd": None,
        "account_summary": None,
        "suid_sgid_summary": None,
        "errors": [],
    }
    sudoers = common_paths["etc_sudoers"]
    if sudoers.is_file() and os.access(sudoers, os.R_OK):
        text = _safe_read_text(sudoers)
        if text is None:
            facts["errors"].append("sudoers_unreadable")
        else:
            facts["sudoers_has_nopasswd"] = "NOPASSWD" in text
    passwd = common_paths["etc_passwd"]
    if passwd.is_file() and os.access(passwd, os.R_OK):
        text = _safe_read_text(passwd)
        if text is not None:
            rows = [line for line in text.splitlines() if line and not line.startswith("#")]
            login_shells = sum(1 for line in rows if not line.endswith(("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")))
            facts["account_summary"] = {"accounts": len(rows), "login_shells": login_shells}
    facts["suid_sgid_summary"] = _bounded_suid_sgid_summary(
        common_paths[name] for name in ("usr_local_bin", "usr_bin", "bin", "sbin")
    )
    return facts


def _bounded_suid_sgid_summary(roots: Any) -> dict[str, Any]:
    summary = {
        "dirs_checked": 0,
        "entries_checked": 0,
        "suid_count": 0,
        "sgid_count": 0,
        "errors": 0,
    }
    for root in roots:
        try:
            if not root.is_dir():
                continue
            summary["dirs_checked"] += 1
            for child in root.iterdir():
                try:
                    info = child.lstat()
                except OSError:
                    summary["errors"] += 1
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                summary["entries_checked"] += 1
                if info.st_mode & stat.S_ISUID:
                    summary["suid_count"] += 1
                if info.st_mode & stat.S_ISGID:
                    summary["sgid_count"] += 1
        except OSError:
            summary["errors"] += 1
    return summary


def collect_repo_facts(repo_root: Path | None = None) -> dict[str, Any]:
    root = (repo_root or Path.cwd()).resolve()
    tracked = _tracked_files(root)
    facts: dict[str, Any] = {
        "tracked_count": len(tracked),
        "lockfiles": [],
        "manifests": [],
        "ci_workflows": [],
        "secret_findings": [],
        "private_key_markers": [],
        "unsafe_pipeline_markers": [],
        "debug_markers": [],
        "placeholder_crypto_markers": [],
        "digest_claims": [],
        "vendored_binary_markers": [],
        "env_files": [],
        "known_files": {},
        "errors": [],
    }
    lock_names = {"Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.lock"}
    manifest_names = {"Cargo.toml", "package.json", "pyproject.toml", "requirements.txt", "go.mod"}
    for path in tracked:
        rel = _repo_relative(root, path)
        name = path.name
        if name in lock_names:
            facts["lockfiles"].append(rel)
        if name in manifest_names:
            facts["manifests"].append(rel)
        if rel.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
            facts["ci_workflows"].append(rel)
        if name.startswith(".env"):
            facts["env_files"].append(rel)
        if "/target/" in rel or rel.endswith((".bin", ".so", ".dll", ".dylib", ".exe")):
            text = _safe_read_text(path)
            if text is None:
                facts["vendored_binary_markers"].append(rel)
        if path.suffix not in TEXT_SUFFIXES:
            continue
        text = _safe_read_text(path)
        if text is None:
            continue
        if not _is_negative_fixture(rel):
            for pattern_name, pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    marker = {"type": pattern_name, "path": rel}
                    facts["secret_findings"].append(marker)
                    if pattern_name == "private_key_marker":
                        facts["private_key_markers"].append(marker)
        if _has_unsafe_pipeline_marker(text) and not rel.startswith("tests/"):
            facts["unsafe_pipeline_markers"].append(rel)
        if DEBUG_MARKER_PATTERN.search(text) and not rel.startswith("tests/"):
            facts["debug_markers"].append(rel)
        if PLACEHOLDER_CRYPTO_PATTERN.search(text) and not rel.startswith(("tests/", "docs/")):
            facts["placeholder_crypto_markers"].append(rel)
        if _is_negative_fixture(rel):
            continue
        for match in DIGEST_PATTERN.finditer(text):
            literal = match.group(0).split(":", 1)[-1].split("=", 1)[-1].strip()
            algo = "sha3-512" if "sha3" in match.group(0).lower() else "sha256"
            expected = 128 if algo == "sha3-512" else 64
            facts["digest_claims"].append(
                {
                    "path": rel,
                    "algorithm": algo,
                    "valid": len(literal) == expected and all(char in "0123456789abcdefABCDEF" for char in literal),
                }
            )
    for key, rel in {
        "wuci_install_manifest": "install/wuci-install-manifest.v1",
        "wuci_install_signature": "install/wuci-install-manifest.v1.sig",
        "daylight_npt_report": "build/daylight/npt-v1/daylight-npt.report.json",
        "score_integrity_report": "audits/daylight/score-integrity/index.json",
        "site_validator": "site/validate.mjs",
        "public_evidence_firewall": "tools/daylight_public_evidence_firewall.py",
        "v20_capsule": "build/daylight/v20-aperture-singularity-capsule.json",
        "backup_evidence": "build/wuci-backup/backup-evidence.json",
        "logging_evidence": "docs/WUCI_LOGGING.md",
        "security_boundary": "docs/SECURITY_BOUNDARY.md",
        "release_runbook": "docs/WUCI_OS_RELEASE_RUNBOOK.md",
        "machine_passoff": "docs/MACHINE_PASSOFF.md",
        "contributor_bootstrap": "docs/CONTRIBUTOR_BOOTSTRAP.md",
        "ssv_docs": "docs/DAYLIGHT_SSV_V1.md",
    }.items():
        path = root / rel
        facts["known_files"][key] = {
            "path": rel,
            "exists": path.is_file(),
            "sha256": _sha256_file(path) if path.is_file() else None,
    }
    backup_evidence = facts["known_files"]["backup_evidence"]
    backup_evidence.update(
        _backup_evidence_status(root, root / backup_evidence["path"])
        if backup_evidence["exists"]
        else {"valid": False, "summary": "backup evidence missing"}
    )
    for list_key in (
        "lockfiles",
        "manifests",
        "ci_workflows",
        "secret_findings",
        "private_key_markers",
        "unsafe_pipeline_markers",
        "debug_markers",
        "placeholder_crypto_markers",
        "digest_claims",
        "vendored_binary_markers",
        "env_files",
    ):
        facts[list_key] = sorted(facts[list_key], key=lambda item: str(item))
    return facts


def _classify_ipv4(hex_address: str) -> str:
    try:
        value = int(hex_address, 16)
    except ValueError:
        return "unknown"
    octets = [(value >> shift) & 0xFF for shift in (0, 8, 16, 24)]
    if octets[0] == 127:
        return "loopback"
    if octets == [0, 0, 0, 0]:
        return "wildcard"
    return "non_loopback"


def _classify_ipv6(hex_address: str) -> str:
    if hex_address == "0" * 32:
        return "wildcard"
    if hex_address.endswith("01000000") and hex_address[:-8] == "0" * 24:
        return "loopback"
    return "non_loopback"


def _parse_proc_net(path: Path, family: str) -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return listeners
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        local = parts[1]
        if ":" not in local:
            continue
        address, port_hex = local.rsplit(":", 1)
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        bind = _classify_ipv6(address) if family == "tcp6" else _classify_ipv4(address)
        listeners.append({"family": family, "bind": bind, "port": port, "admin_port": port in ADMIN_PORTS})
    return listeners


def collect_network_facts() -> dict[str, Any]:
    listeners = _parse_proc_net(Path("/proc/net/tcp"), "tcp") + _parse_proc_net(Path("/proc/net/tcp6"), "tcp6")
    return {
        "listeners": sorted(listeners, key=lambda item: (item["bind"], item["family"], item["port"])),
        "errors": [],
    }


def collect_process_facts() -> dict[str, Any]:
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return {"process_count": None, "errors": ["proc_unavailable"]}
    count = 0
    for child in proc_root.iterdir():
        if child.name.isdigit():
            count += 1
    return {"process_count": count, "errors": []}


def collect_daylight_facts(repo_root: Path | None = None) -> dict[str, Any]:
    repo = collect_repo_facts(repo_root)
    known = repo["known_files"]
    return {
        "daylight_npt_report": known["daylight_npt_report"],
        "score_integrity_report": known["score_integrity_report"],
        "site_validator": known["site_validator"],
        "v20_capsule": known["v20_capsule"],
        "backup_evidence": known["backup_evidence"],
        "logging_evidence": known["logging_evidence"],
        "security_boundary": known["security_boundary"],
        "release_runbook": known["release_runbook"],
        "machine_passoff": known["machine_passoff"],
        "contributor_bootstrap": known["contributor_bootstrap"],
        "ssv_docs": known["ssv_docs"],
        "public_evidence_firewall": known["public_evidence_firewall"],
        "errors": [],
    }


def collect_all(repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or Path.cwd()
    return {
        "platform": collect_platform(),
        "filesystem": collect_filesystem_facts(),
        "repo": collect_repo_facts(root),
        "network": collect_network_facts(),
        "process": collect_process_facts(),
        "daylight": collect_daylight_facts(root),
    }
