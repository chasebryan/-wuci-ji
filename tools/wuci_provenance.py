#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_FILE_ROOTS = (
    "AGENTS.md",
    "BUILD_NOTES.md",
    "LICENSE",
    "NOTICE",
    "Makefile",
    "README.md",
    "authority",
    "docs",
    "include",
    "install",
    "src",
    "tests",
    "tools",
)
TOOL_COMMANDS = {
    "as": ["as", "--version"],
    "ld": ["ld", "--version"],
    "zig": ["zig", "version"],
    "python": [sys.executable, "--version"],
    "qemu-x86_64": ["qemu-x86_64", "--version"],
    "nm": ["nm", "--version"],
    "objdump": ["objdump", "--version"],
    "sha256sum": ["sha256sum", "--version"],
    "git": ["git", "--version"],
}
BINARY_PATHS = (
    "build/wuci-ji",
    "build/wuci-ji-linux-x86_64",
    "build/wuci-gate-contract",
    "build/wuci-warrant",
    "build/wuci-witness",
    "build/wuci-ledger-tool",
)


class ProvenanceError(Exception):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def command_output(argv: list[str], cwd: Path) -> str | None:
    proc = run(argv, cwd)
    if proc.returncode != 0:
        return None
    return (proc.stdout or proc.stderr).strip()


def git_output(repo: Path, *args: str) -> str:
    proc = run(["git", *args], repo)
    if proc.returncode != 0:
        raise ProvenanceError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout.strip()


def iter_paths(repo: Path) -> list[Path]:
    paths: list[Path] = []
    for root_name in DEFAULT_FILE_ROOTS:
        root = repo / root_name
        if not root.exists():
            continue
        if root.is_file():
            paths.append(root)
            continue
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(repo).as_posix())


def role_for(path: str) -> str:
    if path in {"LICENSE", "NOTICE"}:
        return "license"
    if path.startswith("src/") or path.startswith("include/"):
        return "assembly-source"
    if path.startswith("tools/"):
        return "tooling"
    if path.startswith("tests/"):
        return "test"
    if path.startswith("docs/"):
        return "documentation-policy"
    if path.startswith("authority/"):
        return "fixture-authority"
    if path.startswith("install/"):
        return "install-evidence"
    if path in {"Makefile", "AGENTS.md", "BUILD_NOTES.md", "README.md"}:
        return "project-control"
    return "other"


def file_record(repo: Path, path: Path) -> dict[str, Any]:
    rel = path.relative_to(repo).as_posix()
    stat = path.stat()
    return {
        "path": rel,
        "role": role_for(rel),
        "sha256": sha256_file(path),
        "size": stat.st_size,
    }


def executable_record(repo: Path, name: str, argv: list[str]) -> dict[str, Any]:
    exe = shutil.which(argv[0])
    version = command_output(argv, repo)
    record: dict[str, Any] = {
        "name": name,
        "command": argv,
        "available": exe is not None and version is not None,
        "path": exe,
        "version": version.splitlines()[0] if version else None,
    }
    if exe:
        exe_path = Path(exe)
        if exe_path.exists() and exe_path.is_file():
            try:
                record["sha256"] = sha256_file(exe_path)
            except OSError:
                record["sha256"] = None
    return record


def binary_record(repo: Path, rel: str) -> dict[str, Any]:
    path = repo / rel
    if not path.exists():
        return {"path": rel, "present": False}
    if path.is_symlink() or not path.is_file():
        return {"path": rel, "present": True, "regular_file": False}
    return {
        "path": rel,
        "present": True,
        "regular_file": True,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def display_path(repo: Path, path: Path) -> str:
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.as_posix()


def tree_digest(files: list[dict[str, Any]]) -> str:
    h = hashlib.sha256()
    for record in files:
        h.update(record["path"].encode("utf-8"))
        h.update(b"\0")
        h.update(str(record["size"]).encode("ascii"))
        h.update(b"\0")
        h.update(record["sha256"].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def build_sbom(repo: Path, version: str) -> dict[str, Any]:
    files = [file_record(repo, path) for path in iter_paths(repo)]
    return {
        "schema": "wuci-sbom-v1",
        "name": "wuci-ji",
        "version": version,
        "license": "Apache-2.0",
        "network_required": False,
        "package_manager_dependencies": [],
        "file_count": len(files),
        "source_tree_sha256": tree_digest(files),
        "files": files,
        "toolchain": [
            executable_record(repo, name, argv)
            for name, argv in sorted(TOOL_COMMANDS.items())
        ],
    }


def build_git_state(repo: Path) -> dict[str, Any]:
    status = git_output(repo, "status", "--porcelain=v1")
    return {
        "branch": git_output(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "commit": git_output(repo, "rev-parse", "HEAD"),
        "dirty": bool(status),
        "status_sha256": sha256_bytes(status.encode("utf-8")),
    }


def build_provenance(repo: Path, sbom_path: Path, profile_path: Path) -> dict[str, Any]:
    sbom = json.loads(read_text(sbom_path))
    profile = json.loads(read_text(profile_path))
    return {
        "schema": "wuci-provenance-v1",
        "name": "wuci-ji",
        "license": "Apache-2.0",
        "sbom_path": display_path(repo, sbom_path),
        "sbom_sha256": sha256_file(sbom_path),
        "source_tree_sha256": sbom["source_tree_sha256"],
        "git": build_git_state(repo),
        "host": {
            "uname": command_output(["uname", "-a"], repo),
            "python": sys.version.split()[0],
            "logical_cpus": os.cpu_count(),
        },
        "qemu": {
            "cpu": os.environ.get("QEMU_CPU", "Haswell-v4"),
            "runner": os.environ.get("QEMU_RUNNER", "qemu-x86_64 -cpu Haswell-v4"),
        },
        "binary_artifacts": [binary_record(repo, rel) for rel in BINARY_PATHS],
        "high_attestation_profile": {
            "path": display_path(repo, profile_path),
            "sha256": sha256_file(profile_path),
            "status": profile["status"],
            "non_claims": profile["explicit_non_claims"],
        },
        "production_readiness": {
            "claim": "not-production-ready",
            "reason": "production readiness requires non-fixture authority, independent audit or equivalent review evidence, real release authority, and removal or explicit containment of current research-only crypto limits",
            "current_best_lane": "make high-attestation-proof",
        },
    }


def verify_sbom(repo: Path, sbom_path: Path) -> None:
    observed = json.loads(read_text(sbom_path))
    expected = build_sbom(repo, observed["version"])
    if observed != expected:
        raise ProvenanceError("SBOM does not match current deterministic repo inventory")


def verify_provenance(repo: Path, sbom_path: Path, provenance_path: Path, profile_path: Path) -> None:
    provenance = json.loads(read_text(provenance_path))
    if provenance["schema"] != "wuci-provenance-v1":
        raise ProvenanceError("unexpected provenance schema")
    if provenance["license"] != "Apache-2.0":
        raise ProvenanceError("provenance must record Apache-2.0 license")
    if provenance["sbom_sha256"] != sha256_file(sbom_path):
        raise ProvenanceError("provenance SBOM digest mismatch")
    if provenance["high_attestation_profile"]["sha256"] != sha256_file(profile_path):
        raise ProvenanceError("provenance profile digest mismatch")
    if provenance["production_readiness"]["claim"] != "not-production-ready":
        raise ProvenanceError("production-ready claim is not permitted by current evidence")


def command_emit(args: argparse.Namespace) -> None:
    repo = Path(args.repo).resolve()
    sbom_path = (repo / args.sbom).resolve()
    provenance_path = (repo / args.provenance).resolve()
    profile_path = (repo / args.profile).resolve()

    sbom = build_sbom(repo, args.version)
    write_json(sbom_path, sbom)
    provenance = build_provenance(repo, sbom_path, profile_path)
    write_json(provenance_path, provenance)
    if not args.quiet:
        print(f"wrote SBOM: {sbom_path}")
        print(f"wrote provenance: {provenance_path}")


def command_verify(args: argparse.Namespace) -> None:
    repo = Path(args.repo).resolve()
    sbom_path = (repo / args.sbom).resolve()
    provenance_path = (repo / args.provenance).resolve()
    profile_path = (repo / args.profile).resolve()
    verify_sbom(repo, sbom_path)
    verify_provenance(repo, sbom_path, provenance_path, profile_path)
    if not args.quiet:
        print("wuci provenance: PASS")


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit and verify local WUCI SBOM/provenance evidence.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("emit", "verify"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--repo", default=".")
        cmd.add_argument("--sbom", default="build/wuci-sbom.json")
        cmd.add_argument("--provenance", default="build/wuci-provenance.json")
        cmd.add_argument("--profile", default="docs/wuci_high_attestation_profile.json")
        cmd.add_argument("--quiet", action="store_true")
        if name == "emit":
            cmd.add_argument("--version", default=os.environ.get("WUCI_VERSION", "0.1"))
            cmd.set_defaults(func=command_emit)
        else:
            cmd.set_defaults(func=command_verify)

    args = parser.parse_args()
    try:
        args.func(args)
    except ProvenanceError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
