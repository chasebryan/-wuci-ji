#!/usr/bin/env python3
"""Prepare digest-bound off-host contingency requests for final Wuci-OS publish."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

import wuci_release_gate


SCHEMA = "wuci-os-release-contingency-packet-v1"
DEFAULT_OUT = Path("build/wuci-os/release-contingencies")
DEFAULT_RELEASE_GATE = Path("build/wuci-os/release-evidence/release-gate.json")

NON_CLAIMS = (
    "This packet does not retire release blockers by itself.",
    "Hardware trace, release signature, and witness ledger evidence must be produced by their respective operators.",
    "Fixture/demo keys or local-only ledgers must not be used as production release authority.",
)


class ContingencyError(RuntimeError):
    pass


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def require_regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ContingencyError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ContingencyError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ContingencyError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise ContingencyError(f"{label} must not be hardlinked: {path}")
    return info


def read_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    require_regular(path, "release gate")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContingencyError(f"release gate must be a JSON object: {path}")
    return value


def fsync_parent(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_text_atomic(path: Path, text: str, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
        fsync_parent(path.parent)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    write_text_atomic(path, stable_json(value))


def reset_output_dir(path: Path, *, force: bool) -> None:
    if path.exists() or path.is_symlink():
        if not force:
            raise ContingencyError(f"output already exists; pass --force to replace: {path}")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ContingencyError(f"output directory must not be a symlink: {path}")
        if not stat.S_ISDIR(info.st_mode):
            raise ContingencyError(f"output path must be a directory: {path}")
        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            root_path = Path(root)
            for name in files:
                item = root_path / name
                if item.is_symlink():
                    raise ContingencyError(f"refusing to remove symlink in output: {item}")
                item.unlink()
            for name in dirs:
                item = root_path / name
                if item.is_symlink():
                    raise ContingencyError(f"refusing to remove symlink directory in output: {item}")
                item.rmdir()
    path.mkdir(parents=True, exist_ok=True)
    fsync_parent(path.parent)


def hardware_text(context: dict[str, Any]) -> str:
    return f"""Wuci-OS hardware trace contingency

Final ISO:
  path: {context['iso_path']}
  sha256: {context['iso_sha256']}
  bytes: {context['iso_bytes']}

Final manifest:
  path: {context['manifest_path']}
  sha256: {context['manifest_sha256']}
  bytes: {context['manifest_bytes']}

On the reference machine, boot this exact ISO. After the Wuci prompt appears,
run:

  wuci-release-hardware-trace /tmp/wuci-hardware-boot.log

Bind the captured transcript on the build host:

  python3 tools/wuci_release_gate.py hardware-trace \\
    --manifest build/wuci-os/final/manifest.json \\
    --iso build/wuci-os/final/Wuci-OS-x86_64-musl.iso \\
    --boot-log /path/to/wuci-hardware-boot.log \\
    --hardware-id "ThinkPad X200s:<serial-or-local-id>" \\
    --operator "<operator>" \\
    --observed-at-utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

Required markers: WJ>_, Wuci-OS live profile, wuci-network, INSTALL.
Do not include Wi-Fi passwords, API keys, shell history, or private home data.
"""


def signing_text(context: dict[str, Any]) -> str:
    return f"""Wuci-OS manifest signature contingency

Sign only this final manifest:
  path: {context['manifest_path']}
  sha256: {context['manifest_sha256']}
  bytes: {context['manifest_bytes']}

The final ISO bound by that manifest is:
  path: {context['iso_path']}
  sha256: {context['iso_sha256']}
  bytes: {context['iso_bytes']}

Use the production Wuci-OS release key, not fixture/demo authority.

  minisign -S -s /path/to/wuci-os-release.key \\
    -m build/wuci-os/final/manifest.json \\
    -x build/wuci-os/final/manifest.json.minisig

Verify and bind the detached signature:

  python3 tools/wuci_release_gate.py verify-signature \\
    --manifest build/wuci-os/final/manifest.json \\
    --iso build/wuci-os/final/Wuci-OS-x86_64-musl.iso \\
    --signature build/wuci-os/final/manifest.json.minisig \\
    --public-key-file /path/to/wuci-os-release.pub
"""


def witness_text(context: dict[str, Any]) -> str:
    return f"""Wuci-OS witness ledger contingency

Append the signed final-manifest digest to the operated WUCI-WITNESS ledger.

Final manifest sha256:
  {context['manifest_sha256']}

Final ISO sha256:
  {context['iso_sha256']}

After the operated ledger returns an entry, head, and inclusion proof, bind it:

  python3 tools/wuci_release_gate.py witness \\
    --manifest build/wuci-os/final/manifest.json \\
    --iso build/wuci-os/final/Wuci-OS-x86_64-musl.iso \\
    --signature-evidence build/wuci-os/release-evidence/manifest-signature.json \\
    --ledger-entry /path/to/ledger-entry.txt \\
    --ledger-head /path/to/ledger-head.txt \\
    --inclusion-proof /path/to/inclusion-proof.txt \\
    --operated-ledger-id "wuci-witness-production" \\
    --operator "<operator>" \\
    --ledger-url "https://example.org/wuci-witness/ledger-head.txt"
"""


def finalize_text() -> str:
    return """Wuci-OS final release gate commands

After hardware trace, manifest signature, and witness ledger evidence are
bound, run:

  make wuci-os-release-gate
  make wuci-os-privacy-audit
  make wuci-os-release-bundle

Publish only if build/wuci-os/release-evidence/release-gate.json says:

  "release_allowed": true

If release_allowed is false, the artifact remains an evidence candidate.
"""


def build_packet(
    *,
    manifest: Path,
    iso: Path,
    release_gate: Path,
    out: Path,
    force: bool,
) -> dict[str, Any]:
    context = wuci_release_gate.manifest_context(manifest, iso)
    gate_report = read_json_if_present(release_gate)
    blockers = gate_report.get("blockers", []) if isinstance(gate_report, dict) else []
    if not isinstance(blockers, list):
        blockers = []
    release_allowed = gate_report.get("release_allowed") if isinstance(gate_report, dict) else False
    reset_output_dir(out, force=force)
    files = {
        "HARDWARE-TRACE.txt": hardware_text(context),
        "SIGNING-REQUEST.txt": signing_text(context),
        "WITNESS-REQUEST.txt": witness_text(context),
        "FINALIZE-COMMANDS.txt": finalize_text(),
    }
    for name, text in files.items():
        write_text_atomic(out / name, text)
    packet = {
        "schema": SCHEMA,
        "status": "ready" if release_allowed is True and not blockers else "pending",
        "final_manifest": {
            "path": context["manifest_path"],
            "sha256": context["manifest_sha256"],
            "bytes": context["manifest_bytes"],
        },
        "final_iso": {
            "path": context["iso_path"],
            "sha256": context["iso_sha256"],
            "bytes": context["iso_bytes"],
        },
        "release_gate": {
            "path": str(release_gate),
            "status": gate_report.get("status") if isinstance(gate_report, dict) else "missing",
            "release_allowed": release_allowed,
            "blockers": blockers,
        },
        "operator_packets": sorted(files),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_atomic(out / "contingency-packet.json", packet)
    return packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    build = subparsers.add_parser("build", help="write the off-host contingency packet")
    build.add_argument("--manifest", type=Path, default=wuci_release_gate.DEFAULT_FINAL_MANIFEST)
    build.add_argument("--iso", type=Path, default=wuci_release_gate.DEFAULT_FINAL_ISO)
    build.add_argument("--release-gate", type=Path, default=DEFAULT_RELEASE_GATE)
    build.add_argument("--out", type=Path, default=DEFAULT_OUT)
    build.add_argument("--force", action="store_true")
    build.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "build":
        parser.print_help()
        return 2
    try:
        packet = build_packet(
            manifest=args.manifest,
            iso=args.iso,
            release_gate=args.release_gate,
            out=args.out,
            force=args.force,
        )
    except (ContingencyError, wuci_release_gate.ReleaseGateError) as exc:
        print(f"wuci-release-contingencies: {exc}", file=os.sys.stderr)
        return 1
    if args.json:
        print(stable_json(packet), end="")
    else:
        print(f"wuci-release-contingencies: {packet['status']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
