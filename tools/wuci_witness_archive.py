#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import wuci_witness
import wuci_safeio
import wuci_verifier_identity


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "build" / "wuci-witness-bundle"
DEFAULT_ARCHIVE = REPO_ROOT / "build" / "wuci-witness-bundle.tar"
DEFAULT_SHA256 = REPO_ROOT / "build" / "wuci-witness-bundle.tar.sha256"
DEFAULT_EXTRACT_DIR = REPO_ROOT / "build" / "wuci-witness-archive-check"
ARCHIVE_ROOT = "wuci-publish-bundle-v1"
ARCHIVE_MODE = 0o644
PUBLIC_FILES = tuple(wuci_witness.PUBLIC_FILES[name] for name in (
    "sealed_artifact",
    "manifest",
    "warrant_message",
    "release_receipt",
    "receipt_contract",
    "authority_root",
    "release_decision",
    "publish_index",
    "attestation",
))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


class WitnessArchiveError(RuntimeError):
    pass


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    try:
        return wuci_safeio.sha256_file(path)
    except wuci_safeio.SafeIOError as exc:
        raise WitnessArchiveError(str(exc)) from exc


def write_new_bytes(path: Path, value: bytes, context: str) -> None:
    try:
        wuci_safeio.write_new_bytes(path, value, context, mode=0o600)
    except wuci_safeio.SafeIOError as exc:
        raise WitnessArchiveError(str(exc)) from exc


def write_new_text(path: Path, value: str, context: str) -> None:
    write_new_bytes(path, value.encode("ascii"), context)


def expected_member_name(filename: str) -> str:
    return f"{ARCHIVE_ROOT}/{filename}"


def assert_bundle_verified(bin_path: Path, bundle_dir: Path) -> None:
    try:
        observed, _ = wuci_witness.build_witness_attestation(
            bin_path=bin_path,
            bundle_dir=bundle_dir,
            require_index=True,
            require_attestation=True,
            strict_proof=True,
        )
        expected = wuci_witness.load_json_file(
            bundle_dir / "attestation.json",
            "witness attestation",
        )
        wuci_witness.compare_attestations(expected, observed)
    except wuci_witness.WitnessError as exc:
        raise WitnessArchiveError(str(exc)) from exc


def build_archive_bytes(bundle_dir: Path) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for filename in PUBLIC_FILES:
            path = bundle_dir / filename
            try:
                data = wuci_safeio.read_regular_bytes(
                    path,
                    f"archive source {filename}",
                    reject_symlink=True,
                    reject_hardlink=True,
                )
            except wuci_safeio.SafeIOError as exc:
                raise WitnessArchiveError(str(exc)) from exc
            info = tarfile.TarInfo(expected_member_name(filename))
            info.size = len(data)
            info.mode = ARCHIVE_MODE
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def assert_sha256_sidecar(archive_path: Path, sha256_path: Path) -> None:
    expected = f"{sha256_file(archive_path)}  {archive_path.name}\n"
    try:
        actual = sha256_path.read_text(encoding="ascii")
    except OSError as exc:
        raise WitnessArchiveError(f"could not read archive SHA-256 sidecar {sha256_path}") from exc
    except UnicodeDecodeError as exc:
        raise WitnessArchiveError("archive SHA-256 sidecar is not ASCII") from exc
    if actual != expected:
        raise WitnessArchiveError("archive SHA-256 sidecar does not match archive")


def assert_member_shape(member: tarfile.TarInfo, expected_name: str) -> None:
    if member.name != expected_name:
        raise WitnessArchiveError(f"archive member order/name mismatch: {member.name}")
    if not member.isfile():
        raise WitnessArchiveError(f"archive member must be a regular file: {member.name}")
    if member.issym() or member.islnk():
        raise WitnessArchiveError(f"archive member must not be a link: {member.name}")
    if member.uid != 0 or member.gid != 0:
        raise WitnessArchiveError(f"archive member owner must be zero: {member.name}")
    if member.uname not in {"", "root"} or member.gname not in {"", "root"}:
        raise WitnessArchiveError(f"archive member owner names must be empty/root: {member.name}")
    if member.mtime != 0:
        raise WitnessArchiveError(f"archive member mtime must be zero: {member.name}")
    if member.mode != ARCHIVE_MODE:
        raise WitnessArchiveError(f"archive member mode must be 0644: {member.name}")


def extract_archive(archive_path: Path, extract_dir: Path) -> Path:
    if extract_dir.exists():
        raise WitnessArchiveError(f"refusing to overwrite extract directory: {extract_dir}")
    bundle_dir = extract_dir / ARCHIVE_ROOT
    bundle_dir.mkdir(parents=True)
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            members = archive.getmembers()
            expected_names = [expected_member_name(filename) for filename in PUBLIC_FILES]
            if [member.name for member in members] != expected_names:
                raise WitnessArchiveError("archive members are not the exact public profile")
            for member, filename in zip(members, PUBLIC_FILES):
                assert_member_shape(member, expected_member_name(filename))
                source = archive.extractfile(member)
                if source is None:
                    raise WitnessArchiveError(f"could not read archive member: {member.name}")
                out_path = bundle_dir / filename
                out_path.write_bytes(source.read())
    except (tarfile.TarError, OSError) as exc:
        raise WitnessArchiveError(f"could not extract witness archive {archive_path}") from exc
    return bundle_dir


def run_zig_witness(*, witness_bin: Path, bin_path: Path, bundle_dir: Path) -> None:
    try:
        proc = subprocess.run(
            [
                *RUNNER,
                str(witness_bin),
                "verify",
                str(bundle_dir),
                "--bin",
                str(bin_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise WitnessArchiveError(f"could not execute Zig witness verifier {witness_bin}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        detail = stderr or stdout or f"exit status {proc.returncode}"
        raise WitnessArchiveError(f"Zig witness verifier failed: {detail}")


def run_pack(args: argparse.Namespace) -> int:
    bundle_dir = Path(args.bundle)
    archive_path = Path(args.archive)
    sha256_path = Path(args.sha256)
    assert_bundle_verified(Path(args.bin), bundle_dir)
    archive_bytes = build_archive_bytes(bundle_dir)
    write_new_bytes(archive_path, archive_bytes, "witness archive")
    digest = hashlib.sha256(archive_bytes).hexdigest()
    write_new_text(sha256_path, f"{digest}  {archive_path.name}\n", "archive SHA-256 sidecar")
    print(f"wrote witness archive: {display_path(archive_path)}")
    print(f"wrote witness archive sha256: {display_path(sha256_path)}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    archive_path = Path(args.archive)
    sha256_path = Path(args.sha256)
    extract_dir = Path(args.extract_dir)
    if not archive_path.is_file():
        raise WitnessArchiveError(f"missing witness archive: {archive_path}")
    if not sha256_path.is_file():
        raise WitnessArchiveError(f"missing witness archive SHA-256: {sha256_path}")
    assert_sha256_sidecar(archive_path, sha256_path)
    bundle_dir = extract_archive(archive_path, extract_dir)
    assert_bundle_verified(Path(args.bin), bundle_dir)
    if args.zig_witness:
        run_zig_witness(
            witness_bin=Path(args.zig_witness),
            bin_path=Path(args.bin),
            bundle_dir=bundle_dir,
        )
    print(f"valid witness archive: {display_path(archive_path)}")
    print(f"extracted public bundle: {display_path(bundle_dir)}")
    return 0


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary used for witness verification",
    )
    parser.add_argument(
        "--archive",
        default=str(DEFAULT_ARCHIVE),
        help="witness archive path",
    )
    parser.add_argument(
        "--sha256",
        default=str(DEFAULT_SHA256),
        help="witness archive SHA-256 sidecar path",
    )
    wuci_verifier_identity.add_strict_args(parser)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify deterministic WUCI-WITNESS archives."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack = subparsers.add_parser("pack", help="write a deterministic witness archive")
    add_common_args(pack)
    pack.add_argument(
        "--bundle",
        default=str(DEFAULT_BUNDLE_DIR),
        help="public witness bundle directory",
    )
    pack.set_defaults(func=run_pack)

    verify = subparsers.add_parser("verify", help="verify and extract a witness archive")
    add_common_args(verify)
    verify.add_argument(
        "--extract-dir",
        default=str(DEFAULT_EXTRACT_DIR),
        help="empty destination directory for archive extraction",
    )
    verify.add_argument(
        "--zig-witness",
        help="optional build/wuci-witness verifier to run after extraction",
    )
    verify.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        if hasattr(args, "bin"):
            wuci_verifier_identity.enforce_args(args, Path(args.bin))
        return args.func(args)
    except (
        WitnessArchiveError,
        wuci_verifier_identity.VerifierIdentityError,
    ) as exc:
        print(f"wuci witness archive: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
