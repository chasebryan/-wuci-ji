#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_TOOL = REPO_ROOT / "tools" / "wuci_witness_archive.py"
PUBLIC_FILES = (
    "wuci-ji.self.wj",
    "manifest.txt",
    "warrant-message.txt",
    "release-receipt.json",
    "receipt-contract.txt",
    "authority-root.txt",
    "release-decision.txt",
    "publish-index.txt",
    "attestation.json",
)
ARCHIVE_ROOT = "wuci-publish-bundle-v1"


def run_archive(
    command: str,
    *,
    bin_path: Path,
    archive: Path,
    sha256: Path,
    bundle: Path | None = None,
    extract_dir: Path | None = None,
    zig_witness: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    args = [
        sys.executable,
        str(ARCHIVE_TOOL),
        command,
        "--bin",
        str(bin_path),
        "--archive",
        str(archive),
        "--sha256",
        str(sha256),
    ]
    if bundle is not None:
        args.extend(["--bundle", str(bundle)])
    if extract_dir is not None:
        args.extend(["--extract-dir", str(extract_dir)])
    if zig_witness is not None:
        args.extend(["--zig-witness", str(zig_witness)])
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
        env=os.environ.copy(),
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_archive_verify_fails(
    *,
    bin_path: Path,
    archive: Path,
    sha256: Path,
    extract_dir: Path,
) -> None:
    proc = run_archive(
        "verify",
        bin_path=bin_path,
        archive=archive,
        sha256=sha256,
        extract_dir=extract_dir,
    )
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"wuci witness archive:" in proc.stderr


def write_sidecar(archive: Path, sha256: Path) -> None:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sha256.write_text(f"{digest}  {archive.name}\n", encoding="ascii")


def replace_value(text: str, label: str, value: str) -> str:
    prefix = f"{label}: "
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return "".join(lines)
    raise AssertionError(f"missing label {label}")


def write_custom_archive(
    *,
    bundle: Path,
    archive: Path,
    skip: set[str] | None = None,
    extra_forbidden: bool = False,
    mutate_info: Callable[[tarfile.TarInfo], None] | None = None,
    mutate_data: Callable[[str, bytes], bytes] | None = None,
) -> None:
    skip = skip or set()
    with tarfile.open(archive, mode="w", format=tarfile.GNU_FORMAT) as output:
        for filename in PUBLIC_FILES:
            if filename in skip:
                continue
            data = (bundle / filename).read_bytes()
            if mutate_data is not None:
                data = mutate_data(filename, data)
            info = tarfile.TarInfo(f"{ARCHIVE_ROOT}/{filename}")
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            if mutate_info is not None:
                mutate_info(info)
            output.addfile(info, io.BytesIO(data))
        if extra_forbidden:
            data = b"not public evidence\n"
            info = tarfile.TarInfo(f"{ARCHIVE_ROOT}/artifact.key")
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            output.addfile(info, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check deterministic WUCI-WITNESS archive export and verification."
    )
    parser.add_argument("--bundle", required=True, help="existing public witness bundle")
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(REPO_ROOT / "build" / "wuci-ji")),
        help="wuci-ji binary used for verification",
    )
    parser.add_argument("--zig-witness", help="optional Zig witness verifier")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    bundle = Path(args.bundle)
    bin_path = Path(args.bin)
    zig_witness = Path(args.zig_witness) if args.zig_witness else None

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        archive_a = tmp / "witness-a.tar"
        sha_a = tmp / "witness-a.tar.sha256"
        archive_b = tmp / "witness-b.tar"
        sha_b = tmp / "witness-b.tar.sha256"

        assert_ok(
            run_archive(
                "pack",
                bin_path=bin_path,
                archive=archive_a,
                sha256=sha_a,
                bundle=bundle,
            ),
            "pack first archive",
        )
        assert_ok(
            run_archive(
                "pack",
                bin_path=bin_path,
                archive=archive_b,
                sha256=sha_b,
                bundle=bundle,
            ),
            "pack second archive",
        )
        assert archive_a.read_bytes() == archive_b.read_bytes()

        assert_ok(
            run_archive(
                "verify",
                bin_path=bin_path,
                archive=archive_a,
                sha256=sha_a,
                extract_dir=tmp / "extract-a",
                zig_witness=zig_witness,
            ),
            "verify archive",
        )

        bad_sidecar = tmp / "bad-sidecar.sha256"
        bad_sidecar.write_text(("00" * 32) + f"  {archive_a.name}\n", encoding="ascii")
        assert_archive_verify_fails(
            bin_path=bin_path,
            archive=archive_a,
            sha256=bad_sidecar,
            extract_dir=tmp / "bad-sidecar-extract",
        )
        if hasattr(os, "symlink"):
            linked_sidecar = tmp / "linked-sidecar.sha256"
            linked_sidecar.symlink_to(sha_a)
            assert_archive_verify_fails(
                bin_path=bin_path,
                archive=archive_a,
                sha256=linked_sidecar,
                extract_dir=tmp / "linked-sidecar-extract",
            )
        if hasattr(os, "link"):
            hardlinked_sidecar = tmp / "hardlinked-sidecar.sha256"
            os.link(sha_a, hardlinked_sidecar)
            assert_archive_verify_fails(
                bin_path=bin_path,
                archive=archive_a,
                sha256=hardlinked_sidecar,
                extract_dir=tmp / "hardlinked-sidecar-extract",
            )

        missing_index = tmp / "missing-index.tar"
        write_custom_archive(
            bundle=bundle,
            archive=missing_index,
            skip={"publish-index.txt"},
        )
        missing_index_sha = tmp / "missing-index.tar.sha256"
        write_sidecar(missing_index, missing_index_sha)
        assert_archive_verify_fails(
            bin_path=bin_path,
            archive=missing_index,
            sha256=missing_index_sha,
            extract_dir=tmp / "missing-index-extract",
        )

        forbidden = tmp / "forbidden.tar"
        write_custom_archive(
            bundle=bundle,
            archive=forbidden,
            extra_forbidden=True,
        )
        forbidden_sha = tmp / "forbidden.tar.sha256"
        write_sidecar(forbidden, forbidden_sha)
        assert_archive_verify_fails(
            bin_path=bin_path,
            archive=forbidden,
            sha256=forbidden_sha,
            extract_dir=tmp / "forbidden-extract",
        )

        oversized_member = tmp / "oversized-member.tar"

        def oversize_attestation(filename: str, data: bytes) -> bytes:
            if filename != "attestation.json":
                return data
            return b"{" + b'"pad":"' + (b"A" * (256 * 1024)) + b'"}\n'

        write_custom_archive(
            bundle=bundle,
            archive=oversized_member,
            mutate_data=oversize_attestation,
        )
        oversized_member_sha = tmp / "oversized-member.tar.sha256"
        write_sidecar(oversized_member, oversized_member_sha)
        assert_archive_verify_fails(
            bin_path=bin_path,
            archive=oversized_member,
            sha256=oversized_member_sha,
            extract_dir=tmp / "oversized-member-extract",
        )

        bad_mtime = tmp / "bad-mtime.tar"
        write_custom_archive(
            bundle=bundle,
            archive=bad_mtime,
            mutate_info=lambda info: setattr(info, "mtime", 1)
            if info.name.endswith("/manifest.txt")
            else None,
        )
        bad_mtime_sha = tmp / "bad-mtime.tar.sha256"
        write_sidecar(bad_mtime, bad_mtime_sha)
        assert_archive_verify_fails(
            bin_path=bin_path,
            archive=bad_mtime,
            sha256=bad_mtime_sha,
            extract_dir=tmp / "bad-mtime-extract",
        )

        tampered_decision = tmp / "tampered-decision.tar"

        def tamper_decision(filename: str, data: bytes) -> bytes:
            if filename != "release-decision.txt":
                return data
            text = data.decode("ascii")
            return replace_value(text, "artifact-sha256", "00" * 32).encode("ascii")

        write_custom_archive(
            bundle=bundle,
            archive=tampered_decision,
            mutate_data=tamper_decision,
        )
        tampered_decision_sha = tmp / "tampered-decision.tar.sha256"
        write_sidecar(tampered_decision, tampered_decision_sha)
        assert_archive_verify_fails(
            bin_path=bin_path,
            archive=tampered_decision,
            sha256=tampered_decision_sha,
            extract_dir=tmp / "tampered-decision-extract",
        )

        copied_archive = tmp / "copied.tar"
        copied_sha = tmp / "copied.tar.sha256"
        shutil.copyfile(archive_a, copied_archive)
        write_sidecar(copied_archive, copied_sha)
        assert_ok(
            run_archive(
                "verify",
                bin_path=bin_path,
                archive=copied_archive,
                sha256=copied_sha,
                extract_dir=tmp / "copied-extract",
                zig_witness=zig_witness,
            ),
            "verify copied archive",
        )

    if not args.quiet:
        print("wuci witness archive: PASS")


if __name__ == "__main__":
    main()
