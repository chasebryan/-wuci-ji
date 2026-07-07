"""Deterministic public artifact emission for Aperture Review Capsules.

The public artifact directory contains exactly: the capsule file, every file
listed in the capsule's public manifest (repo-relative layout preserved), and
a SHA256SUMS covering all of them. Nothing is copied before the capsule fully
verifies, every copied byte is re-hashed and re-scanned against the private
material profile at copy time, and a failed build removes its own partial
output.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any

from . import profile
from .canonical_json import loads_json_no_floats
from .capsule import (
    CAPSULE_FILENAME,
    SUMS_FILENAME,
    sums_text_for_manifest,
    verify_capsule,
)
from .pathsafe import (
    PathSafetyError,
    atomic_write_bytes,
    read_public_bytes,
    require_regular_file,
    resolve_under_base,
)


class PublicArtifactError(ValueError):
    pass


def _guard_removable(out: Path, base: Path) -> None:
    resolved = out.resolve()
    if resolved == base or resolved in base.parents:
        raise PublicArtifactError("refusing to clear the base directory or one of its parents")
    if (resolved / ".git").exists():
        raise PublicArtifactError("refusing to clear a directory containing .git")


def build_public_artifact(
    capsule_path: Path | str,
    out_dir: Path | str,
    *,
    base_dir: Path | str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    base = Path(base_dir).resolve() if base_dir is not None else Path.cwd().resolve()
    capsule_file = Path(capsule_path)
    capsule_bytes = read_public_bytes(capsule_file, str(capsule_file), reject_hardlink=False)
    capsule = loads_json_no_floats(capsule_bytes.decode("utf-8"))
    result = verify_capsule(capsule, base_dir=base, check_subject_files=True, check_public_files=True)
    if not result["verified"]:
        raise PublicArtifactError(
            "capsule failed verification before publication: " + "; ".join(result["blockers"][:5])
        )

    out = Path(out_dir)
    if out.is_symlink():
        raise PublicArtifactError(f"refusing to publish through a symlink: {out}")
    if out.exists():
        if not out.is_dir():
            raise PublicArtifactError(f"public artifact output is not a directory: {out}")
        if any(out.iterdir()):
            if not force:
                raise PublicArtifactError(
                    f"refusing to overwrite non-empty public artifact directory without --force: {out}"
                )
            _guard_removable(out, base)
            shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        sums_entries: list[dict[str, Any]] = []
        for entry in capsule["public_manifest"]:
            source = resolve_under_base(entry["path"], base)
            data = read_public_bytes(source, entry["path"])
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise PublicArtifactError(f"public file changed since capsule creation: {entry['path']}")
            reasons = profile.check_path_name(entry["path"])
            reasons.extend(profile.check_content(data, rel_path=entry["path"]))
            if reasons:
                raise PublicArtifactError(
                    f"private material firewall rejected {entry['path']}: {reasons[0]}"
                )
            atomic_write_bytes(out / entry["path"], data)
            sums_entries.append({"path": entry["path"], "sha256": entry["sha256"]})
        atomic_write_bytes(out / CAPSULE_FILENAME, capsule_bytes)
        sums_entries.append(
            {"path": CAPSULE_FILENAME, "sha256": hashlib.sha256(capsule_bytes).hexdigest()}
        )
        sums_entries.sort(key=lambda item: item["path"])
        sums_bytes = sums_text_for_manifest(sums_entries).encode("utf-8")
        atomic_write_bytes(out / SUMS_FILENAME, sums_bytes)
    except (PublicArtifactError, PathSafetyError, OSError, ValueError):
        shutil.rmtree(out, ignore_errors=True)
        raise

    return {
        "out_dir": str(out_dir),
        "file_count": len(capsule["public_manifest"]) + 2,
        "capsule_digest": capsule["capsule_digest"],
        "sums_sha256": hashlib.sha256(sums_bytes).hexdigest(),
    }
