"""Shared constants and helpers for Euclid substrate trial collection."""

from __future__ import annotations

import hashlib
from pathlib import Path


FIRST_COHORT = {
    "buildroot": {
        "display_name": "Buildroot",
        "substrate_class": "image-generator / embedded-appliance-builder",
    },
    "alpine": {
        "display_name": "Alpine Linux",
        "substrate_class": "minimal-linux-distribution",
    },
    "debian-minimal": {
        "display_name": "Debian Minimal",
        "substrate_class": "stable-linux-distribution",
    },
}

TRIAL_STATUS_VALUES = [
    "NO_SUBSTRATE_SELECTED",
    "TRIAL_DATA_PARTIAL",
    "TRIAL_DATA_COMPARABLE",
    "TRIAL_BLOCKED",
]

CANDIDATE_BUILD_STATUS_VALUES = [
    "BUILD_SUCCEEDED",
    "BUILD_NOT_ATTEMPTED",
    "BUILD_ATTEMPTED_FAILED",
    "MISSING_TOOLING",
    "NOT_MEASURED",
]

REQUIRED_TRIAL_FILES = [
    "trial-plan.json",
    "build-notes.md",
    "artifact-manifest.json",
    "package-manifest.txt",
    "package-count.txt",
    "image-size.txt",
    "enabled-services.txt",
    "listening-ports.txt",
    "suid-sgid.txt",
    "kernel-modules.txt",
    "dependency-tree.txt",
    "build-manifest.sha256",
    "substrate-report.json",
    "substrate-report.md",
    "failure-report.md",
]

MEASUREMENT_FILES = [
    "package-manifest.txt",
    "package-count.txt",
    "image-size.txt",
    "enabled-services.txt",
    "listening-ports.txt",
    "suid-sgid.txt",
    "kernel-modules.txt",
    "dependency-tree.txt",
    "build-manifest.sha256",
]

NOETHER_REQUIREMENTS = [
    "GUI absent",
    "default network services absent",
    "listening ports absent unless explicitly allowed",
    "runtime compilers absent unless explicitly justified",
    "each included component has a component-register entry",
    "each current claim has evidence or is listed as a non-claim",
    "release score is invalid without artifact hash",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def text_is_missing(text: str) -> bool:
    markers = [
        "NOT_MEASURED",
        "BUILD_NOT_ATTEMPTED",
        "BUILD_ATTEMPTED_FAILED",
        "MISSING_TOOLING",
    ]
    return any(marker in text for marker in markers)


def measurement_status(path: Path) -> str:
    if not path.is_file():
        return "NOT_MEASURED"
    text = path.read_text(encoding="utf-8", errors="replace")
    if text_is_missing(text):
        return "NOT_MEASURED"
    if text.strip():
        return "PRESENT"
    return "NOT_MEASURED"


def measured_line_count(path: Path) -> str:
    if measurement_status(path) != "PRESENT":
        return "NOT_MEASURED"
    lines = [
        line
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    return str(len(lines))
