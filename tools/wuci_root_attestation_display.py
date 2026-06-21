#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Any


DEFAULT_BUNDLE_DIR = Path("build/wuci-rooted-proof")
WIDTH = min(72, shutil.get_terminal_size((72, 24)).columns)
INNER = WIDTH - 4
REQUIRED_CHECKS = (
    "authority_root_check",
    "authority_root_matches_contract",
    "rooted_gate_check",
    "rooted_gate_open",
    "byte_identical",
    "opened_executable",
)


class DisplayError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DisplayError(f"could not read attestation {path}") from exc
    except json.JSONDecodeError as exc:
        raise DisplayError(f"attestation is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise DisplayError("attestation must be a JSON object")
    return value


def parse_labels(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="ascii")
    except OSError as exc:
        raise DisplayError(f"could not read authority root {path}") from exc
    except UnicodeDecodeError as exc:
        raise DisplayError("authority root is not ASCII") from exc
    labels: dict[str, str] = {}
    for line in text.splitlines():
        if ": " not in line:
            raise DisplayError(f"authority root contains malformed line: {line!r}")
        label, value = line.split(": ", 1)
        labels[label] = value
    return labels


def require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise DisplayError(f"attestation missing string field: {name}")
    return value


def require_check(attestation: dict[str, Any], name: str) -> bool:
    checks = attestation.get("checks")
    if not isinstance(checks, dict):
        raise DisplayError("attestation missing checks object")
    value = checks.get(name)
    if value is not True:
        raise DisplayError(f"rooted attestation check is not true: {name}")
    return True


def shorten(value: str, keep: int = 14) -> str:
    if len(value) <= (keep * 2) + 3:
        return value
    return f"{value[:keep]}...{value[-keep:]}"


def border(char: str = "-") -> str:
    return "+" + (char * (WIDTH - 2)) + "+"


def row(text: str = "") -> str:
    return "| " + text[:INNER].ljust(INNER) + " |"


def rows(label: str, value: str) -> list[str]:
    prefix = f"{label:<18} "
    available = INNER - len(prefix)
    wrapped = textwrap.wrap(value, width=available) or [""]
    result = [row(prefix + wrapped[0])]
    pad = " " * len(prefix)
    result.extend(row(pad + part) for part in wrapped[1:])
    return result


def checked_context(
    attestation: dict[str, Any],
    authority: dict[str, str],
) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    for check in REQUIRED_CHECKS:
        require_check(attestation, check)

    authority_root_sha256 = require_string(
        attestation.get("authority_root_sha256"), "authority_root_sha256"
    )
    authority_group_public_key = require_string(
        attestation.get("authority_group_public_key"), "authority_group_public_key"
    )
    if authority.get("group-public-key") != authority_group_public_key:
        raise DisplayError("authority root group key does not match attestation")

    sha256 = attestation.get("sha256")
    if not isinstance(sha256, dict):
        raise DisplayError("attestation missing sha256 object")
    paths = attestation.get("paths")
    if not isinstance(paths, dict):
        raise DisplayError("attestation missing paths object")
    return authority_root_sha256, authority_group_public_key, sha256, paths


def two_col(left: str, right: str) -> str:
    gap = "  "
    half = (INNER - len(gap)) // 2
    return row(left[:half].ljust(half) + gap + right[:half].ljust(half))


def compact_hash(label: str, value: str) -> str:
    return f"{label:<9} {shorten(value, 10)}"


def render_compact(attestation: dict[str, Any], authority: dict[str, str]) -> str:
    authority_root_sha256, authority_group_public_key, sha256, paths = checked_context(
        attestation,
        authority,
    )

    lines: list[str] = []
    lines.append(border("="))
    lines.append(row("NO SUCH ROOT // WUCI-ROOT"))
    lines.append(row("ROOT: ACHIEVED"))
    lines.append(row("QUORUM: PINNED"))
    lines.append(row("OPEN: ASSEMBLY-ENFORCED"))
    lines.append(border("="))
    lines.append(row("       .--[ROOT]--.      .--[GATE]--.      .--[COPY]--."))
    lines.append(row("       |  key     | ---> |  asm    | ---> |  ==    |"))
    lines.append(row("       '--[PIN]---'      '--[OK]---'      '--[EXE]--'"))
    lines.append(border("-"))
    lines.append(row("ROOT"))
    lines.extend(rows("id", shorten(authority["authority-id"], 12)))
    lines.extend(rows("quorum key", shorten(authority_group_public_key, 12)))
    lines.extend(rows("suite", authority["suite"]))
    lines.append(row("policy            open=true; release/trust/publish=false"))
    lines.append(border("-"))
    lines.append(row("DIGEST BINDINGS"))
    lines.append(row(compact_hash("root", authority_root_sha256)))
    lines.append(
        row(
            compact_hash(
                "contract",
                require_string(sha256.get("receipt_contract"), "sha256.receipt_contract"),
            )
        )
    )
    lines.append(
        row(
            compact_hash(
                "artifact",
                require_string(sha256.get("sealed_artifact"), "sha256.sealed_artifact"),
            )
        )
    )
    lines.append(
        row(
            "binary    "
            + shorten(require_string(sha256.get("original_binary"), "sha256.original_binary"), 10)
            + " == "
            + shorten(require_string(sha256.get("opened_binary"), "sha256.opened_binary"), 10)
        )
    )
    lines.append(border("-"))
    lines.append(row("CHECKS"))
    lines.append(two_col("[OK] authority-root", "[OK] root==contract"))
    lines.append(two_col("[OK] rooted-gate", "[OK] rooted-open"))
    lines.append(two_col("[OK] byte-identical", "[OK] executable"))
    lines.append(border("-"))
    lines.append(
        row(
            "artifact "
            + require_string(paths.get("sealed_artifact"), "paths.sealed_artifact")
        )
    )
    lines.append(
        row(
            "opened   " + require_string(paths.get("opened_binary"), "paths.opened_binary")
        )
    )
    lines.append(border("="))
    lines.append(row("VERDICT: ROOT ACHIEVED. NO UNPINNED QUORUM."))
    lines.append(border("="))
    return "\n".join(lines)


def render_full(attestation: dict[str, Any], authority: dict[str, str]) -> str:
    authority_root_sha256, authority_group_public_key, sha256, paths = checked_context(
        attestation,
        authority,
    )

    lines: list[str] = []
    lines.append(border("="))
    lines.append(row("NO SUCH ROOT // WUCI-ROOT"))
    lines.append(row("WUCI-ROOT / NO SUCH ROOT"))
    lines.append(row("ROOT: ACHIEVED"))
    lines.append(row("QUORUM: PINNED"))
    lines.append(row("OPEN: ASSEMBLY-ENFORCED"))
    lines.append(border("="))
    lines.append(row())
    lines.append(row("      .--[ root of trust ]--."))
    lines.append(row("     /  seal -> warrant -> gate \\"))
    lines.append(row("    |   root -> open -> attest   |"))
    lines.append(row("     \\__ no json. no overwrite. _/"))
    lines.append(row())
    lines.append(border("-"))
    lines.append(row(":: AUTHORITY ROOT"))
    lines.append(row("-----------------"))
    for label in (
        "schema",
        "suite",
        "production",
        "authority-id",
        "group-public-key",
        "allow-open",
        "allow-release",
        "allow-trust",
        "allow-publish",
    ):
        lines.extend(rows(label, authority[label]))
    lines.append(border("-"))
    lines.append(row(":: ATTESTED DIGESTS"))
    lines.append(row("-------------------"))
    lines.extend(rows("authority sha256", authority_root_sha256))
    lines.extend(rows("contract sha256", require_string(sha256.get("receipt_contract"), "sha256.receipt_contract")))
    lines.extend(rows("artifact sha256", require_string(sha256.get("sealed_artifact"), "sha256.sealed_artifact")))
    lines.extend(rows("original binary", shorten(require_string(sha256.get("original_binary"), "sha256.original_binary"))))
    lines.extend(rows("opened binary", shorten(require_string(sha256.get("opened_binary"), "sha256.opened_binary"))))
    lines.append(border("-"))
    lines.append(row(":: MACHINE CHECKS"))
    lines.append(row("-----------------"))
    for check in REQUIRED_CHECKS:
        lines.extend(rows("[OK]", check.replace("_", "-")))
    lines.append(border("-"))
    lines.append(row(":: PATHS"))
    lines.append(row("--------"))
    for key in ("authority_root", "receipt_contract", "sealed_artifact", "opened_binary"):
        lines.extend(rows(key.replace("_", "-"), require_string(paths.get(key), f"paths.{key}")))
    lines.append(border("="))
    lines.append(row("VERDICT: ROOT ACHIEVED. THE MACHINE TRUSTS THIS QUORUM KEY."))
    lines.append(row("OPEN AUTHORITY WAS ASSEMBLY-ENFORCED AND BYTE-IDENTICAL."))
    lines.append(border("="))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Display a terminal ASCII WUCI-ROOT self-release attestation."
    )
    parser.add_argument(
        "--bundle-dir",
        default=str(DEFAULT_BUNDLE_DIR),
        help="rooted self-release proof bundle directory",
    )
    parser.add_argument("--attestation", help="attestation JSON path")
    parser.add_argument("--authority", help="authority root path")
    parser.add_argument("--full", action="store_true", help="show the full proof card")
    args = parser.parse_args()

    bundle_dir = Path(args.bundle_dir)
    attestation_path = Path(args.attestation) if args.attestation else bundle_dir / "attestation.json"
    authority_path = Path(args.authority) if args.authority else bundle_dir / "authority-root.txt"

    try:
        attestation = load_json(attestation_path)
        authority = parse_labels(authority_path)
        if args.full:
            print(render_full(attestation, authority))
        else:
            print(render_compact(attestation, authority))
    except (DisplayError, KeyError) as exc:
        print(f"wuci root display: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
