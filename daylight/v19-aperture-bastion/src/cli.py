"""CLI for Wuci-Ji v2 — Aperture Bastion (Daylight v19).

Every command fails closed: invalid input, missing files, path traversal,
symlinks, malformed JSON, digest mismatches, forbidden claims, and private
material all exit nonzero.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from . import capsule as capsule_mod
from . import claims
from . import firewall as firewall_mod
from . import profile
from . import public_artifact as public_artifact_mod
from .canonical_json import canonical_sha256, json_bytes, load_json_no_floats
from .pathsafe import PathSafetyError, atomic_write_bytes

SHA3_KAT_INPUT = b"aperture-bastion"
SHA3_KAT_EXPECTED = (
    "d9689549fcd2f5aff46820b5a75398cfbd557c4004cd150ac7513935c8038563"
    "955b4080dbb1041922c5d89c747d1bf9aa26e93f598a44f699191de5beb8e1fb"
)
CANONICAL_KAT_DOMAIN = "DAYLIGHT-v19-APERTURE-DOCTOR-KAT:"
CANONICAL_KAT_EXPECTED = "aa96d6a4399c7153a55caadf0ec85f50b0130510a168d044cc85de5c62fc6b9c"
PROFILE_DIGEST_EXPECTED = "d191c651b963806015e1c779fcf72ab7d84cac9c0090f5beeb38a108e3329878"
EXAMPLE_SUBJECT = "daylight/v19-aperture-bastion/examples/example-subject.bin"
EXAMPLE_CAPSULE = "daylight/v19-aperture-bastion/examples/expected-capsule.v19.json"
FORBIDDEN_IMPORT_TOKENS = tuple(
    "import " + name for name in ("socket", "urllib", "http.client", "ssl")
)


def _print_json(value: Any) -> None:
    sys.stdout.buffer.write(json_bytes(value))


def _print_text(value: dict[str, Any]) -> None:
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            continue
        print(f"{key}: {item}")
    for list_key in ("blockers", "notes", "violations", "proofs", "non_claims", "checks"):
        items = value.get(list_key)
        if not items:
            continue
        print(f"{list_key}:")
        for item in items:
            if isinstance(item, dict):
                rendered = ", ".join(f"{k}={v}" for k, v in sorted(item.items()))
                print(f"  - {rendered}")
            else:
                print(f"  - {item}")


def _emit(value: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        _print_json(value)
    else:
        _print_text(value)


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    version = sys.version_info
    check("python_version", version >= (3, 9), f"{version.major}.{version.minor}.{version.micro}")
    check(
        "sha3_512_kat",
        hashlib.sha3_512(SHA3_KAT_INPUT).hexdigest() == SHA3_KAT_EXPECTED,
        "hashlib SHA3-512 known-answer test",
    )
    check(
        "canonical_json_kat",
        canonical_sha256({"a": 1, "b": [1, 2]}, CANONICAL_KAT_DOMAIN) == CANONICAL_KAT_EXPECTED,
        "canonical JSON digest known-answer test",
    )
    check(
        "firewall_profile_pinned",
        profile.PROFILE_DIGEST == PROFILE_DIGEST_EXPECTED,
        f"profile {profile.PROFILE_ID} digest {profile.PROFILE_DIGEST}",
    )
    check(
        "firewall_name_rules",
        bool(profile.check_path_name("vault.key"))
        and bool(profile.check_path_name("smoke-secret.txt"))
        and bool(profile.check_path_name("vault-work/opened.txt"))
        and not profile.check_path_name("scorecard.v19.json"),
        "forbidden name self-test",
    )
    check(
        "firewall_content_rules",
        bool(profile.check_content(b"-----BEGIN RSA PRIVATE KEY-----"))
        and bool(profile.check_content(b"a" * 64))
        and not profile.check_content(b"ordinary public review text"),
        "forbidden marker self-test",
    )
    with tempfile.TemporaryDirectory() as tmp:
        planted = Path(tmp) / "public" / "id_rsa"
        planted.parent.mkdir()
        planted.write_bytes(b"not really a key")
        report = firewall_mod.scan_public_root(planted.parent)
        check(
            "firewall_scan_rejects_planted_secret",
            not report["ok"],
            "temporary fixture scan",
        )
    subject = capsule_mod.REPO_ROOT / EXAMPLE_SUBJECT
    expected = capsule_mod.REPO_ROOT / EXAMPLE_CAPSULE
    check("example_subject_present", subject.is_file(), EXAMPLE_SUBJECT)
    if expected.is_file():
        try:
            result = capsule_mod.verify_capsule_file(expected, base_dir=capsule_mod.REPO_ROOT)
            check("example_capsule_verifies", result["verified"], EXAMPLE_CAPSULE)
        except (ValueError, OSError) as exc:
            check("example_capsule_verifies", False, f"{EXAMPLE_CAPSULE}: {exc}")
    else:
        check("example_capsule_verifies", False, f"missing: {EXAMPLE_CAPSULE}")
    source_root = Path(__file__).resolve().parent
    offending: list[str] = []
    for source_file in sorted(source_root.glob("*.py")):
        text = source_file.read_text(encoding="utf-8")
        for token in FORBIDDEN_IMPORT_TOKENS:
            if token in text:
                offending.append(f"{source_file.name}:{token}")
    check("no_network_imports", not offending, "; ".join(offending) or "src imports no network modules")

    ok = all(item["ok"] for item in checks)
    _emit(
        {
            "command": "doctor",
            "version": __version__,
            "ok": ok,
            "network_access": "none",
            "checks": checks,
        },
        args.format,
    )
    return 0 if ok else 1


def cmd_capsule(args: argparse.Namespace) -> int:
    built = capsule_mod.build_capsule(
        subjects=args.subject,
        base_dir=args.base_dir,
        public_files=args.public_file if args.public_file else None,
        allowed_extra_files=args.allowed_extra,
        binaric_vector_paths=args.binaric_vector if args.binaric_vector else None,
        transition_ledger_path=args.transition_ledger,
        meridian_scorecard_path=args.meridian_scorecard,
        event_horizon_scorecard_path=args.event_horizon_scorecard,
        policy_path=args.policy,
        fixture=args.fixture,
    )
    atomic_write_bytes(Path(args.out), json_bytes(built), force=args.force)
    _emit(
        {
            "command": "capsule",
            "out": args.out,
            "capsule_digest": built["capsule_digest"],
            "subject_sha256": built["subject_sha256"],
            "public_manifest_files": len(built["public_manifest"]),
            "fixture": built["fixture"],
        },
        args.format,
    )
    return 0


def cmd_verify_capsule(args: argparse.Namespace) -> int:
    result = capsule_mod.verify_capsule_file(
        args.capsule,
        base_dir=args.base_dir,
        check_subject_files=not args.no_subject_files,
        check_public_files=not args.no_public_files,
        require_evidence=args.require_evidence,
    )
    result["command"] = "verify-capsule"
    _emit(result, args.format)
    return 0 if result["verified"] else 1


def cmd_public_artifact(args: argparse.Namespace) -> int:
    report = public_artifact_mod.build_public_artifact(
        args.capsule,
        args.out_dir,
        base_dir=args.base_dir,
        force=args.force,
    )
    firewall_report = firewall_mod.run_firewall(args.out_dir)
    if not firewall_report["ok"]:
        shutil.rmtree(args.out_dir, ignore_errors=True)
        _emit(firewall_report, args.format)
        return 1
    report["command"] = "public-artifact"
    report["firewall_ok"] = True
    report["firewall_report_path"] = firewall_report.get("report_path")
    _emit(report, args.format)
    return 0


def cmd_firewall(args: argparse.Namespace) -> int:
    report = firewall_mod.run_firewall(
        args.root,
        report_path=args.report,
        max_file_bytes=args.max_file_bytes,
    )
    _emit(report, args.format)
    return 0 if report["ok"] else 1


def cmd_explain(args: argparse.Namespace) -> int:
    capsule = capsule_mod.load_capsule(args.capsule)
    proofs: list[str] = []
    for entry in capsule["input_subjects"]:
        proofs.append(
            f"subject {entry['subject_path']} bound to sha256 {entry['subject_sha256']} "
            f"and sha3-512 {entry['subject_sha3_512'][:16]}... ({entry['subject_size_bytes']} bytes)"
        )
    proofs.append(
        f"public manifest of {len(capsule['public_manifest'])} file(s) bound; "
        f"SHA256SUMS content pinned as {capsule['public_sha256sums']}"
    )
    for ref in capsule["evidence_refs"]:
        proofs.append(f"evidence {ref['kind']} pinned: {', '.join(ref['paths'])}")
    proofs.append(
        f"private-material profile pinned: {profile.PROFILE_ID} {profile.PROFILE_DIGEST}"
    )
    proofs.append(f"capsule digest {capsule['capsule_digest']} covers every field above")
    _emit(
        {
            "command": "explain",
            "capsule_digest": capsule["capsule_digest"],
            "layer_name": capsule["layer_name"],
            "repo_commit": capsule["repo_commit"],
            "repo_dirty_state": capsule["repo_dirty_state"],
            "fixture": capsule["fixture"],
            "claim_statement": capsule["claim_boundary"]["statement"],
            "proofs": proofs,
            "non_claims": capsule["non_claims"],
        },
        args.format,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-v19-aperture-bastion")
    parser.add_argument("--version", action="version", version=f"daylight-v19-aperture-bastion {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    doctor.set_defaults(func=cmd_doctor)

    capsule = sub.add_parser("capsule")
    capsule.add_argument("--subject", action="append", required=True)
    capsule.add_argument("--out", required=True)
    capsule.add_argument("--base-dir")
    capsule.add_argument("--public-file", action="append", default=[])
    capsule.add_argument("--allowed-extra", action="append", default=[])
    capsule.add_argument("--binaric-vector", action="append", default=[])
    capsule.add_argument("--transition-ledger")
    capsule.add_argument("--meridian-scorecard")
    capsule.add_argument("--event-horizon-scorecard")
    capsule.add_argument("--policy")
    capsule.add_argument("--fixture", action="store_true")
    capsule.add_argument("--force", action="store_true")
    capsule.add_argument("--format", choices=("text", "json"), default="text")
    capsule.set_defaults(func=cmd_capsule)

    verify = sub.add_parser("verify-capsule")
    verify.add_argument("capsule")
    verify.add_argument("--base-dir")
    verify.add_argument("--no-subject-files", action="store_true")
    verify.add_argument("--no-public-files", action="store_true")
    verify.add_argument("--require-evidence", action="store_true")
    verify.add_argument("--format", choices=("text", "json"), default="text")
    verify.set_defaults(func=cmd_verify_capsule)

    public = sub.add_parser("public-artifact")
    public.add_argument("--capsule", required=True)
    public.add_argument("--out-dir", required=True)
    public.add_argument("--base-dir")
    public.add_argument("--force", action="store_true")
    public.add_argument("--format", choices=("text", "json"), default="text")
    public.set_defaults(func=cmd_public_artifact)

    firewall = sub.add_parser("firewall")
    firewall.add_argument("--root", required=True)
    firewall.add_argument("--report")
    firewall.add_argument("--max-file-bytes", type=int, default=profile.DEFAULT_MAX_FILE_BYTES)
    firewall.add_argument("--format", choices=("text", "json"), default="text")
    firewall.set_defaults(func=cmd_firewall)

    explain = sub.add_parser("explain")
    explain.add_argument("capsule")
    explain.add_argument("--format", choices=("text", "json"), default="text")
    explain.set_defaults(func=cmd_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"daylight-v19-aperture-bastion: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
