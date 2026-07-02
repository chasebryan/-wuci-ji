"""CLI for Daylight v20 Aperture Singularity Gate."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

from . import __version__
from . import evidence_audit
from . import external_attestation
from . import falsification
from . import proof_fields
from . import public_artifact
from . import reproducible_builds
from . import singularity_gate
from . import verifier_agreement
from .canonical import canonical_sha256, json_bytes, load_json_no_floats, loads_json_no_floats
from .pathsafe import atomic_write_bytes

CANONICAL_KAT_DOMAIN = "DAYLIGHT-v20-CANONICAL-KAT:"
CANONICAL_KAT_EXPECTED = "7ae120d28dd75ae8ea2a7cc0301744cc91d99b6462fcc2b30ec15ddc2c12ce18"
SHA3_KAT_INPUT = b"daylight-v20-aperture-singularity"
SHA3_KAT_EXPECTED = "06eef4f8ebed2f5d535ffcf06662cd14b5fbaf9c1c0818a25b82758850d67368215aa6c0ddd12a181370bb65b070cf3f5d8baaf4e06ebcd253277713cc5652ae"
FORBIDDEN_IMPORT_TOKENS = tuple("import " + name for name in ("socket", "urllib", "http.client", "ssl"))


def _print_json(value: Any) -> None:
    sys.stdout.buffer.write(json_bytes(value))


def _print_text(value: dict[str, Any]) -> None:
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            continue
        print(f"{key}: {item}")
    for list_key in ("blockers", "proofs", "non_claims", "checks"):
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
    check("python_version", version >= (3, 11), f"{version.major}.{version.minor}.{version.micro}")
    check("sha3_512_kat", hashlib.sha3_512(SHA3_KAT_INPUT).hexdigest() == SHA3_KAT_EXPECTED, "hashlib SHA3-512 known-answer test")
    check("canonical_json_kat", canonical_sha256({"a": 1, "b": [1, 2]}, CANONICAL_KAT_DOMAIN) == CANONICAL_KAT_EXPECTED, "canonical JSON known-answer test")
    try:
        loads_json_no_floats('{"a":1,"a":2}')
        duplicate_rejected = False
    except ValueError:
        duplicate_rejected = True
    try:
        loads_json_no_floats('{"a":1.25}')
        float_rejected = False
    except ValueError:
        float_rejected = True
    check("duplicate_json_keys_rejected", duplicate_rejected, "object_pairs_hook")
    check("json_floats_rejected", float_rejected, "parse_float rejection")
    source_root = Path(__file__).resolve().parent
    offending: list[str] = []
    for source_file in sorted(source_root.glob("*.py")):
        text = source_file.read_text(encoding="utf-8")
        for token in FORBIDDEN_IMPORT_TOKENS:
            if token in text:
                offending.append(f"{source_file.name}:{token}")
    check("no_network_imports", not offending, "; ".join(offending) or "src imports no network modules")
    fixture = singularity_gate.EXAMPLES_ROOT / "aperture-singularity-capsule.fixture.v20.json"
    if fixture.is_file():
        try:
            report = singularity_gate.verify_capsule_file(fixture)
            check("fixture_capsule_verifies", report["verified"] is True, str(fixture))
            check("fixture_declaration_refused", report["allowed"] is False, "fixture must not pass declaration")
        except (OSError, ValueError) as exc:
            check("fixture_capsule_verifies", False, f"{fixture}: {exc}")
            check("fixture_declaration_refused", False, f"{fixture}: {exc}")
    else:
        check("fixture_capsule_verifies", False, f"missing: {fixture}")
        check("fixture_declaration_refused", False, f"missing: {fixture}")
    ok = all(item["ok"] for item in checks)
    _emit({"command": "doctor", "version": __version__, "ok": ok, "network_access": "none", "checks": checks}, args.format)
    return 0 if ok else 1


def cmd_build_capsule(args: argparse.Namespace) -> int:
    capsule = singularity_gate.build_capsule(
        aperture_capsule_path=args.aperture_capsule,
        verifier_bundle_path=args.verifier_bundle,
        external_attestation_path=args.external_attestations,
        reproducible_build_path=args.reproducible_builds,
        falsification_path=args.falsification,
        boundary_debt_path=args.boundary_debt,
        firewall_profile_path=args.firewall_profile_expansion,
        release_tag=args.release_tag,
    )
    atomic_write_bytes(args.out, json_bytes(capsule), force=args.force)
    _emit(
        {
            "command": "build-capsule",
            "out": args.out,
            "capsule_digest": capsule["capsule_digest"],
            "declaration_allowed": capsule["declaration_allowed"],
            "blockers": capsule["blockers"],
        },
        args.format,
    )
    return 0


def cmd_verify_capsule(args: argparse.Namespace) -> int:
    report = singularity_gate.verify_capsule_file(args.capsule)
    report["command"] = "verify-capsule"
    _emit(report, args.format)
    return 0 if report["verified"] else 1


def cmd_score_fields(args: argparse.Namespace) -> int:
    capsule = singularity_gate.load_capsule(args.capsule)
    _emit(
        {
            "command": "score-fields",
            "capsule_digest": capsule["capsule_digest"],
            "omega_sum": capsule["omega_sum"],
            "omega_weak": capsule["omega_weak"],
            "omega_eff": capsule["omega_eff"],
            "score_AM_plus": capsule["score_AM_plus"],
            "proof_fields": capsule["proof_fields"],
        },
        args.format,
    )
    return 0


def cmd_agreement(args: argparse.Namespace) -> int:
    result = verifier_agreement.evaluate_bundle(
        load_json_no_floats(args.verifier_bundle),
        expected_subject=args.expected_subject,
    )
    result["command"] = "agreement"
    _emit(result, args.format)
    return 0


def cmd_blockers(args: argparse.Namespace) -> int:
    capsule = singularity_gate.load_capsule(args.capsule)
    report = singularity_gate.declaration_report(capsule)
    report["command"] = "blockers"
    _emit(report, args.format)
    return 0


def cmd_declaration_gate(args: argparse.Namespace) -> int:
    capsule = singularity_gate.load_capsule(args.capsule)
    report = singularity_gate.declaration_report(capsule)
    report["command"] = "declaration-gate"
    _emit(report, args.format)
    return 0 if report["allowed"] else 1


def cmd_explain(args: argparse.Namespace) -> int:
    capsule = singularity_gate.load_capsule(args.capsule)
    _emit(singularity_gate.explain_capsule(capsule), args.format)
    return 0


def cmd_evidence_audit(args: argparse.Namespace) -> int:
    report = evidence_audit.load_and_audit(args.capsule)
    report["command"] = "evidence-audit"
    _emit(report, args.format)
    return 0 if not report["unclassified_blockers"] else 1


def cmd_public_artifact(args: argparse.Namespace) -> int:
    report = public_artifact.build_public_artifact(
        args.capsule,
        args.out_dir,
        verifier_bundle_path=args.verifier_bundle,
        external_attestation_path=args.external_attestations,
        reproducible_build_path=args.reproducible_builds,
        falsification_path=args.falsification,
        boundary_debt_path=args.boundary_debt,
        firewall_profile_path=args.firewall_profile_expansion,
        force=args.force,
        tar_path=args.tar,
        firewall_report_path=args.firewall_report,
    )
    report["command"] = "public-artifact"
    _emit(report, args.format)
    return 0 if report["firewall_ok"] else 1


def cmd_firewall(args: argparse.Namespace) -> int:
    report = public_artifact.run_firewall(args.root, report_path=args.report)
    report["command"] = "firewall"
    _emit(report, args.format)
    return 0 if report["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-v20-aperture-singularity")
    parser.add_argument("--version", action="version", version=f"daylight-v20-aperture-singularity {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    doctor.set_defaults(func=cmd_doctor)

    build = sub.add_parser("build-capsule")
    build.add_argument("--aperture-capsule", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--verifier-bundle")
    build.add_argument("--external-attestations")
    build.add_argument("--reproducible-builds")
    build.add_argument("--falsification")
    build.add_argument("--boundary-debt")
    build.add_argument("--firewall-profile-expansion")
    build.add_argument("--release-tag", default="v20-aperture-singularity-fixture")
    build.add_argument("--force", action="store_true")
    build.add_argument("--format", choices=("text", "json"), default="text")
    build.set_defaults(func=cmd_build_capsule)

    verify = sub.add_parser("verify-capsule")
    verify.add_argument("capsule")
    verify.add_argument("--format", choices=("text", "json"), default="text")
    verify.set_defaults(func=cmd_verify_capsule)

    score = sub.add_parser("score-fields")
    score.add_argument("capsule")
    score.add_argument("--format", choices=("text", "json"), default="text")
    score.set_defaults(func=cmd_score_fields)

    agreement = sub.add_parser("agreement")
    agreement.add_argument("verifier_bundle")
    agreement.add_argument("--expected-subject")
    agreement.add_argument("--format", choices=("text", "json"), default="text")
    agreement.set_defaults(func=cmd_agreement)

    blockers = sub.add_parser("blockers")
    blockers.add_argument("capsule")
    blockers.add_argument("--format", choices=("text", "json"), default="text")
    blockers.set_defaults(func=cmd_blockers)

    gate = sub.add_parser("declaration-gate")
    gate.add_argument("capsule")
    gate.add_argument("--format", choices=("text", "json"), default="text")
    gate.set_defaults(func=cmd_declaration_gate)

    explain = sub.add_parser("explain")
    explain.add_argument("capsule")
    explain.add_argument("--format", choices=("text", "json"), default="text")
    explain.set_defaults(func=cmd_explain)

    audit = sub.add_parser("evidence-audit")
    audit.add_argument("capsule")
    audit.add_argument("--format", choices=("text", "json"), default="text")
    audit.set_defaults(func=cmd_evidence_audit)

    public = sub.add_parser("public-artifact")
    public.add_argument("--capsule", required=True)
    public.add_argument("--out-dir", required=True)
    public.add_argument("--verifier-bundle")
    public.add_argument("--external-attestations")
    public.add_argument("--reproducible-builds")
    public.add_argument("--falsification")
    public.add_argument("--boundary-debt")
    public.add_argument("--firewall-profile-expansion")
    public.add_argument("--tar")
    public.add_argument("--firewall-report")
    public.add_argument("--force", action="store_true")
    public.add_argument("--format", choices=("text", "json"), default="text")
    public.set_defaults(func=cmd_public_artifact)

    firewall = sub.add_parser("firewall")
    firewall.add_argument("--root", required=True)
    firewall.add_argument("--report")
    firewall.add_argument("--format", choices=("text", "json"), default="text")
    firewall.set_defaults(func=cmd_firewall)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"daylight-v20-aperture-singularity: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
