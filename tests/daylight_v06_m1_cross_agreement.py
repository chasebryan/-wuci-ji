#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import daylight_v06_m1_independent_open as independent_open
import daylight_v06_m1_static_vectors as static_vectors


REPO = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = REPO / "daylight-equation" / "fixtures" / "daylight-v06-m1"
DEFAULT_EVIDENCE = REPO / "daylight-equation" / "evidence" / "daylight-v06-m1-cross-agreement.v1.json"


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def load_fixture_results(fixture: Path) -> dict[str, dict[str, Any]]:
    results = static_vectors.load_json(fixture / "TEST_RESULTS.json")
    if results["total"] != 32 or results["passed"] != 32 or results["failed"] != 0:
        raise AssertionError("fixture TEST_RESULTS summary is not fully passing")
    return {entry["vector_id"]: entry for entry in results["results"]}


def vector_dirs(fixture: Path) -> list[Path]:
    out = sorted(
        path
        for group in ("valid", "negative")
        for path in (fixture / "vectors" / group).iterdir()
        if path.is_dir()
    )
    if len(out) != 32:
        raise AssertionError(f"expected 32 vectors, found {len(out)}")
    return out


def generate(fixture: Path) -> dict[str, Any]:
    fixture_by_id = load_fixture_results(fixture)
    vectors = []
    for vector_dir in vector_dirs(fixture):
        vector_id = vector_dir.name
        manifest = static_vectors.load_json(vector_dir / "manifest.json")
        omega = static_vectors.read_hex_file(vector_dir / "omega.cbor.hex")
        static_stage = static_vectors.evaluate_public_precheck(omega)
        independent = independent_open.open_independent(
            omega,
            independent_open.load_secrets(vector_dir),
        )
        fixture_entry = fixture_by_id[vector_id]
        fixture_actual = fixture_entry["actual"]
        independent_actual = {
            "aead_dec_called": independent.aead_dec_called,
            "artifact_hex": independent.artifact.hex() if independent.artifact is not None else None,
            "ok": independent.ok,
            "private_kem_called": independent.private_kem_called,
            "rejection_stage": independent.rejection_stage,
        }

        for key, expected in independent_actual.items():
            if fixture_actual[key] != expected:
                raise AssertionError(f"{vector_id}: independent Open disagrees on {key}")
        if fixture_entry["expected_result"] != manifest["expected_result"]:
            raise AssertionError(f"{vector_id}: fixture result disagrees with manifest")
        if fixture_entry["expected_rejection_stage"] != manifest["expected_rejection_stage"]:
            raise AssertionError(f"{vector_id}: fixture stage disagrees with manifest")
        if static_stage is not None and static_stage != manifest["expected_rejection_stage"]:
            raise AssertionError(f"{vector_id}: static public stage disagrees with manifest")
        if static_stage is None and manifest["private_kem_allowed"] is False:
            raise AssertionError(f"{vector_id}: static checker missed public rejection")

        vectors.append(
            {
                "aead_dec_called": independent.aead_dec_called,
                "expected_rejection_stage": manifest["expected_rejection_stage"],
                "expected_result": manifest["expected_result"],
                "fixture_runner_ok": fixture_entry["ok"],
                "independent_open_ok": independent.ok,
                "independent_open_stage": independent.rejection_stage,
                "private_kem_called": independent.private_kem_called,
                "public_precheck_stage": static_stage,
                "vector_id": vector_id,
            }
        )

    public_rejections = sum(1 for item in vectors if item["public_precheck_stage"] is not None)
    private_or_valid = len(vectors) - public_rejections
    return {
        "as_of": "2026-06-27",
        "fixture": "daylight-equation/fixtures/daylight-v06-m1",
        "implementations": [
            "fixture_runner_recorded_results",
            "independent_static_public_precheck",
            "independent_fixture_profile_private_open",
        ],
        "schema_version": 1,
        "subject": "Daylight_v0.6_M1_fixture_cross_agreement",
        "summary": {
            "aead_called_vectors": sum(1 for item in vectors if item["aead_dec_called"]),
            "all_agree": True,
            "private_kem_called_vectors": sum(1 for item in vectors if item["private_kem_called"]),
            "private_or_valid_vectors": private_or_valid,
            "public_rejection_vectors": public_rejections,
            "total_vectors": len(vectors),
        },
        "vectors": vectors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Daylight v0.6 M1 cross-implementation agreement evidence.")
    parser.add_argument("--write", action="store_true", help="rewrite the checked-in evidence file")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    fixture = Path(os.environ.get("DAYLIGHT_V06_M1_FIXTURE", str(DEFAULT_FIXTURE)))
    if not fixture.is_absolute():
        fixture = REPO / fixture
    fixture = fixture.resolve()
    evidence = generate(fixture)
    encoded = canonical_json(evidence)

    if args.write:
        DEFAULT_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_EVIDENCE.write_text(encoded, encoding="utf-8")
    else:
        existing = DEFAULT_EVIDENCE.read_text(encoding="utf-8")
        if existing != encoded:
            raise AssertionError("cross-agreement evidence is stale; rerun with --write")

    if not args.quiet:
        print(f"daylight-v06-m1-cross-agreement: verified {evidence['summary']['total_vectors']} vectors")


if __name__ == "__main__":
    main()
