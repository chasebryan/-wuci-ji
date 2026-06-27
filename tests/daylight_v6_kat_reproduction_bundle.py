#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
BUNDLE = REPO / "daylight-equation" / "evidence" / "daylight-v6-kat-reproduction-bundle.v1.json"
AGREEMENT = REPO / "daylight-equation" / "evidence" / "daylight-v6-provider-vector-agreement.v1.json"
MAKEFILE = REPO / "Makefile"
README = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "README.md"
BUILD_TARGETS = REPO / "docs" / "BUILD_TARGETS.md"


def sha3_512(path: Path) -> str:
    return hashlib.sha3_512(path.read_bytes()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def make_target(command: str) -> str:
    prefix = "make "
    if not command.startswith(prefix):
        raise AssertionError(f"expected make command: {command}")
    return command.removeprefix(prefix)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Daylight v6 KAT reproduction bundle.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    bundle = read_json(BUNDLE)
    agreement = read_json(AGREEMENT)
    makefile = MAKEFILE.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")

    assert bundle["schema"] == "daylight-v6-kat-reproduction-bundle-v1"
    assert bundle["subject"] == "Daylight_v0.6_provider_kat_reproduction_bundle"
    assert bundle["summary"]["score_delta"] == 0
    assert bundle["summary"]["production_allowed"] is False
    assert bundle["summary"]["public_authority_external"] is True
    assert bundle["summary"]["reference_negative_cases"] == agreement["summary"]["reference_negative_cases"]
    assert bundle["summary"]["reference_negative_corpus_all_fail_closed"] is True
    assert bundle["bundle_verification_command"] == "make daylight-v6-kat-reproduction-bundle-test"
    assert "daylight-v6-kat-reproduction-bundle-test:" in makefile
    assert "daylight-v6-kat-reproduction-bundle-test" in build_targets

    non_claims = bundle["non_claims"]
    assert "this KAT reproduction bundle is not an external review" in non_claims
    assert "this KAT reproduction bundle is not an independent implementation" in non_claims
    assert "this KAT reproduction bundle does not raise the Daylight score" in non_claims

    agreement_inputs = {item["path"]: item["sha3_512"] for item in agreement["inputs"]}
    artifacts = bundle["reproduction_artifacts"]
    assert len(artifacts) == bundle["summary"]["artifact_count"]
    vector_artifacts = [item for item in artifacts if item["path"] in agreement_inputs]
    assert len(vector_artifacts) == bundle["summary"]["vector_artifact_count"]

    for artifact in artifacts:
        path = artifact["path"]
        abs_path = REPO / path
        assert abs_path.is_file(), path
        assert artifact["sha3_512"] == sha3_512(abs_path)
        command = artifact["verification_command"]
        target = make_target(command)
        assert f"{target}:" in makefile
        if path in agreement_inputs:
            assert artifact["sha3_512"] == agreement_inputs[path]

    assert sha3_512(AGREEMENT) == next(
        item["sha3_512"] for item in artifacts if item["path"] == str(AGREEMENT.relative_to(REPO))
    )

    generation_commands = bundle["generation_commands"]
    assert len(generation_commands) == 4
    for item in generation_commands:
        assert item["working_directory"] == "daylight-equation/rust/daylight-crypto"
        assert item["command"] in readme

    if not args.quiet:
        print("Daylight v6 KAT reproduction bundle: PASS")


if __name__ == "__main__":
    main()
