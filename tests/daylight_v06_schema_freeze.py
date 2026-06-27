#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODEL = REPO / "daylight-equation" / "research" / "daylight-v06-schema-freeze.v1.json"
MODEL_DOC = REPO / "daylight-equation" / "research" / "daylight-v06-schema-freeze.md"
REFERENCE = REPO / "daylight-equation" / "references" / "dlv0.5" / "v0.6M1-HARDENING.md"
FIXTURE_PROFILE = REPO / "daylight-equation" / "fixtures" / "daylight-v06-m1" / "spec" / "M1_FIXTURE_PROFILE.md"
V6_IMPL = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "src" / "v6.rs"
SCHEMA_VECTOR = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "vectors" / "daylight-v6-schema-vector-v1.txt"
NEGATIVE_CORPUS = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "vectors" / "daylight-v6-reference-negative-corpus-v1.txt"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
MAKEFILE = REPO / "Makefile"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    model = json.loads(MODEL.read_text(encoding="utf-8"))
    doc = MODEL_DOC.read_text(encoding="utf-8")
    reference = REFERENCE.read_text(encoding="utf-8")
    fixture_profile = FIXTURE_PROFILE.read_text(encoding="utf-8")
    v6_impl = V6_IMPL.read_text(encoding="utf-8")
    schema_vector = SCHEMA_VECTOR.read_text(encoding="utf-8")
    negative_corpus = NEGATIVE_CORPUS.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert model["schema"] == "daylight-v06-schema-freeze-v1"
    assert model["subject"] == "Daylight_v0.6"
    assert model["status"] == "m1-byte-schema-freeze-evidence-not-production"

    for surface in model["frozen_schema_surfaces"]:
        short_surface = surface.removesuffix(" schema")
        assert surface in reference
        assert short_surface in fixture_profile
        assert surface in doc

    for label in model["frozen_transcript_labels"]:
        assert label in reference
        assert label in v6_impl

    for label in model["frozen_kdf_labels"]:
        assert label in reference or label in v6_impl
        assert label in v6_impl

    for context in model["frozen_contexts"]:
        assert context in v6_impl
        assert context in reference or context.startswith("WUCI-DAYLIGHT:")

    for stage in model["frozen_rejection_stages"]:
        assert stage in reference
        assert stage in v6_impl

    assert model["checked_properties"] == {
        "schema_surfaces_present_in_reference_and_fixture_profile": True,
        "transcript_labels_present_in_reference_and_rust": True,
        "kdf_labels_present_in_reference_or_rust": True,
        "rejection_stages_present_in_reference_and_rust": True,
        "schema_vector_roundtrip_test_linked": True,
        "negative_corpus_test_linked": True,
    }

    assert model["evidence_vectors"] == [
        "daylight-equation/rust/daylight-crypto/vectors/daylight-v6-schema-vector-v1.txt",
        "daylight-equation/rust/daylight-crypto/vectors/daylight-v6-reference-negative-corpus-v1.txt",
    ]
    assert "version=daylight-v6-schema-vector-v1" in schema_vector
    assert "expected_rejection_stage=REJECT_AUTH_SIGNATURE" in schema_vector
    assert "version=daylight-v6-reference-negative-corpus-v1" in negative_corpus
    assert "all_fail_closed=true" in negative_corpus

    for non_claim in model["non_claims"]:
        assert non_claim in doc

    assert "daylight-v06-schema-freeze-test" in scorecard
    assert "daylight-v06-schema-freeze-test:" in makefile
    assert "daylight-v06-schema-freeze.v1.json" in scorecard
    assert "Daylight_v0.6_research_score = 955 / 1000" in scorecard

    if not args.quiet:
        print("Daylight v0.6 schema freeze: PASS")


if __name__ == "__main__":
    main()
