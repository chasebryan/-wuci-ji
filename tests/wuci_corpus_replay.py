#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_corpus_replay.py"
BIN = REPO_ROOT / "build" / "wuci-ji"
REQUIRED_SURFACES = {
    "armor",
    "authority-root",
    "envelope",
    "gate-contract",
    "ledger-entry",
    "ledger-head",
    "ledger-proof",
    "wjnext-model",
    "wjstar-model",
}


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def check_report(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "wuci-parser-corpus-replay-v2"
    assert data["deterministic_mutation_mode"] is True
    assert data["offensive_fuzzing"] is False
    assert data["network_required"] is False
    assert data["runtime_sandbox_claim"] is False
    assert data["fail_closed"] is True
    assert data["timeouts"] == 0
    assert data["signals"] == 0
    assert data["accepted_cases"] > 0
    assert data["rejected_cases"] > 0
    assert data["accepted_cases"] + data["rejected_cases"] == data["cases"]
    assert data["seed_cases"] == data["files"]
    assert data["seed_accepted"] > 0
    assert data["seed_rejected"] > 0
    assert data["seed_accepted"] + data["seed_rejected"] == data["seed_cases"]
    assert data["wjstar_model_covered"] is True
    assert data["wjnext_model_covered"] is True
    assert REQUIRED_SURFACES.issubset(data["surfaces"])
    assert set(data["required_surfaces"]) == REQUIRED_SURFACES
    assert set(data["surface_outcomes"]) == REQUIRED_SURFACES
    assert {"seed", "empty", "truncate-half", "append-nul"}.issubset(
        data["mutation_families"]
    )
    assert data["cases"] == len(data["results"])
    for surface, outcome in data["surface_outcomes"].items():
        assert surface in REQUIRED_SURFACES
        assert outcome["cases"] == data["surfaces"][surface]
        assert outcome["accepted"] + outcome["rejected"] == outcome["cases"]
        assert outcome["seed_accepted"] + outcome["seed_rejected"] == outcome["seed_cases"]
        assert outcome["seed_cases"] >= 1
        assert outcome["parsers"]
    assert data["surface_outcomes"]["wjnext-model"]["seed_accepted"] == 1
    assert data["surface_outcomes"]["wjstar-model"]["seed_accepted"] == 1
    assert data["surface_outcomes"]["ledger-entry"]["seed_accepted"] == 1
    assert data["surface_outcomes"]["ledger-head"]["seed_accepted"] == 1
    assert data["surface_outcomes"]["ledger-proof"]["seed_accepted"] == 2
    assert data["surface_outcomes"]["envelope"]["seed_rejected"] == 3
    for result in data["results"]:
        assert result["surface"] in REQUIRED_SURFACES
        assert result["parser"] in {"assembly-cli", "python-internal"}
        assert isinstance(result["accepted"], bool)
        assert result["timeout"] is False
        assert result["signal"] is None
        assert len(result["payload_sha256"]) == 64


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI parser corpus replay evidence.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    if not BIN.is_file():
        raise SystemExit(f"missing binary: {BIN}")
    with tempfile.TemporaryDirectory(prefix="wuci-corpus-replay-test-") as tmp_name:
        report = Path(tmp_name) / "parser-corpus-replay.json"
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "--bin",
                    str(BIN),
                    "--out",
                    str(report),
                    "--quiet",
                ]
            ),
            "run parser corpus replay",
        )
        check_report(report)

    if not args.quiet:
        print("wuci parser corpus replay: PASS")


if __name__ == "__main__":
    main()
