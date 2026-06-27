#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
REQUIRED_SURFACES = (
    "armor",
    "authority-root",
    "envelope",
    "gate-contract",
    "ledger-entry",
    "ledger-head",
    "ledger-proof",
    "wjnext-model",
    "wjstar-model",
)
MUTATION_FAMILIES = (
    "seed",
    "empty",
    "truncate-half",
    "drop-last-byte",
    "append-nul",
    "append-junk-line",
    "flip-first-bit",
    "flip-last-high-bit",
    "crlf",
    "duplicate",
    "long-prefix",
)

sys.path.insert(0, str(REPO_ROOT / "tools"))
import wuci_ledger  # noqa: E402


class CorpusReplayError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mutation_cases(data: bytes) -> list[tuple[str, bytes]]:
    cases = [
        ("seed", data),
        ("empty", b""),
        ("truncate-half", data[: max(0, len(data) // 2)]),
        ("append-nul", data + b"\x00"),
        ("append-junk-line", data + b"junk: value\n"),
        ("crlf", data.replace(b"\n", b"\r\n")),
        ("duplicate", data + data),
        ("long-prefix", b"A" * 128 + data),
    ]
    if data:
        flipped = bytearray(data)
        flipped[0] ^= 0x01
        cases.append(("flip-first-bit", bytes(flipped)))
        flipped = bytearray(data)
        flipped[-1] ^= 0x80
        cases.append(("flip-last-high-bit", bytes(flipped)))
        cases.append(("drop-last-byte", data[:-1]))
    else:
        cases.extend(
            [
                ("flip-first-bit", b"\x01"),
                ("flip-last-high-bit", b"\x80"),
                ("drop-last-byte", b""),
            ]
        )
    return cases


def classify(path: Path) -> str:
    rel = path.as_posix()
    if "/envelope/" in rel:
        return "envelope"
    if "/armor/" in rel:
        return "armor"
    if "/authority-root/" in rel:
        return "authority-root"
    if "/gate-contract/" in rel:
        return "gate-contract"
    if "/ledger-entry/" in rel:
        return "ledger-entry"
    if "/ledger-head/" in rel:
        return "ledger-head"
    if "/ledger-proof/" in rel:
        return "ledger-proof"
    if "/wjnext-model/" in rel:
        return "wjnext-model"
    if "/wjstar-model/" in rel:
        return "wjstar-model"
    return "unknown"


def run_process(argv: list[str], *, cwd: Path, timeout: float = 5.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "accepted": False,
            "returncode": None,
            "signal": None,
            "stderr_bytes": 0,
            "stdout_bytes": 0,
            "timeout": True,
        }
    signal = -proc.returncode if proc.returncode < 0 else None
    return {
        "accepted": proc.returncode == 0,
        "returncode": proc.returncode,
        "signal": signal,
        "stderr_bytes": len(proc.stderr),
        "stdout_bytes": len(proc.stdout),
        "timeout": False,
    }


def write_gate_artifact(bin_path: Path, work: Path) -> Path:
    plain = work / "gate-artifact.txt"
    sealed = work / "gate-artifact.wj"
    plain.write_bytes(b"wuci parser corpus replay gate artifact\n")
    proc = run_process(
        [
            str(bin_path),
            "seal-file-v2",
            "11" * 32,
            "2233445566778899aabbccddeeff0011",
            str(plain),
            str(sealed),
        ],
        cwd=REPO_ROOT,
    )
    if proc["returncode"] != 0:
        raise CorpusReplayError("could not create Gate parser replay artifact")
    return sealed


def internal_parse(surface: str, payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
        if surface == "ledger-entry":
            wuci_ledger.parse_entry(text)
        elif surface == "ledger-head":
            wuci_ledger.parse_head(text)
        elif surface == "ledger-proof":
            if text.startswith("schema: wuci-ledger-inclusion-proof-v1\n"):
                wuci_ledger.parse_proof(
                    text,
                    wuci_ledger.INCLUSION_FIELDS,
                    wuci_ledger.INCLUSION_SCHEMA,
                    "ledger inclusion proof",
                )
            elif text.startswith("schema: wuci-ledger-consistency-proof-v1\n"):
                wuci_ledger.parse_proof(
                    text,
                    wuci_ledger.CONSISTENCY_FIELDS,
                    wuci_ledger.CONSISTENCY_SCHEMA,
                    "ledger consistency proof",
                )
            else:
                raise CorpusReplayError("unsupported ledger proof schema")
        elif surface == "wjstar-model":
            value = json.loads(text)
            if not isinstance(value, dict):
                raise CorpusReplayError("WJ* model corpus must be a JSON object")
            if value.get("schema") != "wuci-wjstar-model-v1":
                raise CorpusReplayError("WJ* model corpus schema mismatch")
            if (
                value.get("composition")
                != "WJ* = GoldenLock_v1(AEAD + FROST_(3/5,4/5) + H-Merkle + G + R)"
            ):
                raise CorpusReplayError("WJ* model composition mismatch")
            golden_lock = value.get("golden_lock")
            if (
                not isinstance(golden_lock, dict)
                or golden_lock.get("schema") != "wuci-golden-lock-v1"
            ):
                raise CorpusReplayError("WJ* Golden Lock schema mismatch")
            transcript = golden_lock.get("transcript")
            if (
                not isinstance(transcript, dict)
                or transcript.get("domain") != "wuci/golden-lock/v1"
                or transcript.get("canonicalization") != "C14N_G"
            ):
                raise CorpusReplayError("WJ* Golden Lock transcript mismatch")
            if golden_lock.get("golden_rule") != "No plaintext before Gate.":
                raise CorpusReplayError("WJ* Golden Lock rule mismatch")
            if not isinstance(value.get("accept_predicate"), list):
                raise CorpusReplayError("WJ* model accept_predicate must be a list")
            if not isinstance(value.get("open_predicate"), list):
                raise CorpusReplayError("WJ* model open_predicate must be a list")
        elif surface == "wjnext-model":
            value = json.loads(text)
            if not isinstance(value, dict):
                raise CorpusReplayError("WJ-next model corpus must be a JSON object")
            if value.get("schema") != "wuci-wjnext-model-v1":
                raise CorpusReplayError("WJ-next model corpus schema mismatch")
            if value.get("composition") != "WJ_next = Accept_v2_mu(a, Omega)":
                raise CorpusReplayError("WJ-next model composition mismatch")
            transcript = value.get("transcript")
            if not isinstance(transcript, dict) or transcript.get("domain") != "wuci/transcript/v2":
                raise CorpusReplayError("WJ-next model transcript domain mismatch")
            pq_modes = value.get("pq_modes")
            if not isinstance(pq_modes, dict):
                raise CorpusReplayError("WJ-next model pq_modes must be an object")
            pq_secure = pq_modes.get("pq-secure")
            if not isinstance(pq_secure, dict) or pq_secure.get("accepted") is not False:
                raise CorpusReplayError("WJ-next pq-secure mode must stay false until earned")
        else:
            raise CorpusReplayError(f"unsupported internal parser surface: {surface}")
        return {
            "accepted": True,
            "returncode": 0,
            "signal": None,
            "stderr_bytes": 0,
            "stdout_bytes": 0,
            "timeout": False,
        }
    except (UnicodeDecodeError, json.JSONDecodeError, wuci_ledger.LedgerError, CorpusReplayError):
        return {
            "accepted": False,
            "returncode": 1,
            "signal": None,
            "stderr_bytes": 0,
            "stdout_bytes": 0,
            "timeout": False,
        }


def replay_payload(
    *,
    bin_path: Path,
    gate_artifact: Path,
    surface: str,
    sample: Path,
    payload: bytes,
    mutation: str,
    work: Path,
) -> dict[str, Any] | None:
    sample_path = work / f"{surface}-{sample.stem}-{mutation}.bin"
    sample_path.write_bytes(payload)
    parser_kind = "assembly-cli"
    if surface == "envelope":
        outcome = run_process([str(bin_path), "inspect-file", str(sample_path)], cwd=REPO_ROOT)
    elif surface == "armor":
        outcome = run_process(
            [str(bin_path), "dearmor-file", str(sample_path), str(work / f"{sample_path.name}.out")],
            cwd=REPO_ROOT,
        )
    elif surface == "authority-root":
        outcome = run_process([str(bin_path), "authority-root-verify", str(sample_path)], cwd=REPO_ROOT)
    elif surface == "gate-contract":
        outcome = run_process(
            [str(bin_path), "gate-contract-verify", str(gate_artifact), str(sample_path)],
            cwd=REPO_ROOT,
        )
    elif surface in {"ledger-entry", "ledger-head", "ledger-proof", "wjnext-model", "wjstar-model"}:
        parser_kind = "python-internal"
        outcome = internal_parse(surface, payload)
    else:
        return None
    return {
        "surface": surface,
        "sample": sample.relative_to(REPO_ROOT).as_posix(),
        "mutation": mutation,
        "parser": parser_kind,
        "payload_bytes": len(payload),
        "payload_sha256": sha256_bytes(payload),
        **outcome,
    }


def replay_one(bin_path: Path, gate_artifact: Path, corpus_file: Path, work: Path) -> list[dict[str, Any]]:
    data = corpus_file.read_bytes()
    surface = classify(corpus_file)
    results: list[dict[str, Any]] = []
    for mutation, payload in mutation_cases(data):
        result = replay_payload(
            bin_path=bin_path,
            gate_artifact=gate_artifact,
            surface=surface,
            sample=corpus_file,
            payload=payload,
            mutation=mutation,
            work=work,
        )
        if result is not None:
            results.append(result)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay deterministic local parser corpus.")
    parser.add_argument("--bin", default=str(DEFAULT_BIN))
    parser.add_argument("--corpus", default="tests/corpus")
    parser.add_argument("--out", required=True)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        bin_path = Path(args.bin)
        if not bin_path.is_file():
            raise CorpusReplayError(f"missing binary: {bin_path}")
        corpus = Path(args.corpus).resolve()
        files = sorted(path for path in corpus.rglob("*") if path.is_file())
        all_results: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="wuci-corpus-replay-") as tmp_name:
            work = Path(tmp_name)
            gate_artifact = write_gate_artifact(bin_path, work)
            for path in files:
                all_results.extend(replay_one(bin_path, gate_artifact, path, work))
        surfaces: dict[str, int] = {}
        surface_outcomes: dict[str, dict[str, Any]] = {}
        for result in all_results:
            surface = result["surface"]
            surfaces[surface] = surfaces.get(surface, 0) + 1
            outcome = surface_outcomes.setdefault(
                surface,
                {
                    "cases": 0,
                    "accepted": 0,
                    "rejected": 0,
                    "seed_cases": 0,
                    "seed_accepted": 0,
                    "seed_rejected": 0,
                    "parsers": [],
                },
            )
            outcome["cases"] += 1
            if result["accepted"]:
                outcome["accepted"] += 1
            else:
                outcome["rejected"] += 1
            if result["mutation"] == "seed":
                outcome["seed_cases"] += 1
                if result["accepted"]:
                    outcome["seed_accepted"] += 1
                else:
                    outcome["seed_rejected"] += 1
            if result["parser"] not in outcome["parsers"]:
                outcome["parsers"].append(result["parser"])
        for outcome in surface_outcomes.values():
            outcome["parsers"].sort()
        signals = sum(1 for result in all_results if result["signal"] is not None)
        timeouts = sum(1 for result in all_results if result["timeout"] is True)
        accepted_cases = sum(1 for result in all_results if result["accepted"] is True)
        rejected_cases = len(all_results) - accepted_cases
        seed_cases = sum(1 for result in all_results if result["mutation"] == "seed")
        seed_accepted = sum(
            1
            for result in all_results
            if result["mutation"] == "seed" and result["accepted"] is True
        )
        seed_rejected = seed_cases - seed_accepted
        missing_surfaces = sorted(set(REQUIRED_SURFACES).difference(surfaces))
        if missing_surfaces:
            raise CorpusReplayError(f"missing required parser corpus surfaces: {', '.join(missing_surfaces)}")
        report = {
            "schema": "wuci-parser-corpus-replay-v2",
            "accepted_cases": accepted_cases,
            "corpus": str(corpus),
            "deterministic_mutation_mode": True,
            "fail_closed": signals == 0 and timeouts == 0,
            "files": len(files),
            "cases": len(all_results),
            "mutation_families": list(MUTATION_FAMILIES),
            "required_surfaces": list(REQUIRED_SURFACES),
            "offensive_fuzzing": False,
            "network_required": False,
            "rejected_cases": rejected_cases,
            "runtime_sandbox_claim": False,
            "seed_accepted": seed_accepted,
            "seed_cases": seed_cases,
            "seed_rejected": seed_rejected,
            "signals": signals,
            "surface_outcomes": surface_outcomes,
            "surfaces": surfaces,
            "timeouts": timeouts,
            "wjstar_model_covered": surfaces.get("wjstar-model", 0) > 0,
            "wjnext_model_covered": surfaces.get("wjnext-model", 0) > 0,
            "results": all_results,
        }
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_name(out.name + ".tmp")
        tmp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, out)
        if not args.quiet:
            print(f"wrote parser corpus replay: {out}")
        return 0
    except (OSError, subprocess.TimeoutExpired, CorpusReplayError) as exc:
        print(f"wuci corpus replay: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
