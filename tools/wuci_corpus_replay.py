#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"


class CorpusReplayError(RuntimeError):
    pass


def run(argv: list[str], *, cwd: Path, timeout: float = 5.0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def mutated_cases(data: bytes) -> list[bytes]:
    cases = [b"", data[: max(0, len(data) // 2)], data + b"\x00"]
    if data:
        flipped = bytearray(data)
        flipped[0] ^= 0x01
        cases.append(bytes(flipped))
        flipped = bytearray(data)
        flipped[-1] ^= 0x80
        cases.append(bytes(flipped))
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
    return "unknown"


def replay_one(bin_path: Path, corpus_file: Path, work: Path) -> list[dict[str, Any]]:
    data = corpus_file.read_bytes()
    surface = classify(corpus_file)
    results: list[dict[str, Any]] = []
    for index, payload in enumerate([data, *mutated_cases(data)]):
        sample = work / f"{surface}-{corpus_file.stem}-{index}.bin"
        sample.write_bytes(payload)
        if surface == "envelope":
            argv = [str(bin_path), "inspect-file", str(sample)]
        elif surface == "armor":
            argv = [str(bin_path), "dearmor-file", str(sample), str(work / f"{sample.name}.out")]
        elif surface == "authority-root":
            argv = [str(bin_path), "authority-root-verify", str(sample)]
        elif surface == "gate-contract":
            argv = [str(bin_path), "gate-contract-verify", str(sample), str(sample)]
        elif surface == "ledger-entry":
            argv = [str(bin_path), "ledger-leaf-file", str(sample)]
        else:
            continue
        proc = run(argv, cwd=REPO_ROOT)
        if proc.returncode < 0:
            raise CorpusReplayError(f"{corpus_file} terminated by signal {-proc.returncode}")
        results.append(
            {
                "surface": surface,
                "sample": corpus_file.relative_to(REPO_ROOT).as_posix(),
                "mutation": index,
                "returncode": proc.returncode,
                "stdout_bytes": len(proc.stdout),
                "stderr_bytes": len(proc.stderr),
            }
        )
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
            for path in files:
                all_results.extend(replay_one(bin_path, path, work))
        report = {
            "schema": "wuci-parser-corpus-replay-v1",
            "corpus": str(corpus),
            "files": len(files),
            "cases": len(all_results),
            "offensive_fuzzing": False,
            "network_required": False,
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
