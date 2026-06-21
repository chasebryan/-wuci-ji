#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CAGE_TOOL = REPO_ROOT / "tools" / "wuci_cage.py"
QCAGE_TOOL = REPO_ROOT / "tools" / "wuci_qcage.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


def run_cmd(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    env["WUCI_JI_RUNNER"] = " ".join(RUNNER)
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
        env=env,
    )


def run_cage(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(CAGE_TOOL), *args])


def run_qcage(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(QCAGE_TOOL), *args])


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_qcage_fails(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode != 0, context
    assert b"wuci qcage:" in proc.stderr, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def load_witness_helpers():
    helper_path = REPO_ROOT / "tests" / "wuci_witness.py"
    spec = importlib.util.spec_from_file_location("wuci_witness_test_helpers", helper_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_cage_attestation(bundle: Path, out: Path) -> None:
    assert_ok(
        run_cage(["attest", "--bin", str(BIN), "--bundle", str(bundle), "--out", str(out)]),
        "write CAGE attestation",
    )
    assert_ok(
        run_cage(
            [
                "verify",
                "--bin",
                str(BIN),
                "--bundle",
                str(bundle),
                "--attestation",
                str(out),
            ]
        ),
        "verify CAGE attestation",
    )


def write_inventory_and_graph(tmp: Path) -> tuple[Path, Path]:
    inventory = tmp / "crypto-inventory.json"
    graph = tmp / "build-graph.json"
    assert_ok(
        run_qcage(["crypto-inventory", "--repo", ".", "--out", str(inventory)]),
        "write crypto inventory",
    )
    assert_ok(
        run_qcage(["build-graph", "--repo", ".", "--out", str(graph)]),
        "write build graph",
    )
    return inventory, graph


def qcage_attest_args(
    *,
    cage: Path,
    bundle: Path,
    inventory: Path,
    graph: Path,
    mode: str,
    out: Path,
) -> list[str]:
    return [
        "attest",
        "--bin",
        str(BIN),
        "--cage-attestation",
        str(cage),
        "--witness-bundle",
        str(bundle),
        "--crypto-inventory",
        str(inventory),
        "--build-graph",
        str(graph),
        "--mode",
        mode,
        "--T-migrate",
        "3",
        "--T-trust",
        "10",
        "--T-CRQC",
        "10",
        "--out",
        str(out),
    ]


def qcage_verify_args(
    *,
    attestation: Path,
    cage: Path,
    bundle: Path,
    inventory: Path,
    graph: Path,
) -> list[str]:
    return [
        "verify",
        "--bin",
        str(BIN),
        "--attestation",
        str(attestation),
        "--cage-attestation",
        str(cage),
        "--witness-bundle",
        str(bundle),
        "--crypto-inventory",
        str(inventory),
        "--build-graph",
        str(graph),
    ]


def mutate_inventory(path: Path, algorithm: str, field: str, value) -> None:
    data = read_json(path)
    for entry in data["entries"]:
        if entry["algorithm"] == algorithm:
            entry[field] = value
            write_json(path, data)
            return
    raise AssertionError(f"missing algorithm {algorithm}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-QCAGE attestation behavior.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    helpers = load_witness_helpers()
    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        bundle = tmp / "witness-bundle"
        helpers.build_public_witness_bundle(bundle, tmp / "work")

        cage = tmp / "wuci-cage-attestation.json"
        build_cage_attestation(bundle, cage)
        inventory, graph = write_inventory_and_graph(tmp)

        qcage = tmp / "wuci-qcage-attestation.json"
        assert_ok(
            run_qcage(
                qcage_attest_args(
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                    mode="compat",
                    out=qcage,
                )
            ),
            "write QCAGE compat attestation",
        )
        assert_ok(
            run_qcage(
                qcage_verify_args(
                    attestation=qcage,
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                )
            ),
            "verify QCAGE compat attestation",
        )

        value = read_json(qcage)
        assert value["quantum_safe"] is False
        assert value["pq_authority_verified"] is False
        assert value["qcage_decision"] == "allow-classic-cage-with-quantum-warning"
        assert "sha256" in value["public_evidence_digest_vectors"]["artifact"]
        assert "sha384" in value["public_evidence_digest_vectors"]["artifact"]
        assert "sha512" in value["public_evidence_digest_vectors"]["artifact"]

        assert_qcage_fails(
            run_qcage(
                qcage_attest_args(
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                    mode="hybrid-required",
                    out=tmp / "hybrid.json",
                )
            ),
            "hybrid-required fails closed",
        )
        assert_qcage_fails(
            run_qcage(
                qcage_attest_args(
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                    mode="pq-required",
                    out=tmp / "pq.json",
                )
            ),
            "pq-required fails closed",
        )

        quantum_safe = tmp / "quantum-safe-overclaim.json"
        modified = read_json(qcage)
        modified["quantum_safe"] = True
        write_json(quantum_safe, modified)
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=quantum_safe,
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                )
            ),
            "quantum_safe true without PQ rejected",
        )

        external = tmp / "external-pq-unpinned.json"
        modified = read_json(qcage)
        modified["pq_authority_profile"] = "external-verified"
        write_json(external, modified)
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=external,
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                )
            ),
            "external PQ verifier without metadata rejected",
        )

        missing_sha384 = tmp / "missing-sha384.json"
        modified = read_json(qcage)
        del modified["artifact_sha384"]
        write_json(missing_sha384, modified)
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=missing_sha384,
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                )
            ),
            "missing sha384 rejected",
        )

        missing_sha512 = tmp / "missing-sha512.json"
        modified = read_json(qcage)
        del modified["artifact_sha512"]
        write_json(missing_sha512, modified)
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=missing_sha512,
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                )
            ),
            "missing sha512 rejected",
        )

        mldsa_inventory = tmp / "mldsa-overclaim.json"
        shutil.copyfile(inventory, mldsa_inventory)
        mutate_inventory(mldsa_inventory, "ML-DSA", "implemented", True)
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=qcage,
                    cage=cage,
                    bundle=bundle,
                    inventory=mldsa_inventory,
                    graph=graph,
                )
            ),
            "ML-DSA fake implementation rejected",
        )

        secp_inventory = tmp / "secp-overclaim.json"
        shutil.copyfile(inventory, secp_inventory)
        mutate_inventory(secp_inventory, "secp256k1", "quantum_status", "quantum-safe")
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=qcage,
                    cage=cage,
                    bundle=bundle,
                    inventory=secp_inventory,
                    graph=graph,
                )
            ),
            "secp256k1 quantum-safe overclaim rejected",
        )

        graph_tamper = tmp / "build-graph-tampered.json"
        shutil.copyfile(graph, graph_tamper)
        graph_value = read_json(graph_tamper)
        graph_value["repo"] = "tampered"
        write_json(graph_tamper, graph_value)
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=qcage,
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph_tamper,
                )
            ),
            "build graph tampering rejected",
        )

        tampered_bundle = tmp / "tampered-witness-bundle"
        shutil.copytree(bundle, tampered_bundle)
        with (tampered_bundle / "manifest.txt").open("ab") as handle:
            handle.write(b"# tamper\n")
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=qcage,
                    cage=cage,
                    bundle=tampered_bundle,
                    inventory=inventory,
                    graph=graph,
                )
            ),
            "witness bundle tampering rejected",
        )

        sha256_only = tmp / "sha256-only.json"
        modified = read_json(qcage)
        modified["public_evidence_digest_vectors"]["artifact"] = {
            "sha256": modified["artifact_sha256"]
        }
        write_json(sha256_only, modified)
        assert_qcage_fails(
            run_qcage(
                qcage_verify_args(
                    attestation=sha256_only,
                    cage=cage,
                    bundle=bundle,
                    inventory=inventory,
                    graph=graph,
                )
            ),
            "sha256-only digest vector rejected",
        )

    if not args.quiet:
        print("wuci qcage attestation: PASS")


if __name__ == "__main__":
    main()
