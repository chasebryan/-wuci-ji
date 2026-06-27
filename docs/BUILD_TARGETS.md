# WUCI Build Targets

Native build and most targeted tests require Linux x86_64 with GNU `as`/`ld`.
The full native `make test` target also requires BMI2 and AVX because the
current assembly X25519 helper uses those instructions. On Linux hosts without
those CPU features, use `make test-linux` for the cross-built ELF's Python
harness. The qemu lane defaults to `QEMU_CPU=Haswell-v4`, which supplies the
BMI2/AVX instruction surface required by the current X25519 helper under user
mode QEMU. Override `QEMU_CPU` only when the selected model is known to expose
those instructions, and run targeted non-X25519 proof lanes natively.

The long-term test direction is assembly-first: fast assembly-owned regression
lanes for stable crypto, parser, Gate, manifest, and ledger invariants, with
Python kept for fixture generation and host-policy orchestration. See
`docs/ASSEMBLY_TEST_STRATEGY.md`.

## Minimal

```sh
make build-linux
make asm-smoke
make test
make install-test
make install-sign-current INSTALL_SIGNING_KEY=/absolute/path/to/root-signing-key
make parser-adversarial-test
make aead-boundary-test
make secret-path-isolation-test
```

## Native Proof Lanes

```sh
make asm-regression
make authority-root-check
make gate-contract-asm
make self-release-asm-contract-proof
make self-release-anchored-proof
make self-release-rooted-proof
make self-release-publish-bundle
make self-release-witness-bundle
make self-release-witness-archive
make ledger-asm-test
make ledger-proof-test
make self-release-ledger-bundle
make harden0-proof
make harden-proof
make cage-proof
make qcage-proof
make witness-zig
make witness-zig-test
make witness-archive-test
make reproducible-build-metadata
```

## High Attestation

```sh
make high-attestation-profile
make high-attestation-proof
make sbom-provenance
make sbom-provenance-test
make carrot-policy
make kernel-sandbox-proof
make rust-sandbox-build
make rust-sandbox-test
make pq-verifier-detect
make pq-verifier-real-attest
make pq-verifier-real
make pq-verifier-test
make production-authority-verify
make production-readiness-gates
make crypto-self-audit
make crypto-self-audit-test
make parser-corpus-replay
make wjgold-model-test
make golden-lock-policy-matrix
make verify-release-bundle
make host-capacity
```

`high-attestation-profile` checks the machine-readable defensive baseline in
`docs/wuci_high_attestation_profile.json`. The baseline maps current U.S.
government defensive guidance into local WUCI controls without claiming runtime
sandboxing, no-network containment outside the CARROT proof lane, quantum
safety, production authority, or absence of vulnerabilities.

`high-attestation-proof` composes the profile check, pinned qemu X25519 CPU
smoke, assembly smoke/regression audit, HARDEN policy, CAGE/QCAGE policy and
bundle checks, SBOM/provenance evidence, CARROT kernel no-network proof,
compiled Rust sandbox wrapper evidence, real-PQ verifier detection, optional
pinned real-PQ verifier evidence, crypto self-audit evidence, deterministic
local parser corpus replay, release bundle verification, production-readiness
gates, Gate contract assembly checks, and the full qemu Linux CLI test.

`parser-corpus-replay` replays committed parser corpora plus deterministic
mutations through assembly parser/verifier surfaces and internal public-parser
checks. The v2 evidence requires envelope, armor, authority-root, Gate contract,
ledger entry, ledger head, ledger proof, and WJ* model coverage, with zero
timeouts and zero signal terminations. It is local fail-closed replay evidence,
not offensive fuzzing or a coverage-guided CI fuzzer.

`parser-corpus-replay-test` validates the v2 JSON evidence shape.
`parser-hardening-proof` composes replay generation and validation for the
high-attestation lane.

`daylight-v06-fail-closed-model-test` checks the partial Daylight v0.6
fail-closed ordering model in
`daylight-equation/research/daylight-v06-fail-closed-model.v1.json` and
`daylight-equation/research/daylight-v06-fail-closed-model.md`. It verifies
single-predicate `Open = bottom` behavior and the `PublicPreOK = 0` barrier
against private KEM, AEAD decrypt, and plaintext materialization. It is not a
complete confidentiality, authorization, downgrade-resistance, or production
authority proof.

`wjstar-model-test` checks the formal WJ* composition model in
`docs/wuci_wjstar_model.json` and `docs/wuci_wjstar_model.md`, including the
AEAD/FROST/Gate/Merkle/witness open predicate, Golden Lock v1 transcript, the
3-of-5 normal open/release threshold, and the 4-of-5 root/authority/audit
ceremony threshold. It is a model-consistency gate, not a production
cryptography claim.

`wjnext-model-test` checks the WJ-next canonical transcript model in
`docs/wuci_wjnext_model.json` and `docs/wuci_wjnext_model.md`. It pins
`T_v2 = C14N_v2(...)`, `m_v2 = H("wuci/transcript/v2" || T_v2)`, the typed
acceptance predicate, and the PQ modes where `compat` is allowed,
`hybrid-evidence` requires ML-DSA verification plus pins/KATs, and `pq-secure`
stays false until earned.

`wjgold-model-test` checks `docs/wuci_golden_lock_model.json`,
`docs/wuci_golden_lock_model.md`, and
`tools/wuci_golden_lock_model.py`. It validates the WJ-GOLD acceptance model:
allowed actions, pressure-to-threshold/PQ-mode consistency, participant count,
custody-domain diversity, `pq-secure` fail-closed behavior, hybrid-evidence
flags, public witness/ledger/provenance/install evidence, private-material
absence, no-downgrade rules, and claim discipline. It is an evidence-model gate,
not production cryptography, host security, runtime sandboxing, or a
post-quantum system security claim.

`golden-lock-policy-matrix` checks `docs/wuci_golden_lock_policy.json` and the
deterministic transcript fixture in `docs/wuci_golden_lock_transcript_fixture.json`.
It validates pressure-to-threshold/PQ-mode mapping, `DomainQuorum_3/5`,
`NoDowngrade`, `ClaimOK`, the "No plaintext before Gate" rule, and pinned
`C14N_G` / `m_G` fixture evidence. It is a policy/transcript proof lane, not a
production 5-party FROST implementation.

`verify-release-bundle` writes `build/wuci-release-bundle-verification.json`.
It verifies SBOM/provenance, CARROT, PQ detector, optional pinned real-PQ
evidence, crypto self-audit, parser hardening replay, production authority policy,
optional signed non-fixture production authority evidence, optional signed
external audit evidence, witness bundle, ledger history, install manifest
signature, binary hashes, and Rust no-network wrapper evidence. The output
remains an evidence candidate and records blockers instead of claiming
production readiness.

`pq-verifier-real-attest` and `pq-verifier-real` are explicit
external-evidence lanes. They require caller-supplied `PQ_VERIFIER_BIN`, KAT
paths, implementation metadata, `REAL_PQ_VERIFIER_EVIDENCE`, and reviewed pins
before any real-PQ evidence can clear a release blocker.

`pq-verifier-fips204-proof` is the bundled local Rust FIPS 204 ML-DSA verifier
lane. It builds `tools/wuci-pq-fips204-verify`, runs selftest and deterministic
KAT verification, emits `build/wuci-real-pq-verifier.json`, and writes
`build/wuci-pq-fips204-pins.json`. This clears only the real-PQ verifier
evidence gate when those files are passed to release verification.

`production-authority-verify` is also explicit. It requires
`PRODUCTION_AUTHORITY_ROOT`, `PRODUCTION_AUTHORITY_CEREMONY`,
`PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY`, and
`PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE`; fixture roots and unsigned
ceremonies fail closed.

`external-audit-test` exercises the signed external-audit evidence verifier.
Release verification requires all four external-audit inputs together:
`EXTERNAL_AUDIT_EVIDENCE`, `EXTERNAL_AUDIT_REPORT`,
`EXTERNAL_AUDIT_ROOT_KEY`, and `EXTERNAL_AUDIT_SIGNATURE`.

`host-capacity` prints the detected logical CPU count. Independent proof lanes
can be run with `make -jN`; targets that share witness, ledger, CAGE, QCAGE, or
release evidence paths are serialized through their Make dependencies.

`kernel-sandbox-proof` is local kernel evidence: it requires Linux support for
seccomp filters plus unprivileged user and network namespaces and passes only
when `wuci-ji sandbox-seccomp-net-deny-selftest` installs a network-syscall deny
filter and observes AF_INET socket creation denied with `EPERM`. It is not a
general runtime sandbox or VM boundary.

`rust-sandbox-test` builds `tools/wuci_sandbox.rs`, runs the Rust wrapper's own
seccomp no-network selftest, then executes `wuci-ji selftest` under the wrapper.
It requires `rustc`; the Makefile also checks the standard `~/.cargo/bin/rustc`
location when Rust is installed by rustup but not exported in `PATH`.

`sbom-provenance` emits and verifies `build/wuci-sbom.json` and
`build/wuci-provenance.json` without network access. The generated provenance
records Apache-2.0 licensing, toolchain evidence, git state, binary hashes, the
pinned qemu CPU model, the high-attestation profile digest, and the current
non-production-ready status.

## Zig Proof Lanes

```sh
make gate-contract-zig
make zig-release-proof
make zig-release-contract-proof
make zig-release-asm-contract-proof
make zig-release-anchored-proof
make zig-release-rooted-proof
make zig-release-release-contract-proof
make zig-release-publish-bundle
make zig-release-witness-bundle
make zig-release-witness-archive
make zig-release-ledger-bundle
```

On a Linux host that needs user-mode QEMU for the Zig-built ELF, pass
`RELEASE_RUNNER="qemu-x86_64 -cpu Haswell-v4"`.

## CI Mirrors

```sh
make ci-native
make ci-zig
```

`check-asm-immediates` is a legacy static disassembly audit. It remains
available as an opt-in target:

```sh
make check-asm-immediates
```
