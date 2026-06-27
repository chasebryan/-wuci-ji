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
make pq-verifier-detect
make pq-verifier-test
make production-readiness-gates
make crypto-self-audit
make crypto-self-audit-test
```

`high-attestation-profile` checks the machine-readable defensive baseline in
`docs/wuci_high_attestation_profile.json`. The baseline maps current U.S.
government defensive guidance into local WUCI controls without claiming runtime
sandboxing, no-network containment outside the CARROT proof lane, quantum
safety, production authority, or absence of vulnerabilities.

`high-attestation-proof` composes the profile check, pinned qemu X25519 CPU
smoke, assembly smoke/regression audit, HARDEN policy, CAGE/QCAGE policy and
bundle checks, SBOM/provenance evidence, CARROT kernel no-network proof,
real-PQ verifier detection, crypto self-audit evidence, production-readiness
gates, Gate contract assembly checks, and the full qemu Linux CLI test.

`kernel-sandbox-proof` is local kernel evidence: it requires Linux support for
seccomp filters plus unprivileged user and network namespaces and passes only
when `wuci-ji sandbox-seccomp-net-deny-selftest` installs a network-syscall deny
filter and observes AF_INET socket creation denied with `EPERM`. It is not a
general runtime sandbox or VM boundary.

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
