# WUCI Release Process

There are no production releases today. The current release posture is
production-readiness evidence candidate, not production-ready. See
`docs/PRODUCTION_READINESS.md`.

Each real release must contain:

- Source commit.
- Clean-tree release provenance.
- SBOM and provenance artifacts from `make sbom-provenance`.
- Built binary and SHA-256/SHA-384/SHA-512 digests.
- Build host and toolchain versions: `uname`, GNU `as`, GNU `ld`, Zig, Python,
  and `sha256sum`.
- WUCI witness bundle.
- WUCI ledger entry, head, inclusion proof, and consistency proof.
- Install manifest and detached OpenSSH signature.
- Install root key fingerprint.
- README excerpt warning that Wuci-ji is research-only, not production crypto,
  not a runtime sandbox, not post-quantum secure, and not independently
  audited.

Recommended local release preflight:

```sh
make clean
make test
make install-test
make self-release-witness-bundle
make self-release-ledger-bundle
make cage-proof
make qcage-proof
make harden-proof
make high-attestation-proof
make sbom-provenance
make verify-release-bundle
```

`make verify-release-bundle` writes
`build/wuci-release-bundle-verification.json`. The verifier recomputes binary
digests, checks SBOM/provenance, CARROT, PQ detector, crypto self-audit, parser
replay, witness, ledger, install signature, and Rust wrapper evidence. A
successful verifier run is release evidence only; it records production
authority policy and blockers but does not create production authority,
external crypto audit assurance, runtime sandbox completeness, or quantum-safe
status.

Do not publish a release that relies on fixture authority while describing it
as production trust.
