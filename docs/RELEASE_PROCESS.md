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
- WJ-GOLD model validation result for the intended open/release evidence
  profile.
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
make wjgold-model-test
make high-attestation-proof
make sbom-provenance
make verify-release-bundle
```

`make wjgold-model-test` validates the repo-native Golden Lock acceptance
model for artifact authorization and release evidence. It checks structured
fixture evidence, pressure levels, threshold/PQ-mode rules, custody-domain
diversity, public witness/ledger/provenance/install evidence, and overclaim
rejection. Passing this target is release evidence only; it does not establish
production cryptography, host security, runtime sandbox completeness,
post-quantum system security, independent audit, or production authority.

When the install root key holder is ready to bind the current build, sign the
current manifest noninteractively:

```sh
make install-sign-current INSTALL_SIGNING_KEY=/absolute/path/to/root-signing-key
make install-verify INSTALL_ROOT_KEY=install/wuci-install-root.v1.pub
```

The signing key is never committed. `install-sign-current` regenerates the
manifest for the current binary, creates an OpenSSH detached signature in the
`wuci-install-v1` namespace, and verifies that signature against the install
root public key before writing `$(INSTALL_SIGNATURE)`.

Optional real-PQ verifier evidence is external and pinned. The verifier command
must implement:

```text
<verifier> verify --algorithm ML-DSA --public-key <kat-pub> --message <kat-msg> --signature <kat-sig>
```

Generate candidate evidence with:

```sh
make pq-verifier-real-attest \
  PQ_VERIFIER_BIN=/absolute/path/to/reviewed-pq-verifier \
  PQ_VERIFIER_IMPLEMENTATION='implementation-name' \
  PQ_VERIFIER_VERSION='implementation-version' \
  PQ_KAT_PUBLIC_KEY=/absolute/path/to/kat.pub \
  PQ_KAT_MESSAGE=/absolute/path/to/kat.msg \
  PQ_KAT_SIGNATURE=/absolute/path/to/kat.sig \
  REAL_PQ_VERIFIER_EVIDENCE=/absolute/path/to/wuci-real-pq.json
```

The candidate still fails production release verification until
`docs/wuci_pq_verifier_pins.json` contains a reviewed pin for the verifier
binary digest, implementation metadata, algorithm, and
`wuci-pq-external-verify-v1` protocol.

For the bundled local Rust FIPS 204 ML-DSA verifier lane, run:

```sh
make pq-verifier-fips204-proof
```

That target builds `tools/wuci-pq-fips204-verify`, runs selftest and KAT
verification, emits `build/wuci-real-pq-verifier.json`, and writes
`build/wuci-pq-fips204-pins.json`. Use those files with release verification by
passing:

```sh
REAL_PQ_VERIFIER_EVIDENCE=build/wuci-real-pq-verifier.json
PQ_VERIFIER_PINS=build/wuci-pq-fips204-pins.json
```

This clears only the real-PQ verifier evidence gate. It does not make WUCI-JI
quantum-safe and does not replace independent audit.

Optional non-fixture production authority evidence is also external. Emit and
ceremonially sign it outside fixture paths:

```sh
python3 tools/wuci_production_authority.py emit-root \
  --group-public-key <compressed-secp256k1-frost-group-key> \
  --allow-open \
  --allow-release \
  --out /absolute/path/to/wuci-production-authority.txt

python3 tools/wuci_production_authority.py ceremony \
  --authority /absolute/path/to/wuci-production-authority.txt \
  --operator 'release operator identity' \
  --ceremony-id prod-authority-YYYYMMDD \
  --threshold 4 \
  --signer-count 5 \
  --out /absolute/path/to/wuci-production-authority-ceremony.json

python3 tools/wuci_production_authority.py sign-ceremony \
  --ceremony /absolute/path/to/wuci-production-authority-ceremony.json \
  --signing-key /absolute/path/to/ceremony-root-signing-key \
  --ceremony-root-key /absolute/path/to/ceremony-root.pub \
  --signature /absolute/path/to/wuci-production-authority-ceremony.sig
```

Optional independent external audit evidence is also external and signed. The
report and signing keys must stay outside fixture paths:

```sh
python3 tools/wuci_external_audit.py emit \
  --report /absolute/path/to/external-audit-report.txt \
  --auditor 'external auditor identity' \
  --audit-id external-audit-YYYYMMDD \
  --production-sufficient \
  --out /absolute/path/to/wuci-external-audit.json

python3 tools/wuci_external_audit.py sign-evidence \
  --evidence /absolute/path/to/wuci-external-audit.json \
  --signing-key /absolute/path/to/external-audit-signing-key \
  --audit-root-key /absolute/path/to/external-audit-root.pub \
  --signature /absolute/path/to/wuci-external-audit.sig
```

The verifier requires scope covering `crypto`, `pq-verifier`,
`production-authority`, `release-bundle`, and `runtime-sandbox`, current
`reviewed_commit`, report SHA-256/SHA-384/SHA-512 matches, and a valid
OpenSSH signature in the `wuci-external-audit-v1` namespace. Unsigned
verification is test-only.

Then pass the external evidence into release verification:

```sh
make verify-release-bundle \
  REAL_PQ_VERIFIER_EVIDENCE=/absolute/path/to/wuci-real-pq.json \
  PQ_VERIFIER_PINS=/absolute/path/to/wuci-pq-pins.json \
  PRODUCTION_AUTHORITY_ROOT=/absolute/path/to/wuci-production-authority.txt \
  PRODUCTION_AUTHORITY_CEREMONY=/absolute/path/to/wuci-production-authority-ceremony.json \
  PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY=/absolute/path/to/ceremony-root.pub \
  PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE=/absolute/path/to/wuci-production-authority-ceremony.sig \
  EXTERNAL_AUDIT_EVIDENCE=/absolute/path/to/wuci-external-audit.json \
  EXTERNAL_AUDIT_REPORT=/absolute/path/to/external-audit-report.txt \
  EXTERNAL_AUDIT_ROOT_KEY=/absolute/path/to/external-audit-root.pub \
  EXTERNAL_AUDIT_SIGNATURE=/absolute/path/to/wuci-external-audit.sig
```

`make verify-release-bundle` writes
`build/wuci-release-bundle-verification.json`. The verifier recomputes binary
digests, checks SBOM/provenance, CARROT, PQ detector, optional pinned real-PQ
evidence, crypto self-audit, parser hardening replay, optional signed production
authority evidence, optional signed external audit evidence, witness, ledger,
install signature, and Rust wrapper evidence. A successful verifier run is
release evidence only; it does not create runtime sandbox completeness or
quantum-safe system status.

Do not publish a release that relies on fixture authority while describing it
as production trust.
