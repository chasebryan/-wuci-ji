# WUCI-Angel

Angel is the coupling gate between Daylight and Penumbra.

Daylight can score local evidence and claim discipline. Penumbra can seal and
open only when a verifying transcript re-derives the AEAD key. Neither one can
prove external facts from inside this repository: independent review, production
authority, witness operation, deployment entropy, the production Meridian
re-deriver, or host containment posture.

Angel fills that gap by checking local external residue. It reads a manifest,
verifies pinned attestation files, and emits a deterministic gap report.

## Boundary

Angel is:

- a deterministic local gate over external attestation artifacts;
- a SHA-256 pinning and issuer-class check for Daylight/Penumbra gap residue;
- fail-closed when required residue is absent, stale, malformed, symlinked,
  hardlinked, fixture-issued, or overclaimed.

Angel is not:

- a new cryptographic primitive;
- production authority, an operated ledger, or an independent reviewer;
- a runtime sandbox or no-network enforcement layer;
- a post-quantum verifier;
- a replacement for Daylight scoring or Penumbra proof-gated opening.

## Gaps

The v1 registry is emitted by:

```sh
python3 tools/wuci_angel.py gaps
```

The default required gaps are:

- `penumbra.crypto-integration.external-review`
- `penumbra.secret-entropy.external-bound`
- `penumbra.meridian-rederiver.external-attestation`
- `daylight.independent-external-review`
- `daylight.production-authority.external-root`
- `daylight.operated-witness-ledger.external-entry`
- `host.containment-posture.external-evidence`

Each gap has an allowed issuer class. An attestation with the wrong issuer class
does not retire the gap.

## Manifest

An Angel manifest has schema `wuci-angel-gap-manifest-v1`:

```json
{
  "schema": "wuci-angel-gap-manifest-v1",
  "subject": {
    "name": "penumbra-daylight-coupling"
  },
  "required_gaps": [
    "penumbra.crypto-integration.external-review"
  ],
  "attestations": [
    {
      "path": "angel-attestations/review.json",
      "sha256": "lowercase_sha256_of_review_json"
    }
  ],
  "non_claims": [
    "Angel records local external residue; it does not verify the real-world truth of that residue."
  ]
}
```

Attestation paths are relative to the manifest directory. Absolute paths,
`..`, symlinks, and hardlinks are rejected.

## Attestation

An attestation file has schema `wuci-angel-attestation-v1`:

```json
{
  "schema": "wuci-angel-attestation-v1",
  "attestation_id": "northstar-review-001",
  "issuer": "Northstar Audit Lab",
  "issuer_class": "independent-reviewer",
  "completed_utc": "2026-07-04T00:00:00Z",
  "fills": [
    "penumbra.crypto-integration.external-review"
  ],
  "subject_sha256": "lowercase_subject_sha256",
  "statement": "Bounded external residue attestation for the listed Angel gaps.",
  "offensive_tooling_included": false,
  "non_claims": [
    "Angel does not replace Daylight scoring or Penumbra proof-gated opening."
  ]
}
```

The gate rejects reserved overclaim categories such as absolute-break-resistance,
quantum-safety, security guarantees, and runtime-sandbox assertions. It also
rejects fixture, demo, sample, test, example, or self-issued issuers.

## Commands

Create templates:

```sh
python3 tools/wuci_angel.py template manifest --out build/wuci-angel/angel-gap-manifest.json
python3 tools/wuci_angel.py template attestation --out build/wuci-angel/angel-attestations/review.json
```

Evaluate a manifest:

```sh
python3 tools/wuci_angel.py gate \
  --manifest build/wuci-angel/angel-gap-manifest.json \
  --out build/wuci-angel/angel-gap-report.json
```

The report schema is `wuci-angel-gap-report-v1`. `coupling_allowed` is true only
when every required gap is retired by at least one valid attestation and no
attestation in the manifest is invalid.
