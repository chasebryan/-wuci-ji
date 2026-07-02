# Wuci-Ji v2 — Aperture Bastion (Daylight v19)

Aperture Bastion is the public-review aperture over the Daylight/Wuci-Ji
evidence stack. It produces deterministic public review capsules, verifies
subject and manifest digests, runs a strict public artifact firewall, and
keeps every claim tied to evidence. It sits above Daylight v18 Binaric
Bastion as a review/measurement/evidence control plane; it does not replace
it and does not change any upstream score.

```text
NoProof(x) -> NoClaim(x) -> NoRelease(x)
NoEvidence(x) -> NoScore(x) -> NoRelease(x)
ManualScore(x) -> Reject(x)
Public evidence must exclude private material.
```

## Commands

```sh
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli doctor
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli capsule --subject <path> --out <capsule.json>
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli verify-capsule <capsule.json>
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli public-artifact --capsule <capsule.json> --out-dir build/daylight/v19-aperture-bastion-public
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli firewall --root build/daylight/v19-aperture-bastion-public
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli explain <capsule.json>
```

Optional evidence bindings on `capsule`: `--binaric-vector` (repeatable, in
chain order), `--transition-ledger`, `--meridian-scorecard`,
`--event-horizon-scorecard`, `--policy`, plus `--public-file` (repeatable)
and `--allowed-extra`.

## Make targets

```sh
make daylight-v19-aperture-bastion-doctor
make daylight-v19-aperture-bastion-capsule-demo
make daylight-v19-aperture-bastion-verify
make daylight-v19-aperture-bastion-public-artifact
make daylight-v19-aperture-bastion-firewall
make daylight-v19-aperture-bastion-test
make daylight-v19-aperture-bastion-ci
# short aliases
make aperture-bastion-doctor
make aperture-bastion-test
make aperture-bastion-ci
```

## What the capsule proves

- Subject bytes are bound to SHA-256 and SHA3-512 digests and a size.
- Upstream Daylight evidence (v18 binaric vector chains and transition
  ledgers, v15 Meridian scorecards, v17 Event Horizon scorecards, policy
  files) is pinned by digest and re-checked with fail-closed consistency
  gates: broken vector chains, manual score edits, contribution-sum
  mismatches, self-signed "external" attestations behind perfect scores,
  fixture scorecards marked claim-usable, and reserved perfect AM+ values
  all reject.
- The public artifact contains exactly the capsule, the declared manifest
  files, and SHA256SUMS; extras fail unless explicitly allowed by the
  capsule's manifest policy, and everything is scanned against the pinned
  private-material profile before and after publication.
- The capsule digest is canonical and deterministic; editing any score,
  claim, digest, manifest entry, or boundary statement fails verification,
  and forbidden authority claims fail even if the digest is recomputed.

## Boundaries

- No floats. No network. No symlinks, hardlinks, or hidden files in public
  artifacts. No absolute or traversing manifest paths.
- Not production cryptography, not runtime containment, not host
  cleanliness, not FIPS validated, not government validated, not externally
  certified, not whole-system post-quantum safe, not an independent audit,
  and not a perfect Daylight score claim from repository-owned evidence.

See [docs/WUCI_JI_V2_APERTURE_BASTION.md](../../docs/WUCI_JI_V2_APERTURE_BASTION.md),
[docs/APERTURE_BASTION_SECURITY_BOUNDARY.md](../../docs/APERTURE_BASTION_SECURITY_BOUNDARY.md),
and [specs/daylight-v19-aperture-review-capsule.md](specs/daylight-v19-aperture-review-capsule.md).
