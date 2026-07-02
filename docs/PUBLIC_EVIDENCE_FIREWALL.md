# Daylight Public Evidence Firewall

The Daylight Public Evidence Firewall is a hard CI gate for public artifacts,
witness bundles, release bundles, and uploaded build outputs.

## Laws

```text
PrivateMaterial and PublicArtifact -> Reject
SecretPath and UploadPath -> Reject
PlaintextHashOracle and PublicIndex -> Reject
MissingFirewall and ArtifactUpload -> Reject
BroadBuildRoot and ArtifactUpload -> Reject
```

## Directory Boundary

Private work products and public evidence do not share a publish root.

```text
build/daylight/v15-meridian-private/  # keys, vaults, smoke work, plaintext fixtures
build/daylight/v15-meridian-public/   # scorecard, receipt, manifest, frontier only
```

Only the public directory may be uploaded.

## Private Material

Private material includes:

- private keys, vault keys, passphrases, raw LUKS keys
- plaintext secrets and smoke test plaintexts
- local vault state and private vault stores
- private transcripts
- content-confirmation hashes of sealed plaintext
- non-public fixture material

## Public Artifact Profile

Daylight v15 Meridian public evidence is exactly:

- `scorecard.v15-meridian.json`
- `reproducibility-receipt.v15-meridian.json`
- `frontier-report.v15-meridian.json`
- `frontier-report.v15-meridian.md`
- `ledger.with-scorecard.jsonl`
- `artifact-manifest.json`
- `SHA256SUMS`

Any extra file rejects.

## Commands

```sh
make daylight-public-evidence-firewall-test
make daylight-public-artifact-firewall
make daylight-private-material-regression-test
make daylight-security-ratchet-test
```

The firewall emits JSON with schema
`daylight-public-evidence-firewall-v1` and exits nonzero on any critical
violation.
