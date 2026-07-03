# Wuci-Ji Enterprise Adoption

This guide describes safe enterprise adoption modes for the Wuci-Ji Daylight
Standard. These modes do not require a company to replace existing security
products. Existing tools can emit or feed evidence.

## Mode A: Claim Firewall

Use case: prevent unsupported README, release note, website, and marketing
claims.

Commands:

```sh
python3 tools/daylight_conformance.py reject-overclaims --path README.md
make daylight-npt-ci
```

Required inputs: claim surfaces and DaylightNPT registry.

Output artifact: overclaim report or DaylightNPT report.

Failure conditions: unsupported certification, production, runtime, PQ,
government, or numeric-score claim.

Allowed claims: bounded evidence and research status.

Forbidden claims: certification, approval, production authority, general runtime
containment, or security replacement claims without evidence.

## Mode B: Release Evidence Gate

Use case: block release until claim, evidence, provenance, and reproducibility
requirements pass.

Commands:

```sh
python3 tools/daylight_conformance.py score --claims claims.json --evidence evidence.json --out scorecard.json
python3 tools/daylight_conformance.py gate --release release.json --scorecard scorecard.json
```

Required inputs: claim objects, evidence objects, and release-gate policy.

Output artifact: scorecard and gate decision.

Failure conditions: missing evidence, missing provenance, manual score,
unsupported claim, open production blocker, or absent runtime evidence for a
runtime claim.

Allowed claims: release is evidence-bound under stated policy.

Forbidden claims: release is secure, certified, unbreakable, or approved unless
the issuing evidence exists.

## Mode C: Supply-Chain Evidence Gate

Use case: bind SBOM, provenance, build transcript, artifact digests, and
signatures.

Commands:

```sh
make sbom-provenance
python3 tools/daylight_conformance.py status --project .
```

Required inputs: SBOM, provenance, artifact digests, build transcript, and
signature records.

Output artifact: conformance report and audit packet inputs.

Failure conditions: digest mismatch, unsigned required artifact, missing
producer, missing source commit, or unpinned environment.

Allowed claims: supply-chain evidence exists for the stated artifact.

Forbidden claims: SLSA certification or complete supply-chain assurance unless
external authority proves it.

## Mode D: Audit Packet Generator

Use case: create reviewer packets for internal auditors, customers, or external
assessors.

Commands:

```sh
python3 tools/daylight_conformance.py status --project . > conformance.json
python3 tools/daylight_product_score.py
```

Required inputs: docs, schemas, examples, status JSON, validation outputs.

Output artifact: conformance report and product readiness JSON.

Failure conditions: missing boundary docs, missing non-claims, missing schemas,
or unsupported public claims.

Allowed claims: internal audit packet exists.

Forbidden claims: independent audit completion unless signed external review
evidence exists.

## Mode E: Control Mapping Export

Use case: export evidence-to-control mapping for governance and security teams.

Commands:

```sh
python3 tools/daylight_conformance.py control-map --claims claims.json --out control-map.json
```

Required inputs: claims with control references.

Output artifact: Daylight control-map objects.

Failure conditions: control has no evidence, gap is untracked, or mapping is
presented as certification.

Allowed claims: evidence maps to listed control family.

Forbidden claims: compliance, certification, or authorization solely from a map.

## Mode F: Monitoring-Downgrade Prototype

Use case: accept monitoring signals that can downgrade claims after release.

Commands:

```sh
python3 tools/daylight_conformance.py monitor-signal --input signal.json --state daylight-state.json
```

Required inputs: monitor-signal objects and existing claim state.

Output artifact: updated claim state.

Failure conditions: signal lacks related claim, timestamp, downgrade rule, or
required action.

Allowed claims: monitoring can downgrade stated authority.

Forbidden claims: continuous authorization, cATO authorization, or runtime
containment unless actual authority and runtime evidence exist.

## Mode G: External Evidence Intake

Use case: accept signed independent rebuilds, third-party review reports,
red-team findings, and falsification results.

Commands:

```sh
python3 tools/daylight_conformance.py validate --input external-attestation.json
python3 tools/daylight_conformance.py status --project .
```

Required inputs: signed, pinned, scoped, non-fixture attestations and evidence.

Output artifact: external evidence record or upgraded conformance report.

Failure conditions: fixture attestation, unsigned material, unpinned key,
ambiguous scope, expired report, or missing non-claim acknowledgement.

Allowed claims: external evidence exists for the stated scope.

Forbidden claims: D9 formal authority unless the actual external authority
issued it.
