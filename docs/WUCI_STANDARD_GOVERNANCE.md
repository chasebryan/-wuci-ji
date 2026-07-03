# Wuci-Ji Daylight Standard Governance

A standard cannot become default if every change feels arbitrary. The Daylight
equation must be stable, versioned, and reviewable.

## Versioning

- Specification versions use `vN` directories under `specs/daylight-equation/`.
- Schema versions include the schema version in both filename and `schema`
  field.
- Breaking schema changes require a new version.
- Deprecations must identify replacement fields and removal timing.

## Registries

The standard maintains registries for:

- Evidence types.
- Forbidden claims.
- Conformance profiles.
- Score models.
- Control maps.
- Extension namespaces.

## Extension Namespace Rules

- Extension fields must use a namespaced key.
- Extensions must not override required v1 semantics.
- Extensions must not create certification, production, runtime, PQ, or
  government-authority claims.
- Extensions must be ignorable by a v1 reader unless declared required by a
  profile.

## Dispute Process

Disputes should identify:

- Claim ID.
- Evidence object.
- Reproduction command.
- Boundary disagreement.
- Proposed change.
- Falsification path.

Manual score edits are not an acceptable dispute resolution.

## Vulnerability Disclosure

Security issues use `SECURITY.md` and
`docs/WUCI_VULNERABILITY_RESPONSE.md`. Vulnerability evidence can downgrade
claims, block releases, or expire old authority.

## Changelog and Compatibility

Every standard change must state:

- Affected schemas.
- Affected examples.
- Affected conformance levels.
- Compatibility impact.
- Migration guidance.

## Governance Non-Claim

Governance makes the standard reviewable. It does not create production
authority, certification, government approval, or audit completion.
