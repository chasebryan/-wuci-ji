# Daylight v20 Firewall Profile Review

Contract for the `firewall_profile_reviews` entries of an external evidence
bundle. Enforced by
`daylight/v20-aperture-singularity/src/external_evidence.py`; documented by
`schema/firewall-profile-review.schema.json`.

## Purpose

An external reviewer reads the public-artifact firewall profile - the rules
that decide what may appear in the v20 public review artifact - together with
its negative test matrix, and reports a finding level. The review scope is
exactly the firewall profile; it is not a system audit and is never treated
as one.

## Review fields

```json
{
  "review_id": "...",
  "reviewer_identity": "...",
  "reviewer_independence_class": "external",
  "review_scope": "aperture-public-artifact-firewall-profile",
  "profile_digest": "...",
  "reviewed_rules_digest": "...",
  "negative_cases_digest": "...",
  "finding_level": "none|minor|major|critical|contradiction",
  "fixture": false,
  "claim_usable": true,
  "attestation_ref": "..."
}
```

## Binding to the current profile

The three digests bind your review to the exact profile you reviewed:

- `profile_digest` - the pinned profile identity digest
  (`src/firewall_profile.py:profile_digest`).
- `reviewed_rules_digest` - the digest of the enforced rule constants:
  expected file list, forbidden suffixes, forbidden path parts, forbidden
  name pattern, secret marker digests, and the size limit
  (`src/external_evidence.py:firewall_rules_digest`).
- `negative_cases_digest` - the digest of the required negative-case matrix
  (`src/external_evidence.py:firewall_negative_cases_digest`).

To read the currently expected values, run the intake verifier on any bundle
with `--format json` and inspect
`sections.firewall_profile_reviews.expected_profile_digest`,
`expected_rules_digest`, and `expected_negative_cases_digest`. When the
profile or rules change, these digests change and old reviews stop binding.
That is intentional: a review of last month's rules says nothing about
today's rules.

## Rejection matrix

A review (or the section) is rejected when:

- reviewer identity contains a reserved token, or independence class is not
  `external`
- `fixture` is true, or `claim_usable` is not true
- scope is not exactly `aperture-public-artifact-firewall-profile`
- any of the three digests does not match the current values
- finding level is `critical` or `contradiction` (a blocking finding stops
  the gate rather than being averaged away)
- the review is not bound to an admissible pinned attestation
- no review is present at all

`none`, `minor`, and `major` finding levels are recorded truthfully; only
blocking levels stop the section, and a blocking finding must be resolved in
the repository, never argued away in the bundle.
