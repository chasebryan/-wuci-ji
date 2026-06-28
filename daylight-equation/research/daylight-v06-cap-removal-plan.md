# Daylight V0.6 Cap Removal Plan

This file records the evidence needed to move Daylight v0.6 beyond the current
cap-limited peer-review evaluation score.

```text
Daylight_v0.6_peer_review_evaluation_score = 8250 / 10000
Daylight_v0.6_research_score = 975 / 1000
ScoreIncreaseAuthorized = 0
ProductionAllowed = 0
RuntimeContainmentClaim = 0
WholeSystemPostQuantumSafetyClaim = 0
ExternalReviewClaim = 0
OfficialEndorsementClaim = 0
```

The machine-readable source is
`daylight-v06-cap-removal-plan.v1.json`. The verifier is
`tools/daylight_cap_removal.py`, and the local proof target is:

```sh
make daylight-v06-cap-removal-test
make daylight-v06-peer-review-score-test
make daylight-v06-authority-verifier-test
make production-readiness-gates
```

## Current Cap Logic

The 10,000-point model remains capped at 8250. The active caps are:

```text
no_independent_external_reviews_tracked                  cap <= 9000
no_integrated_public_authority                           cap <= 8500
no_production_authority_publish_authority_or_trust_gate  cap <= 8250
no_runtime_containment_enforcement                       cap <= 8250
no_whole_system_post_quantum_safety_claim                cap <= 8500
```

The controlling blockers are production publish/trust authority and runtime
containment. They cannot be cleared by wording, desk review, or fixture
evidence.

## Publish And Trust Gate Contract

The next production-authority surface is intentionally staged:

```text
publish-authorized-rooted <authority> <artifact> <contract>
trust-authorized-rooted <authority> <artifact> <contract>
```

`publish-authorized-rooted` and `trust-authorized-rooted` are implemented only
as assembly decision paths that verify rooted contract evidence and then emit
fail-closed unauthorized decisions while `allow-publish` and `allow-trust`
remain false. They do not publish, install trust, or create production
authority. Fixture authority must not satisfy either command. The current
fixture roots must continue to carry:

```text
production: false
allow-trust: false
allow-publish: false
```

Full activation requires a non-fixture production authority root, signed Golden
Lock 4-of-5 ceremony evidence, positive production publish/trust authority
decisions, authority parsing that accepts `allow-publish` and `allow-trust`
only for production roots, and negative tests for fixture roots, wrong actions,
malformed contracts, and policy mismatches.

## Runtime Containment Contract

Runtime containment remains a separate blocker. A future score increase needs a
named OS-enforced containment profile with fail-closed tests. The existing
CARROT/no-network lane can be part of that evidence, but it is not a broad
runtime sandbox claim.

## Integrated Public Authority

Daylight public authority remains incomplete until certificate, revocation,
transparency-log, install, witness, publish, and trust predicate proofs are
digest-bound to local evidence and the Daylight authority verifier reports
integrated public authority.

## Boundary

Non-claims:

```text
this plan does not raise the Daylight score
this plan does not create production authority
this plan does not complete publish or trust production authority
this plan does not authorize trust production authority
this plan does not claim runtime containment
this plan does not claim whole-system post-quantum safety
this plan does not count as independent external review
```
