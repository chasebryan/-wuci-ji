# Daylight v17.1 Event Horizon Kernel

Daylight v17 Singularity is the public declaration. Daylight v17.1 Event
Horizon is the deterministic verifier that decides whether that declaration is
allowed. Daylight v17.2 Cross-Verifier Horizon adds refusal diagnostics and the
canonical verifier-output vector lane. Daylight v17.3 Triangulation Gate adds
the first independent Rust verifier vector while keeping declaration fail-closed
until a real third verifier exists.

Event Horizon is a research scoring kernel. It does not modify Daylight v15
Meridian scores, does not inflate the conservative Daylight M score, and does
not claim production certification, external certification, FIPS validation,
runtime containment, or whole-system post-quantum safety.

## Constants

```text
B = 1,000,000,000
UNIT = AM+
PERFECT_RESERVED_AM_PLUS = 1,000,000,000
DECLARATION_TARGET_AM_PLUS = 999,999,999
EPSILON = 1 / 10^12
KAPPA = 5
LN_1E9 = 20.723265836946411156161923092159277868409913397658
```

`1,000,000,000 AM+` is mathematically reserved. A generated score must never
exceed `999,999,999 AM+`.

All score-critical computation uses `decimal.Decimal` with precision at least
100 and rational strings for field weights and thresholds. JSON floats are
rejected during parsing and Python float instances are rejected before scoring
or hashing.

## Field Registry

`rules/fields.v17.json` contains exactly ten fields:

```text
F1  ClaimClosure
F2  SelfProgress
F3  HermeticArtifact
F4  ReplayDepth
F5  MultiImplementation
F6  AdversarialFuzzing
F7  FormalProof
F8  CryptoConstruction
F9  PublicFalsification
F10 BoundaryDiscipline
```

The alpha weights are rational strings and sum to `27/2`. Field thresholds are
also rational strings. A field cannot be declared closed by a direct state value;
its closure is derived only from proof atoms.

## Proof Atom Model

Each proof atom contains:

```text
id
field_id
credit
verifier_key
description
replay_required
collapse_if_failed
stale_after_days
fixture_allowed
```

Optional evidence paths are allowed for verifier keys that need local files.
Evidence paths must remain under `daylight/v17-singularity/`, must be relative,
must not contain `..`, and must resolve to regular non-symlink files when a file
is required.

The kernel never executes shell commands from JSON. `verifier_key` is a fixed
allowlist of Python functions. Unknown verifier keys reject.

Field closure is:

```text
possible_credit_i = sum(atom.credit for atom.field_id = i)
verified_credit_i = sum(atom.credit for atom.field_id = i and verifier passes)
C_i = verified_credit_i / possible_credit_i
```

If `verified_credit_i == possible_credit_i`, perfect reserve applies:

```text
C_i = 1 - EPSILON
perfect_reserve_applied = true
```

## Weakest-Field Governor

```text
R_i = max(EPSILON, 1 - C_i)
Omega_i = -ln(R_i)
Omega_sum = sum_i alpha_i * Omega_i
Omega_weak = KAPPA * min_i(Omega_i)

Omega_eff =
  max(0, min(Omega_sum, Omega_weak)
         - Debt
         - OverclaimDebt
         - StalenessDebt)

S_AM+ =
  min(999999999, floor(1000000000 * (1 - exp(-Omega_eff))))
```

A weak field cannot be averaged away by stronger fields.

## Collapse Laws

The score collapses to zero if any hard condition is present:

```text
contradiction_debt > 0
critical_break_debt > 0
score_inflation_M != 0
manual_score_detected = true
forged_scorecard_accepted = true
opens_without_policy_evidence = true
severe_boundary_overclaim = true
proof atom with collapse_if_failed fails
```

When collapse is true:

```text
score_AM_plus = 0
declared = false
status = singularity_collapsed
```

## Declaration Gate

Declaration is allowed only if:

```text
scorecard verifies
declared = true
claim_usable = true
fixture = false
fracture_suite_passed = true
cross_verifier_agreement_passed = true
collapse = false
```

The scorecard declaration predicate requires:

```text
Omega_eff >= ln(10^9)
every field threshold passes
contradiction_debt = 0
critical_break_debt = 0
score_inflation_M = 0
collapse = false
fracture_suite_passed = true
cross_verifier_agreement_passed = true
claim_usable = true
fixture = false
```

The committed current scorecard verifies but declaration-gate refuses by
default because real three-verifier agreement evidence is absent.

The declaration gate reports every blocker, not only the first blocker. Required
blockers include:

```text
omega_eff below declaration threshold
score_AM_plus below declaration target
field threshold failure
collapse=true
contradiction_debt > 0
critical_break_debt > 0
score_inflation_M != 0
fracture_suite_passed=false
cross_verifier_agreement_passed=false
claim_usable=false
fixture=true
```

The current scorecard is refused for at least:

```text
omega_eff below declaration threshold
score_AM_plus below declaration target
cross_verifier_agreement_passed=false
```

## Curvature Gap Reporting

Scorecards report the remaining discrete and curvature gap:

```text
declaration_residue_AM_plus = 1,000,000,000 - score_AM_plus
declaration_score_gap_AM_plus = 999,999,999 - score_AM_plus
omega_gap_to_declaration = ln(10^9) - omega_eff
residue_collapse_factor_to_declaration = exp(omega_gap_to_declaration)
```

For the committed current scorecard, this reports `313 AM+` remaining discrete
residue, a `312 AM+` target-score gap, positive curvature gap, and an additional
collapse factor of about `312.5x`.

## Cross-Verifier Output Vector

The canonical verifier vector is:

```text
{
  implementation_family,
  implementation_digest,
  fields_digest,
  proof_atoms_digest,
  state_digest,
  omega_sum_decimal,
  omega_weak_decimal,
  omega_eff_decimal,
  score_AM_plus,
  residue_AM_plus,
  declaration_residue_AM_plus,
  declaration_score_gap_AM_plus,
  collapse,
  declared,
  status,
  scorecard_predigest
}
```

Agreement passes only if at least three vectors exist, implementation families
are distinct, and every score-critical field matches across all vectors and the
current Python reference vector. `verifier_outputs` are excluded from the state
digest to avoid self-referential vector proofs.

v17.3 accepts `python-reference` plus `rust-independent` only as
`partial_2_of_3`. `cross_verifier_agreement_passed` remains false, and the
declaration blocker vector includes `verifier quorum incomplete: 2/3`. The
third family, `zig-or-minimal-c-independent`, is intentionally absent until it
exists as a real verifier.

## Daylight Horizon Alpha

Daylight Horizon Alpha is the product layer over Event Horizon:

```text
No verified evidence -> no unlock
No proof atoms -> no release
No policy satisfaction -> no plaintext
No valid horizon state -> no authority
```

Horizon Vault `.dhv` objects bind a public header, policy digest, Event Horizon
scorecard digest, authorization tag, and AEAD ciphertext. Open recomputes the
current scorecard, checks the sealed policy, reproduces the authorization tag,
then verifies the AEAD tag. Inspect is keyless and never releases plaintext.

Horizon Release `.dhr` capsules bind an artifact digest, policy, scorecard
digest, blocker vector, release status, and non-claim boundary. Research release
can pass under research policy. Declaration and production release are refused
until the scorecard declaration and production authority evidence actually pass.

Horizon Alpha reuses the repository's Daylight v15 pure-stdlib RFC 8439
reference AEAD. This is not production cryptography, not production release
authority, not external certification, not FIPS validation, not runtime
containment, and not whole-system post-quantum safety.

## Fracture Suite

The fracture suite mutates a valid scorecard in memory and requires every fake
path to reject:

```text
M1  edited score_AM_plus
M2  edited omega_eff_decimal
M3  edited field verified_credit
M4  edited debt_uomega
M5  edited fields_digest
M6  edited proof_atoms_digest
M7  edited state_digest
M8  removed proof atom
M9  forged fixture flag
M10 forged claim_usable flag
M11 score_inflation_M changed to nonzero
M12 collapse flag edited
M13 status edited
M14 declared edited
M15 scorecard_digest edited
```

`fracture_suite_passed=true` means all required mutations rejected.

## Fixture Versus Claim-Usable

`examples/state.declaration-fixture.json` is a mathematical fixture only:

```text
fixture = true
claim_usable = false
boundary = "fixture demonstration only; not external certification"
```

The fixture may demonstrate `999,999,999 AM+`, but it must not pass
declaration-gate.

## Digests

Canonical JSON digests are domain-separated:

```text
DAYLIGHT-v17-EVENT-HORIZON-FIELDS:
DAYLIGHT-v17-EVENT-HORIZON-PROOF-ATOMS:
DAYLIGHT-v17-EVENT-HORIZON-STATE:
DAYLIGHT-v17-EVENT-HORIZON-SCORECARD:
DAYLIGHT-v17-EVENT-HORIZON-FRACTURE:
```

Manual edits to score, omega, debt, field credits, registry digests, state
digest, or scorecard digest must reject.
