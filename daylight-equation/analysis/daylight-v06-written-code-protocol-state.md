# Daylight V0.6 Written Code Protocol State

This note records the Rust written-code form of the current cap-limited
Daylight v0.6 research posture:

```text
Daylight_v0.6_peer_review_evaluation_score = 8250 / 10000
ProductionAllowed = 0
RuntimeContainmentClaim = 0
WholeSystemPostQuantumSafetyClaim = 0
ExternalReviewClaim = 0
OfficialEndorsementClaim = 0
```

It does not replace `daylight-equation/SCORECARD.md`, the 10,000-point
peer-review scoring model, the symbolic model, or the Z3 proof. It is a code
integration note for reviewers.

## Code Boundary

The implementation now has two explicit Rust surfaces:

- `daylight-equation/rust/daylight-model/src/lib.rs` defines the Daylight v0.6
  public/private `Open` predicates, checks their fail-closed truth table, and
  records the 8250/10000 research boundary with every production, runtime
  containment, whole-system post-quantum-safety, external-review, and official
  endorsement claim held at zero.
- `daylight-equation/rust/daylight-crypto/src/v6.rs` exposes
  `daylight_authorized_envelope_v6`, which constructs a
  `DaylightAuthorizedEnvelopeV6` only after public predicates and the 8250
  boundary pass. The provider-backed private path is
  `daylight_open_authorized_v6_with_kems`, which consumes that typed state.

This is not a wrapper around a successful production `Open`. It is the current
research protocol lifecycle made explicit in code:

```text
DaylightEnvelopeV6
  -> daylight_authorized_envelope_v6(...)
  -> DaylightAuthorizedEnvelopeV6
  -> daylight_open_authorized_v6_with_kems(...)
  -> DaylightOpenReportV6
```

The public vector precheck still fails closed at `REJECT_AUTH_SIGNATURE` for
the schema vector because integrated production certificate, revocation, log,
install, witness, publish, and trust authority are not implemented.

## Review Command

```sh
make daylight-v06-protocol-state-test
```

This target runs the std-only model predicate tests and the Rust crypto
authorized-state test. It is local deterministic research evidence only.

## Non-Claims

This written-code state is not production authority, not runtime containment,
not whole-system post-quantum-safety evidence, not external peer review, and
not official endorsement. It does not authorize testing third-party systems,
scanning networks, reproducing vulnerabilities against live targets, generating
exploit payloads, building jailbreak harnesses, or adding malware logic.
