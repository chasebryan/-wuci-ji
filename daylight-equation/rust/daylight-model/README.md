# daylight-model

This crate is a std-only Daylight Equation model scaffold.

It currently provides:

- v0.4 action sets by Daylight release level `r`, where level 0 is
  research/proof only, open begins at level 1, release/install begin at level
  2, and root/audit actions require level 3.
- Mode and signer/domain threshold profiles by release level `r`.
- Claim levels by release level `r`.
- Profile-dependent authorization requirement sets for `D2-HYBRID`, `D3-ROOT`,
  and `D2-HYBRID-FROST`.
- Conservative security-strength vector constants.
- Downgrade policy arithmetic over policy minimums and ledger monotonicity.
- Threshold probability arithmetic with explicit independent-signer
  assumptions.
- Daylight v0.6 public/private `Open` predicate names, truth-table helpers,
  and the cap-limited 8250/10000 research boundary with production, runtime
  containment, whole-system post-quantum-safety, external-review, and official
  endorsement claims held at zero.

It deliberately does not implement cryptography, parsing of untrusted Daylight
artifacts, networking, runtime sandboxing, or production authority.

```sh
cargo test --offline
```
