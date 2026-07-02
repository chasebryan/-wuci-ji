# Security Policy

Wuci-Ji is a defensive research artifact. Its exact claim boundary is
maintained in [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md): it is not
production cryptography, not a runtime sandbox, not post-quantum secure, not
production authority, and not independently audited. Reports that show a proof
lane claiming more than that boundary are security reports here too.

## Reporting a Vulnerability

Please use GitHub private vulnerability reporting for this repository
(Security tab -> "Report a vulnerability"). Do not open a public issue for an
unpatched vulnerability.

A useful report includes:

- the affected surface (assembly machine, Gate/Witness/Ledger, Daylight
  package, Meridian envelope/vault, Wuci-OS lane, installer, or website),
- the commit hash you tested,
- reproduction steps or a failing proof-lane invocation,
- what the report breaks: secrecy, integrity, authorization, evidence honesty,
  or an overclaim of the stated boundary.

## Scope Notes

- Public Evidence Invariant: no public Daylight artifact, witness bundle,
  release bundle, CI artifact, or uploaded build output may contain private
  material. Public artifact paths must be generated from public-only staging
  directories. Broad build roots must not be uploaded. A CI lane that uploads
  artifacts without first running the Public Evidence Firewall is invalid.
- Fixture material (`authority/*.fixture.*`, `daylight-equation/fixtures/`,
  `daylight/v15-meridian/examples/demo.key`) is intentionally public test
  evidence, not a secret. Reports that fixture keys are "leaked" are out of
  scope; reports that fixture authority can pass as production authority are in
  scope.
- Public evidence artifacts must not contain vault keys, plaintext secrets,
  opened plaintext, private vault stores, or privately openable demo envelopes.
  A public evidence package is allowed to contain only the documented public
  evidence profile for that lane.
- The Daylight AEAD implementations are documented as non-constant-time
  research references. Timing side channels in them are a known, stated
  boundary rather than a new finding; bypasses of the fail-closed authorization
  logic are in scope.
- The website (`site/`) ships no third-party scripts and performs all
  encryption locally in the browser. Anything that would make the published page
  execute non-`'self'` script is in scope.

## Handling

Reports are acknowledged as quickly as possible, and fixes land as ordinary
reviewed commits with proof-lane coverage where the surface allows it. There is
no bug bounty. Coordinated disclosure is appreciated; please allow a reasonable
window for a fix before publishing details.
