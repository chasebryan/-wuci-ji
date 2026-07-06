# ZP-1 / Wuci-Ji Coupling Boundary

## Classification

RUNTIME_GATE_31_ZP1_WUCIJI_COUPLING_PROOF_LANE

## Coupling Mode

- ZP-1 is imported as a pinned research dependency under third_party/zp1.
- Wuci-Ji metadata is bound into ZP-1 as AAD.
- The first bridge uses ZP-1 test-utils only.
- This verifies interface compatibility and AAD binding only.

## Authority Boundary

- ZP-1 does not replace WJSEAL.
- ZP-1 does not replace WUCI-GATE.
- ZP-1 does not replace Daylight.
- ZP-1 does not replace WuciOS validation.
- ZP-1 does not provide production release authority.
- ZP-1 does not alter WuciOS generated score evidence.
- ZP-1 does not create external validation.

## Provider Boundary

- The bridge uses InsecureTestProvider only under test-utils.
- InsecureTestProvider is not cryptographic.
- No production provider is enabled.
- No production secrets may be sealed with this bridge.
- Real-provider promotion requires a separate gate, real ML-KEM-1024 and
  ML-DSA-87 provider evidence, KATs, provider error-collapse review,
  canonical key encoding review, side-channel review, and external crypto
  review.

## AAD Contract

```text
WUCIJI-ZP1-AAD-v1\n
artifact_sha256=<64 lowercase hex chars>\n
receipt_sha256=<64 lowercase hex chars>\n
gate_policy_sha256=<64 lowercase hex chars>\n
wuciji_claim_boundary=research_proof_not_production\n
zp1_provider_boundary=test_utils_only_until_real_provider_reviewed\n
```

Rules:

- Use LF only.
- No CRLF.
- No JSON.
- No maps.
- No key reordering.
- No omitted lines.
- No extra trailing fields.
- The final byte must be LF.
- All SHA-256 fields must be exactly 64 lowercase hex characters.
- Any uppercase hex, non-hex character, empty digest, or wrong length must fail.

## Validation

- make zp1-upstream-test
- make zp1-wuciji-bridge-test
- make zp1-wuciji-coupling-test
- git diff --check
- make site-validate

## Non-Claims

This coupling is not production cryptography, not post-quantum security,
not production readiness, not external validation, not independent audit,
not runtime containment, not production authority, not WJSEAL replacement,
not Gate replacement, and not a WuciOS score increase.
