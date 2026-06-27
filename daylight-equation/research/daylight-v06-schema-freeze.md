# Daylight V0.6 Schema Freeze Evidence

This is checked M1 byte-schema freeze evidence for Daylight v0.6. It is not a
complete formal model, not external review, and not production authority.

The checked source is `daylight-v06-schema-freeze.v1.json`. The verifier is
`tests/daylight_v06_schema_freeze.py` and the top-level proof target is:

```sh
make daylight-v06-schema-freeze-test
```

## Frozen Surfaces

The manifest freezes these M1 byte-level surfaces against the v0.6 hardening
reference, fixture profile, and Rust v6 implementation:

```text
Deterministic-CBOR-Daylight-v6 schema
Envelope_v6 schema
Header_v6 schema
AuxBlock_v6 schema
Policy_v6 schema
KeySetPub_v6 schema
AuthBlock_v6 schema
PrivatePayload_v6 schema
T0/T1/AuthMsg labels
KDF labels
Rejection stages
```

The manifest also links the schema vector and provider-backed reference
negative corpus so schema and rejection-stage drift is caught by executable
tests.

## Boundary

Non-claims:

```text
this freeze evidence is not a complete formal model
this freeze evidence is not external review
this freeze evidence is not production authority
this freeze evidence does not claim runtime containment
this freeze evidence does not claim whole-system post-quantum safety
```
