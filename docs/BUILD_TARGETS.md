# WUCI Build Targets

Native build and most targeted tests require Linux x86_64 with GNU `as`/`ld`.
The full native `make test` target also requires BMI2 and AVX because the
current assembly X25519 helper uses those instructions. On Linux hosts without
those CPU features, use `make test-linux` for the cross-built ELF's Python
harness. The qemu lane defaults to `QEMU_CPU=Haswell-v4`, which supplies the
BMI2/AVX instruction surface required by the current X25519 helper under user
mode QEMU. Override `QEMU_CPU` only when the selected model is known to expose
those instructions, and run targeted non-X25519 proof lanes natively.

The long-term test direction is assembly-first: fast assembly-owned regression
lanes for stable crypto, parser, Gate, manifest, and ledger invariants, with
Python kept for fixture generation and host-policy orchestration. See
`docs/ASSEMBLY_TEST_STRATEGY.md`.

`machine-passoff-test` checks the fresh-machine continuation handoff in
`docs/MACHINE_PASSOFF.md`, including the read order, score boundary, next
publish/trust Gate slice, and required local continuation commands.

## Minimal

```sh
make build-linux
make machine-passoff-test
make asm-smoke
make test
make install-test
make install-sign-current INSTALL_SIGNING_KEY=/absolute/path/to/root-signing-key
make parser-adversarial-test
make aead-boundary-test
make secret-path-isolation-test
```

## Website

```sh
make site-daylight-status
make site-validate
make site-live-check
```

`site-daylight-status` regenerates the committed website Daylight status JSON
from the v17 scorecard. `site-validate` checks the local static artifact for
fresh evidence, required discovery metadata, CodeMeta JSON-LD research software
metadata, canonical HTTPS metadata, official Wuci-Ji imagery, and
claim-boundary text. `site-live-check` probes the deployed public host and
fails unless the HTTPS apex, server-side HTTP to HTTPS redirect, `www`
redirect, HSTS header, discovery files, CodeMeta JSON-LD, status JSON, and
official image assets are live. It is a hosted deployment gate, not a proof of
host cleanliness or runtime containment.

## Native Proof Lanes

```sh
make asm-regression
make authority-root-check
make gate-contract-asm
make self-release-asm-contract-proof
make self-release-anchored-proof
make self-release-rooted-proof
make self-release-publish-bundle
make self-release-witness-bundle
make self-release-witness-archive
make ledger-asm-test
make ledger-proof-test
make self-release-ledger-bundle
make harden0-proof
make harden-proof
make cage-proof
make qcage-proof
make witness-zig
make witness-zig-test
make witness-archive-test
make reproducible-build-metadata
```

## High Attestation

```sh
make high-attestation-profile
make high-attestation-proof
make sbom-provenance
make sbom-provenance-test
make carrot-policy
make kernel-sandbox-proof
make rust-sandbox-build
make rust-sandbox-test
make pq-verifier-detect
make pq-verifier-real-attest
make pq-verifier-real
make pq-verifier-test
make production-authority-verify
make production-readiness-gates
make crypto-self-audit
make crypto-self-audit-test
make parser-corpus-replay
make wjgold-model-test
make golden-lock-policy-matrix
make verify-release-bundle
make host-capacity
```

`high-attestation-profile` checks the machine-readable defensive baseline in
`docs/wuci_high_attestation_profile.json`. The baseline maps current U.S.
government defensive guidance into local WUCI controls without claiming runtime
sandboxing, no-network containment outside the CARROT proof lane, quantum
safety, production authority, or absence of vulnerabilities.

`high-attestation-proof` composes the profile check, pinned qemu X25519 CPU
smoke, assembly smoke/regression audit, HARDEN policy, CAGE/QCAGE policy and
bundle checks, SBOM/provenance evidence, CARROT kernel no-network proof,
compiled Rust sandbox wrapper evidence, real-PQ verifier detection, optional
pinned real-PQ verifier evidence, crypto self-audit evidence, deterministic
local parser corpus replay, release bundle verification, production-readiness
gates, Gate contract assembly checks, and the full qemu Linux CLI test.

`parser-corpus-replay` replays committed parser corpora plus deterministic
mutations through assembly parser/verifier surfaces and internal public-parser
checks. The v2 evidence requires envelope, armor, authority-root, Gate contract,
ledger entry, ledger head, ledger proof, and WJ* model coverage, with zero
timeouts and zero signal terminations. It is local fail-closed replay evidence,
not offensive fuzzing or a coverage-guided CI fuzzer.

`parser-corpus-replay-test` validates the v2 JSON evidence shape.
`parser-hardening-proof` composes replay generation and validation for the
high-attestation lane.

`daylight-v06-peer-review-score-test` checks the additive 10,000-point
Daylight v0.6 peer-review scoring model in
`daylight-equation/analysis/daylight-v06-peer-review-scoring-model-10000.v1.json`
and
`daylight-equation/analysis/daylight-v06-peer-review-scoring-model-10000.md`.
It verifies the component sum, cap-limited final score, active hard caps,
legal-safety nullifier, supplied ChatGPT desk-review artifact, non-claim text,
required evidence links, and that the existing 975/1000 research scorecard
remains unchanged. It is not an external review, not an official endorsement,
not a production-readiness claim, not runtime containment evidence, and not a
whole-system post-quantum-safety claim.

`daylight-v06-cap-removal-test` checks the fail-closed cap-removal plan in
`daylight-equation/research/daylight-v06-cap-removal-plan.v1.json` and
`daylight-equation/research/daylight-v06-cap-removal-plan.md`. It verifies that
the 8250/10000 cap remains active, that `publish-authorized-rooted` is only a
fail-closed decision path, that `trust-authorized-rooted` is also only a
fail-closed decision path, that fixture authority cannot satisfy publish/trust,
and that WUCI production-authority tooling still rejects trust/publish
authority until positive production Gate authority exists. It does not raise
the score, create production authority, implement runtime containment, or count
as external review.

`daylight-v06-fail-closed-model-test` checks the partial Daylight v0.6
fail-closed ordering model in
`daylight-equation/research/daylight-v06-fail-closed-model.v1.json` and
`daylight-equation/research/daylight-v06-fail-closed-model.md`. It verifies
single-predicate `Open = bottom` behavior and the `PublicPreOK = 0` barrier
against private KEM, AEAD decrypt, and plaintext materialization, and checks
the non-production provider-backed v6 reference `Seal`/`Open` implementation
link. It is not a complete confidentiality, authorization, downgrade-resistance,
or production authority proof.

`daylight-v06-schema-freeze-test` checks the Daylight v0.6 byte-schema freeze
evidence in `daylight-equation/research/daylight-v06-schema-freeze.v1.json` and
`daylight-equation/research/daylight-v06-schema-freeze.md`. It verifies frozen
schema surface names, transcript labels, KDF labels, rejection stages, schema
vector hooks, and negative-corpus hooks against the current Rust v6 lane and
reference docs. It is not a formal model, external review, or production
authority proof.

`daylight-v06-m4-symbolic-model-test` checks the Daylight v0.6 M4 symbolic
model in `daylight-equation/research/daylight-v06-m4-symbolic-model.v1.json`
and `daylight-equation/research/daylight-v06-m4-symbolic-model.md`. It
exhaustively checks the 20-predicate public/private `Open` truth table for
confidentiality assumptions, authorization requirements, downgrade
requirements, and fail-closed release behavior. It is not a mechanized
theorem-prover proof, external review, production authority, runtime
containment, or whole-system post-quantum-safety evidence.

`daylight-v06-protocol-state-test` checks the Rust written-code form of the
current 8250/10000 Daylight v0.6 research boundary. It runs the std-only
`daylight-model` v0.6 predicate tests, including the 20-predicate truth table
and zero-claim boundary, and checks that the Rust crypto lane constructs a
`DaylightAuthorizedEnvelopeV6` before entering the provider-backed private
`Open` path. It is not production authority, runtime containment evidence,
whole-system post-quantum-safety evidence, or external review.

`wuci-daylight-bridge-test` composes the Daylight v0.6 protocol-state target
with the Wuci-Ji envelope bridge. It checks that the Daylight Rust crate
classifies WJSEAL v1/v2/v3 envelope bytes, records the 8250/10000 zero-claim
boundary, keeps `daylight_private_open_authorized=false`, and requires WUCI-GATE
for plaintext release. It does not decrypt, verify AEAD tags, accept keys,
replace Gate, create production authority, claim runtime containment, or claim
whole-system post-quantum safety.

`daylight-v06-m4-z3-proof-test` checks the Daylight v0.6 M4 Z3 proof in
`daylight-equation/research/daylight-v06-m4-z3-proof.smt2`,
`daylight-equation/research/daylight-v06-m4-z3-proof.v1.json`, and
`daylight-equation/research/daylight-v06-m4-z3-proof.md`. It runs Z3 over 38
negated Boolean predicate obligations and requires every query to return
`unsat`. It is a mechanized predicate proof, not external review, production
authority, runtime containment, whole-system post-quantum-safety evidence, or
a cryptographic primitive proof.

`daylight-v06-1000-preflight-test` checks the Daylight v0.6 1000 preflight in
`daylight-equation/research/daylight-v06-1000-preflight.v1.json` and
`daylight-equation/research/daylight-v06-1000-preflight.md`. It verifies that
the current repo remains blocked from a 1000/1000 claim until integrated public
authority, at least two independent external reviews, and signed non-fixture
production authority evidence are all tracked. It is a fail-closed readiness
gate, not score evidence.

`daylight-v06-1000-claim-gate-test` checks `tools/daylight_1000_gate.py`, the
composed Daylight v0.6 1000 claim gate. It reads the scorecard, machine
scorecard, preflight, optional signed external review set, and optional signed
Daylight authority evidence, then exits nonzero until every 1000 checkpoint
condition is proved. It is not external review, not production authority, and
does not raise the score.

`daylight-v06-1000-checkpoint-test` checks
`tools/daylight_1000_checkpoint.py`, the guarded Daylight v0.6 1000 checkpoint
writer. It refuses to write a checkpoint artifact unless the composed 1000
claim gate is ready. It is not external review, not production authority, and
does not raise the score.

`daylight-v06-authority-verifier-test` checks `tools/daylight_authority.py`,
the Daylight v0.6 public-authority candidate verifier. It exercises signed
non-fixture WUCI open/release authority verification and proves the candidate
does not satisfy integrated Daylight public authority until publish/trust
authority support and all predicate integrations exist. It also requires
true public-authority predicates to be proof-bound by digest-checked local
evidence, binds the ceremony root key SHA-256, and rejects self-claiming extra
fields in authority evidence. It is not production authority and does not raise
the score.

`daylight-v06-external-review-packet-test` checks the Daylight v0.6 external
review packet in
`daylight-equation/evidence/daylight-v06-external-review-packet.v1.json` and
`daylight-equation/analysis/daylight-v06-external-review-packet.md`. It
verifies that the packet links the current 975 evidence set, review questions,
local proof commands, and external review acceptance criteria while keeping
`ExternalReviewClaim = 0`. It is not an external review and does not raise the
score.

`daylight-v06-external-review-verifier-test` checks
`tools/daylight_external_review.py`, the signed Daylight v0.6 external-review
evidence verifier. It exercises evidence emission, OpenSSH Ed25519 signing,
single-review verification, root-key digest binding, review-set manifest
emission, two-review-set verification, strict manifest shape, portable relative
manifest paths, and failure cases for unsigned, duplicate, self-claiming,
root-key-mismatched, path-escaping, scope-incomplete, and report-tampered
evidence. It is not itself an external review and does not raise the score.

`daylight-v6-provider-private-roundtrip-test` checks the Rust Daylight v6
private-roundtrip evidence vector. It covers typed `PrivatePayload_v6` CBOR,
provider-backed AEAD seal/open with `AD = T0`, artifact commitment checking,
and continued public-precheck rejection before private work. It is not a full
provider-backed public `Seal`/`Open` lane.

`daylight-v6-provider-vector-agreement-test` checks the provider-backed v6
vector-agreement evidence in
`daylight-equation/evidence/daylight-v6-provider-vector-agreement.v1.json`. It
verifies that the KEM/key-schedule, private-roundtrip, and reference
`Seal`/`Open` vectors agree on artifact identity, public rejection boundary,
production-disallowed state, and non-production reference-lane boundaries. It
is not independent external review or production authority.

`daylight-v6-kat-reproduction-bundle-test` checks
`daylight-equation/evidence/daylight-v6-kat-reproduction-bundle.v1.json`. It
pins the current provider-backed v6 KEM, private-roundtrip, reference
`Seal`/`Open`, reference negative-corpus, and vector-agreement artifacts by
SHA3-512 and verifies their local reproduction commands. It is not a second
implementation, independent external review, production authority, or score
increase.

`daylight-v6-reference-seal-open-test` checks the Rust Daylight v6 reference
`Seal`/`Open` evidence vector. It covers provider-backed ML-KEM-1024,
DHKEM(P-384,HKDF-SHA384), AEAD seal/open, typed private payload decoding,
artifact commitment checking, explicit non-production external public precheck
evidence, and fail-closed mutation tests. It is not production authority,
integrated public authority, runtime containment, or whole-system
post-quantum-safety evidence.

## Daylight v18 Binaric Bastion

Daylight v18 Binaric Bastion is the binary-measurement substrate under
`daylight/v18-bastion`. v18.0 measures regular files into canonical Binaric
Vectors, and v18.1 authorizes vector changes through a signed local user
transition plus append-only transition ledger inclusion. It is not host
cleanliness proof, runtime containment, production cryptography, production
identity, FIPS validation, external certification, or whole-system
post-quantum-safety evidence.

```sh
make daylight-v18-bastion-measure
make daylight-v18-bastion-verify
make daylight-v18-bastion-test
make daylight-v18-bastion-transition-demo
make daylight-v18-bastion-transition-test
make daylight-v18-bastion-transition-ledger-verify
```

`daylight-v18-bastion-measure` regenerates
`daylight/v18-bastion/examples/example-vector.v18.json` from the committed
example subject. `daylight-v18-bastion-verify` verifies that vector against the
current subject bytes. `daylight-v18-bastion-test` runs the v18 measurement,
transition, tamper, no-float, path-safety, and CLI tests.
`daylight-v18-bastion-transition-demo` proves tamper rejects without a signed
and ledgered transition, then accepts the fixture transition. The fixture
passphrase is demonstration-only and not production security.

## Wuci-Ji v2 — Aperture Bastion (Daylight v19)

Aperture Bastion under `daylight/v19-aperture-bastion` produces
deterministic, claim-bounded Aperture Review Capsules and runs a strict
public artifact firewall before anything is uploaded. It is not production
cryptography, runtime containment, host cleanliness, FIPS validation,
government validation, external certification, whole-system post-quantum
safety, or an independent audit.

```sh
make daylight-v19-aperture-bastion-doctor
make daylight-v19-aperture-bastion-capsule-demo
make daylight-v19-aperture-bastion-verify
make daylight-v19-aperture-bastion-public-artifact
make daylight-v19-aperture-bastion-firewall
make daylight-v19-aperture-bastion-test
make daylight-v19-aperture-bastion-ci
make aperture-bastion-doctor
make aperture-bastion-test
make aperture-bastion-ci
```

`daylight-v19-aperture-bastion-verify` re-verifies the committed fixture
capsule `daylight/v19-aperture-bastion/examples/expected-capsule.v19.json`.
`daylight-v19-aperture-bastion-capsule-demo` builds a live capsule over the
example subject with v18 vector-chain, v18 transition-ledger, v15 Meridian,
v17 Event Horizon, and policy evidence references, then verifies it with
`--require-evidence`. `daylight-v19-aperture-bastion-public-artifact` emits
the public directory and `daylight-v19-aperture-bastion-firewall` scans it,
writing the report outside the public root only on a pass. See
`docs/WUCI_JI_V2_APERTURE_BASTION.md`.

`daylight-v6-reference-negative-corpus-test` checks the Rust Daylight v6
reference negative corpus in
`daylight-equation/rust/daylight-crypto/vectors/daylight-v6-reference-negative-corpus-v1.txt`.
It covers non-production external public-precheck denials,
production-disallowed denial, and private-path AEAD, commitment, derivation,
and leak-validation failures. It is not a full provider-backed corpus or
independent external review.

`daylight-v6-nightlight-battery-test` checks the Nightlight v6 equation
battery in
`daylight-equation/rust/daylight-crypto/vectors/nightlight-v6-equation-battery-v1.txt`.
It aggregates the existing v6 schema, provider KEM, private-roundtrip,
reference `Seal`/`Open`, and reference negative-corpus evidence into
an open-ended deterministic equation gate. The current battery covers malformed
CBOR, schema mutation, suite downgrade, aux-hash drift, policy denial, review,
log, install, witness, claims, KEM-shape, and auth-block-shape simulations at
the public boundary, plus the existing private-path AEAD, commitment,
derivation, and leak-validation checks. It does not add offensive logic,
network behavior, production
authority, runtime containment, whole-system post-quantum-safety claims, or a
score increase.

`daylight-v6-nightlight-deep-assessment-test` checks the Nightlight v6 deep
assessment vector in
`daylight-equation/rust/daylight-crypto/vectors/nightlight-v6-deep-assault-assessment-v1.txt`.
It applies deterministic coverage learning over the local fail-closed
Nightlight corpus, ranks risk/novelty arms, emits prioritized epochs, and
records gap recommendations for future defensive tests. It does not add
offensive logic, network behavior, production authority, runtime containment,
whole-system post-quantum-safety claims, or a score increase.

`wjstar-model-test` checks the formal WJ* composition model in
`docs/wuci_wjstar_model.json` and `docs/wuci_wjstar_model.md`, including the
AEAD/FROST/Gate/Merkle/witness open predicate, Golden Lock v1 transcript, the
3-of-5 normal open/release threshold, and the 4-of-5 root/authority/audit
ceremony threshold. It is a model-consistency gate, not a production
cryptography claim.

`wjnext-model-test` checks the WJ-next canonical transcript model in
`docs/wuci_wjnext_model.json` and `docs/wuci_wjnext_model.md`. It pins
`T_v2 = C14N_v2(...)`, `m_v2 = H("wuci/transcript/v2" || T_v2)`, the typed
acceptance predicate, and the PQ modes where `compat` is allowed,
`hybrid-evidence` requires ML-DSA verification plus pins/KATs, and `pq-secure`
stays false until earned.

`wjgold-model-test` checks `docs/wuci_golden_lock_model.json`,
`docs/wuci_golden_lock_model.md`, and
`tools/wuci_golden_lock_model.py`. It validates the WJ-GOLD acceptance model:
allowed actions, pressure-to-threshold/PQ-mode consistency, participant count,
custody-domain diversity, `pq-secure` fail-closed behavior, hybrid-evidence
flags, public witness/ledger/provenance/install evidence, private-material
absence, no-downgrade rules, and claim discipline. It is an evidence-model gate,
not production cryptography, host security, runtime sandboxing, or a
post-quantum system security claim.

`golden-lock-policy-matrix` checks `docs/wuci_golden_lock_policy.json` and the
deterministic transcript fixture in `docs/wuci_golden_lock_transcript_fixture.json`.
It validates pressure-to-threshold/PQ-mode mapping, `DomainQuorum_3/5`,
`NoDowngrade`, `ClaimOK`, the "No plaintext before Gate" rule, and pinned
`C14N_G` / `m_G` fixture evidence. It is a policy/transcript proof lane, not a
production 5-party FROST implementation.

`verify-release-bundle` writes `build/wuci-release-bundle-verification.json`.
It verifies SBOM/provenance, CARROT, PQ detector, optional pinned real-PQ
evidence, crypto self-audit, parser hardening replay, production authority policy,
optional signed non-fixture production authority evidence, optional signed
external audit evidence, witness bundle, ledger history, install manifest
signature, binary hashes, and Rust no-network wrapper evidence. The output
remains an evidence candidate and records blockers instead of claiming
production readiness.

`pq-verifier-real-attest` and `pq-verifier-real` are explicit
external-evidence lanes. They require caller-supplied `PQ_VERIFIER_BIN`, KAT
paths, implementation metadata, `REAL_PQ_VERIFIER_EVIDENCE`, and reviewed pins
before any real-PQ evidence can clear a release blocker.

`pq-verifier-fips204-proof` is the bundled local Rust FIPS 204 ML-DSA verifier
lane. It builds `tools/wuci-pq-fips204-verify`, runs selftest and deterministic
KAT verification, emits `build/wuci-real-pq-verifier.json`, and writes
`build/wuci-pq-fips204-pins.json`. This clears only the real-PQ verifier
evidence gate when those files are passed to release verification.

`production-authority-verify` is also explicit. It requires
`PRODUCTION_AUTHORITY_ROOT`, `PRODUCTION_AUTHORITY_CEREMONY`,
`PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY`, and
`PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE`; fixture roots and unsigned
ceremonies fail closed.

`external-audit-test` exercises the signed external-audit evidence verifier.
Release verification requires all four external-audit inputs together:
`EXTERNAL_AUDIT_EVIDENCE`, `EXTERNAL_AUDIT_REPORT`,
`EXTERNAL_AUDIT_ROOT_KEY`, and `EXTERNAL_AUDIT_SIGNATURE`.

`host-capacity` prints the detected logical CPU count. Independent proof lanes
can be run with `make -jN`; targets that share witness, ledger, CAGE, QCAGE, or
release evidence paths are serialized through their Make dependencies.

`kernel-sandbox-proof` is local kernel evidence: it requires Linux support for
seccomp filters plus unprivileged user and network namespaces and passes only
when `wuci-ji sandbox-seccomp-net-deny-selftest` installs a network-syscall deny
filter and observes AF_INET socket creation denied with `EPERM`. It is not a
general runtime sandbox or VM boundary.

`rust-sandbox-test` builds `tools/wuci_sandbox.rs`, runs the Rust wrapper's own
seccomp no-network selftest, then executes `wuci-ji selftest` under the wrapper.
It requires `rustc`; the Makefile also checks the standard `~/.cargo/bin/rustc`
location when Rust is installed by rustup but not exported in `PATH`.

`sbom-provenance` emits and verifies `build/wuci-sbom.json` and
`build/wuci-provenance.json` without network access. The generated provenance
records Apache-2.0 licensing, toolchain evidence, git state, binary hashes, the
pinned qemu CPU model, the high-attestation profile digest, and the current
non-production-ready status.

## Zig Proof Lanes

```sh
make gate-contract-zig
make zig-release-proof
make zig-release-contract-proof
make zig-release-asm-contract-proof
make zig-release-anchored-proof
make zig-release-rooted-proof
make zig-release-release-contract-proof
make zig-release-publish-bundle
make zig-release-witness-bundle
make zig-release-witness-archive
make zig-release-ledger-bundle
```

On a Linux host that needs user-mode QEMU for the Zig-built ELF, pass
`RELEASE_RUNNER="qemu-x86_64 -cpu Haswell-v4"`.

## CI Mirrors

```sh
make ci-native
make ci-zig
```

`check-asm-immediates` is a legacy static disassembly audit. It remains
available as an opt-in target:

```sh
make check-asm-immediates
```

## Daylight v15 Meridian Artifact Lane

Meridian is the installable evidence-derived scoring artifact under
`daylight/v15-meridian`. See
[DAYLIGHT_V15_MERIDIAN_SOFTWARE_ARTIFACT.md](DAYLIGHT_V15_MERIDIAN_SOFTWARE_ARTIFACT.md).

```sh
make daylight-meridian-test            # full package suite (scoring + AEAD vectors + envelope)
make daylight-meridian-verify          # regenerate + evidence-bound verify the example scorecard
make daylight-meridian-frontier        # print internal ceiling, residue, and external frontier
make daylight-meridian-perfect-demo    # demonstrate 1,000,000M from external-attestation fixtures
make daylight-meridian-artifact        # write build/daylight/v15-meridian-public/ (scorecard, receipt, frontier, manifest, SHA256SUMS)
make daylight-meridian-public-artifact # stage the exact public evidence upload profile and guard it
make daylight-meridian-public-artifact-test # regression test: no keys/plaintext/private envelopes in public evidence
make daylight-public-evidence-firewall-test # recreate private-material fixtures and require rejection
make daylight-public-artifact-firewall # scan public artifact, verify manifest, and check upload workflows
make daylight-security-ratchet-test    # fail if public evidence invariants are removed
make daylight-meridian-envelope-test   # RFC 8439/5869 AEAD vectors + envelope fail-closed matrix
make daylight-meridian-envelope-demo   # seal -> inspect -> open the committed Meridian Authorized Envelope
make daylight-meridian-smoke           # CLI smoke checks (incl. seal/open)
make daylight-meridian-package         # offline package metadata + entrypoint check
make daylight-meridian-ci              # test + smoke + artifact (GitHub Actions lane)
```

Private work products and public evidence do not share a publish root:
`build/daylight/v15-meridian-private/` contains smoke and vault work, while
`build/daylight/v15-meridian-public/` contains only uploadable public evidence.
CI uploads only the public root after
`tools/daylight_public_evidence_firewall.py` scans it, verifies the manifest,
and checks upload workflows. Vault keys, plaintext secrets, opened plaintext,
vault stores, plaintext hash oracles, and private sealed envelopes reject before
upload.

The Meridian Authorized Envelope (`seal`/`open`/`envelope-inspect`) encrypts with
a vector-checked RFC 8439 ChaCha20-Poly1305 AEAD gated by evidence-derived
obligation logic. See
[WUCI_DAYLIGHT_V15_MERIDIAN_ENVELOPE.md](WUCI_DAYLIGHT_V15_MERIDIAN_ENVELOPE.md).

`daylight-meridian-test` and the CI lane stay standalone (not folded into
`make test`), matching the v14C+ package convention. The lane is Python-only and
needs no assembler, linker, or Zig.

## Daylight v17 Singularity

Daylight v17 Singularity is the deterministic residue-collapse research scoring
layer under `daylight/v17-singularity`. The v17.1 Event Horizon kernel computes
AM+ from committed proof atoms, integer micro-omega debt, weakest-field
governance, and canonical digests. The v17.2 Cross-Verifier Horizon adds
blocker-vector diagnostics and verifier-output agreement checks. The v17.3
Triangulation Gate adds the first independent Rust verifier vector while
keeping quorum fail-closed at `partial_2_of_3`. It
does not modify Daylight v15/v16 M scores and does not claim production
certification, runtime containment, FIPS validation, external certification, or
whole-system post-quantum safety.

```sh
make daylight-v17-event-horizon-test
make daylight-v17-event-horizon-score
make daylight-v17-event-horizon-fixture-demo
make daylight-v17-event-horizon-fracture
make daylight-v17-event-horizon-vector
make daylight-v17-event-horizon-rust-vector
make daylight-v17-event-horizon-rust-test
make daylight-v17-event-horizon-triangulation
make daylight-v17-event-horizon-agreement
make daylight-v17-event-horizon-blockers
make daylight-v17-event-horizon-frontier
make daylight-v17-event-horizon-declaration-gate
make daylight-horizon-alpha-test
make daylight-horizon-alpha-vault-demo
make daylight-horizon-alpha-release-demo
```

`daylight-v17-event-horizon-score` regenerates the committed current scorecard.
`daylight-v17-event-horizon-fixture-demo` regenerates the declaration fixture,
which reaches `999,999,999 AM+` only as a math fixture with `fixture=true` and
`claim_usable=false`.
`daylight-v17-event-horizon-declaration-gate` runs the Event Horizon checks:
proof-atom verification, weakest-field scoring, scorecard digest verification,
fracture mutations, and the cross-verifier data-model gate. It is expected to
refuse the committed current scorecard until real three-verifier agreement
evidence exists. Independent Rust/Zig/Lean verifier lanes are not claimed by
this target.

`daylight-v17-event-horizon-vector` regenerates the Python reference verifier
vector. `daylight-v17-event-horizon-rust-vector` regenerates the independent
Rust verifier vector. `daylight-v17-event-horizon-triangulation` proves the
Python+Rust bundle is only `partial_2_of_3`, then reports the current blockers.
`daylight-v17-event-horizon-agreement` expects the partial bundle to fail full
agreement. `daylight-v17-event-horizon-frontier` lists weakest fields and open
proof atoms. `daylight-v17-event-horizon-blockers` reports all current
declaration blockers without converting refusal into a failed Make target.

## Daylight Horizon Alpha

Daylight Horizon Alpha is the product layer over v17: evidence-gated vault and
release control. It uses Event Horizon scorecards as policy input and enforces:
no policy satisfaction means no plaintext or release gate.

```sh
make daylight-horizon-alpha-test
make daylight-horizon-alpha-vault-demo
make daylight-horizon-alpha-release-demo
```

`daylight-horizon-alpha-test` runs the policy, vault, and release gate tests.
`daylight-horizon-alpha-vault-demo` initializes a local alpha vault, seals a
file, keylessly inspects the `.dhv` object, opens it under current evidence, and
compares the plaintext. `daylight-horizon-alpha-release-demo` prepares,
verifies, and gates a research `.dhr` release capsule. Research pass is not
production authority, not production cryptography, not runtime containment, not
FIPS validation, not external certification, and not whole-system
post-quantum-safety evidence.
