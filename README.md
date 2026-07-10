# Wuci-Ji / 无此机

<img width="1983" height="793" alt="noether-forge-banner" src="https://github.com/user-attachments/assets/20f8c936-ae32-4230-863e-d00c6f7098cb" />

<p align="center">
  <strong>Sealed artifacts. Receipt-bound release. Public evidence.</strong><br>
  A defensive x86_64 assembly research system for turning security claims into
  deterministic, inspectable proof lanes.
</p>

<p align="center">
  <a href="https://nosuchmachine.net/">Project site</a> ·
  <a href="docs/SECURITY_BOUNDARY.md">Security boundary</a> ·
  <a href="docs/BUILD_TARGETS.md">Build targets</a> ·
  <a href="docs/PRODUCTION_READINESS.md">Readiness blockers</a> ·
  <a href="CITATION.cff">Citation</a>
</p>

> [!IMPORTANT]
> Wuci-Ji is a research and public-review artifact. It does not claim production
> readiness, production cryptography, production trust authority, general
> runtime containment, whole-system post-quantum safety, independent audit
> completion, or official endorsement.

## Why Wuci-Ji Exists

Security language is easy to inflate. Wuci-Ji explores a stricter alternative:
make each important claim point to bytes, a deterministic verifier, a receipt,
and an explicit refusal path.

The repository combines an assembly artifact core with authorization contracts,
public witness bundles, append-only history proofs, defensive perimeter checks,
Daylight evidence protocols, WuciOS review tooling, and a browser-first encrypted
message application.

| The repository can demonstrate | The repository deliberately refuses to infer |
| --- | --- |
| Artifact bytes were sealed, inspected, hashed, and checked through explicit proof lanes. | That custom research cryptography is suitable for production. |
| Rooted Gate contracts can authorize supported open/release paths and fail closed on reserved publish/trust actions. | Production publish authority is not established; trust authority is not established by fixture roots or denial-only commands. |
| Witness and ledger tools can create deterministic public evidence and local history proofs. | An operated transparency-log service or proof of host cleanliness. |
| CAGE, QCAGE, HARDEN, INSTALL, CARROT, and Daylight can emit bounded evidence about their implemented controls. | General OS containment, quantum safety, certification, accreditation, or absence of vulnerabilities. |

## Start Here

Choose the shortest path that matches your host.

### Native Linux x86_64

The full native lane requires GNU `as`/`ld` and a CPU with BMI2 and AVX for the
current assembly X25519 helper.

```sh
make help
make test
build/wuci-ji --help
build/wuci-ji selftest
```

### Portable Linux build

With Zig installed, build a static x86_64 Linux artifact:

```sh
make build-linux
```

On Linux without the required native CPU feature surface, run the cross-built
binary through the tested QEMU lane:

```sh
make test-linux
```

### First review pass

These checks give a useful overview without running every research lane:

```sh
make machine-passoff-test
make wuci-daylight-bridge-test
make daylight-npt-ci
make site-validate
```

See [the build-target guide](docs/BUILD_TARGETS.md) for host requirements,
QEMU configuration, and the complete target catalog. Shared build/proof lanes
should run serially unless a Make target already composes their dependencies.

## System Shape

```text
artifact bytes
    |
    v
WJSEAL envelope + public manifest
    |
    v
authorization receipt ---> rooted Gate contract
    |                              |
    |                              v
    |                    open/release decision
    v
public witness bundle ---> ledger history proof
    |                              |
    +-----------+------------------+
                v
       HARDEN / CAGE / QCAGE
                |
                v
     Daylight review + claim gates
```

The diagram shows evidence flow, not an OS sandbox. Assembly owns the narrow
envelope, Gate, and final-output boundary; Python and Zig provide deterministic
fixture, policy, orchestration, installer, and public-verifier layers. The exact
ownership table lives in [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md).

## Core Surfaces

| Surface | What it does | Boundary |
| --- | --- | --- |
| **WJSEAL / assembly core** | Hashes, seals, opens, inspects, armors, and manifests artifacts; implements the narrow authenticated-output path. | Research implementation; not independently audited; not production cryptography. |
| **Warrant** | Produces deterministic authorization receipts for review workflows. | Committed FROST authority is fixture-only. |
| **Gate / Root / Anchor** | Verifies flat and rooted contracts for open/release, with fail-closed publish/trust decisions. | Positive production publish/trust authority is not implemented. |
| **Witness** | Emits keyless public evidence bundles with a fixed public file profile. | Private keys, plaintext binaries, and private transcripts are excluded. |
| **Ledger** | Builds domain-separated Merkle history, inclusion, and consistency evidence. | Local deterministic history, not a hosted public log. |
| **HARDEN** | Checks verifier identity, safe I/O, fixture quarantine, reserved actions, public-file links, and ledger mutation. | Defensive perimeter hardening only. |
| **CAGE** | Verifies the legitimacy and public-file safety of evidence artifacts. | Artifact airlock; not runtime sandboxing. |
| **QCAGE** | Records digest vectors, crypto inventory, build graph, and quantum-migration debt. | Quantum-aware evidence; not a quantum-safe claim. |
| **INSTALL** | Verifies a signed local manifest and copied install root before atomic local installation. | Noninteractive local install proof; fixture authority is not install authority. |
| **CARROT** | Exercises a narrow seccomp and namespace no-network proof lane on supporting Linux kernels. | Not general sandboxing or VM containment. |
| **Daylight** | Turns evidence, score boundaries, blockers, and reviewer inputs into deterministic protocol state. | Evidence/provenance discipline; not certification. |

## Using the Assembly Artifact

The command matrix is built into the binary:

```sh
build/wuci-ji --help
```

A small, safe orientation set:

```sh
# Create and verify a local key file.
umask 077
build/wuci-ji keygen > artifact.key

# Seal to a new path; existing output files are refused.
build/wuci-ji seal-file-keyfile-v2 artifact.key \
  00112233445566778899aabbccddeeff \
  artifact.bin artifact.wj

# Inspect public structure without supplying a key.
build/wuci-ji inspect-file artifact.wj
build/wuci-ji manifest-file artifact.wj

# Open to a new path after authenticated verification.
build/wuci-ji open-file-keyfile artifact.key artifact.wj artifact.opened.bin
```

For public inspection without decrypting, use Wuci-Prism:

```sh
tools/wuci-prism inspect artifact.wj
tools/wuci-prism manifest artifact.wj
tools/wuci-prism boundary artifact.wj
```

Wuci-Prism accepts no secret key and does not unlock or release plaintext. It
reports visible WJSEAL structure, artifact hashes, and Gate-required status.

> [!CAUTION]
> The examples above demonstrate repository behavior; they are not key-management
> guidance for production systems. Keep private material out of the repository.

## Proof and Verification Lanes

| Goal | Command |
| --- | --- |
| Native assembly and integration suite | `make test` |
| Install proof test lane | `make install-test` |
| Gate contract matrix | `make gate-workflow` |
| HARDEN defensive perimeter | `make harden-proof` |
| CAGE artifact legitimacy | `make cage-proof` |
| QCAGE quantum-risk metadata | `make qcage-proof` |
| Public witness + ledger evidence | `make self-release-ledger-bundle` |
| Composed high-attestation lane | `make high-attestation-proof` |
| Daylight v15 Meridian | `make daylight-meridian-ci` |
| Daylight v20 public-evidence gate | `make daylight-v20-aperture-singularity-ci` |
| Numeric-claim precision firewall | `make daylight-npt-ci` |
| WuciOS v2.4 structure | `make wucios-validate` |
| Static website | `make site-validate` |
| README status and claim anchors | `make readme-remaster-check` |

`make high-attestation-proof` composes many local checks. Its success strengthens
local evidence only; it does not create production authority, general runtime
containment, external review, quantum safety, or a vulnerability-free claim.

## Daylight Evidence Stack

Daylight is the repository's proof-and-claim discipline. Its recurring laws are:

```text
NoProof(x)    -> NoClaim(x)   -> NoRelease(x)
NoEvidence(x) -> NoScore(x)   -> NoRelease(x)
NoTrace(x)    -> NoTrust(x)
ManualScore(x) -> Reject(x)
```

The versioned packages are kept separately so reviewers can inspect each model,
fixture set, schema, and verifier without hiding changes behind one moving API.

| Layer | Focus | Entry point |
| --- | --- | --- |
| v14C+ | Deterministic exact-rational candidate scoring from frozen inputs. | [daylight/v14c-plus/](daylight/v14c-plus/) |
| v15 Meridian | Evidence-derived obligation scoring, authorized envelopes, and a local vault. | [daylight/v15-meridian/](daylight/v15-meridian/) |
| v15+ Solstice | Hermetic frontier evidence and rootset-governed external attestations. | [daylight/v15-solstice/](daylight/v15-solstice/) |
| v16 Zenith / Analemma | Separate assurance and self-progress measures without inflating the conservative claim score. | [Zenith](daylight/v16-zenith/) / [Analemma](daylight/v16-analemma/) |
| v17 Singularity / Horizon Alpha | Residue-collapse research, verifier agreement, blocker diagnostics, and evidence-gated artifacts. | [daylight/v17-singularity/](daylight/v17-singularity/) |
| v18 Binaric Bastion | Binary measurement vectors and signed transition history. | [daylight/v18-bastion/](daylight/v18-bastion/) |
| v19 Aperture Bastion | Deterministic public-review capsules and a strict public artifact firewall. | [daylight/v19-aperture-bastion/](daylight/v19-aperture-bastion/) |
| v20 Aperture Singularity Gate | External evidence intake, canonical verifier output, rebuild receipts, blocker vectors, and declaration refusal. | [daylight/v20-aperture-singularity/](daylight/v20-aperture-singularity/) |
| DaylightNPT v1 | Precision firewall for numeric and certification-like public claims. | [docs/DAYLIGHT_NPT_V1.md](docs/DAYLIGHT_NPT_V1.md) |

Start a v20 public review with the
[reviewer quickstart](docs/DAYLIGHT_V20_REVIEWER_QUICKSTART.md) and
[reviewer packet](docs/DAYLIGHT_V20_REVIEWER_PACKET.md). The committed v20
fixture intentionally refuses declaration; repository-owned evidence cannot
self-issue the missing independent review, rebuild, verifier-family, and pinned
attestation evidence.

Tracked score-integrity records live under
[audits/daylight/score-integrity/](audits/daylight/score-integrity/). They are
recomputation and claim-boundary records, not certification or external audit
evidence.

## Daylight Bottle

[Daylight Bottle](apps/bottle/) is a browser-first encrypted
message-in-a-bottle application for `bottle.nosuchmachine.net`.

```text
static public keyring
        |
        v
sender browser -- local age encryption --> ciphertext-only API --> storage
                                                                  |
recipient browser <-- candidate ciphertexts <---------------------+
        |
        +-- local identity + local decryption
```

The TypeScript client uses the installed `age-encryption` package through a
small adapter. The same-origin Worker API accepts ciphertext and public metadata;
private identities, passphrases, plaintext messages, and decrypted bodies stay
in the browser. The MVP keyring is manually curated and has no public
self-registration endpoint. New drops are accepted only when the keyname and
fingerprint match an active record bundled from that keyring.

```sh
cd apps/bottle
npm ci
npm run check
npm run dev
```

`npm run check` runs lint, strict type checking, tests, the production build,
bundle/header verification, and a Wrangler dry run. Read
[apps/bottle/README.md](apps/bottle/README.md) for the architecture and
[apps/bottle/DEPLOYMENT.md](apps/bottle/DEPLOYMENT.md) for deployment and
rollback.

Each production build also emits a versioned same-origin release manifest that
binds the source commit, build inputs, keyring, security headers, Worker source,
artifact hashes, and explicit raw/gzip budgets. It is self-published provenance,
not independent attestation. The checked-in keyring remains empty until an
operator approves a public record whose private identity is held elsewhere, and
the Worker rejects every drop until an active record is approved.

> [!WARNING]
> Daylight evidence records what the service accepted; it is not encryption and
> it does not mathematically prove that a server never observed plaintext.
> Delivered JavaScript, the public keyring, the browser, the machine, and the
> recipient identity are all part of the trust boundary.

## WuciOS and NOXFRAME

WuciOS is an evidence-first operating-system image and review lane. The current
authoritative direction is the
[WuciOS v2.4 Reduction Gate](docs/wucios/WUCIOS_V24_REDUCTION_GATE.md): Noether
Core is GUI-free, substrate candidates are evaluated rather than assumed, and
desktop material is non-authoritative.

Useful entry points:

```sh
make wucios-validate
make wucios-fluff-audit
make wucios-substrate-matrix
make noxframe-launch
```

NOXFRAME is a bounded local operator console with session-local state, virtual
files, proof-lane commands, and explicit dry-run adapters. It does not provide a
general host shell or default network passthrough. See
[docs/noxframe/README.md](docs/noxframe/README.md).

## WuciOS v2.4 Reviewer/Status Baseline

`main` adopts the WuciOS v2.4 reviewer/status-documentation baseline. The
baseline is a public review and status integration boundary, not a production or
deployment authorization.

- Post-main adoption stabilization: [docs/wucios/v2.4/post-main-adoption-stabilization.md](docs/wucios/v2.4/post-main-adoption-stabilization.md)
- PR/merge packet: [docs/wucios/v2.4/pr-merge-consideration-packet.md](docs/wucios/v2.4/pr-merge-consideration-packet.md)
- Gate status ledger: [docs/wucios/v2.4/gate-status-ledger.md](docs/wucios/v2.4/gate-status-ledger.md)
- External transmission packet: [docs/wucios/v2.4/external-transmission-packet.md](docs/wucios/v2.4/external-transmission-packet.md)
- Generated WuciOS v2.4 Alpine Substrate Trial score evidence records: `96.0 / 100.0`
- Canonical artifact SHA-256: `95f3cb750357eeb2cd840ddfc7b62c6addf08b2d66079871a4d8e8efdd9ae45f`

This does not claim production readiness, external validation, full runtime
validation, bootability, long-running stability, operational deployment
approval, certification or accreditation, government endorsement, or a score
increase. Raw runtime evidence remains local/ignored unless separately
authorized.

## Security and Claim Boundaries

Keep these distinctions intact when reviewing, modifying, or describing the
project:

- **Defensive only.** Repository work must not add exploit generation,
  vulnerability reproduction, offensive scanning, jailbreak harnesses, malware,
  or network attack logic.
- **CAGE is not containment.** It validates artifact legitimacy and public
  evidence shape; it does not isolate a running process.
- **CARROT is narrow.** Its seccomp/namespace lane proves only the tested kernel
  conditions on supporting hosts.
- **QCAGE is not quantum safety.** Classical signatures and key agreement remain
  classical; a real pinned PQ verifier closes only its own verifier gate.
- **Fixture authority stays fixture authority.** Committed FROST material and
  fixture roots cannot authorize production publish, trust, or installation.
- **Daylight scores are bounded evidence telemetry.** They do not certify the
  system or replace missing external review.
- **Browser JavaScript is trusted code for Bottle.** A compromised origin,
  browser, machine, extension, swapped public key, or stolen identity can expose
  messages.
- **Secrets stay private.** Never commit root signing keys, private identities,
  passphrases, plaintext artifacts, or private transcripts.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
[docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md), and
[docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) before changing a
security claim.

## Repository Map

```text
src/                 x86_64 assembly core
include/             shared assembly constants
tests/               native and orchestration tests
tools/               verifiers, proof tooling, installers, and operator CLIs
authority/           fixture authority roots and public test material
install/             signed-manifest install evidence
daylight/            versioned Daylight execution and review packages
daylight-equation/   earlier protocol-state and scoring research
audits/              tracked public audit/recomputation records
wucios/              WuciOS overlays and image-lane material
apps/bottle/         Daylight Bottle browser app and Worker API
site/                static nosuchmachine.net site
docs/                specifications, boundaries, runbooks, and reviewer packets
third_party/         pinned external/reference components
```

For a guided handoff, read these in order:

1. [BUILD_NOTES.md](BUILD_NOTES.md)
2. [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md)
3. [docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md)
4. [docs/MACHINE_PASSOFF.md](docs/MACHINE_PASSOFF.md)
5. [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md)

Before editing, also read [AGENTS.md](AGENTS.md); it contains the repository's
defensive-development and claim-discipline rules.

## Development Notes

- Prefer deterministic fixtures, temporary directories, offline tests, and
  stdlib-only Python for the proof lanes that already follow that boundary.
- Do not loosen fail-closed checks to make a fixture pass.
- Reject symlinks and hardlinks on public evidence paths where the owning lane
  requires it.
- Keep browser dependencies bundled locally; Bottle must not load analytics,
  remote fonts, CDN scripts, third-party scripts, or other external runtime
  resources.
- Run `git diff --check` and the narrowest relevant proof target before the full
  composed lane.

## License and Citation

Wuci-Ji is licensed under the [Apache License 2.0](LICENSE). Attribution and
included-project notices are in [NOTICE](NOTICE).

If you use the research artifact, cite **Wuci-Ji v2.2 — Aperture Bastion** with
the metadata in [CITATION.cff](CITATION.cff).
