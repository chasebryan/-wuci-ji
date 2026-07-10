# Noether Forge source-only external review

Status: **source-only external review candidate**.

This repository publishes the Noether Forge source, repeat-build-checked build
pipeline, pinned upstream identities, schemas, tests, and bounded review
instructions. It does not distribute the resulting ISO, Alpine APK payloads,
package caches, compiled Wuci-Ji binary, kernel, initramfs, modloop, EFI image,
firmware, or bootloader binaries.

The image is derived from authenticated Alpine inputs. It is not produced,
approved, certified, or endorsed by the Alpine Linux project.

Reviewers acquire the authenticated Alpine inputs directly from the upstream
locations recorded in `alpine-input-lock.json`. The explicit fetch step checks
the upstream ISO SHA-256 and SHA-512, verifies its detached GPG signature, and
verifies the locked APK closure before an offline build begins.

This review lane is defined by
`wucios/releases/noether-forge-v2.4.0/external-review.json`. It is not a GitHub
Release or an official WuciOS release. It does not confer production authority,
external certification, or permission to redistribute a reviewer-built
binary.

## Review from source

Start from a clean checkout of the review commit. Do not reuse an input cache
from an unrelated checkout when recording independent review results.

```sh
make wucios-noether-forge-source-guard
make wucios-noether-forge-review-evidence
make wucios-noether-forge-test
make wucios-validate
make wucios-noether-forge-fetch
make wucios-noether-forge-build
make wucios-noether-forge-verify
```

Only `wucios-noether-forge-fetch` performs network acquisition. Build,
inspection, BIOS/UEFI boot verification, and internal readiness consume the
pinned local cache. This is a workflow property, not kernel-enforced network
isolation.

Generated files stay under `build/`, which is intentionally excluded from Git.
Do not commit, attach, mirror, or publish the generated ISO or upstream binary
inputs from this source-review lane.

### Build prerequisites

Use a Linux x86_64 host with Python 3, Git, GNU Make, GNU `as` and `ld`, `file`,
GnuPG, `xorriso`, and `qemu-system-x86_64`. The input gate currently requires
`xorriso` to report `1.5.8.pl02`; the recorded input lock identifies the tested
GnuPG and QEMU versions but does not strictly pin them. UEFI verification also
needs a stateless OVMF firmware image. The default path is
`/usr/share/edk2/ovmf/OVMF.stateless.fd`. On another layout, run the Python tool
directly and pass `--ovmf /path/to/OVMF.fd` to its `internal`, `boot`, or
`launch` command.

```sh
make wucios-noether-forge-build
python3 tools/wucios/noether_forge.py internal \
  --firmware all --ovmf /path/to/OVMF.fd
```

Allow network access for the fetch step only. Plan for about 375 MB of network
acquisition and at least 3 GiB of free space for the Alpine input, locked APK
cache, two temporary ISO builds, inspection files, and the final private image.

### Determinism boundary

The build gate requires two complete builds to be byte-identical within one
clean checkout and host toolchain. The embedded source manifest binds the Git
commit, branch, and clean/dirty state. A checkout on a different branch, a
detached HEAD, or a different host toolchain is therefore not promised to
produce the same ISO digest. Cross-host reproducibility has not been
established.

### Third-party obligations inventory

`wucios/releases/noether-forge-v2.4.0/third-party-obligations.json` is generated
deterministically from `alpine-input-lock.json` and `package-lock.json`. Check
that the committed matrix still matches those locks with:

```sh
python3 tools/wucios/noether_obligations.py check
```

Every row records its locked artifact origin and digest plus explicit package,
version, source-metadata, license-metadata, notice, firmware, redistribution,
and export-review fields. Facts absent from the locked records intentionally
remain `NOASSERTION`, `not-reviewed`, or `not-determined`. The inventory does
not inspect downloaded APK contents, perform network access, decide which
notices are required, classify cryptography, or provide redistribution or
export clearance. Regenerate it after an intentional lock change with
`python3 tools/wucios/noether_obligations.py write`, review the diff, and rerun
the source-review gates.

### Physical-hardware observation records

The schema at
`wucios/schemas/noether-forge-physical-hardware-observation.schema.json` binds
an operator record to the reviewed Git commit and the privately built ISO's
SHA-256, SHA-384, and SHA-512. It also records redacted hardware, firmware,
capture-host, tool, and observed-result fields. The tracked record under
`fixtures/` is synthetic and exercises the verifier only; its subject is not an
ISO and it records no boot result.

For a real observation, copy the fixture outside the repository, change
`record_status` to `operator-observation`, change `subject_kind` to
`private-reviewer-built-iso`, and replace every fixture value with the actual
sanitized observation. Verify the record and its private local artifact with:

```sh
python3 tools/wucios/noether_hardware_observation.py \
  /path/to/sanitized-hardware-observation.json \
  --iso /path/to/WuciOS-v2.4.0-Noether-Forge-x86_64.iso \
  --expected-commit 0123456789abcdef0123456789abcdef01234567
```

Replace the example commit with the exact reviewed commit. The verifier uses
only the Python standard library, rejects symlink and hardlink inputs, rejects
extra fields and positive validation/authority claims, and optionally
recomputes the ISO digest vector. A passing result establishes record
consistency only; it is not independent hardware validation, certification,
official release authority, or proof of OS containment.

## What to review

- Confirm every fetched object matches its pinned digest and signature.
- Confirm both complete builds are byte-identical within the reviewed clean
  checkout and toolchain.
- Confirm SeaBIOS and OVMF boot the exact promoted ISO and observe its digest.
- Review the locked accounts, command-restricted `doas` policy, OpenRC
  runlevels, default-drop nftables rules, package closure, privileged-file
  allowlist, and zero-listener evidence.
- Review source-manifest coverage, safe archive handling, privacy checks, SBOM
  scope, provenance, and bounded claim language.
- Report licensing, corresponding-source, firmware-notice, export-control, or
  hardware-evidence gaps separately from runtime defects.
- Review every `NOASSERTION` and unreviewed row in the obligations inventory;
  do not interpret a locked digest as legal clearance.

## Reporting results

Bind reports to the reviewed Git commit and, if an ISO was built privately, to
its SHA-256, SHA-384, and SHA-512. State the exact commands and host-tool
versions used. A boot screenshot or video may supplement a report after
privacy review, but it does not replace a machine-readable, digest-bound
hardware observation.

Do not include private keys, tokens, credentials, workstation paths, serial or
asset identifiers, MAC or IP addresses, Wi-Fi identifiers, shell history,
faces, room details, or location metadata in a public report.

Use [GitHub private vulnerability reporting](https://github.com/chasebryan/-wuci-ji/security/advisories/new)
for a sensitive security finding; private reporting is enabled for this
repository. Do not put an exploitable or privacy-sensitive report in a public
issue. General, non-sensitive review results may use the repository issue
tracker. Do not attach the locally built ISO to either route.

## Claim boundary

Use this description:

> WuciOS 2.4.0 Noether Forge source-only external review candidate. Reviewers
> fetch authenticated Alpine 3.24.1 inputs and build locally. No ISO or upstream
> binary payload is distributed by this review lane. The candidate has not
> passed the WuciOS public-release gate and is not an official or production
> release.

Repository-owned Daylight evidence is scoped provenance and claim checking; it
is not external certification. Do not claim production cryptography, general
runtime sandboxing, quantum safety, government approval, independent audit, or
publish/trust authority from this source-review packet.

Wuci-Ji source is provided under the repository Apache-2.0 `LICENSE` and
`NOTICE`. Third-party binary redistribution and encryption export treatment
remain separate legal questions. The generated SPDX document is an inventory
whose license conclusions remain `NOASSERTION`; it is not license clearance.
This engineering review policy is not legal advice or an export
classification.
