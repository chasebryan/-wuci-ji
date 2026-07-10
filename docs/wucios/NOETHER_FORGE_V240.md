# WuciOS 2.4.0 - Noether Forge

Noether Forge is the internally maintained Alpine implementation of the WuciOS
v2.4 Noether Core profile. It replaces the legacy Void/Xfce workstation ISO
lane; the old image is historical input only and is never renamed or promoted
by this pipeline.

## Release identity

- Product: WuciOS
- Version: 2.4.0
- Codename: Noether Forge
- Profile: Noether Core
- Substrate: Alpine Linux 3.24.1 x86_64
- Artifact: `WuciOS-v2.4.0-Noether-Forge-x86_64.iso`
- ISO volume: `WuciOS 2.4 Noether Forge`

## Runtime shape

Noether Forge is a live, TTY-first reviewer environment. It has no GUI,
browser, desktop environment, default network service, listening port, runtime
compiler, or development-header package.

The live identities are:

- `wj`: UID 1000, local-console operator, not a `wheel` member.
- `wj_low`: UID 1001, no administrative group membership.
- `root`: no direct login.

All three password hashes are locked. `wj` is autologged in only on the live
local console and receives passwordless `doas` authority restricted to reading
the nftables ruleset, powering off, and entering the `wj_low` shell.
This is an explicit ephemeral live-console trust boundary, not an
installed-system credential model. `wj_low` cannot use `doas`.

The runtime loads a real nftables policy with input, forward, and output set to
default-drop and loopback-only allowances. BIOS and UEFI validation boot QEMU
with no network device. Those measured properties do not constitute a general
runtime sandbox or OS-containment claim.

## Real reviewer tools

The ISO carries and tests:

- the current statically linked Wuci-Ji assembly binary;
- the actual stdlib Python Daylight claim scanner;
- the actual keyless Wuci-Prism inspector;
- OpenSSL and Alpine's signed APK verification surface;
- a runtime verifier that inventories accounts, packages, services, listeners,
  routes, interfaces, privileged files, nftables rules, modules, and the exact
  boot-media SHA-256.

Positive and negative Daylight and Wuci-Prism fixtures execute during boot. A
precomputed status file cannot cause the runtime PASS marker.

## Build and maintenance

Input acquisition is the only networked action:

```sh
make wucios-noether-forge-fetch
```

It downloads only locked files, checks the Alpine ISO SHA-256 and SHA-512,
verifies the detached GPG signature against fingerprint
`0482D84022F52DF1C4E7CD43293ACD0907D9495A`, verifies every APK signature with
keys extracted from that authenticated ISO, and proves the exact package
closure can install offline.

The build command performs no network operations and consumes only the pinned
local cache; this is a workflow property, not OS-level network isolation:

```sh
make wucios-noether-forge-build
```

It builds the hybrid ISO twice with a locked `SOURCE_DATE_EPOCH`, replays the
authenticated BIOS/UEFI boot equipment with xorriso, prunes unused APK blobs,
and promotes only byte-identical results. The signed upstream APK index remains
intact; it is broader catalog metadata, while exactly 52 locked APK payloads are
present on the medium and installed at boot.

Full internal verification is:

```sh
make wucios-noether-forge-verify
```

That command re-inspects the exact ISO, boots it from the virtual CD in both
SeaBIOS and OVMF/UEFI under TCG, verifies the guest-observed `/dev/sr0` digest,
runs the runtime contract and interactive Wuci-Ji checks, requests clean
poweroff, and writes the internal readiness packet.

Generated outputs live under:

```text
build/wucios/noether-forge-v2.4.0/release/
```

After a successful build, launch the same TTY-first image interactively with:

```sh
make wucios-noether-forge-launch
```

The launch path attaches the serial console directly to the terminal and adds
no virtual network device. The ISO autologs into the locked-password `wj` live
console. Run `wuci-poweroff` for a clean exit.

To maintain the release, update the Alpine and package locks deliberately,
rerun the input verifier, rerun both complete builds, and rerun both firmware
boots. The pipeline never performs an implicit rolling update.

## Source-only external review

The source, build pipeline, pinned upstream identities, schemas, tests, and
bounded review instructions may be published for external review without
publishing the generated ISO or upstream binary payloads. Reviewers fetch the
authenticated Alpine inputs and build locally. See
[Noether Forge source-only external review](NOETHER_FORGE_EXTERNAL_REVIEW.md).

This source-review lane is not a GitHub Release, an official WuciOS release, or
permission to redistribute a reviewer-built ISO. The authenticated Alpine
substrate does not imply Alpine Linux project endorsement.

## Publication boundary

An internally ready ISO is not automatically a public release. These holds
remain separate and fail closed:

- clean release-source commit and annotated tag;
- boot evidence from the reference physical hardware;
- production release-key signature;
- operated WUCI-WITNESS inclusion proof;
- explicit publication authorization.

No build or verification command creates a tag, production signature, witness
entry, GitHub release, or upload.
