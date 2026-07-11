# WuciOS 2.4.0 - Noether Forge

Noether Forge is the internally maintained Alpine realization of the WuciOS
v2.4 Noether Core profile. It is a TTY-first, GUI-free live ISO built from
authenticated Alpine 3.24.1 x86_64 standard and extended release media plus an
exact signed and whole-file-digest-locked 52-APK closure.

This implementation pass follows a repository-maintainer decision to replace
the legacy ISO lane with an Alpine build. The historical Phase 3C closeout
remains a true historical record; it did not itself open this implementation
scope or grant binary publication authority.

The pipeline separates networked input acquisition from the offline build:

```sh
make wucios-noether-forge-fetch
make wucios-noether-forge-build
make wucios-noether-forge-verify
make wucios-noether-forge-internal
```

The internal readiness gate does not tag, sign with a production key, append to
an operated witness, publish, or substitute QEMU for reference-hardware boot
evidence.

The closure uses 49 APK members from the GPG-authenticated extended release
media and three exact post-release Alpine APKs. Libexpat 2.8.2-r0 incorporates
upstream's 2.8.2 security fixes; openrc/openrc-user 0.63.2-r0 retain the current
reviewed compatible pair. Those three official versioned URLs are mutable
availability locators even though size, SHA-256, SHA-512, package identity, and
the exact Alpine 6165 signing key are enforced. If Alpine removes or changes a
locator, fetch fails closed. Moving all 52 packages into authenticated future
point-release media remains the preferred maintenance path.

## External review

The public review lane is source-only. Reviewers fetch the pinned Alpine inputs
from their recorded upstream locations and build locally; this repository does
not publish or mirror the generated ISO or upstream binary payloads. This is
not an Alpine Linux project endorsement. See
[`docs/wucios/NOETHER_FORGE_EXTERNAL_REVIEW.md`](../../../docs/wucios/NOETHER_FORGE_EXTERNAL_REVIEW.md)
and [`external-review.json`](external-review.json).

The tracked [`third-party-obligations.json`](third-party-obligations.json) is a
deterministic inventory generated from the locked Alpine artifact records and
the initramfs patch provenance specification.
Unknown source, license, notice, firmware, redistribution, and export-review
facts remain `NOASSERTION` or explicitly unreviewed. It is a review aid, not
legal clearance. A schema and synthetic fixture also define a digest-bound
physical-hardware observation format. Its mutable fields use a closed,
size-bounded vocabulary rather than free prose, and verifier success establishes
record consistency only; it does not claim that hardware validation has
occurred.

Noether Forge modifies the authenticated `/init` member derived byte-for-byte
from Alpine mkinitfs 3.14.0-r0 `initramfs-init.in`, whose upstream package
metadata declares `GPL-2.0-only`. The separately marked GPL-2.0-only
`initramfs-patch-spec.json` contains only WUCI-JI-authored replacement
fragments. Replaced upstream spans are referenced only by member-relative
offset, length, and SHA-256. The exact upstream archive, source template, and
instantiated member are digest-bound; see `PATCH-NOTICE.md`. This engineering
provenance is not legal advice, a license conclusion for other components, or
redistribution clearance. This project does not distribute the generated ISO,
and proposed binary distribution remains prohibited pending independent review
of corresponding-source, notice, license, trademark, export, firmware, and
other obligations.
