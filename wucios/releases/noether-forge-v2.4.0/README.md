# WuciOS 2.4.0 - Noether Forge

Noether Forge is the internally maintained Alpine realization of the WuciOS
v2.4 Noether Core profile. It is a TTY-first, GUI-free live ISO built from an
authenticated Alpine 3.24.1 x86_64 standard image and an exact signed APK
closure.

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

## External review

The public review lane is source-only. Reviewers fetch the pinned Alpine inputs
from their recorded upstream locations and build locally; this repository does
not publish or mirror the generated ISO or upstream binary payloads. This is
not an Alpine Linux project endorsement. See
[`docs/wucios/NOETHER_FORGE_EXTERNAL_REVIEW.md`](../../../docs/wucios/NOETHER_FORGE_EXTERNAL_REVIEW.md)
and [`external-review.json`](external-review.json).

The tracked [`third-party-obligations.json`](third-party-obligations.json) is a
deterministic inventory generated only from the locked Alpine artifact records.
Unknown source, license, notice, firmware, redistribution, and export-review
facts remain `NOASSERTION` or explicitly unreviewed. It is a review aid, not
legal clearance. A schema and synthetic fixture also define a digest-bound
physical-hardware observation format without claiming that hardware validation
has occurred.
