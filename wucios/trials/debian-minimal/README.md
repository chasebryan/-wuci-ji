# Debian Minimal Euclid Phase 2 Probe

This directory contains the tracked Debian minimal build feasibility probe for
WuciOS v2.4 Euclid Trial Phase 2.

Default mode is `SAFE_DETECT_ONLY`. It detects local tooling, including
`debootstrap`, `fakeroot`, and `fakechroot`, then writes evidence under
`build/wucios/trials/debian-minimal/phase-2/`.

Build attempts require:

```sh
WUCIOS_EUCLID_ALLOW_ATTEMPT=1 make wucios-euclid-trial-phase-2-attempt
```

This candidate remains unranked. WuciOS does not select a substrate in Phase 2.
