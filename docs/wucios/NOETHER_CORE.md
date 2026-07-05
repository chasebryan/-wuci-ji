# Noether Core

Noether Core is the invariant-preserving WuciOS base profile. It is TTY-first, GUI-free, network-minimized, evidence-bound, and designed to preserve explicit security invariants.

Noether Core is the serious WuciOS v2.4 release profile.

## Allowed Classes

- bootloader
- kernel
- init
- shell
- filesystem-tooling
- local-audit-tooling
- hashing-tooling
- signature-tooling
- manifest-tooling
- firewall-tooling
- daylight-tooling
- wuci-ji-tooling
- wuci-prism-tooling
- review-generation-tooling

## Forbidden Classes

- gui
- desktop-environment
- browser
- office-suite
- media-player
- game
- large-theme-pack
- wallpaper-pack
- default-network-service
- unjustified-suid
- unjustified-sgid
- runtime-compiler
- runtime-development-header
- social-media-material
- speculative-claim-material

## Invariants

- GUI absent by default.
- Default network services absent by default.
- Listening ports absent unless explicitly allowed.
- Runtime compilers absent unless explicitly justified.
- Each included component has a component-register entry.
- Each current claim has evidence or is listed as a non-claim.
- Release score is invalid without artifact hash.

## Disqualifiers

- Xfce present.
- Browser present.
- Unapproved listening port present.
- Default SSH server enabled.
- Component without register entry.
- Score without artifact hash.
- Claim of external certification.
- Claim of perfect security.
- Claim of government approval.
