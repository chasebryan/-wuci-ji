# Noether Forge initramfs patch notice

`initramfs-patch-spec.json` contains WUCI-JI modifications intended to be
inserted into the Alpine mkinitfs `initramfs-init.in` program. The patch
specification and those replacement fragments are treated as
`GPL-2.0-only`; the repository-wide Apache-2.0 license does not override this
release-scoped notice. The corresponding license text is in
`LICENSES/GPL-2.0-only.txt`.

The authenticated upstream source is Alpine mkinitfs 3.14.0-r0 as carried in
the locked Alpine Linux 3.24.1 standard ISO. The exact upstream 3.14.0 archive
and `initramfs-init.in` template are digest-recorded in the patch specification;
substituting `@VERSION@` with `3.14.0-r0` yields the exact locked 30,037-byte
`/init` member. The repository does not copy the replaced upstream source
spans. `alpine-input-lock.json` identifies those spans by member-relative
offset, length, and SHA-256, and binds the complete source and modified member
digests.

The modified init script produced during a local build remains subject to the
upstream program's license and this modification notice. This source-only
review repository does not provide legal clearance for binary redistribution.
Anyone distributing a generated ISO must independently satisfy applicable
source, notice, license, trademark, export, and other obligations.
