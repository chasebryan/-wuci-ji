# Wuci-OS QEMU Boot Trace - 2026-06-30

Status: local boot-smoke pass.

Artifact:

```text
build/wuci-os/final/Wuci-OS-x86_64-musl.iso
sha256: d64693429bf18b3be13e6b8a9067687115baa43bb77a45aabfad6822b3356df4
bytes: 1725038592
```

Command:

```sh
timeout 150s /usr/libexec/qemu-kvm \
  -m 2048 \
  -smp 2 \
  -machine pc,accel=tcg \
  -cdrom build/wuci-os/final/Wuci-OS-x86_64-musl.iso \
  -boot d \
  -nographic \
  -serial mon:stdio \
  -no-reboot \
  -net none
```

Observed checkpoint excerpt:

```text
Booting from DVD/CD...
ISOLINUX 6.03 2014-10-06
Wuci-OS live profile
Wuci-OS x86_64-musl base
wuci-os-live login: wj (automatic login)
Wuci-OS live profile active. Run: wuci-status | wuci-attest | wuci-enter
WJ>_
```

Result:

```text
qemu_boot_smoke: pass
prompt_reached: WJ>_
```

Boundary:

This trace proves that the local final ISO reached the Wuci prompt in QEMU.
It does not by itself clear the full release gate. Remaining release-gate
work includes package-closure evidence, manifest-bound boot trace evidence,
hardware boot trace evidence, final manifest signature evidence, and witness
ledger entry evidence.
