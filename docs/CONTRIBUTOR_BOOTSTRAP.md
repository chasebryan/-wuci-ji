# WUCI Contributor Bootstrap

WUCI-JI is a Linux x86_64 research/proof artifact. Native execution is not
promised on macOS, Windows, arm64, or non-Linux kernels.

## Required Tools

| Workflow | Required tools |
| --- | --- |
| Native build/test | Linux x86_64, GNU `as`, GNU `ld`, Python 3 |
| Full native `make test` | Native build/test tools plus BMI2 and AVX CPU support |
| Linux+QEMU test | Zig, Python 3, `qemu-x86_64` |
| Zig cross-build | Zig |
| Install proof | Python 3, OpenSSH `ssh-keygen`, copied install root key |
| Install signing | OpenSSH `ssh-keygen`, external private install signing key |
| CARROT kernel proof | Linux `unshare` with unprivileged user+network namespaces and seccomp filter support |
| Rust sandbox wrapper build/test | `rustc` |

## Native Linux

```sh
make clean
make test
```

If the host lacks BMI2 or AVX, use the qemu lane instead of full native
`make test`.

## Parallel Proof Runs

The Makefile detects host logical CPUs through `HOST_LOGICAL_CPUS`:

```sh
make host-capacity
make -j$(nproc) high-attestation-proof
```

Independent build and proof targets can use all available cores. Targets that
write shared witness, ledger, CAGE, QCAGE, or release-bundle paths are
serialized by their dependencies, so the project is usable on hosts larger than
dual-core systems without requiring every evidence path to be race-free under
arbitrary parallel execution.

## Linux With QEMU

```sh
make clean
make build-linux
make test-linux
```

If `qemu-x86_64` is not on `PATH`, pass it explicitly:

```sh
make test-linux QEMU_X86_64=/path/to/qemu-x86_64
```

The default qemu CPU is `Haswell-v4` because the current X25519 helper requires
BMI2 and AVX.

## Non-Linux Cross-Build

```sh
make clean
make build-linux
file build/wuci-ji-linux-x86_64
```

This produces a Linux ELF. It does not make WUCI-JI a native macOS or Windows
binary.

## Install And Audit

```sh
mkdir -p ~/.config/wuci-ji
cp install/wuci-install-root.v1.pub ~/.config/wuci-ji/install-root.pub
make install-proof INSTALL_ROOT_KEY=$HOME/.config/wuci-ji/install-root.pub INSTALL_PREFIX=$HOME/.local
~/.local/bin/wuci-ji-audit
```

The install lane is noninteractive and requires a local copied root key. It
does not fetch remote code or claim runtime/PQ assurance.

Release signing is also noninteractive, but it requires the private install
root signing key holder:

```sh
make install-sign-current INSTALL_SIGNING_KEY=/absolute/path/to/root-signing-key
```

The command regenerates the current manifest, signs it in the
`wuci-install-v1` OpenSSH namespace, and verifies the detached signature before
writing it. Do not put private signing keys in the repository.

## Common Failures

- `full native test requires BMI2`: use `make test-linux` with qemu.
- `full native test requires AVX`: use `make test-linux` with qemu.
- `test-linux requires Linux user-mode qemu-x86_64`: install qemu-user or set
  `QEMU_X86_64`.
- `rustc is required`: install Rust before running `make rust-sandbox-build`.
- `wuci-sandbox selftest`: run `make rust-sandbox-test` to build the wrapper,
  install its seccomp no-network filter, and execute `wuci-ji selftest` under
  the wrapper.
- `kernel seccomp no-network probe did not deny socket creation`: the host
  kernel or policy does not support the CARROT proof lane as configured.
- `install root key`: copy `install/wuci-install-root.v1.pub` to the configured
  local path before running install proof targets.

## Compatibility Matrix

| Host | Supported path |
| --- | --- |
| Linux x86_64 with BMI2/AVX | Native build and full native tests |
| Linux x86_64 without BMI2/AVX | Native non-X25519 targets plus qemu test lane |
| macOS or other non-Linux host | Zig cross-build only; run Linux ELF under a Linux runner |
| arm64 Linux | Cross-build/run through an x86_64 Linux path; native execution is not claimed |
| Windows | Not claimed |
