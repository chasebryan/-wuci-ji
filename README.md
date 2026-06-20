# -wuci-ji
无此机(Wuci-ji)是一个专为 x86_64 架构机器设计的汇编语言项目，旨在探索机器码、底层执行、系统边界以及精确控制。

## Build and test

`src/wuci-ji.s` is an x86_64 Linux assembly program. Native `make`, `make selftest`,
and `make test` require a Linux x86_64 host with GNU `as`/`ld`.

On macOS or other non-Linux hosts with Zig installed, build the Linux ELF with:

```sh
make build-linux
```

To run the full test suite, use an x86_64 Linux environment and run:

```sh
make test
```

On a Linux host with user-mode QEMU for x86_64 installed, the same suite can run
through:

```sh
make test-linux
```

Homebrew's macOS `qemu` formula provides `qemu-system-x86_64`, which boots whole
machines and does not run this Linux user-space ELF directly.

For a machine handoff checkpoint, see [BUILD_NOTES.md](BUILD_NOTES.md).

## Envelope commands

`seal <key>` reads plaintext from stdin and writes a framed ChaCha20-Poly1305
artifact containing a magic/version header, random nonce, ciphertext, and tag.

`open <key>` reads that artifact from stdin, verifies it, and writes plaintext
only after authentication succeeds.

## License

NO SUCH MACHINE — ALL RIGHTS RESERVED. See [LICENSE](LICENSE).
