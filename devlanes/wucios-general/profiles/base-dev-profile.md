# WuciOS Base Developer Profile

Purpose: define a minimal developer-usable environment profile for future
WuciOS work.

This profile is planning-only. It does not install packages, modify a rootfs, or
authorize package-manager behavior.

## Planned Categories

- Shell and base utilities: readable shell, core file tools, process inspection,
  text inspection, environment inspection.
- Editor tooling: minimal terminal editor support and configuration guidance.
- Compiler/toolchain support: future package set for C/C++ and related build
  workflows.
- Source-control tooling: future Git-oriented workflow support.
- Scripting support: conservative shell and Python planning, stdlib-first where
  practical.
- Documentation tools: man pages, local docs, changelog and README workflows.
- Archive/hash tools: tar, gzip, xz, zip planning, and SHA-256/SHA-384/SHA-512
  verification support.
- Network tools: requires separate authorization before enabling, installing,
  probing, or validating network behavior.
- Package-manager behavior: requires separate authorization before package
  installation, repository use, update behavior, or package-manager correctness
  claims.
- Service/init behavior: future work only; no init correctness or service
  behavior is claimed by this profile.
