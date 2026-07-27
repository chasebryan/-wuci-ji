# WuciOS Lovelace Laboratory

Lovelace Laboratory is the separate WuciOS research/development and defensive
analysis profile. It contains programming toolchains, NOXFRAME, and pinned
Ghidra headless support that are deliberately forbidden from Noether Core.
It is non-default, non-release-authoritative, and not a production profile.

The checked-in source implements the builder, host supervisor, guest overlay,
strict profile contract, and unit/static tests. That source state is not by
itself a built or boot-validated artifact. Report each runtime property only
after its named command passes against the current output.

The security and residual-risk contract is
[Lovelace Laboratory containment boundary](LOVELACE_CONTAINMENT_BOUNDARY.md).

## Host requirements

The build lane requires a complete Git worktree with its `.git` metadata,
Linux x86_64, Python 3, Git, GNU `as`, `ld`, `chown`, `cp`, `find`, `stat`,
and `cmp`, `gpg`, xorriso 1.5.8.pl02, `qemu-img`, e2fsprogs 1.47.0 (`mke2fs`,
`debugfs`, and `e2fsck`), and fakeroot 1.33. GNU `cp` must support
`--sparse=always` and `--reflink=auto`. Those exact filesystem-tool versions, the checked-in
`mke2fs.conf`, fixed filesystem geometry, and post-build metadata
normalization are part of the byte-reproducibility contract. Functional boot
and Ghidra tests additionally require `qemu-system-x86_64`. A defensive
hostile cell also requires `/usr/bin/bwrap`, a usable `/dev/kvm`, a non-root
host-side QEMU process, QEMU sandbox support, and the supervisor's resource
gates. Optional hostile payload ingress additionally requires the exact trusted
root-owned `/usr/sbin/mke2fs` and `/usr/sbin/debugfs` paths.
Missing any hostile-cell layer causes that mode to fail closed; it never falls
back to TCG.

Every interactive launch and launch plan through the digest-bound `wuci-lab`
supervisor requires the exact `/usr/bin/qemu-system-x86_64` executable to be
regular, root-owned, executable, and non-setuid/non-setgid. The builder-local
functional TCG smokes use a separately version-checked host-tool path and do
not validate that interactive supervisor path. The canonical hostile smoke
additionally requires exact root-owned `/usr/bin/qemu-img` and `/usr/bin/bwrap`.
`/dev/kvm` must be a securely configured character device that is readable and
writable by the non-root operator.

The guest intentionally permits the `lab` account to obtain guest root through
`doas`. The hostile cell therefore assumes the entire guest, including guest
root, is attacker controlled. Guest-local UID separation is not a containment
layer, and “unprivileged QEMU” refers only to the host-side QEMU process.

By default, inputs are cached under
`build/wucios/inputs/lovelace-laboratory-v0.1.0/` and outputs are written under
`build/wucios/lovelace-laboratory-v0.1.0/`. Override those ignored roots with
`LOVELACE_CACHE` and `LOVELACE_OUTPUT` when needed.

The builder normally resolves xorriso only from the fixed system path. If an
operator has installed the exact supported version in a private prefix because
system-package installation is unavailable, set `LOVELACE_XORRISO` to its
absolute executable path. The builder resolves the path, rejects foreign-owned,
writable, set-ID, non-executable, or wrong-version files, and never uses that
variable for another tool.

## Acquire, verify, and build

First run the network-free source contracts:

```sh
make wucios-lovelace-source-test
```

Only the following target acquires runtime inputs from the network:

```sh
make wucios-lovelace-fetch
```

It explicitly fetches the authenticated Alpine boot material, exact Alpine
v3.24 package indexes and APK closure, and the digest-locked official Ghidra
archive. It also regenerates `package-lock.json`; review any resulting lock
diff. Fetch does not authorize redistribution of those third-party binaries.

Once the cache exists, the following commands perform no network requests:

```sh
make wucios-lovelace-inputs
make wucios-lovelace-build
make wucios-lovelace-reproducibility
make wucios-lovelace-structural-verify
```

`inputs` verifies locked sizes, hashes, Alpine signatures, package identities,
and the Ghidra archive digest. `build` performs an offline, no-script APK
installation and creates an immutable sparse ext4 base image.
`reproducibility` performs two complete builds in independent output roots,
requires byte-for-byte equality for the base image, kernel, initramfs, and
pre-validation manifest, and writes local evidence only after both builds pass.
`structural-verify` checks the exact artifact digests, ext4 structure, embedded
runtime marker, programming tools, NOXFRAME, and Ghidra headless path without
booting. Runtime evidence and its manifest binding cover the exact base image,
kernel, initramfs, package lock, and source-input vector; replacing any member
invalidates the evidence. These commands do not create release authority or
prove containment.

## Functional guest validation

The boot smoke uses an explicit temporary qcow2 overlay, no virtual network
device, and TCG:

```sh
make wucios-lovelace-boot-smoke
```

It boots the guest, runs the freshly and privately assembled native Wuci-Ji
self-test, and exercises Python 3, C, C++, x86_64 assembly, Rust, and Go. It
checks that NOXFRAME and the Ghidra headless entry point are present, then
verifies that the immutable base-image digest did not change. TCG here is
functional evidence only, not an untrusted-code isolation boundary. Functional
TCG uses the pinned QEMU CPU model
`Broadwell-v4,pcid=off,x2apic=off,tsc-deadline=off,invpcid=off,spec-ctrl=off`;
the runtime producer rejects QEMU feature-filter warnings and records the exact
model in its evidence. This coherent AVX2/BMI2-capable surface avoids relying
on QEMU's synthetic `max` CPU while retaining the native Wuci-Ji requirements.
Every functional producer also rejects kernel panic, oops, soft-lockup,
general-protection-fault, ext4-error, and buffer-I/O-error diagnostics from the
complete bounded console transcript and records their absence in the runtime
evidence. An acceptance marker cannot override one of those failures.
Every functional runtime record retains the complete bounded raw console bytes
in `console_transcript_base64` using canonical RFC 4648 base64, together with
`console_bytes`, `console_sha256`, `console_tail`,
`console_ready_line_end_offset`, and `command_dispatch_offset`. Verification
strictly decodes and canonically re-encodes the retained transcript, recomputes
its byte count, SHA-256, and diagnostic tail, rescans the complete transcript,
and rechecks unique exact-line marker order. Any other complete line beginning
with `LOVELACE_LABORATORY_BOOT ` is a conflicting boot marker and fails the
record. Guest-command result markers must begin at or after the recorded
dispatch offset. After QEMU exits, the producer drains stdout to observed EOF
for at most five seconds before making a complete-transcript claim; evidence
requires `console_eof_observed: true` and
`console_drain_timeout_seconds: 5`. Missing EOF or a drain timeout fails rather
than accepting a prefix transcript. The raw functional transcript is capped at
8 MiB; the retained local JSON evidence remains subject to its separate
bounded-read ceiling. A digest, tail, or declared marker list without the
matching retained bytes is not accepted.
Functional TCG appends `nosoftlockup` because host scheduling pauses do not
provide meaningful guest soft-lockup timing under software emulation; bounded
wall-clock deadlines, exact markers, and exit status remain enforced, and the
exact kernel argument vector is recorded in evidence. The narrower setting
retains the hard-lockup detector where the emulated CPU exposes it. The KVM
hostile profile does not append `nosoftlockup`. Both launchers inherit the
release's ordered `root=/dev/vda rw rootfstype=ext4
console=ttyS0,115200 panic=10` contract; omitting `rootfstype=ext4` can prevent
Alpine's modular ext4 driver from loading, while omitting `panic=10` can leave
the initramfs blocked in an emergency shell.
The smoke does not claim that the opt-in NOXFRAME execution broker was
exercised.

The separate Ghidra acceptance command imports the committed benign ELF
fixture through `analyzeHeadless` in another volatile, offline TCG guest:

```sh
make wucios-lovelace-ghidra-headless
```

It does not validate graphical Ghidra and does not make Ghidra a containment
layer. The acceptance command uses the installed, pinned
`LovelaceGhidraSemanticCheck.java` post-script through the exact
`-scriptPath` and `-postScript` arguments. That script fails unless the current
program is the expected imported `ghidra-smoke` ELF with MD5
`7af3bf4a75edc982a574d9e0290f96fd` and SHA-256
`446c9e5b46a3eb21a7e09f2794bdd58c66491ebd927bc67c36b212d7da08eb8e`,
executable format `Executable and Linking Format (ELF)`, language
`x86:LE:64:default`, headless analysis enabled, the program marked analyzed,
no headless-analysis timeout, a nonzero function count, at least eight
instructions, and the embedded
`lovelace-ghidra-smoke\n` fixture message. Its source and SHA-256 are bound in
the artifact's fixture record. The normal acceptance requires the exact
`LOVELACE_GHIDRA_SEMANTIC_PASS` line before the exact `status=0` and final pass
lines. The hostile smoke passes its fresh per-run challenge to the same
post-script and requires `LOVELACE_GHIDRA_SEMANTIC_PASS <challenge>` as a
unique post-dispatch result, so a static semantic marker cannot satisfy hostile
evidence.

The complete headless process has a bounded 600-second deadline; the command
does not use Ghidra's per-file analysis timeout because that option may continue
after an interrupted partial analysis. The headless heap is explicitly capped
at 2 GiB. The NOXFRAME broker additionally validates 1..8 online vCPUs and sets
the inherited aggregate CPU-time ceiling to `670 * online-vCPU` seconds. That
finite fallback stays beyond NOXFRAME's 660-second outer wall deadline even for
a multithreaded JVM, so CPU accounting cannot shorten the documented wall-time
window. Ghidra receives `/dev/null` as stdin.
The acceptance creates private `projects`, `home`, `config`, `cache`, and `tmp`
directories under one mode-0700 temporary work root and points `HOME`,
`XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, and `TMPDIR` into them. It also confines
Java user-home and temporary state there through `JAVA_TOOL_OPTIONS` settings
for `user.home` and `java.io.tmpdir`. The same fixed environment passes
`-XX:-TieredCompilation`, disabling HotSpot's C1/tiered lane while retaining
C2-compiled execution. This avoids the C1 failure mode observed under the
pinned TCG CPU without falling back to `-Xint`, which cannot complete class
discovery inside the existing 600-second bound. This is a bounded runtime
compatibility setting, not a general JVM safety claim. The legacy guest paths
`/home/lab/.config/ghidra` and `/var/tmp/lab-ghidra` must be absent both before
and after analysis. An exit/signal trap removes the private root on failure;
success additionally requires an empty deleted-project root, explicit removal
of the complete work root, and confirmation that it is absent before the final
pass marker. A timeout, nonzero exit, missing or conflicting semantic result,
project residue, legacy-path write, or cleanup failure cannot promote evidence.
Bounded escaped console diagnostics are included in a failed producer error.

Every reproducibility or runtime-evidence producer holds the private output
lock across verification, the complete build or VM run, immutable-base recheck,
and the evidence/manifest transaction. A concurrent producer fails after the
bounded lock wait instead of racing another VM or publishing mismatched
evidence. Run these targets serially. This artifact-output lock does not
coordinate the repository-wide `make clean` target, which deletes the complete
`build/` tree. Never run `make clean` concurrently with a Lovelace build,
reproducibility run, runtime producer, or evidence update. The commands update
local evidence under the ignored `release/evidence/` output directory; inspect
the emitted JSON before making a local-validation claim.

Exercise the actual opt-in NOXFRAME guest broker across the same six language
routes and its bounded headless-Ghidra route in a separate volatile, offline
TCG guest:

```sh
make wucios-lovelace-noxframe-smoke
```

The Ghidra route passes only when the process exits zero and emits exactly one
`LOVELACE_NOXFRAME_GHIDRA_SEMANTIC_PASS` line before the exact
`noxframe-ghidra-headless:ok` completion line; a zero exit by itself is
insufficient. NOXFRAME caps raw combined broker output at 64 KiB and renders
every byte other than TAB, LF, and printable ASCII as a lowercase `\xNN`
escape. Printable text remains unauthenticated and can imitate prompts or
status messages. This is broker/functionality evidence, not a NOXFRAME or
Ghidra containment claim. Test an ephemeral persistent overlay across two
complete boots with:

```sh
make wucios-lovelace-persistent-round-trip
```

That target writes a deterministic proof token during the first boot, reads it
during the second, checks the qcow2 structure, removes the temporary test
state, and confirms that the immutable base digest did not change. It does not
exercise or modify an operator's named persistent overlay.

The one live-connectivity acceptance target is separately explicit:

```sh
make wucios-lovelace-network-smoke
```

The Internet lane is fixed to this QEMU user-network argument and guest
topology:

```text
user,id=wuci-net,restrict=off,ipv6=off,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15
guest IPv4: 10.0.2.15/24
gateway:    10.0.2.2
DNS proxy:  10.0.2.3
```

The guest resolver file must be exactly these two lines, including the final
line feed:

```text
nameserver 10.0.2.3
options timeout:2 attempts:3
```

Its SHA-256 is
`c235c3d266651c3825b8d5974a0d1ca99a8d592ce1d31e847ca691c97f8866f7`.
The QEMU argument verifier requires the exact user-NAT backend and virtio NIC,
forbids `hostfwd`, and requires a volatile qcow2 disk backed by the immutable
raw base. Evidence retains that parsed `launch_contract`, including TCG,
`q35`, the exact netdev and NIC, absent host forwarding, qcow2 root format,
temporary-overlay use, no direct writable base, and no QEMU snapshot flag.
The verifier compares the complete QEMU argument vector with a freshly
generated expected vector. It rejects every extra argument, including legacy
`-net` forms and `-readconfig`; recognizing the expected options as a subset is
insufficient. Guest setup must produce the exact line:

```text
LOVELACE_LABORATORY_BOOT profile=lovelace-laboratory storage=host-selected network=internet
```

`network=unavailable`, a different address, route, resolver, boot line, network
backend, or disk mode fails the evidence gate. The fixed topology avoids an
undeclared dependency on packet-socket kernel modules, but it does not create a
network boundary.

A pass then requires `ss -H -lntup` itself to exit successfully and its output
to contain zero records. The `guest_listening_sockets` evidence therefore has
`command_succeeded: true` and an empty `observed` array. It means only that this
command observed no TCP or UDP listening sockets visible to the guest lab user
at that probe time. An empty result from a failed `ss` command is rejected, and
the observation says nothing about another protocol, a later listener, or an
application that initiates outbound connections.

The HTTPS probe resolves the unique `sha256-digest` sidecar record from the
artifact-bound shared Alpine lock. It downloads that one URL into a private
temporary guest file. Curl must exit zero before the file is inspected. The
entire response must have exactly the locked sidecar byte count and SHA-256 and
must contain exactly the locked semantic digest line; a prefix match, pipeline
success, truncated transfer, same-size altered body, or any extra response byte
fails. Evidence records the resolved URL as well as
`expected_response_bytes`, `expected_response_sha256`, an equal maximum-response
bound, a 15-second connection timeout, and a 90-second transfer timeout. The VM
has a 1,500-second outer deadline. The complete bounded console record described
above is then independently decoded and rechecked for the exact Internet boot
line, ordered acceptance markers, and result-marker placement after command
dispatch.

The probe command runs inside a parenthesized guest-shell subshell. Its local
`set -e` therefore terminates only that probe on failure and returns control to
the interactive outer shell. The already queued `doas poweroff -f` command can
then execute promptly, allowing the VM runner to finish and record a failure
without leaving the guest at an interactive prompt. A failed probe emits no
Internet pass marker.

This command uses the network and is never a dependency of input verification,
build, structural inspection, or an offline functional test. A pass supports
only a local, artifact-bound observation that this exact guest received this
exact HTTPS response through this QEMU user-NAT configuration. It does not
establish general Internet availability, network isolation, anonymity,
privacy, containment, release authority, or safety for arbitrary malicious
code. Endpoint or path failure remains a failed live dependency and never
falls back to a pass.

## Defensive-cell control-presence validation

Run the canonical KVM-backed hostile-cell smoke only on a deliberately prepared
local host:

```sh
make wucios-lovelace-hostile-smoke
```

The command fails closed unless the host has a securely configured, usable
`/dev/kvm`, the operator is non-root, and the exact root-owned,
non-setuid/non-setgid `/usr/bin/qemu-system-x86_64`, `/usr/bin/qemu-img`, and
`/usr/bin/bwrap` executables pass the supervisor's trust checks. The guest uses
KVM plus the outer bubblewrap namespace and QEMU sandbox, explicit resource
bounds, volatile storage, and no network device, persistent state, host share,
or host-device passthrough into the guest. The outer boundary binds only the
exact `/dev/kvm` device required by QEMU. Guest acceptance commands are not
dispatched until the producer observes the exact unprivileged,
capability-empty, no-new-privileges, seccomp-filtered QEMU process and its
separated namespace identities, the exact hostile boot line, and one ordered
console-ready line. The runner then generates a 256-bit challenge and
materializes the fixed commands; the challenge must not appear in the
pre-dispatch transcript, supervisor arguments, environment, or plan. Results
must be unique, complete, newline-terminated full-transcript lines that begin
at or after dispatch. A pass also requires the exact observed QEMU PID and
`/proc` start-time identity to be gone or reused after the smoke's normal
supervisor unwind; its executable device and inode are bound into the
observation. The producer incrementally rejects a bounded complete console
transcript containing a configured kernel-panic, soft-lockup, exception, ext4,
or block-I/O diagnostic before guest-command dispatch and records
`runtime.forbidden_diagnostics_absent: true` only after the full run passes.
It also requires the console-ready marker within 180 seconds after the
producer first observes the exact constrained QEMU process. Pre-QEMU artifact
verification and private-overlay materialization remain bounded by the
separate 1,800-second overall smoke timeout and do not consume the guest boot
allowance.
The local hostile evidence JSON retains the complete escaped-ASCII transcript,
its byte count and digest, the dispatch offset, and the 12,000-character
diagnostic tail. Evidence validation rechecks exact plan/marker ordering,
pre-dispatch challenge absence, complete result-line offsets, terminal-byte
policy, and forbidden diagnostics over that retained transcript. This raw
runtime evidence remains local under the ignored build root and is not a
public-evidence profile.

The artifact-bound KVM smoke drives the supervisor through a pipe and validates
normal guest poweroff, process disappearance, and volatile-overlay cleanup. It
does not exercise a real operator TTY or signal termination. The handled-signal
restoration and `TCSAFLUSH` handoff are separately locally validated by the
source test's real-PTY regressions; they are implemented controls, not claims
made by the artifact-bound runtime evidence.

The hostile supervisor merges QEMU stderr with the serial stream and renders
only printable ASCII, line feeds, and tabs to the host; carriage-return pairs
are normalized and every other byte is shown as `\xNN`. ESC, C1, DEL,
non-ASCII bytes, and C0 controls other than the explicitly allowed LF and TAB
are never forwarded, and the cell is terminated after more than 32 MiB of raw
console output. This blocks OSC/CSI/DCS and related terminal-parser control
paths. Operator input uses a separate nonblocking one-way pipe with a 1 MiB
pending-input limit; the child does not inherit the host terminal as file
descriptor 0. On normal/error unwind and handled `SIGHUP`, `SIGINT`, `SIGQUIT`,
`SIGTERM`, or `SIGTSTP`, the relay treats restoration failure as fatal, drains
the console for at most five seconds after leader exit, requires the dedicated
process group to disappear, closes relay pipes, and finally restores terminal
state while flushing pending input before host-shell handoff. At console EOF,
it waits at most 0.1 seconds to confirm a just-exited leader through waitpid;
a leader still live after that bounded confirmation fails closed.
These cleanup properties do not cover `SIGKILL`, host-process destruction,
kernel failure, or power loss. Printable guest text is still unauthenticated
and can imitate a prompt or status message. The functional developer and
analysis consoles remain raw trusted-development paths and are not
hostile-code boundaries.

This smoke executes only repository-fixed benign fixtures. A passing result
records local layered-control presence for the exact artifact; it does not
establish perfect isolation, make arbitrary malware safe, or grant release
authority. The result remains `NOT_MEASURED` until the command passes locally
and emits `release/evidence/hostile-kvm-cell.json` for the current artifact
binding. The QEMU identity-disappearance and volatile-overlay checks cover
normal supervisor unwind in the artifact evidence; listed handled-signal
cleanup is source-tested separately. Neither path claims cleanup after
`SIGKILL`, host-process destruction, host crash, or power loss. Process-group
checks cover descendants that remain in the dedicated launch group; they do not
prove absence of a process that escaped that group after compromise.

Run the distinct fixed-benign read-only payload-ingress gate separately:

```sh
make wucios-lovelace-hostile-payload-smoke
```

It attaches only the committed 44-byte
`wucios/fixtures/lovelace/hostile-payload.txt` fixture, not an
operator-selected sample. A pass requires the supervisor and guest to verify
the exact payload and canonical manifest bytes, a guest read-only mount, a
failed guest-root write with no probe residue, and normal-unwind cleanup of the
payload operation root and volatile overlay. The resulting
`release/evidence/hostile-payload-ingress.json` is distinct from
`release/evidence/hostile-kvm-cell.json`, carries no isolation claim, and cannot satisfy
the ordinary hostile-cell gate or establish malware safety.

## Status, storage, and launch

Inspect the current image binding and host capability before launching:

```sh
make wucios-lovelace-status
make wucios-lovelace-launch-plan
```

The launch defaults are `developer`, `volatile`, `none`, and `auto` for profile,
storage, network, and accelerator. Volatile sessions use a private qcow2
overlay and remove it on normal exit or ordinary error unwind. Handling of
`SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM`, and `SIGTSTP` is specific to the
hostile supervisor and covers its payload/overlay allocation and
materialization boundary plus its active escaped-console relay. Non-hostile
process termination, `SIGKILL`, host crashes, or storage failure can prevent
cleanup, so stale private state may require operator review. Cleanup is not an
anti-forensics or storage-remanence guarantee.

The Make entry point also accepts `LOVELACE_MEMORY_MIB` and `LOVELACE_CPUS`.
The default is 4096 MiB and two vCPUs; use at least 6144 MiB for the
runtime-validated Ghidra headless envelope. The dedicated Ghidra and NOXFRAME
functional gates both select that 6144 MiB envelope automatically because each
performs a pinned headless Ghidra analysis under TCG.

Create and re-inspect a named persistent overlay explicitly:

```sh
make wucios-lovelace-overlay-create LOVELACE_OVERLAY=workbench
make wucios-lovelace-overlay-inspect LOVELACE_OVERLAY=workbench
make wucios-lovelace-launch-plan \
  LOVELACE_STORAGE=persistent LOVELACE_OVERLAY=workbench
make wucios-lovelace-launch \
  LOVELACE_STORAGE=persistent LOVELACE_OVERLAY=workbench
```

Overlay creation refuses overwrite. The supervisor stores private overlay
state under `build/wuci-lab/`, holds an exclusive launch lock, and binds the
overlay manifest to the exact immutable base-image path, size, and digest.
Rebuilding or relocating the base invalidates that binding. Persistent mode is
for trusted development or analysis, never the hostile cell.

Retiring or resetting a named overlay is deliberately destructive and uses the
supervisor directly. Set `BASE_IMAGE` to the current absolute raw-image path
and `BASE_SHA256` to its lowercase 64-hex artifact-manifest digest, then use an
exact action/name/digest confirmation token:

```sh
python3 tools/wuci_lab.py overlay remove workbench \
  --base-image "$BASE_IMAGE" --base-sha256 "$BASE_SHA256" \
  --confirm "remove:workbench:$BASE_SHA256"
python3 tools/wuci_lab.py overlay reset workbench \
  --base-image "$BASE_IMAGE" --base-sha256 "$BASE_SHA256" \
  --confirm "reset:workbench:$BASE_SHA256"
```

Both operations take the same per-name lock, validate the qcow2 and manifest
against that exact base, reject symlinks and hardlinks, recheck file identity,
and touch only `workbench.qcow2` and `workbench.json`. They do not glob or
recursively delete the overlay directory. `remove` leaves no named state.
`reset` first removes the validated old state and then creates a fresh overlay;
if fresh creation fails, the old state has already been removed and the command
reports that fact. A base path/digest mismatch, malformed state, collision, or
wrong confirmation fails closed for operator review.

Internet access is a separate explicit selection for benign development or
analysis only:

```sh
make wucios-lovelace-launch-plan LOVELACE_NETWORK=internet
make wucios-lovelace-launch LOVELACE_NETWORK=internet
```

This uses QEMU user-mode NAT without inbound port forwarding or host shares.
It is not an isolation guarantee. Network access is not needed to use the
installed languages, NOXFRAME, or Ghidra.

The image preconfigures `/etc/apk/repositories` to the HTTPS Alpine v3.24
`main` and `community` repositories. That is configuration only: no virtual
NIC exists by default. Runtime `apk` use requires the operator to select
explicit `internet` mode, diverges from the locked immutable base package set,
and is discarded with a volatile overlay or retained only in an explicitly
named persistent overlay. It does not update the artifact lock or inherit its
reproducibility evidence.

For functional operation without KVM, choose TCG explicitly if desired:

```sh
make wucios-lovelace-launch LOVELACE_ACCEL=tcg
```

The supervisor uses the same pinned Broadwell-v4 feature set as the canonical
functional smokes. Hostile KVM mode instead binds `-cpu host`; it never falls
back to TCG. Do not use TCG mode for hostile or kernel-level experiments. A
defensive untrusted-system-code plan is selected only as follows:

```sh
make wucios-lovelace-launch-plan \
  LOVELACE_PROFILE=hostile LOVELACE_STORAGE=volatile \
  LOVELACE_NETWORK=none LOVELACE_ACCEL=kvm \
  LOVELACE_MEMORY_MIB=6144
```

The supervisor refuses hostile mode when KVM, non-root execution, volatile
storage, offline networking, the outer bubblewrap namespace, QEMU sandboxing,
or resource gates are absent. Its bubblewrap root contains an allowlisted,
read-only host QEMU runtime surface plus exact boot-artifact bindings, an
exact `/dev/kvm` binding, and the private writable volatile overlay; host
networking is separately unshared. The system runtime directories are part of
the local trusted computing base. Their top-level binding metadata is checked,
but this lane does not claim a file-by-file digest of their recursive contents.
Even when those gates pass, the result is layered risk reduction rather than a
perfect sandbox or a guarantee that arbitrary malicious code is safe.

After reviewing the exact plan, replace `launch-plan` with `launch` to start
the cell. No target passes a host device through to the guest. Hostile mode
binds only `/dev/kvm` to the QEMU process in the outer boundary; no host
filesystem share, QMP socket, or QEMU monitor is attached.

An operator may add one bounded sample to an explicitly hostile launch as
guest-read-only secondary media. Review a dry plan first; `KERNEL`, `INITRD`,
and `BASE_IMAGE` must be the current absolute artifact paths and the three
digest variables must be their current lowercase SHA-256 values:

```sh
make wucios-lovelace-hostile-payload-launch-plan \
  LOVELACE_HOSTILE_PAYLOAD="$SAMPLE" \
  LOVELACE_HOSTILE_PAYLOAD_SHA256="$SAMPLE_SHA256" \
  LOVELACE_MEMORY_MIB=6144
```

That helper resolves and binds the current built kernel, initramfs, base image,
and their digests. The equivalent direct supervisor form is:

```sh
python3 tools/wuci_lab.py launch \
  --kernel "$KERNEL" --kernel-sha256 "$KERNEL_SHA256" \
  --initrd "$INITRD" --initrd-sha256 "$INITRD_SHA256" \
  --base-image "$BASE_IMAGE" --base-sha256 "$BASE_SHA256" \
  --profile hostile --storage volatile --network none --accel kvm \
  --hostile-payload "$SAMPLE" \
  --hostile-payload-sha256 "$SAMPLE_SHA256" --dry-run
```

Remove `--dry-run` only after reviewing the complete plan. The sample must be a
single-link regular file of at most 64 MiB, contain no symlink component, be
neither group- nor world-writable, and match the supplied digest. The
supervisor rechecks it for drift, copies it without execution into a private
mode-0700 operation root, and writes a manifest containing the source size and
digest plus fixed guest-path, mount-policy, and boundary metadata. It omits the
source host pathname and filename. The supervisor uses exact trusted
`/usr/sbin/mke2fs` with a fixed option vector to build bounded ext4 media, then
uses exact trusted `/usr/sbin/debugfs` to read back and verify the exact payload
and canonical manifest bytes before attachment. The original host pathname is
neither shared with nor visible to QEMU. Bubblewrap read-only-binds only the
private media file to `/run/wuci-payload.ext4`, and QEMU attaches it as a raw
`readonly=on` virtio disk at `/dev/vdb`. No NIC, persistent disk, host directory
share, writable payload attachment, or sample execution is added.

Inside the hostile guest, guest root may mount the already read-only device for
inspection:

```text
doas mkdir -p /payload
doas mount -t ext4 -o ro /dev/vdb /payload
sha256sum /payload/payload.bin
cat /payload/manifest.json
```

The transient payload snapshot, manifest, media, and root overlay are removed
by exact-path cleanup on normal/error unwind and on handled `SIGHUP`, `SIGINT`,
`SIGQUIT`, `SIGTERM`, and `SIGTSTP` while the hostile supervisor is allocating
or materializing payload/overlay state or running its escaped-console relay.
`SIGKILL`, host-process destruction, host crash, power loss, filesystem
failure, or a compromised host can leave
private residue; this is not an anti-forensics guarantee. Payload ingress is a
smaller data-transfer surface, not evidence that arbitrary malicious samples
are safe. Use an appropriately isolated disposable physical host for high-risk
work.

The canonical fixed-benign runtime check for this transport is:

```sh
make wucios-lovelace-hostile-payload-smoke
```

It does not launch an operator-selected sample. Before a successful run the
evidence document is absent and
`manifest.validation.hostile_payload_ingress` remains `NOT_MEASURED`. After all
supervisor, guest exact-byte, read-only/write-rejection, artifact-binding, and
normal-unwind cleanup checks pass, the evidence document has `status: pass` and
the manifest field changes to its exact locally validated status.

## Inside the development guest

The raw serial console opens the trusted outer development environment. Use
this only for developer or analysis profiles; hostile launches use the
escaped-ASCII relay described above. Inside the trusted outer guest, use:

```text
wuci-lab-help
wuci-lab-status
wuci-lab-smoke
wuci-lab-run python3 hello.py
wuci-lab-run c hello.c
wuci-lab-run c++ hello.cpp
wuci-lab-run assembly hello.s
wuci-lab-run rust hello.rs
wuci-lab-run go hello.go
mkdir -p /work/projects
ghidra-headless /work/projects demo \
  -import /usr/share/wucios/fixtures/ghidra/ghidra-smoke \
  -overwrite \
  -scriptPath /usr/share/wucios/fixtures/ghidra/scripts \
  -postScript LovelaceGhidraSemanticCheck.java \
  -deleteProject
```

`wuci-lab-smoke` is the quickest installed demonstration: it runs the six
language routes and checks native Wuci-Ji, NOXFRAME, Java, and Ghidra presence.
The explicit Ghidra command imports the shipped benign fixture, runs the same
semantic post-script, and removes its temporary project after analysis. It is
an interactive demonstration, not canonical acceptance evidence: it does not
establish the producer's private temporary environment, legacy-path checks,
complete host-captured transcript, immutable-base recheck, or transactional
evidence binding. Use `make wucios-lovelace-ghidra-headless` for that bounded
acceptance contract.

NOXFRAME remains metadata-only by default. To enable its fixed programming
broker inside this marked Lovelace guest, place a single regular source file
under `/work` and launch:

```text
noxframe --console --allow-lovelace-lab-run
lab status
lab run python3 hello.py
lab ghidra /work/sample.bin
```

The programming broker accepts only the six fixed language routes and a plain
source filename. It rejects inputs above 1 MiB, makes a bounded private
`O_NOFOLLOW` snapshot before compilation, uses bounded output, CPU, process,
open descriptors, file, and wall time, runs only inside the selected guest,
and never becomes
ambient host command passthrough. The headless-Ghidra route requires both the
same explicit `--allow-lovelace-lab-run` flag and the exact Lovelace guest
runtime marker. It accepts only one plain regular, non-symlink, single-link
`/work/<filename>` input up to 16 MiB, privately snapshots it, uses the pinned
guest `ghidra-headless` path, bounds analysis, and never executes the analyzed
file. Compiler/interpreter routes receive at most 128 open descriptors; the
Java-based Ghidra route receives a separate bounded ceiling of 1,024. Success
requires a zero process exit and exactly one
`LOVELACE_NOXFRAME_GHIDRA_SEMANTIC_PASS` line before the exact
`noxframe-ghidra-headless:ok` completion line; zero exit alone is insufficient.
The broker caps raw combined output at 64 KiB and forwards only TAB, LF, and
printable ASCII, rendering every other byte as a lowercase `\xNN` escape.
Printable text remains unauthenticated and can still spoof prompts or status
messages. Neither NOXFRAME nor Ghidra is a containment boundary. The outer
development guest is also not the hostile-code cell; do not execute malicious
or kernel-level experiments in it.

Power the guest off cleanly with `doas poweroff -f`.

## CI boundary

The `lovelace-source-review` workflow runs only the strict profile tests,
supervisor unit tests, builder configuration/lock tests, and WuciOS registry
validation. It reviews the hostile-smoke contract and fixed-fixture producer
logic, but it does not fetch Alpine or Ghidra inputs, build the image, launch
QEMU, validate Ghidra or NOXFRAME at runtime, exercise persistent or Internet
guest modes, or exercise KVM. The hostile runtime result therefore remains
`NOT_MEASURED` until its named host-local target passes. CI does not prove
containment; runtime properties remain named local, artifact-dependent gates.
