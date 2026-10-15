# Lovelace Laboratory containment boundary

Lovelace Laboratory is a non-default, non-release-authoritative WuciOS
development and defensive-analysis profile. It is deliberately separate from
Noether Core. Its compilers, debuggers, network client, NOXFRAME integration,
Java runtime, and reverse-engineering tools enlarge its trusted computing base
and cannot enter the Noether Core package lock, evidence, or release score.

The machine-readable contract is
`wucios/profiles/lovelace-laboratory.json`. The strict schema is
`wucios/schemas/lovelace-laboratory-profile.schema.json`. These files define an
acceptance target; their existence does not show that a runtime image has been
built, booted, or independently evaluated.

Build, validation, storage, and launch commands are documented in
[WuciOS Lovelace Laboratory](LOVELACE_LABORATORY.md).

## Modes and defaults

The default execution class is benign development. Storage is volatile and
networking is absent unless the operator separately requests a different
allowed mode.

Volatile mode keeps the authenticated base image read-only and discards the
session overlay after a clean exit or ordinary error unwind. Handling of
`SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM`, and `SIGTSTP` is specific to the
hostile supervisor and covers its payload/overlay allocation and
materialization boundary plus its active escaped-console relay. Non-hostile
process termination, `SIGKILL`, host crashes, filesystem or storage failures,
snapshots, swap, hypervisor defects, and
storage remanence can defeat or outlive cleanup and remain outside the claim.
This is cleanup behavior, not a confidentiality or anti-forensics guarantee.

Persistent mode requires an explicit named store. Its implementation must use
an exclusive lock, owner-only permissions, and a manifest bound to the exact
base-image digest. Persistence is allowed only for benign development and
analysis. A persistent store is state management, not containment, and
must never attach to the defensive untrusted-system-code cell.

Named removal and reset are explicit destructive lifecycle actions. Their
confirmation tokens bind the action, validated overlay name, and exact base
digest. Under the same per-name lock, the supervisor validates the qcow2 and
manifest, rejects symlinks and hardlinks, rechecks inode identity, and removes
only the exact image and manifest; it never uses a glob or recursive deletion.
Reset removal is committed before fresh creation, so a creation failure leaves
the old state removed and must be reported as such. Malformed, drifted,
partially missing, or base-mismatched state fails closed for operator review.

The optional `internet` mode is explicit QEMU user-mode NAT for benign
development or analysis. It permits no port forwarding and no host filesystem
share. Its topology is fixed to QEMU's `10.0.2.0/24` user network: guest
`10.0.2.15/24`, gateway `10.0.2.2`, and DNS proxy `10.0.2.3`. The exact QEMU
netdev string is
`user,id=wuci-net,restrict=off,ipv6=off,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15`.
The guest route check requires exactly the five semantic tokens `default via
10.0.2.2 dev eth0`; it ignores only leading, trailing, or repeated shell field
whitespace emitted by `ip`, and rejects every extra route token.
The resolver bytes are exactly `nameserver 10.0.2.3\noptions timeout:2
attempts:3\n`. A network acceptance run must emit exactly
`LOVELACE_LABORATORY_BOOT profile=lovelace-laboratory storage=host-selected network=internet`;
`network=unavailable` or any other boot line fails.

The pinned Alpine v3.24 `main` and `community` HTTPS repository entries are
preconfigured, not preauthorized network access. There is no NIC by default.
Runtime package installation requires explicit `internet` mode, diverges from
the locked base package closure, and survives only when the operator separately
selected a named persistent overlay; volatile-mode changes are discarded on
normal or ordinary error cleanup, subject to the signal limitations above.
Such guest mutation receives no build-reproducibility or artifact-lock claim.

The point-in-time listener probe is exactly `ss -H -lntup`. The command must
exit successfully and emit zero records. This supports only the narrow
statement that no TCP or UDP listening socket was visible to that command at
that moment. A failed command with empty output cannot pass, and the result
does not cover other protocols, future listeners, or outbound clients.

The live HTTPS probe is bound to the unique `sha256-digest` sidecar in the
artifact-bound shared Alpine lock. Curl must successfully write the complete
response to a private temporary guest file before validation. The full file's
byte count and SHA-256 must equal the locked sidecar values, and its complete
content must satisfy the exact locked digest-line contract. Truncation, extra
content, a same-size altered body, or curl failure is a hard failure. There is
no fallback endpoint or degraded pass. The response ceiling equals the locked
byte count, the connection timeout is 15 seconds, the transfer timeout is 90
seconds, and the VM deadline is 1,500 seconds.

Evidence also binds the parsed QEMU launch contract: `q35` with TCG, the exact
user-NAT netdev and virtio NIC, no host forwarding, a temporary qcow2 root
overlay, no direct writable base image, and no QEMU snapshot flag. A different
argument vector cannot inherit the network result. Validation compares the
whole vector with the freshly generated expected vector, so legacy `-net`,
`-readconfig`, and every other extra argument are rejected rather than ignored.

The network probe runs in a parenthesized guest-shell subshell. Probe-local
fail-fast behavior therefore returns to the interactive outer shell on error,
where the already queued poweroff command executes promptly. Failure cannot
strand the guest merely because the probe enabled `set -e`, and it cannot emit
the Internet pass marker.

The evidence retains the complete functional console, bounded to 8 MiB, as
canonical RFC 4648 base64. Its verifier decodes and canonically re-encodes
those bytes, recomputes the recorded byte count, SHA-256, and diagnostic tail,
rescans the full transcript, and independently checks exact unique marker
ordering and result-marker placement after the recorded command-dispatch
offset. It rejects every competing complete line beginning with the Lovelace
boot-marker prefix. Complete-transcript evidence is available only after QEMU
exit and a bounded stdout drain reaches observed EOF within five seconds;
`console_eof_observed` must be true and the recorded drain timeout must be five
seconds. A declared digest, tail, marker list, or boot line without matching
retained bytes is insufficient.

User-mode NAT is not an isolation claim: a guest may reach external systems
and may interact with parts of the QEMU network implementation. Even a passing
probe establishes only one artifact-bound HTTPS response over the exact local
topology. It does not establish network isolation, anonymity, privacy,
containment, general connectivity or availability, release authority, or
safety for arbitrary malicious code. The defensive untrusted-system-code cell
receives no network device at all.

## Two virtualization claims

TCG may boot the development or analysis environment when hardware
virtualization is unavailable. This establishes functional behavior only. TCG
must not run the defensive untrusted-system-code class and must not be cited as
guest-isolation evidence.

The defensive cell is a distinct, disposable KVM-backed VM. Launch must fail
closed unless all required host gates pass:

- a usable KVM device;
- an unprivileged host-side QEMU process;
- a trusted outer bubblewrap process with user, PID, IPC, UTS, cgroup, and
  network namespaces;
- a private read-only root containing an allowlisted host QEMU runtime surface,
  exact boot-artifact inputs, the exact KVM device, and the writable throwaway
  overlay;
- QEMU's sandbox option enabled;
- no virtual network device, host share, or device passthrough; and
- explicit resource bounds.

The host process bound is an account-wide `RLIMIT_NPROC` ceiling of 2048
tasks, not a guest-process or cell-exclusive process limit. The supervisor
measures the real UID's current `/proc` thread count and fails closed unless at
least 128 host-task slots remain before bubblewrap/QEMU launch. Guest process
creation remains bounded indirectly by the VM's fixed CPU and memory resources;
the repository does not claim a per-guest-process quota.

There is no software-emulation fallback. The cell uses a read-only base and a
throwaway volatile overlay. It has no network device, persistent disk, host
filesystem share, virtual clipboard device, USB passthrough, host-device
passthrough, QMP endpoint, or monitor. QEMU user configuration and default
devices are disabled.

The installed `doas` policy intentionally allows the `lab` identity to obtain
guest root. The hostile model therefore assumes attacker-controlled guest root;
guest-local users, permissions, and privilege separation are not containment
layers. “Unprivileged QEMU” describes only the host-side QEMU process and must
not be read as a restriction on workload privilege inside the guest.

Optional hostile payload ingress transfers data through one bounded secondary
disk, not a host share. It is accepted only with the hostile, KVM, offline, and
volatile gates already satisfied. The source must be a digest-bound,
single-link regular file with safe path components and permissions and a size
of at most 64 MiB. The supervisor takes a private `O_NOFOLLOW` snapshot without
executing it and places that snapshot plus a manifest containing source
size/digest and fixed guest/boundary metadata in bounded ext4 media created by
exact trusted `/usr/sbin/mke2fs`. Exact trusted `/usr/sbin/debugfs` then reads
back and verifies the payload and canonical manifest bytes before the
supervisor rechecks source and media identity for launch. Only the private media
file enters bubblewrap as an exact read-only bind; QEMU exposes it with
`readonly=on` at guest `/dev/vdb`.
The original source path, host directory, writable attachment, network device,
and persistent store remain absent. Media construction parses no sample file
format and never executes the sample.

The ext4 media and its host staging files are transient and removed by exact
path and inode on normal/error unwind and on handled `SIGHUP`, `SIGINT`,
`SIGQUIT`, `SIGTERM`, and `SIGTSTP` while the hostile supervisor is allocating
or materializing payload/overlay state or running its escaped-console relay.
Cleanup after `SIGKILL`, host-process destruction, host crash, power loss,
storage failure, or host compromise is not claimed. A read-only ingress path
narrows transfer authority but does not make
Ghidra, NOXFRAME, QEMU, KVM, the guest kernel, or arbitrary malicious input
safe.

There is no virtual clipboard device. In addition, the hostile supervisor
merges QEMU stderr into a bounded serial relay that forwards only printable
ASCII, line feeds, and tabs; it normalizes CRLF and visibly escapes every other
byte. The relay therefore does not pass OSC, CSI, DCS, ESC, C1, DEL, invalid
byte sequences, or C0 controls other than the explicitly allowed LF and TAB to
the host terminal. Operator input reaches the child through a separate
one-way, nonblocking pipe with a 1 MiB pending-input bound, so the child does
not inherit a writable host-terminal descriptor. The relay restores the host
terminal on normal/error unwind and on handled `SIGHUP`, `SIGINT`, `SIGQUIT`,
`SIGTERM`, and `SIGTSTP`; a restoration failure is fatal. Before handing the
TTY back, it checks and terminates surviving launch-group members, closes the
relay pipes, and restores with pending terminal input flushed. Console EOF gets
a bounded 0.1-second waitpid-confirmation window so a just-exited leader is not
misclassified as live; a leader still alive after that window fails closed.
These properties do not apply after `SIGKILL`, host-process destruction, kernel
failure, or power loss. Printable guest text remains unauthenticated and can
spoof prompts. The relay reduces a guest-to-terminal attack surface; it is not a
hypervisor-escape or arbitrary-malware-safety guarantee.

These layers reduce exposure; they do not prove that escape is impossible.
KVM, QEMU, the host kernel, CPU virtualization, firmware, device models, and
resource-control configuration remain in the trusted computing base. Side
channels, hypervisor vulnerabilities, denial of service, host misconfiguration,
and unknown defects remain residual risks. Do not use this profile as a
guarantee that malicious code is safe to execute. High-risk samples still
require an appropriately isolated, disposable host and an operator-approved
research procedure.

The allowlisted system runtime directories are part of that host trusted
computing base. Their top-level binding metadata is checked, but their complete
recursive contents are not individually digest-bound by the current local
evidence.

## Hostile-cell acceptance boundary

The canonical host-local acceptance command is:

```sh
make wucios-lovelace-hostile-smoke
```

The ordinary hostile-cell smoke must fail closed without a securely configured, usable `/dev/kvm`, a
non-root operator, and exact root-owned, non-setuid/non-setgid
`/usr/bin/qemu-system-x86_64`, `/usr/bin/qemu-img`, and `/usr/bin/bwrap`
executables. It exercises only fixed benign fixtures in a volatile KVM guest
inside the outer bubblewrap boundary, with no guest network, persistence, host
share, or host-device passthrough into the guest. The outer boundary binds only
the exact `/dev/kvm` device required by QEMU. Before dispatching any guest
acceptance command, the producer observes the exact QEMU executable identity,
unprivileged UID set, empty effective capabilities, no-new-privileges state,
seccomp filters, command line, and separated namespace identities. It also
fully validates the canonical materialized launch plan and requires the
observed QEMU command line to equal that plan before writing any command to the
guest console. It requires the exact hostile boot line
`LOVELACE_LABORATORY_BOOT profile=lovelace-laboratory storage=host-selected network=none`
and a unique, ordered console-ready line. Only then does the
runner generate its 256-bit challenge and materialize the fixed command set;
the challenge must be absent from the pre-dispatch transcript, supervisor
arguments, environment, and materialized plan. Each result must be a unique,
complete, newline-terminated full-transcript line whose start offset is at or
after command dispatch. The Ghidra command runs the pinned
`LovelaceGhidraSemanticCheck.java` post-script with that challenge, and hostile
evidence requires the exact
`LOVELACE_GHIDRA_SEMANTIC_PASS <challenge>` result in addition to the
challenge-bound Ghidra completion result. A static marker cannot satisfy this
per-run binding. On the artifact-bound smoke's normal supervisor unwind, it
requires the observed PID and
`/proc` start-time identity to be absent or reused; the executable device and
inode are bound into that observation. The canonical release boot arguments
must be used exactly, the console-ready marker must arrive within 180 seconds
after the exact constrained QEMU process is first observed, pre-QEMU
verification and materialization remain inside the separate bounded overall
runtime,
configured kernel/initramfs/storage failure strings are rejected from the
complete bounded transcript, only TAB, LF, and printable ASCII bytes are
forwarded to the host while every non-allowlisted byte is escaped, and raw
console output is capped at 32 MiB. The local ignored
evidence retains the complete escaped transcript, digest, byte count, and
dispatch offset so evidence validation can recheck these transcript
properties; it is not part of a public profile.

That artifact-bound KVM smoke uses piped supervisor input and normal guest
poweroff. It validates normal-unwind process, overlay, and transcript
properties, not real-TTY signal restoration. Handled-signal restoration and
the pending-input flush are separately locally validated with a real PTY in
the network-free source suite.

A passing result supports only a local claim that those KVM-plus-bubblewrap
layers and selected fail-closed controls were present for the exact bound
artifact. It does not establish perfect isolation, make arbitrary malware safe,
or grant release authority. Until the exact local runtime command passes, this
property remains `NOT_MEASURED`; source-level CI reviews only its contract and
producer logic. The artifact evidence records normal-unwind QEMU disappearance.
The implementation's listed handled-signal unwind is source-tested separately;
neither path proves cleanup after `SIGKILL`, host-process destruction, host
crash, or power loss. Process-group cleanup does not prove the absence of a
descendant that escaped that group after compromise.

The separately gated fixed-benign payload-ingress acceptance command is:

```sh
make wucios-lovelace-hostile-payload-smoke
```

The payload smoke attaches only
`wucios/fixtures/lovelace/hostile-payload.txt` (44 bytes,
SHA-256
`cf7fe660be24036a09dfde459549fc0cb2fa57fd6551d6b207e450d1f9b320d5`).
It requires exact supervisor semantic readback of `/payload.bin` and
`/manifest.json`, exact guest byte comparisons, a read-only mount, rejection of
a guest-root write with no probe residue, and normal-unwind removal of both the
payload operation root and volatile overlay. Its release-relative evidence is
`release/evidence/hostile-payload-ingress.json`, has `isolation_claim: false`, and does
not satisfy the ordinary `hostile-kvm-bwrap-cell` gate (`hostile_kvm_cell` is
the corresponding manifest validation field). An operator-selected or
malicious sample is outside this acceptance result.

## NOXFRAME boundary

NOXFRAME remains a bounded console and session model. Its default behavior is
metadata-only and it is not a shell sandbox, kernel boundary, hypervisor, or
host-containment mechanism.

An implementation may expose an explicit guest-command broker. The broker is
disabled by default, accepts an argument-vector boundary, and targets only the
selected guest domain. It must never become ambient host command passthrough.
Programming-language acceptance applies both to the normal WuciOS guest shell
and to commands delivered through that guest broker; it grants NOXFRAME no
additional containment authority.

The guest-only `lab ghidra /work/<plain-file>` route is dual-gated by the same
explicit `--allow-lovelace-lab-run` option and the exact Lovelace runtime
marker. It rejects traversal, metacharacters, subdirectories, symlinks,
hardlinks, non-regular inputs, and files above 16 MiB; it privately snapshots
the accepted file before invoking the fixed bounded headless runner. The route
does not execute the analyzed input and cannot target the host. Successful
analysis requires a zero process exit and exactly one
`LOVELACE_NOXFRAME_GHIDRA_SEMANTIC_PASS` line before the exact
`noxframe-ghidra-headless:ok` completion line; zero exit alone is insufficient.
The broker caps raw combined output at 64 KiB and forwards only TAB, LF, and
printable ASCII, rendering every other byte as a lowercase `\xNN` escape.
Printable text remains unauthenticated and can imitate prompts or status text.
These are broker, result-shape, and terminal-output controls, not NOXFRAME or
Ghidra containment claims.

## Ghidra boundary

The initial Ghidra acceptance target is the `analyzeHeadless` entry point on a
pinned OpenJDK 21 runtime, with networking absent by default. Graphical Ghidra
operation is not claimed by this contract.

Canonical acceptance imports only the committed benign `ghidra-smoke` ELF and
runs the pinned `LovelaceGhidraSemanticCheck.java` post-script. The script
requires the exact imported-file MD5
`7af3bf4a75edc982a574d9e0290f96fd` and SHA-256
`446c9e5b46a3eb21a7e09f2794bdd58c66491ebd927bc67c36b212d7da08eb8e`,
`Executable and Linking Format (ELF)`, language `x86:LE:64:default`, headless
analysis enabled, the program marked analyzed without a reported analysis
timeout, more than zero functions, at least eight instructions, and the
embedded `lovelace-ghidra-smoke\n` message. Its path, SHA-256, and semantic
marker are part of the artifact-bound fixture record. The functional TCG
acceptance requires its exact semantic line; the hostile KVM acceptance gives
the script the fresh 256-bit run challenge and requires the semantic line to
carry that challenge after dispatch.

For each acceptance, `projects`, `home`, `config`, `cache`, and `tmp` are
created beneath one private mode-0700 work root. `HOME`, `XDG_CONFIG_HOME`,
`XDG_CACHE_HOME`, and `TMPDIR` point there, while `JAVA_TOOL_OPTIONS` directs
both `user.home` and `java.io.tmpdir` there and fixes HotSpot to
`-XX:-TieredCompilation`; `GHIDRA_HEADLESS_MAXMEM=2G` fixes the headless heap
ceiling. The NOXFRAME route validates the supported 1..8 online-vCPU range and
sets its inherited aggregate CPU ceiling to `670 * online-vCPU` seconds. This
keeps the finite CPU fallback beyond the 660-second outer broker wall deadline,
including for multithreaded Java execution. The compiler setting disables the C1/tiered compiler implicated in
the pinned TCG failure while retaining bounded C2 execution; interpreted
`-Xint` execution is deliberately not accepted because it misses the existing
600-second process deadline. The setting is runtime compatibility evidence,
not a claim that the JVM or analyzer is a containment boundary. The legacy paths
`/home/lab/.config/ghidra` and `/var/tmp/lab-ghidra` must be absent before and
after Ghidra runs. Failure cleanup is trap-backed; a successful result also
requires deleted-project emptiness, explicit work-root removal, and observed
work-root absence before its final pass marker. These are bounded state and
acceptance checks, not a confidentiality, anti-forensics, or containment claim.

Ghidra parses attacker-controlled binary formats and is part of the analysis
trusted computing base. It is an analysis tool, not a containment layer.
Untrusted input should be analyzed only in a disposable analysis environment,
and analysis success does not authorize executing the sample.

## Evidence and claim discipline

A runtime implementation must emit the exact evidence outputs named by the
profile before any corresponding behavior is described as locally validated.
At minimum, evidence must bind the exact base-image, kernel, initramfs,
package-lock, and source-input vector; selected storage and network modes;
toolchain probes; NOXFRAME guest-broker probe; Ghidra headless probe;
defensive-cell launch gates; the exact observed QEMU identity and its
disappearance after normal supervisor exit; and the overlay cleanup result. A
schema name or console marker by itself is not sufficient evidence.

The artifact-output lock serializes cooperating Lovelace build and evidence
producers that share an output root. It does not coordinate the repository-wide
`make clean` target. Because `make clean` deletes the complete `build/` tree, it
must never run concurrently with any Lovelace build, reproducibility run,
runtime producer, or evidence update.

Functional runtime evidence must also retain the full bounded raw console in
canonical base64 and bind its byte count, SHA-256, derived diagnostic tail,
console-ready boundary, and command-dispatch offset. Verification must derive
those values again from the retained bytes and recheck exact ordered marker
lines and post-dispatch result placement. For Internet evidence, the exact
QEMU user-NAT topology, Internet boot line, successful zero-record listener
probe, and complete artifact-bound Alpine sidecar response are additional
requirements. None of these observations grants network-containment or
release authority.

Lovelace Laboratory makes no production-readiness, release-authority,
certification, perfect-isolation, escape-proof, safe-malware, side-channel
confidentiality, network-isolation, anonymity, or TCG hostile-isolation claim.
Neither NOXFRAME, Ghidra, nor the QEMU user-NAT reachability probe is a
containment boundary.
