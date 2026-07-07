AS ?= as
LD ?= ld
PYTHON ?= python3
PYPY ?= .tools/bin/pypy3
NM ?= nm
OBJDUMP ?= objdump
RUSTC ?= $(shell if command -v rustc >/dev/null 2>&1; then command -v rustc; elif [ -x "$(HOME)/.cargo/bin/rustc" ]; then printf '%s\n' "$(HOME)/.cargo/bin/rustc"; fi)
CARGO ?= $(shell if command -v cargo >/dev/null 2>&1; then command -v cargo; elif [ -x "$(HOME)/.cargo/bin/cargo" ]; then printf '%s\n' "$(HOME)/.cargo/bin/cargo"; fi)
ZP1_DIR ?= third_party/zp1
WUCIJI_ZP1_BRIDGE_DIR ?= tools/wuciji-zp1-bridge
ZIG ?= zig
ZIG_VERSION := $(shell if command -v $(ZIG) >/dev/null 2>&1; then $(ZIG) version; fi)
ZIG_TOOL_IMPL ?= $(if $(filter 0.13.%,$(ZIG_VERSION)),python-compat,zig)
QEMU_X86_64 ?= qemu-x86_64
QEMU_CPU ?= Haswell-v4
QEMU_RUNNER ?= $(QEMU_X86_64) -cpu $(QEMU_CPU)

HOST_OS := $(shell uname -s)
HOST_ARCH := $(shell uname -m)

TARGET := build/wuci-ji
ASM_SOURCES := src/main.s src/wuci-ji.s src/gate_contract.s src/ledger.s src/regression.s src/sandbox.s src/sys.s src/encoding.s src/frost.s src/hmac_hkdf.s src/secp256k1_field.s src/secp256k1_point.s src/secp256k1_scalar.s src/sha256.s src/x25519.s
OBJECTS := $(patsubst src/%.s,build/%.o,$(ASM_SOURCES))
CROSS_SOURCES := $(patsubst src/%.s,build/%.zig.s,$(ASM_SOURCES))
CROSS_TARGET := build/wuci-ji-linux-x86_64
ZIG_GATE_CONTRACT := build/wuci-gate-contract
ZIG_WARRANT := build/wuci-warrant
ZIG_WITNESS := build/wuci-witness
ZIG_LEDGER := build/wuci-ledger-tool
ZIG_TARGET ?= x86_64-linux-musl
ZIG_GLOBAL_CACHE_DIR ?= build/.zig-cache/global
ZIG_LOCAL_CACHE_DIR ?= build/.zig-cache/local
RELEASE_BIN ?= $(TARGET)
RELEASE_RUNNER ?=
FROST_AUTHZ_DEMO_DIR ?= build/frost-authz-demo
GATE_DEMO_DIR ?= build/wuci-gate-demo
SELF_RELEASE_DEMO_DIR ?= build/wuci-self-release-demo
SELF_RELEASE_ATTESTATION ?= $(SELF_RELEASE_DEMO_DIR)/attestation.json
SELF_RELEASE_CONTRACT ?= $(SELF_RELEASE_DEMO_DIR)/receipt-contract.txt
SELF_RELEASE_AUTHORITY ?= $(SELF_RELEASE_DEMO_DIR)/authority-root.txt
NOXFRAME_SELF_RELEASE_DEMO_DIR ?= build/noxframe/self-release
NOXFRAME_SELF_RELEASE_ATTESTATION ?= $(NOXFRAME_SELF_RELEASE_DEMO_DIR)/attestation.json
NOXFRAME_WITNESS_BUNDLE_DIR ?= build/noxframe/self-release-witness
NOXFRAME_WITNESS_WORK_DIR ?= $(NOXFRAME_WITNESS_BUNDLE_DIR).work
NOXFRAME_LEDGER_DIR ?= build/noxframe/self-release-ledger
NOXFRAME_LEDGER_INCLUSION_PROOF ?= $(NOXFRAME_LEDGER_DIR)/inclusion-proof.txt
NOXFRAME_LEDGER_CONSISTENCY_PROOF ?= $(NOXFRAME_LEDGER_DIR)/consistency-proof.txt
WITNESS_BUNDLE_DIR ?= build/wuci-witness-bundle
WITNESS_WORK_DIR ?= $(WITNESS_BUNDLE_DIR).work
WITNESS_ARCHIVE ?= $(WITNESS_BUNDLE_DIR).tar
WITNESS_ARCHIVE_SHA256 ?= $(WITNESS_ARCHIVE).sha256
WITNESS_ARCHIVE_CHECK_DIR ?= $(WITNESS_BUNDLE_DIR).archive-check
LEDGER_DEMO_DIR ?= build/wuci-ledger-demo
LEDGER_DIR ?= build/wuci-ledger
LEDGER_INCLUSION_PROOF ?= $(LEDGER_DIR)/inclusion-proof.txt
LEDGER_CONSISTENCY_PROOF ?= $(LEDGER_DIR)/consistency-proof.txt
CAGE_ATTESTATION ?= build/wuci-cage-attestation.json
CAGE_LEDGER_ENTRY ?= build/wuci-cage-ledger-entry.txt
CAGE_LEDGER_LEAF ?= build/wuci-cage-ledger-leaf.txt
CAGE_RUN_DENIAL ?= build/wuci-cage-run-denied.txt
QCAGE_CRYPTO_INVENTORY ?= build/wuci-qcage-crypto-inventory.json
QCAGE_BUILD_GRAPH ?= build/wuci-qcage-build-graph.json
QCAGE_ATTESTATION ?= build/wuci-qcage-attestation.json
HARDEN_TRUSTED_BIN_SHA256 ?=
HARDEN_STRICT ?= 1
WUCI_SBOM ?= build/wuci-sbom.json
WUCI_PROVENANCE ?= build/wuci-provenance.json
DAYLIGHT_MERIDIAN_PRIVATE_DIR ?= build/daylight/v15-meridian-private
DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR ?= build/daylight/v15-meridian-public
DAYLIGHT_MERIDIAN_ARTIFACT_DIR ?= $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR)
DAYLIGHT_APERTURE_CAPSULE ?= build/daylight/v19-aperture-bastion-capsule.json
DAYLIGHT_APERTURE_PUBLIC_DIR ?= build/daylight/v19-aperture-bastion-public
DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE ?= build/daylight/v20-aperture-singularity-capsule.json
DAYLIGHT_V20_APERTURE_SINGULARITY_PUBLIC_DIR ?= build/daylight/v20-aperture-singularity-public
DAYLIGHT_V20_APERTURE_SINGULARITY_TAR ?= build/daylight/v20-aperture-singularity-public-review-artifact.tar.gz
DAYLIGHT_V20_APERTURE_SINGULARITY_FIREWALL_REPORT ?= build/daylight/firewall-report.v20.json
DAYLIGHT_SSV_REPORT ?= build/daylight/ssv-v1/daylight-ssv.report.json
DAYLIGHT_SSV_PYTHONPATH ?= daylight/ssv/v1:tools:.
CARROT_POLICY ?= docs/wuci_carrot_runtime_policy.json
CARROT_ATTESTATION ?= build/wuci-carrot-attestation.json
PQ_VERIFIER_EVIDENCE ?= build/wuci-pq-verifier.json
REAL_PQ_VERIFIER_EVIDENCE ?=
PQ_VERIFIER_PINS ?= docs/wuci_pq_verifier_pins.json
LOCAL_REAL_PQ_VERIFIER_EVIDENCE ?= build/wuci-real-pq-verifier.json
LOCAL_PQ_VERIFIER_PINS ?= build/wuci-pq-fips204-pins.json
PQ_VERIFIER_BIN ?=
PQ_VERIFIER_ALGORITHM ?= ML-DSA
PQ_VERIFIER_IMPLEMENTATION ?=
PQ_VERIFIER_VERSION ?=
PQ_KAT_PUBLIC_KEY ?=
PQ_KAT_MESSAGE ?=
PQ_KAT_SIGNATURE ?=
PQ_FIPS204_MANIFEST ?= tools/wuci-pq-fips204-verify/Cargo.toml
PQ_FIPS204_SOURCE_BIN ?= tools/wuci-pq-fips204-verify/target/release/wuci-pq-fips204-verify
PQ_FIPS204_BIN ?= build/wuci-pq-fips204-verify
PQ_FIPS204_KAT_DIR ?= build/wuci-pq-fips204-kat
PQ_FIPS204_KAT_PUBLIC_KEY ?= $(PQ_FIPS204_KAT_DIR)/mldsa65-public.key
PQ_FIPS204_KAT_MESSAGE ?= $(PQ_FIPS204_KAT_DIR)/mldsa65-message.bin
PQ_FIPS204_KAT_SIGNATURE ?= $(PQ_FIPS204_KAT_DIR)/mldsa65-signature.bin
CRYPTO_SELF_AUDIT ?= build/wuci-crypto-self-audit.json
EXTERNAL_AUDIT_EVIDENCE ?=
EXTERNAL_AUDIT_REPORT ?=
EXTERNAL_AUDIT_ROOT_KEY ?=
EXTERNAL_AUDIT_SIGNATURE ?=
PARSER_CORPUS_REPLAY ?= build/wuci-parser-corpus-replay.json
RELEASE_BUNDLE_VERIFICATION ?= build/wuci-release-bundle-verification.json
RUST_SANDBOX ?= build/wuci-sandbox
DAYLIGHT_V06_M1_FIXTURE ?= daylight-equation/fixtures/daylight-v06-m1
HOST_LOGICAL_CPUS ?= $(shell nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')
INSTALL_PREFIX ?= $(HOME)/.local
INSTALL_ROOT_KEY ?= $(HOME)/.config/wuci-ji/install-root.pub
INSTALL_MANIFEST ?= install/wuci-install-manifest.v1
INSTALL_SIGNATURE ?= install/wuci-install-manifest.v1.sig
INSTALL_ALLOW_PREFIX ?=
INSTALL_SIGNING_KEY ?=
PRODUCTION_AUTHORITY_ROOT ?=
PRODUCTION_AUTHORITY_CEREMONY ?=
PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY ?=
PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE ?=
WUCI_VERSION ?= 0.1
AUTHORITY_ROOT ?= authority/wuci-root.fixture.txt
AUTHORITY_ROOT_SHA256 ?= authority/wuci-root.fixture.sha256
RELEASE_AUTHORITY_ROOT ?= authority/wuci-release-root.fixture.txt
RELEASE_AUTHORITY_ROOT_SHA256 ?= authority/wuci-release-root.fixture.sha256
FROST_FIXTURE_GROUP_PUBLIC_KEY ?= 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4

.PHONY: help aead-boundary-test all asm-regression asm-smoke authority-anchor-test authority-root-check authority-root-fixture authority-root-metal-check build-linux cage-attestation-test cage-bundle-test cage-ledger-entry cage-policy-matrix cage-proof carrot-policy check-asm-immediates check-native check-native-x25519 check-pypy check-qemu-user check-qemu-x25519-cpu ci ci-native ci-zig clean crypto-self-audit crypto-self-audit-test daylight-scorecard-test daylight-v06-1000-checkpoint-test daylight-v06-1000-claim-gate-test daylight-v06-1000-preflight-test daylight-v06-authority-verifier-test daylight-v06-cap-removal-test daylight-v06-external-review-packet-test daylight-v06-external-review-verifier-test daylight-v06-fail-closed-model-test daylight-v06-m1-cross-agreement-test daylight-v06-m1-fixture-test daylight-v06-m1-independent-open-test daylight-v06-m1-static-test daylight-v06-m4-symbolic-model-test daylight-v06-m4-z3-proof-test daylight-v06-peer-review-score-test daylight-v06-schema-freeze-test daylight-v6-kat-reproduction-bundle-test daylight-v6-provider-kem-evidence-test daylight-v6-provider-private-roundtrip-test daylight-v6-provider-vector-agreement-test daylight-v6-reference-negative-corpus-test daylight-v6-reference-seal-open-test external-audit-test frost-authz frost-authz-demo frost-demo frost-workflow gate-boundary gate-contract-asm gate-contract-zig gate-demo gate-policy-matrix gate-receipt-contract gate-workflow golden-lock-policy-matrix harden-action-policy-test harden-fixture-quarantine-test harden-ledger-mutation-test harden-policy-matrix harden-proof harden-safeio-test harden-verifier-identity-test harden-witness-symlink-test harden0-action-policy-test harden0-fixture-quarantine-test harden0-policy-matrix harden0-proof harden0-safeio-test harden0-verifier-identity-test harden0-witness-safeio-test high-attestation-profile high-attestation-proof host-capacity install-audit install-key-check install-manifest install-proof install-sign-current install-test install-verify kernel-sandbox-proof ledger-asm-demo ledger-asm-test ledger-proof-test ledger-zig-history machine-passoff-test parser-adversarial-test parser-corpus-replay parser-corpus-replay-test parser-hardening-proof pq-verifier-detect pq-verifier-fips204-build pq-verifier-fips204-proof pq-verifier-real pq-verifier-real-attest pq-verifier-test production-authority-verify production-readiness-gates publish-attestation-test publish-index publish-witness pythonless-public-verify qcage-attestation-test qcage-build-graph qcage-crypto-inventory qcage-model-test qcage-policy-matrix qcage-proof qcage-risk release-rooted-contract reproducible-build-metadata rooted-proof-display rust-sandbox-build rust-sandbox-test sbom-provenance sbom-provenance-test secret-path-isolation-test self-release-anchored-proof self-release-asm-contract-bundle self-release-asm-contract-demo self-release-ledger-bundle self-release-publish-bundle self-release-release-contract-demo self-release-release-contract-proof self-release-rooted-bundle self-release-rooted-demo self-release-rooted-proof self-release-witness-archive self-release-witness-bundle test test-linux test-pypy selftest selftest-linux verify-release-bundle verify-self-release-bundle witness-archive witness-archive-test witness-archive-verify witness-archive-zig-test witness-archive-zig-verify witness-attestation-test witness-zig witness-zig-test wjgold-model-test wjnext-model-test wjstar-model-test zig-release-anchored-proof zig-release-asm-contract-proof zig-release-contract-proof zig-release-ledger-bundle zig-release-proof zig-release-publish-bundle zig-release-release-contract-proof zig-release-rooted-proof zig-release-witness-archive zig-release-witness-bundle
.PHONY: daylight-v06-protocol-state-test
.PHONY: wuci-daylight-bridge-test
.PHONY: daylight-v6-nightlight-battery-test
.PHONY: daylight-v6-nightlight-deep-assessment-test
.PHONY: self-release-asm-contract-proof self-release-attestation-test self-release-bundle self-release-contract-bundle self-release-demo
.PHONY: harden0-ledger-mutation-test
.PHONY: install-local wuci-install
.PHONY: wuci-prism-test wuci-progress-test
.PHONY: noxframe-launch noxframe-launch-test noxframe-self-release black-ice-launch black-ice-launch-test
.PHONY: wuci-kaiju-test wuci-os-test
.PHONY: daylight-cplus-test daylight-cplus-score daylight-cplus-verify daylight-cplus-corpus
.PHONY: daylight-public-evidence-firewall-test daylight-public-artifact-firewall daylight-private-material-regression-test daylight-security-ratchet-test daylight-meridian-test daylight-meridian-score daylight-meridian-verify daylight-meridian-corpus daylight-meridian-frontier daylight-meridian-perfect-demo daylight-meridian-artifact daylight-meridian-public-artifact daylight-meridian-public-artifact-test daylight-meridian-package daylight-meridian-smoke daylight-meridian-ci daylight-meridian-envelope-demo daylight-meridian-envelope-test daylight-meridian-vault-test daylight-meridian-vault-demo
.PHONY: daylight-solstice-score daylight-solstice-verify daylight-solstice-artifact daylight-solstice-frontier daylight-solstice-external-demo daylight-solstice-test daylight-solstice-ci
.PHONY: daylight-zenith-verify daylight-zenith-report daylight-zenith-test daylight-zenith-ci
.PHONY: daylight-analemma-verify daylight-analemma-report daylight-analemma-test daylight-analemma-ci
.PHONY: daylight-v16-awe-test
.PHONY: daylight-v17-event-horizon-score daylight-v17-event-horizon-verify daylight-v17-event-horizon-test daylight-v17-event-horizon-doctor daylight-v17-event-horizon-fracture daylight-v17-event-horizon-declaration-gate daylight-v17-event-horizon-fixture-demo daylight-v17-event-horizon-vector daylight-v17-event-horizon-rust-vector daylight-v17-event-horizon-rust-test daylight-v17-event-horizon-triangulation daylight-v17-event-horizon-agreement daylight-v17-event-horizon-blockers daylight-v17-event-horizon-frontier
.PHONY: daylight-v17-singularity-score daylight-v17-singularity-verify daylight-v17-singularity-test daylight-v17-singularity-doctor daylight-v17-singularity-fixture-demo daylight-v17-singularity-declaration-gate
.PHONY: daylight-horizon-alpha-test daylight-horizon-alpha-vault-demo daylight-horizon-alpha-release-demo
.PHONY: daylight-v18-bastion-measure daylight-v18-bastion-verify daylight-v18-bastion-test daylight-v18-bastion-transition-demo daylight-v18-bastion-transition-test daylight-v18-bastion-transition-ledger-verify
.PHONY: daylight-v19-aperture-bastion-doctor daylight-v19-aperture-bastion-capsule-demo daylight-v19-aperture-bastion-verify daylight-v19-aperture-bastion-public-artifact daylight-v19-aperture-bastion-firewall daylight-v19-aperture-bastion-test daylight-v19-aperture-bastion-ci aperture-bastion-doctor aperture-bastion-test aperture-bastion-ci
.PHONY: daylight-v20-aperture-singularity-doctor daylight-v20-aperture-singularity-test daylight-v20-aperture-singularity-capsule-demo daylight-v20-aperture-singularity-agreement daylight-v20-aperture-singularity-blockers daylight-v20-aperture-singularity-evidence-audit daylight-v20-aperture-singularity-score-ceiling daylight-v20-aperture-singularity-external-evidence daylight-v20-aperture-singularity-declaration-gate daylight-v20-aperture-singularity-public-artifact daylight-v20-aperture-singularity-verify-public-artifact daylight-v20-aperture-singularity-firewall daylight-v20-aperture-singularity-ci
.PHONY: daylight-v20-ed25519-attestation-test daylight-v20-canonical-verifier-output daylight-v20-verifier-output-digest daylight-v20-verifier-quorum daylight-v20-verifier-quorum-test
.PHONY: daylight-v20-external-evidence-test daylight-v20-external-evidence-demo daylight-v20-external-evidence-verify daylight-v20-score-ceiling-report daylight-v20-rebuild-receipts
.PHONY: daylight-npt daylight-npt-test daylight-npt-report daylight-npt-ci daylight-ssv daylight-ssv-test daylight-ssv-report daylight-ssv-ci daylight-score-integrity-audit daylight-score-integrity-audit-directory-check
.PHONY: site-daylight-status site-daylight-status-check site-validate site-live-check
.PHONY: readme-remaster-check readme-remaster-fix readme-remaster
.PHONY: daylight-standard-schema-test daylight-standard-examples-test daylight-conformance-test daylight-product-score daylight-standard-site-test daylight-standard-ci
.PHONY: wucios-validate wucios-fluff-audit wucios-substrate-matrix wucios-euclid-trial-phase-1 wucios-euclid-trial-phase-2 wucios-euclid-trial-phase-2-json wucios-euclid-trial-phase-2b wucios-euclid-trial-phase-2b-json wucios-euclid-trial-phase-2-attempt wucios-euclid-probe-buildroot wucios-euclid-probe-alpine wucios-euclid-probe-debian-minimal wucios-euclid-probe-void wucios-euclid-probe-nixos wucios-euclid-probe-guix wucios-euclid-probe-yocto wucios-euclid-probe-openbsd-reference wucios-euclid-buildrooms-phase-3a wucios-euclid-buildrooms-phase-3a-json wucios-buildroom-probe-buildroot wucios-buildroom-probe-alpine wucios-buildroom-probe-debian-minimal wucios-buildroom-probe-void wucios-buildroom-probe-nixos wucios-buildroom-probe-guix wucios-buildroom-probe-yocto wucios-buildroom-probe-openbsd-reference euclid-phase-2 euclid-phase-3a euclid-build-probes buildroom-readiness wucios-surface-inventory wucios-review wucios-score noether-check godel-check euclid-matrix tarski-review kolmogorov-budget shannon-ledger
.PHONY: wucios-euclid-buildrooms-phase-3b-readiness wucios-euclid-buildrooms-phase-3b-readiness-json wucios-buildroom-readiness-buildroot wucios-buildroom-readiness-alpine wucios-buildroom-readiness-debian-minimal wucios-buildroom-readiness-void wucios-buildroom-readiness-nixos wucios-buildroom-readiness-guix wucios-buildroom-readiness-yocto wucios-buildroom-readiness-openbsd-reference euclid-phase-3b-readiness buildroom-remediation-plan test-authorization-matrix
.PHONY: wucios-euclid-buildrooms-phase-3c-a wucios-euclid-buildrooms-phase-3c-a-json wucios-euclid-buildrooms-phase-3c-a-smoke wucios-euclid-buildrooms-phase-3c-a-smoke-json wucios-euclid-buildrooms-phase-3c-a-guardrails euclid-phase-3c-a buildroom-smoke-l1 buildroom-smoke-l2 buildroom-smoke-guardrails
.PHONY: wucios-euclid-direct-rootfs-phase-3c-b wucios-euclid-direct-rootfs-phase-3c-b-json wucios-euclid-direct-rootfs-phase-3c-b-scaffold wucios-euclid-direct-rootfs-phase-3c-b-scaffold-json wucios-euclid-direct-rootfs-phase-3c-b-guardrails wucios-direct-rootfs-prep-buildroot wucios-direct-rootfs-prep-alpine wucios-direct-rootfs-prep-debian-minimal wucios-direct-rootfs-prep-void euclid-phase-3c-b direct-rootfs-prep direct-rootfs-scaffold direct-rootfs-guardrails
.PHONY: wucios-euclid-store-root-phase-3c-c wucios-euclid-store-root-phase-3c-c-json wucios-euclid-store-root-phase-3c-c-scaffold wucios-euclid-store-root-phase-3c-c-scaffold-json wucios-euclid-store-root-phase-3c-c-guardrails wucios-store-root-prep-nixos wucios-store-root-prep-guix euclid-phase-3c-c store-root-prep store-root-scaffold store-root-guardrails
.PHONY: wucios-euclid-yocto-phase-3c-d wucios-euclid-yocto-phase-3c-d-json wucios-euclid-yocto-phase-3c-d-scaffold wucios-euclid-yocto-phase-3c-d-scaffold-json wucios-euclid-yocto-phase-3c-d-guardrails wucios-yocto-prep euclid-phase-3c-d yocto-prep yocto-scaffold yocto-guardrails
.PHONY: wucios-euclid-openbsd-reference-phase-3c-e wucios-euclid-openbsd-reference-phase-3c-e-json wucios-euclid-openbsd-reference-phase-3c-e-scaffold wucios-euclid-openbsd-reference-phase-3c-e-scaffold-json wucios-euclid-openbsd-reference-phase-3c-e-guardrails wucios-openbsd-reference-prep euclid-phase-3c-e openbsd-reference-prep openbsd-reference-scaffold openbsd-reference-guardrails
.PHONY: wucios-idempotence-check wucios-clean-validation
.PHONY: zp1-upstream-test zp1-wuciji-bridge-test zp1-wuciji-coupling-test

all: check-native $(TARGET)

help:
	@printf '%s\n' "Wuci-Ji local targets"
	@printf '%s\n' ""
	@printf '%s\n' "WuciOS v2.4 Reduction Gate:"
	@printf '%s\n' "  make wucios-validate          Validate WuciOS v2.4 structure"
	@printf '%s\n' "  make wucios-fluff-audit       Scan current surfaces for denied claim phrases"
	@printf '%s\n' "  make wucios-substrate-matrix  Generate Euclid substrate matrix"
	@printf '%s\n' "  make wucios-euclid-trial-phase-1"
	@printf '%s\n' "                                Generate first-cohort substrate trial protocol"
	@printf '%s\n' "  make wucios-euclid-trial-phase-2"
	@printf '%s\n' "                                Run safe detect-only build feasibility probes"
	@printf '%s\n' "  make wucios-euclid-trial-phase-2-json"
	@printf '%s\n' "                                Run Phase 2 probes and print JSON"
	@printf '%s\n' "  make wucios-euclid-trial-phase-2b"
	@printf '%s\n' "                                Run Phase 2B full-cohort safe probes"
	@printf '%s\n' "  make wucios-euclid-trial-phase-2b-json"
	@printf '%s\n' "                                Run Phase 2B full-cohort probes and print JSON"
	@printf '%s\n' "  make wucios-euclid-trial-phase-2-attempt"
	@printf '%s\n' "                                Guarded opt-in Phase 2 build attempt"
	@printf '%s\n' "  make wucios-euclid-buildrooms-phase-3a"
	@printf '%s\n' "                                Define and detect Phase 3A build-room readiness"
	@printf '%s\n' "  make wucios-euclid-buildrooms-phase-3a-json"
	@printf '%s\n' "                                Run Phase 3A readiness and print JSON"
	@printf '%s\n' "  make wucios-euclid-buildrooms-phase-3b-readiness"
	@printf '%s\n' "                                Run Phase 3B readiness diagnostics"
	@printf '%s\n' "  make wucios-euclid-buildrooms-phase-3b-readiness-json"
	@printf '%s\n' "                                Run Phase 3B readiness diagnostics and print JSON"
	@printf '%s\n' "  make wucios-euclid-buildrooms-phase-3c-a"
	@printf '%s\n' "                                Run Phase 3C-A L1 backend smoke detection"
	@printf '%s\n' "  make wucios-euclid-buildrooms-phase-3c-a-json"
	@printf '%s\n' "                                Run Phase 3C-A L1 detection and print JSON"
	@printf '%s\n' "  make wucios-euclid-buildrooms-phase-3c-a-guardrails"
	@printf '%s\n' "                                Run Phase 3C-A negative guardrail checks"
	@printf '%s\n' "  WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1 make wucios-euclid-buildrooms-phase-3c-a-smoke"
	@printf '%s\n' "                                Run authorized synthetic non-substrate L2 smoke"
	@printf '%s\n' "  WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1 make wucios-euclid-buildrooms-phase-3c-a-smoke-json"
	@printf '%s\n' "                                Run authorized synthetic non-substrate L2 smoke and print JSON"
	@printf '%s\n' "  make wucios-euclid-direct-rootfs-phase-3c-b"
	@printf '%s\n' "                                Run Phase 3C-B direct-rootfs L1 policy checks"
	@printf '%s\n' "  make wucios-euclid-direct-rootfs-phase-3c-b-json"
	@printf '%s\n' "                                Run Phase 3C-B L1 policy checks and print JSON"
	@printf '%s\n' "  make wucios-euclid-direct-rootfs-phase-3c-b-guardrails"
	@printf '%s\n' "                                Run Phase 3C-B negative guardrail checks"
	@printf '%s\n' "  WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-direct-rootfs-phase-3c-b-scaffold"
	@printf '%s\n' "                                Generate authorized non-artifact direct-rootfs scaffolding"
	@printf '%s\n' "  WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-direct-rootfs-phase-3c-b-scaffold-json"
	@printf '%s\n' "                                Generate authorized non-artifact scaffolding and print JSON"
	@printf '%s\n' "  make wucios-euclid-store-root-phase-3c-c"
	@printf '%s\n' "                                Run Phase 3C-C NixOS/Guix store-root L1 policy checks"
	@printf '%s\n' "  make wucios-euclid-store-root-phase-3c-c-json"
	@printf '%s\n' "                                Run Phase 3C-C L1 policy checks and print JSON"
	@printf '%s\n' "  make wucios-euclid-store-root-phase-3c-c-guardrails"
	@printf '%s\n' "                                Run Phase 3C-C negative guardrail checks"
	@printf '%s\n' "  WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-store-root-phase-3c-c-scaffold"
	@printf '%s\n' "                                Generate authorized non-artifact NixOS/Guix scaffolding"
	@printf '%s\n' "  WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-store-root-phase-3c-c-scaffold-json"
	@printf '%s\n' "                                Generate authorized NixOS/Guix scaffolding and print JSON"
	@printf '%s\n' "  make wucios-euclid-yocto-phase-3c-d"
	@printf '%s\n' "                                Run Phase 3C-D Yocto layer/recipe L1 policy checks"
	@printf '%s\n' "  make wucios-euclid-yocto-phase-3c-d-json"
	@printf '%s\n' "                                Run Phase 3C-D L1 policy checks and print JSON"
	@printf '%s\n' "  make wucios-euclid-yocto-phase-3c-d-guardrails"
	@printf '%s\n' "                                Run Phase 3C-D negative guardrail checks"
	@printf '%s\n' "  WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-yocto-phase-3c-d-scaffold"
	@printf '%s\n' "                                Generate authorized non-artifact Yocto scaffolding"
	@printf '%s\n' "  WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-yocto-phase-3c-d-scaffold-json"
	@printf '%s\n' "                                Generate authorized Yocto scaffolding and print JSON"
	@printf '%s\n' "  make wucios-euclid-openbsd-reference-phase-3c-e"
	@printf '%s\n' "                                Run Phase 3C-E OpenBSD reference L1 policy checks"
	@printf '%s\n' "  make wucios-euclid-openbsd-reference-phase-3c-e-json"
	@printf '%s\n' "                                Run Phase 3C-E L1 policy checks and print JSON"
	@printf '%s\n' "  make wucios-euclid-openbsd-reference-phase-3c-e-guardrails"
	@printf '%s\n' "                                Run Phase 3C-E negative guardrail checks"
	@printf '%s\n' "  WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-openbsd-reference-phase-3c-e-scaffold"
	@printf '%s\n' "                                Generate authorized non-artifact OpenBSD reference scaffolding"
	@printf '%s\n' "  WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-openbsd-reference-phase-3c-e-scaffold-json"
	@printf '%s\n' "                                Generate authorized OpenBSD reference scaffolding and print JSON"
	@printf '%s\n' "  make buildroom-remediation-plan"
	@printf '%s\n' "                                Alias for Phase 3B readiness diagnostics"
	@printf '%s\n' "  make test-authorization-matrix"
	@printf '%s\n' "                                Alias for Phase 3B readiness diagnostics"
	@printf '%s\n' "  make wucios-euclid-probe-buildroot"
	@printf '%s\n' "                                Run Buildroot Phase 2 detect-only probe"
	@printf '%s\n' "  make wucios-euclid-probe-alpine"
	@printf '%s\n' "                                Run Alpine Phase 2 detect-only probe"
	@printf '%s\n' "  make wucios-euclid-probe-debian-minimal"
	@printf '%s\n' "                                Run Debian minimal Phase 2 detect-only probe"
	@printf '%s\n' "  make wucios-euclid-probe-void"
	@printf '%s\n' "                                Run Void Phase 2 detect-only probe"
	@printf '%s\n' "  make wucios-euclid-probe-nixos"
	@printf '%s\n' "                                Run NixOS Phase 2 detect-only probe"
	@printf '%s\n' "  make wucios-euclid-probe-guix"
	@printf '%s\n' "                                Run Guix Phase 2 detect-only probe"
	@printf '%s\n' "  make wucios-euclid-probe-yocto"
	@printf '%s\n' "                                Run Yocto Phase 2 detect-only probe"
	@printf '%s\n' "  make wucios-euclid-probe-openbsd-reference"
	@printf '%s\n' "                                Run OpenBSD reference Phase 2 detect-only probe"
	@printf '%s\n' "  make buildroom-readiness      Alias for Phase 3A build-room readiness"
	@printf '%s\n' "  make wucios-surface-inventory Collect local surface inventory"
	@printf '%s\n' "  make wucios-score             Generate invalid/no-artifact score material"
	@printf '%s\n' "  make wucios-review            Generate partial Tarski review packet"
	@printf '%s\n' "  make wucios-idempotence-check"
	@printf '%s\n' "                                Verify safe validation does not modify tracked files"
	@printf '%s\n' ""
	@printf '%s\n' "Safe local checks:"
	@printf '%s\n' "  make site-validate"
	@printf '%s\n' "  make readme-remaster-check    Verify README WuciOS v2.4 status anchors"
	@printf '%s\n' "  make readme-remaster-fix      Repair bounded README status anchors"
	@printf '%s\n' "  make readme-remaster          Remaster README and re-run anchor checks"
	@printf '%s\n' "  make daylight-npt-test"
	@printf '%s\n' "  make daylight-standard-schema-test"

daylight-npt:
	PYTHONPATH=daylight/npt/v1 $(PYTHON) -m daylight_npt scan --registry daylight/npt/v1/number-claims.registry.json --out build/daylight/npt-v1/daylight-npt.report.json README.md BUILD_NOTES.md SECURITY.md docs daylight site data audits

daylight-npt-report: daylight-npt
	@printf '%s\n' "daylight-npt report: build/daylight/npt-v1/daylight-npt.report.json"

daylight-npt-test:
	PYTHONPATH=daylight/npt/v1 $(PYTHON) -m unittest discover -s tests/daylight_npt -t .

daylight-npt-ci: daylight-npt-test daylight-npt-report
	@printf '%s\n' "daylight-npt-ci: complete"

daylight-ssv:
	PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv audit --out $(DAYLIGHT_SSV_REPORT)

daylight-ssv-report: daylight-ssv
	@printf '%s\n' "daylight-ssv report: $(DAYLIGHT_SSV_REPORT)"

daylight-ssv-test:
	PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m unittest discover -s tests/daylight_ssv -t .

daylight-ssv-ci: daylight-ssv-test
	PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv check-model
	PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv validate-report daylight/ssv/v1/examples/perfect.json
	PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv validate-report daylight/ssv/v1/examples/mixed-score.json
	PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv validate-report daylight/ssv/v1/examples/critical-override.json
	PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv validate-report daylight/ssv/v1/examples/missing-evidence.json
	! PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv validate-report daylight/ssv/v1/examples/invalid-score-too-precise.json
	! PYTHONPATH=$(DAYLIGHT_SSV_PYTHONPATH) $(PYTHON) -m daylight_ssv validate-report daylight/ssv/v1/examples/invalid-score-over-100.json
	@printf '%s\n' "daylight-ssv-ci: complete"

daylight-score-integrity-audit: daylight-npt
	$(PYTHON) tools/daylight_score_integrity_audit.py

daylight-score-integrity-audit-directory-check:
	$(PYTHON) tools/daylight_score_integrity_record.py check

daylight-standard-schema-test:
	$(PYTHON) tools/daylight_standard_validate.py schema-test

daylight-standard-examples-test:
	$(PYTHON) tools/daylight_standard_validate.py examples-test

daylight-conformance-test:
	@mkdir -p build/daylight
	$(PYTHON) tools/daylight_conformance.py validate --input examples/daylight-standard/minimal-claim.json
	$(PYTHON) tools/daylight_conformance.py validate --input examples/daylight-standard/evidence-example.json
	! $(PYTHON) tools/daylight_conformance.py validate --input examples/daylight-standard/unsupported-certification-claim.json
	$(PYTHON) tools/daylight_conformance.py score --claims examples/daylight-standard/minimal-claim.json --evidence examples/daylight-standard/evidence-example.json --out build/daylight/daylight-standard-scorecard.json
	$(PYTHON) tools/daylight_conformance.py gate --release examples/daylight-standard/release-gate-pass.json --scorecard build/daylight/daylight-standard-scorecard.json
	! $(PYTHON) tools/daylight_conformance.py gate --release examples/daylight-standard/release-gate-fail-no-evidence.json --scorecard build/daylight/daylight-standard-scorecard.json
	$(PYTHON) tools/daylight_conformance.py explain --scorecard build/daylight/daylight-standard-scorecard.json
	$(PYTHON) tools/daylight_conformance.py control-map --claims examples/daylight-standard/minimal-claim.json --out build/daylight/daylight-standard-control-map.json
	$(PYTHON) tools/daylight_conformance.py status --project . > build/daylight/daylight-standard-conformance-report.json
	! $(PYTHON) tools/daylight_conformance.py monitor-signal --input examples/daylight-standard/monitor-signal-example.json --state build/daylight/daylight-monitor-state.json

daylight-product-score:
	$(PYTHON) tools/daylight_product_score.py

daylight-standard-site-test:
	$(MAKE) site-validate

daylight-standard-ci: daylight-standard-schema-test daylight-standard-examples-test daylight-conformance-test daylight-product-score daylight-npt-ci daylight-standard-site-test
	@printf '%s\n' "daylight-standard-ci: complete"

daylight-cplus-score:
	PYTHONPATH=daylight/v14c-plus $(PYTHON) -m src.cli score --ledger daylight/v14c-plus/examples/ledger.seed.jsonl --corpus daylight/v14c-plus/examples/corpus.seed.jsonl --out daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json --receipt daylight/v14c-plus/examples/reproducibility-receipt.v14c-plus.json --output-ledger daylight/v14c-plus/examples/ledger.with-scorecard.jsonl

daylight-cplus-verify: daylight-cplus-score
	PYTHONPATH=daylight/v14c-plus $(PYTHON) -m src.cli verify-scorecard daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json

daylight-cplus-corpus:
	PYTHONPATH=daylight/v14c-plus $(PYTHON) -m src.cli freeze-corpus --corpus daylight/v14c-plus/examples/corpus.seed.jsonl --out daylight/v14c-plus/examples/corpus.snapshot.json

daylight-cplus-test: daylight-cplus-verify
	PYTHONPATH=daylight/v14c-plus $(PYTHON) -m unittest discover -s daylight/v14c-plus/tests -t daylight/v14c-plus

daylight-meridian-score:
	rm -f daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json daylight/v15-meridian/examples/reproducibility-receipt.v15-meridian.json daylight/v15-meridian/examples/ledger.with-scorecard.jsonl
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli score --ledger daylight/v15-meridian/examples/ledger.seed.jsonl --corpus daylight/v15-meridian/examples/corpus.seed.jsonl --out daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json --receipt daylight/v15-meridian/examples/reproducibility-receipt.v15-meridian.json --output-ledger daylight/v15-meridian/examples/ledger.with-scorecard.jsonl

daylight-meridian-verify: daylight-meridian-score
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli verify-scorecard daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json --ledger daylight/v15-meridian/examples/ledger.seed.jsonl --corpus daylight/v15-meridian/examples/corpus.seed.jsonl

daylight-meridian-corpus:
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli freeze-corpus --corpus daylight/v15-meridian/examples/corpus.seed.jsonl --out daylight/v15-meridian/examples/corpus.snapshot.json

daylight-meridian-frontier:
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli frontier

daylight-meridian-perfect-demo:
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli score --ledger daylight/v15-meridian/examples/ledger.perfect.jsonl --corpus daylight/v15-meridian/examples/corpus.seed.jsonl --out daylight/v15-meridian/examples/expected-scorecard.perfect.v15-meridian.json
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli verify-scorecard daylight/v15-meridian/examples/expected-scorecard.perfect.v15-meridian.json --ledger daylight/v15-meridian/examples/ledger.perfect.jsonl --corpus daylight/v15-meridian/examples/corpus.seed.jsonl

daylight-meridian-test: daylight-meridian-verify
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m unittest discover -s daylight/v15-meridian/tests -t daylight/v15-meridian

daylight-meridian-artifact:
	rm -rf $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR)
	mkdir -p $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR)
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli artifact --out-dir $(DAYLIGHT_MERIDIAN_ARTIFACT_DIR) --command-label "make daylight-meridian-artifact"
	$(PYTHON) tools/daylight_public_evidence_firewall.py scan $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR) --profile daylight-v15-meridian-public
	$(PYTHON) tools/daylight_public_evidence_firewall.py verify-manifest $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR)/artifact-manifest.json --root $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR)

daylight-meridian-public-artifact: daylight-meridian-artifact
	$(PYTHON) tools/daylight_public_evidence_firewall.py scan $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR) --profile daylight-v15-meridian-public

daylight-public-evidence-firewall-test:
	$(PYTHON) tests/daylight_public_evidence_firewall.py

daylight-security-ratchet-test:
	$(PYTHON) tests/daylight_security_ratchet.py

daylight-public-artifact-firewall: daylight-meridian-public-artifact
	$(PYTHON) tools/daylight_public_evidence_firewall.py scan $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR) --profile daylight-v15-meridian-public
	$(PYTHON) tools/daylight_public_evidence_firewall.py verify-manifest $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR)/artifact-manifest.json --root $(DAYLIGHT_MERIDIAN_PUBLIC_ARTIFACT_DIR)
	@status=0; for workflow in .github/workflows/*.yml; do $(PYTHON) tools/daylight_public_evidence_firewall.py check-workflow $$workflow || status=$$?; done; exit $$status

daylight-private-material-regression-test: daylight-public-evidence-firewall-test daylight-security-ratchet-test

daylight-meridian-public-artifact-test: daylight-public-artifact-firewall daylight-private-material-regression-test

daylight-meridian-smoke:
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli --version
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli doctor
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli score --format text
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli frontier
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli frontier --json >/dev/null
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli attestation-template --obligation-id o.q7.external_red_team --signer-id ext:red-team >/dev/null
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli explain --scorecard daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json >/dev/null
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli gate --scorecard daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json --ledger daylight/v15-meridian/examples/ledger.seed.jsonl --corpus daylight/v15-meridian/examples/corpus.seed.jsonl --min-score 998900 --require-no-open-internal --allow-external-residue
	mkdir -p $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli seal --keyfile daylight/v15-meridian/examples/demo.key --min-score 998900 --message "meridian smoke" --nonce 000000000000000000000000 --out $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke.mae
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli open --keyfile daylight/v15-meridian/examples/demo.key --in $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke.mae >/dev/null
	rm -rf $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-vault
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault init --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-vault --force
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault status --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-vault >/dev/null
	printf 'smoke\n' > $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-secret.txt
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault seal --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-secret.txt --name smoke
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault open --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-vault smoke --out $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-secret.out
	cmp $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-secret.txt $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/smoke-secret.out

daylight-meridian-envelope-demo:
	mkdir -p $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli seal --keyfile daylight/v15-meridian/examples/demo.key --min-score 998900 --require-closed o.q1.master_law_executable o.q4.fail_closed_tests --message "Daylight v15 Meridian: sealed by evidence, opened by proof." --nonce 000000000000000000000000 --out $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/demo.mae
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli envelope-inspect --in $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/demo.mae
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli open --keyfile daylight/v15-meridian/examples/demo.key --in $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/demo.mae

daylight-meridian-envelope-test:
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m unittest tests.test_aead_vectors tests.test_envelope

daylight-meridian-vault-test:
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m unittest tests.test_vault

daylight-meridian-vault-demo:
	rm -rf $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault-work
	mkdir -p $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault-work
	printf 'meridian vault demo: sealed by evidence, opened by proof.\n' > $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault-work/secret.txt
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault init --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault --force
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault status --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault seal --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault-work/secret.txt --name demo
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault list --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli vault open --vault $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault demo --out $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault-work/secret.out
	cmp $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault-work/secret.txt $(DAYLIGHT_MERIDIAN_PRIVATE_DIR)/vault-work/secret.out
	@echo "daylight-meridian-vault-demo: evidence-gated roundtrip OK"

daylight-meridian-package:
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -c "from src import __version__; print('daylight-meridian', __version__)"
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli --version
	PYTHONPATH=daylight/v15-meridian $(PYTHON) -m src.cli doctor

daylight-meridian-ci: daylight-meridian-test daylight-meridian-smoke daylight-meridian-vault-demo daylight-public-artifact-firewall daylight-meridian-public-artifact-test
	@echo "daylight-meridian-ci: complete"

daylight-solstice-score:
	PYTHONPATH=daylight/v15-solstice $(PYTHON) -m src.cli score --ledger daylight/v15-solstice/examples/ledger.seed.jsonl --corpus daylight/v15-solstice/examples/corpus.seed.jsonl --rootset daylight/v15-solstice/rules/external-rootset.solstice.json --out daylight/v15-solstice/examples/expected-scorecard.v15-solstice.json --receipt daylight/v15-solstice/examples/reproducibility-receipt.v15-solstice.json --output-ledger daylight/v15-solstice/examples/output-ledger.v15-solstice.jsonl

daylight-solstice-verify: daylight-solstice-score
	PYTHONPATH=daylight/v15-solstice $(PYTHON) -m src.cli verify-scorecard daylight/v15-solstice/examples/expected-scorecard.v15-solstice.json --ledger daylight/v15-solstice/examples/ledger.seed.jsonl --corpus daylight/v15-solstice/examples/corpus.seed.jsonl --rootset daylight/v15-solstice/rules/external-rootset.solstice.json --receipt daylight/v15-solstice/examples/reproducibility-receipt.v15-solstice.json --output-ledger daylight/v15-solstice/examples/output-ledger.v15-solstice.jsonl

daylight-solstice-frontier:
	PYTHONPATH=daylight/v15-solstice $(PYTHON) -m src.cli frontier --ledger daylight/v15-solstice/examples/ledger.seed.jsonl --corpus daylight/v15-solstice/examples/corpus.seed.jsonl --rootset daylight/v15-solstice/rules/external-rootset.solstice.json

daylight-solstice-artifact:
	PYTHONPATH=daylight/v15-solstice $(PYTHON) -m src.cli artifact --ledger daylight/v15-solstice/examples/ledger.seed.jsonl --corpus daylight/v15-solstice/examples/corpus.seed.jsonl --rootset daylight/v15-solstice/rules/external-rootset.solstice.json --out-dir build/daylight/v15-solstice --command-label "make daylight-solstice-artifact"

daylight-solstice-external-demo:
	PYTHONPATH=daylight/v15-solstice $(PYTHON) -m unittest tests.test_signed_external_credit

daylight-solstice-test:
	PYTHONPATH=daylight/v15-solstice $(PYTHON) -m unittest discover -s daylight/v15-solstice/tests -t daylight/v15-solstice

daylight-solstice-ci: daylight-solstice-verify daylight-solstice-test daylight-solstice-artifact
	@echo "daylight-solstice-ci: complete"

daylight-zenith-verify: daylight-solstice-artifact
	PYTHONPATH=daylight/v16-zenith $(PYTHON) -m src.cli verify-artifact build/daylight/v15-solstice

daylight-zenith-report: daylight-solstice-artifact
	PYTHONPATH=daylight/v16-zenith $(PYTHON) -m src.cli report build/daylight/v15-solstice --out-dir build/daylight/v16-zenith
	PYTHONPATH=daylight/v16-zenith $(PYTHON) -m src.cli verify-report build/daylight/v16-zenith

daylight-zenith-test:
	PYTHONPATH=daylight/v16-zenith $(PYTHON) -m unittest discover -s daylight/v16-zenith/tests -t daylight/v16-zenith

daylight-zenith-ci: daylight-zenith-verify daylight-zenith-report daylight-zenith-test
	@echo "daylight-zenith-ci: complete"

daylight-analemma-verify: daylight-solstice-artifact
	PYTHONPATH=daylight/v16-analemma $(PYTHON) -m src.cli verify-artifact build/daylight/v15-solstice

daylight-analemma-report: daylight-solstice-artifact
	PYTHONPATH=daylight/v16-analemma $(PYTHON) -m src.cli report build/daylight/v15-solstice --out-dir build/daylight/v16-analemma
	PYTHONPATH=daylight/v16-analemma $(PYTHON) -m src.cli verify-report build/daylight/v16-analemma

daylight-analemma-test:
	PYTHONPATH=daylight/v16-analemma $(PYTHON) -m unittest discover -s daylight/v16-analemma/tests -t daylight/v16-analemma

daylight-analemma-ci: daylight-analemma-verify daylight-analemma-report daylight-analemma-test
	@echo "daylight-analemma-ci: complete"

daylight-v16-awe-test:
	PYTHONPATH=daylight/v16-analemma-crypto $(PYTHON) -m unittest discover -s daylight/v16-analemma-crypto/tests -t daylight/v16-analemma-crypto

daylight-v17-event-horizon-score:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli score --state daylight/v17-singularity/examples/state.current.json --atoms daylight/v17-singularity/rules/proof-atoms.v17.json --out daylight/v17-singularity/examples/expected-scorecard.current.v17.json --format text
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli score --state daylight/v17-singularity/examples/state.current.json --atoms daylight/v17-singularity/rules/proof-atoms.v17.json --out daylight/v17-singularity/examples/current-scorecard.v17.json --format text

daylight-v17-event-horizon-verify:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli verify-scorecard daylight/v17-singularity/examples/expected-scorecard.current.v17.json --state daylight/v17-singularity/examples/state.current.json --atoms daylight/v17-singularity/rules/proof-atoms.v17.json --format text

daylight-v17-event-horizon-doctor:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli doctor --format text

daylight-v17-event-horizon-fracture:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli fracture --state daylight/v17-singularity/examples/state.current.json --format text

daylight-v17-event-horizon-vector:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli vector --state daylight/v17-singularity/examples/state.current.json --out daylight/v17-singularity/examples/verifier-vector.python-reference.current.v17.json --format text

daylight-v17-event-horizon-rust-vector:
	$(CARGO) run --quiet --manifest-path daylight/v17-singularity/rust/event-horizon-verifier/Cargo.toml -- --out daylight/v17-singularity/examples/verifier-vector.rust-current.v17.json

daylight-v17-event-horizon-rust-test:
	$(CARGO) test --quiet --manifest-path daylight/v17-singularity/rust/event-horizon-verifier/Cargo.toml

daylight-v17-event-horizon-agreement:
	! PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli agreement --state daylight/v17-singularity/examples/state.current.json --vectors daylight/v17-singularity/examples/verifier-vectors.python-rust-current.v17.json --format text

daylight-v17-event-horizon-triangulation: daylight-v17-event-horizon-rust-test daylight-v17-event-horizon-rust-vector daylight-v17-event-horizon-vector
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -c "from pathlib import Path; from src.canonical_json import json_bytes, load_json_no_floats; from src import verifier_vector; root=Path('daylight/v17-singularity'); payload={'version': verifier_vector.VECTOR_BUNDLE_VERSION, 'vectors':[load_json_no_floats(root/'examples/verifier-vector.python-reference.current.v17.json'), load_json_no_floats(root/'examples/verifier-vector.rust-current.v17.json')]}; (root/'examples/verifier-vectors.python-rust-current.v17.json').write_bytes(json_bytes(payload))"
	! PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli agreement --state daylight/v17-singularity/examples/state.current.json --vectors daylight/v17-singularity/examples/verifier-vectors.python-rust-current.v17.json --format text
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli blockers --scorecard daylight/v17-singularity/examples/expected-scorecard.current.v17.json --state daylight/v17-singularity/examples/state.current.json --format text

daylight-v17-event-horizon-blockers:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli blockers --scorecard daylight/v17-singularity/examples/expected-scorecard.current.v17.json --state daylight/v17-singularity/examples/state.current.json --atoms daylight/v17-singularity/rules/proof-atoms.v17.json --format text

daylight-v17-event-horizon-frontier:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli frontier --state daylight/v17-singularity/examples/state.current.json --format text

daylight-v17-event-horizon-fixture-demo:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli fixture-demo --state daylight/v17-singularity/examples/state.declaration-fixture.json --out daylight/v17-singularity/examples/expected-scorecard.declaration-fixture.v17.json --format text
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli verify-scorecard daylight/v17-singularity/examples/expected-scorecard.declaration-fixture.v17.json --state daylight/v17-singularity/examples/state.declaration-fixture.json --atoms daylight/v17-singularity/rules/proof-atoms.v17.json --format text
	! PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli declaration-gate --scorecard daylight/v17-singularity/examples/expected-scorecard.declaration-fixture.v17.json --state daylight/v17-singularity/examples/state.declaration-fixture.json --atoms daylight/v17-singularity/rules/proof-atoms.v17.json --format text

daylight-v17-event-horizon-declaration-gate:
	! PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli declaration-gate --scorecard daylight/v17-singularity/examples/expected-scorecard.current.v17.json --state daylight/v17-singularity/examples/state.current.json --atoms daylight/v17-singularity/rules/proof-atoms.v17.json --format text

daylight-v17-event-horizon-test:
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m unittest discover -s daylight/v17-singularity/tests -t daylight/v17-singularity

daylight-v17-singularity-score: daylight-v17-event-horizon-score
daylight-v17-singularity-verify: daylight-v17-event-horizon-verify
daylight-v17-singularity-doctor: daylight-v17-event-horizon-doctor
daylight-v17-singularity-fixture-demo: daylight-v17-event-horizon-fixture-demo
daylight-v17-singularity-declaration-gate: daylight-v17-event-horizon-declaration-gate
daylight-v17-singularity-test: daylight-v17-event-horizon-test

daylight-horizon-alpha-test: daylight-public-evidence-firewall-test
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m unittest tests.test_horizon_policy tests.test_horizon_vault tests.test_horizon_release

daylight-horizon-alpha-vault-demo:
	mkdir -p build/daylight/horizon
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli horizon-vault init --root build/daylight/horizon/vault --force --format text
	printf 'Daylight Horizon Alpha vault demo\n' > build/daylight/horizon/secret.txt
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli horizon-vault seal --root build/daylight/horizon/vault --in build/daylight/horizon/secret.txt --out build/daylight/horizon/secret.txt.dhv --nonce-hex 000000000000000000000001 --format text
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli horizon-vault inspect --in build/daylight/horizon/secret.txt.dhv --format text
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli horizon-vault open --root build/daylight/horizon/vault --in build/daylight/horizon/secret.txt.dhv --out build/daylight/horizon/secret.opened.txt --format text
	cmp build/daylight/horizon/secret.txt build/daylight/horizon/secret.opened.txt

daylight-horizon-alpha-release-demo:
	mkdir -p build/daylight/horizon
	printf 'Daylight Horizon Alpha release demo\n' > build/daylight/horizon/release-artifact.txt
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli horizon-release prepare --artifact build/daylight/horizon/release-artifact.txt --out build/daylight/horizon/release-artifact.txt.dhr --mode research --format text
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli horizon-release verify --release build/daylight/horizon/release-artifact.txt.dhr --artifact build/daylight/horizon/release-artifact.txt --format text
	PYTHONPATH=daylight/v17-singularity $(PYTHON) -m src.cli horizon-release gate --release build/daylight/horizon/release-artifact.txt.dhr --artifact build/daylight/horizon/release-artifact.txt --format text

daylight-v18-bastion-measure:
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli measure --subject daylight/v18-bastion/examples/example-subject.bin --out daylight/v18-bastion/examples/example-vector.v18.json --format text

daylight-v18-bastion-verify:
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli verify-vector daylight/v18-bastion/examples/example-vector.v18.json --format text

daylight-v18-bastion-test: daylight-public-evidence-firewall-test
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m unittest discover -s daylight/v18-bastion/tests -t daylight/v18-bastion

daylight-v18-bastion-transition-test:
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m unittest tests.test_user_ceremony tests.test_transition_ledger tests.test_transition_cli

daylight-v18-bastion-transition-ledger-verify:
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli transition-ledger-verify --ledger daylight/v18-bastion/examples/transition-ledger.v18.json --format text

daylight-v18-bastion-transition-demo:
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli verify-vector daylight/v18-bastion/examples/transition.before.v18.json --format text
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli verify-vector daylight/v18-bastion/examples/transition.after.v18.json --format text
	DAYLIGHT_BASTION_PASSPHRASE=daylight-v18-fixture-passphrase PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli transition-verify --before daylight/v18-bastion/examples/transition.before.v18.json --after daylight/v18-bastion/examples/transition.after.v18.json --transition daylight/v18-bastion/examples/transition-record.v18.json --format text
	PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli transition-ledger-verify --ledger daylight/v18-bastion/examples/transition-ledger.v18.json --format text
	@if PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli tamper-check --before daylight/v18-bastion/examples/transition.before.v18.json --after daylight/v18-bastion/examples/transition.after.v18.json --format text; then echo "expected tamper-check without transition to fail"; exit 1; else echo "tamper without transition rejected"; fi
	DAYLIGHT_BASTION_PASSPHRASE=daylight-v18-fixture-passphrase PYTHONPATH=daylight/v18-bastion $(PYTHON) -m src.cli tamper-check --before daylight/v18-bastion/examples/transition.before.v18.json --after daylight/v18-bastion/examples/transition.after.v18.json --transition daylight/v18-bastion/examples/transition-record.v18.json --ledger daylight/v18-bastion/examples/transition-ledger.v18.json --format text

daylight-v19-aperture-bastion-doctor:
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m src.cli doctor

daylight-v19-aperture-bastion-verify:
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m src.cli verify-capsule daylight/v19-aperture-bastion/examples/expected-capsule.v19.json

daylight-v19-aperture-bastion-capsule-demo:
	mkdir -p build/daylight
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m src.cli capsule \
		--subject daylight/v19-aperture-bastion/examples/example-subject.bin \
		--public-file daylight/v19-aperture-bastion/examples/example-subject.bin \
		--public-file daylight/v18-bastion/examples/transition.before.v18.json \
		--public-file daylight/v18-bastion/examples/transition.after.v18.json \
		--public-file daylight/v18-bastion/examples/transition-ledger.v18.json \
		--public-file daylight/v17-singularity/examples/expected-scorecard.current.v17.json \
		--public-file daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json \
		--binaric-vector daylight/v18-bastion/examples/transition.before.v18.json \
		--binaric-vector daylight/v18-bastion/examples/transition.after.v18.json \
		--transition-ledger daylight/v18-bastion/examples/transition-ledger.v18.json \
		--meridian-scorecard daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json \
		--event-horizon-scorecard daylight/v17-singularity/examples/expected-scorecard.current.v17.json \
		--policy docs/wuci_cage_policy.json \
		--out $(DAYLIGHT_APERTURE_CAPSULE) --force
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m src.cli verify-capsule $(DAYLIGHT_APERTURE_CAPSULE) --require-evidence
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m src.cli explain $(DAYLIGHT_APERTURE_CAPSULE)

daylight-v19-aperture-bastion-public-artifact: daylight-v19-aperture-bastion-capsule-demo
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m src.cli public-artifact --capsule $(DAYLIGHT_APERTURE_CAPSULE) --out-dir $(DAYLIGHT_APERTURE_PUBLIC_DIR) --force

daylight-v19-aperture-bastion-firewall: daylight-v19-aperture-bastion-public-artifact
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m src.cli firewall --root $(DAYLIGHT_APERTURE_PUBLIC_DIR)

daylight-v19-aperture-bastion-test: daylight-public-evidence-firewall-test
	PYTHONPATH=daylight/v19-aperture-bastion $(PYTHON) -m unittest discover -s daylight/v19-aperture-bastion/tests -t daylight/v19-aperture-bastion

daylight-v19-aperture-bastion-ci: daylight-v19-aperture-bastion-test daylight-v19-aperture-bastion-doctor daylight-v19-aperture-bastion-verify daylight-v19-aperture-bastion-firewall
	@echo "daylight-v19-aperture-bastion-ci: complete"

aperture-bastion-doctor: daylight-v19-aperture-bastion-doctor
aperture-bastion-test: daylight-v19-aperture-bastion-test
aperture-bastion-ci: daylight-v19-aperture-bastion-ci

daylight-v20-aperture-singularity-doctor:
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli doctor

daylight-v20-aperture-singularity-test:
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m unittest discover -s daylight/v20-aperture-singularity/tests -t daylight/v20-aperture-singularity

daylight-v20-aperture-singularity-capsule-demo:
	mkdir -p build/daylight
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli build-capsule --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --out $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --force
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli explain $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)

daylight-v20-aperture-singularity-agreement:
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli agreement daylight/v20-aperture-singularity/examples/verifier-agreement.full-3-of-3.v20.json --expected-subject v20-aperture-singularity-fixture
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli agreement daylight/v20-aperture-singularity/examples/verifier-agreement.partial-2-of-3.v20.json --expected-subject v20-aperture-singularity-fixture

daylight-v20-aperture-singularity-blockers: daylight-v20-aperture-singularity-capsule-demo
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli blockers $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)

daylight-v20-aperture-singularity-evidence-audit: daylight-v20-aperture-singularity-capsule-demo
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli evidence-audit $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)

daylight-v20-aperture-singularity-score-ceiling: daylight-v20-aperture-singularity-capsule-demo
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli score-ceiling $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli score-ceiling-report --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)

daylight-v20-aperture-singularity-external-evidence: daylight-v20-aperture-singularity-capsule-demo daylight-v20-rebuild-receipts
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.valid-shape.nonclaim.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli explain-external-blockers daylight/v20-aperture-singularity/examples/external-evidence.valid-shape.nonclaim.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.signed-nonclaim.v20.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json

daylight-v20-rebuild-receipts: daylight-v20-aperture-singularity-capsule-demo
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m unittest tests.test_rebuild_receipts
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-rebuild-receipt daylight/v20-aperture-singularity/examples/external-rebuild-receipt.valid-fixture.v20.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-rebuild-receipt daylight/v20-aperture-singularity/examples/external-rebuild-receipt.rejected-internal.v20.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-rebuild-receipt daylight/v20-aperture-singularity/examples/external-rebuild-receipt.rejected-digest-mismatch.v20.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-rebuild-receipt daylight/v20-aperture-singularity/examples/external-rebuild-receipt.rejected-unsigned.v20.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-rebuild-receipt daylight/v20-aperture-singularity/examples/external-rebuild-receipt.rejected-missing-nonclaims.v20.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json

daylight-v20-canonical-verifier-output: daylight-v20-aperture-singularity-capsule-demo
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli canonical-verifier-output --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --out build/daylight/v20-canonical-verifier-output.json --force

daylight-v20-verifier-output-digest: daylight-v20-canonical-verifier-output
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verifier-output-digest --canonical-output build/daylight/v20-canonical-verifier-output.json

daylight-v20-verifier-quorum-test:
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m unittest tests.test_verifier_quorum

daylight-v20-verifier-quorum: daylight-v20-verifier-output-digest daylight-v20-verifier-quorum-test
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.valid-fixture.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-two-of-three.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-duplicate-family.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-output-mismatch.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-fail-decision.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-unattested.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-internal-family.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-placeholder-digest.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-verifier-quorum --bundle daylight/v20-aperture-singularity/examples/external-evidence.verifier-quorum.rejected-more-than-three.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --pinned-material daylight/v20-aperture-singularity/examples/external-verification-material.signed-nonclaim.v20.json

daylight-v20-external-evidence-test:
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m unittest tests.test_external_evidence_intake tests.test_independent_rebuild_receipts tests.test_firewall_profile_review tests.test_claim_usable_verifier_vectors tests.test_pinned_attestation_verification tests.test_rebuild_receipts tests.test_verifier_quorum

daylight-v20-ed25519-attestation-test:
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m unittest tests.test_pinned_attestation_verification

daylight-v20-external-evidence-demo: daylight-v20-aperture-singularity-capsule-demo
	@echo "daylight-v20-external-evidence-demo: rejection examples below must be refused"
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.empty.reject.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.self-signed.reject.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.internal-reviewer.reject.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.fixture.reject.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.digest-mismatch.reject.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.unpinned-key.reject.json --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json

daylight-v20-external-evidence-verify: daylight-v20-aperture-singularity-external-evidence

daylight-v20-score-ceiling-report: daylight-v20-aperture-singularity-capsule-demo
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli score-ceiling-report --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)

daylight-v20-aperture-singularity-declaration-gate: daylight-v20-aperture-singularity-capsule-demo
	! PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli declaration-gate $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE)

daylight-v20-aperture-singularity-public-artifact: daylight-v20-aperture-singularity-capsule-demo
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli public-artifact --capsule $(DAYLIGHT_V20_APERTURE_SINGULARITY_CAPSULE) --out-dir $(DAYLIGHT_V20_APERTURE_SINGULARITY_PUBLIC_DIR) --tar $(DAYLIGHT_V20_APERTURE_SINGULARITY_TAR) --firewall-report $(DAYLIGHT_V20_APERTURE_SINGULARITY_FIREWALL_REPORT) --force

daylight-v20-aperture-singularity-verify-public-artifact: daylight-v20-aperture-singularity-public-artifact
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-public-artifact $(DAYLIGHT_V20_APERTURE_SINGULARITY_PUBLIC_DIR) --expected-release-tag v20-aperture-singularity-fixture
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli verify-public-artifact $(DAYLIGHT_V20_APERTURE_SINGULARITY_TAR) --expected-release-tag v20-aperture-singularity-fixture

daylight-v20-aperture-singularity-firewall: daylight-v20-aperture-singularity-public-artifact
	PYTHONPATH=daylight/v20-aperture-singularity $(PYTHON) -m src.cli firewall --root $(DAYLIGHT_V20_APERTURE_SINGULARITY_PUBLIC_DIR) --report $(DAYLIGHT_V20_APERTURE_SINGULARITY_FIREWALL_REPORT)

daylight-v20-aperture-singularity-ci: daylight-v20-aperture-singularity-test daylight-v20-ed25519-attestation-test daylight-v20-rebuild-receipts daylight-v20-verifier-quorum daylight-v20-aperture-singularity-doctor daylight-v20-aperture-singularity-capsule-demo daylight-v20-aperture-singularity-agreement daylight-v20-aperture-singularity-blockers daylight-v20-aperture-singularity-evidence-audit daylight-v20-aperture-singularity-score-ceiling daylight-v20-score-ceiling-report daylight-v20-external-evidence-test daylight-v20-external-evidence-demo daylight-v20-external-evidence-verify daylight-v20-aperture-singularity-declaration-gate daylight-v20-aperture-singularity-verify-public-artifact daylight-v20-aperture-singularity-firewall
	@echo "daylight-v20-aperture-singularity-ci: complete"

site-daylight-status:
	$(PYTHON) tools/site_daylight_status.py

site-daylight-status-check:
	$(PYTHON) tools/site_daylight_status.py --check

site-validate: site-daylight-status-check
	node site/validate.mjs

site-live-check:
	$(PYTHON) tools/site_live_check.py

readme-remaster-check:
	tools/remaster-readme.sh --check

readme-remaster-fix:
	tools/remaster-readme.sh --fix

readme-remaster:
	tools/remaster-readme.sh --write
	tools/remaster-readme.sh --check

wucios-validate:
	$(PYTHON) tools/wucios/validate_wucios.py

wucios-fluff-audit:
	$(PYTHON) tools/wucios/scan_claims.py

wucios-substrate-matrix:
	$(PYTHON) tools/wucios/generate_substrate_matrix.py

wucios-euclid-trial-phase-1:
	$(PYTHON) tools/wucios/run_euclid_trial.py

wucios-euclid-trial-phase-2:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py

wucios-euclid-trial-phase-2-json:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --json

wucios-euclid-trial-phase-2b:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --phase2b

wucios-euclid-trial-phase-2b-json:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --phase2b --json

wucios-euclid-buildrooms-phase-3a:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py

wucios-euclid-buildrooms-phase-3a-json:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --json

wucios-euclid-buildrooms-phase-3b-readiness:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py

wucios-euclid-buildrooms-phase-3b-readiness-json:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --json

wucios-euclid-buildrooms-phase-3c-a:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3c_a.py

wucios-euclid-buildrooms-phase-3c-a-json:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3c_a.py --json

wucios-euclid-buildrooms-phase-3c-a-smoke:
	@if [ "$${WUCIOS_PHASE3CA_ALLOW_L2_SMOKE:-}" != "1" ]; then printf '%s\n' "Phase 3C-A L2 synthetic smoke is not authorized. Set WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1 to run the synthetic non-substrate backend smoke test."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3c_a.py --l2-smoke

wucios-euclid-buildrooms-phase-3c-a-smoke-json:
	@if [ "$${WUCIOS_PHASE3CA_ALLOW_L2_SMOKE:-}" != "1" ]; then printf '%s\n' "Phase 3C-A L2 synthetic smoke is not authorized. Set WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1 to run the synthetic non-substrate backend smoke test."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3c_a.py --l2-smoke --json

wucios-euclid-buildrooms-phase-3c-a-guardrails:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3c_a.py --guardrails

wucios-euclid-direct-rootfs-phase-3c-b:
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py

wucios-euclid-direct-rootfs-phase-3c-b-json:
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --json

wucios-euclid-direct-rootfs-phase-3c-b-scaffold:
	@if [ "$${WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-B L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1 to generate non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --l2-scaffold

wucios-euclid-direct-rootfs-phase-3c-b-scaffold-json:
	@if [ "$${WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-B L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1 to generate non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --l2-scaffold --json

wucios-euclid-direct-rootfs-phase-3c-b-guardrails:
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --guardrails

wucios-direct-rootfs-prep-buildroot:
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --candidate buildroot

wucios-direct-rootfs-prep-alpine:
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --candidate alpine

wucios-direct-rootfs-prep-debian-minimal:
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --candidate debian-minimal

wucios-direct-rootfs-prep-void:
	$(PYTHON) tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py --candidate void

wucios-euclid-store-root-phase-3c-c:
	$(PYTHON) tools/wucios/run_euclid_store_root_phase_3c_c.py

wucios-euclid-store-root-phase-3c-c-json:
	$(PYTHON) tools/wucios/run_euclid_store_root_phase_3c_c.py --json

wucios-euclid-store-root-phase-3c-c-scaffold:
	@if [ "$${WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-C L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1 to generate NixOS/Guix non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_store_root_phase_3c_c.py --l2-scaffold

wucios-euclid-store-root-phase-3c-c-scaffold-json:
	@if [ "$${WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-C L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1 to generate NixOS/Guix non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_store_root_phase_3c_c.py --l2-scaffold --json

wucios-euclid-store-root-phase-3c-c-guardrails:
	$(PYTHON) tools/wucios/run_euclid_store_root_phase_3c_c.py --guardrails

wucios-store-root-prep-nixos:
	$(PYTHON) tools/wucios/run_euclid_store_root_phase_3c_c.py --candidate nixos_store_root

wucios-store-root-prep-guix:
	$(PYTHON) tools/wucios/run_euclid_store_root_phase_3c_c.py --candidate guix_store_root

wucios-euclid-yocto-phase-3c-d:
	$(PYTHON) tools/wucios/run_euclid_yocto_phase_3c_d.py

wucios-euclid-yocto-phase-3c-d-json:
	$(PYTHON) tools/wucios/run_euclid_yocto_phase_3c_d.py --json

wucios-euclid-yocto-phase-3c-d-scaffold:
	@if [ "$${WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-D L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1 to generate Yocto non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_yocto_phase_3c_d.py --l2-scaffold

wucios-euclid-yocto-phase-3c-d-scaffold-json:
	@if [ "$${WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-D L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1 to generate Yocto non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_yocto_phase_3c_d.py --l2-scaffold --json

wucios-euclid-yocto-phase-3c-d-guardrails:
	$(PYTHON) tools/wucios/run_euclid_yocto_phase_3c_d.py --guardrails

wucios-yocto-prep:
	$(PYTHON) tools/wucios/run_euclid_yocto_phase_3c_d.py --candidate yocto_layer_recipe

wucios-euclid-openbsd-reference-phase-3c-e:
	$(PYTHON) tools/wucios/run_euclid_openbsd_reference_phase_3c_e.py

wucios-euclid-openbsd-reference-phase-3c-e-json:
	$(PYTHON) tools/wucios/run_euclid_openbsd_reference_phase_3c_e.py --json

wucios-euclid-openbsd-reference-phase-3c-e-scaffold:
	@if [ "$${WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-E L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1 to generate OpenBSD reference non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_openbsd_reference_phase_3c_e.py --l2-scaffold

wucios-euclid-openbsd-reference-phase-3c-e-scaffold-json:
	@if [ "$${WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD:-}" != "1" ]; then printf '%s\n' "Phase 3C-E L2 non-artifact scaffold is not authorized. Set WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1 to generate OpenBSD reference non-artifact preparation scaffolding."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_openbsd_reference_phase_3c_e.py --l2-scaffold --json

wucios-euclid-openbsd-reference-phase-3c-e-guardrails:
	$(PYTHON) tools/wucios/run_euclid_openbsd_reference_phase_3c_e.py --guardrails

wucios-openbsd-reference-prep:
	$(PYTHON) tools/wucios/run_euclid_openbsd_reference_phase_3c_e.py --reference openbsd_reference

wucios-euclid-trial-phase-2-attempt:
	@if [ "$${WUCIOS_EUCLID_ALLOW_ATTEMPT:-}" != "1" ]; then printf '%s\n' "Refusing Phase 2 build attempts: set WUCIOS_EUCLID_ALLOW_ATTEMPT=1 explicitly."; exit 1; fi
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --attempt-builds --allow-network

wucios-euclid-probe-buildroot:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate buildroot

wucios-euclid-probe-alpine:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate alpine

wucios-euclid-probe-debian-minimal:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate debian-minimal

wucios-euclid-probe-void:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate void

wucios-euclid-probe-nixos:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate nixos

wucios-euclid-probe-guix:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate guix

wucios-euclid-probe-yocto:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate yocto

wucios-euclid-probe-openbsd-reference:
	$(PYTHON) tools/wucios/run_euclid_trial_phase_2.py --candidate openbsd-reference

wucios-buildroom-probe-buildroot:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate buildroot

wucios-buildroom-probe-alpine:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate alpine

wucios-buildroom-probe-debian-minimal:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate debian-minimal

wucios-buildroom-probe-void:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate void

wucios-buildroom-probe-nixos:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate nixos

wucios-buildroom-probe-guix:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate guix

wucios-buildroom-probe-yocto:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate yocto

wucios-buildroom-probe-openbsd-reference:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3a.py --candidate openbsd-reference

wucios-buildroom-readiness-buildroot:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate buildroot

wucios-buildroom-readiness-alpine:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate alpine

wucios-buildroom-readiness-debian-minimal:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate debian-minimal

wucios-buildroom-readiness-void:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate void

wucios-buildroom-readiness-nixos:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate nixos

wucios-buildroom-readiness-guix:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate guix

wucios-buildroom-readiness-yocto:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate yocto

wucios-buildroom-readiness-openbsd-reference:
	$(PYTHON) tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py --candidate openbsd-reference

wucios-surface-inventory:
	tools/wucios/surface_inventory.sh

wucios-score:
	$(PYTHON) tools/wucios/score_wucios.py

wucios-review: wucios-surface-inventory wucios-substrate-matrix wucios-euclid-trial-phase-1 wucios-euclid-trial-phase-2 wucios-euclid-trial-phase-2b wucios-score
	$(PYTHON) tools/wucios/generate_review_packet.py

wucios-idempotence-check:
	@$(MAKE) wucios-validate
	@$(MAKE) wucios-fluff-audit
	@$(MAKE) wucios-substrate-matrix
	@$(MAKE) wucios-euclid-trial-phase-1
	@$(MAKE) wucios-euclid-trial-phase-2
	@$(MAKE) wucios-euclid-trial-phase-2b
	@$(MAKE) wucios-euclid-buildrooms-phase-3a
	@$(MAKE) wucios-euclid-buildrooms-phase-3b-readiness
	@$(MAKE) wucios-euclid-buildrooms-phase-3c-a
	@$(MAKE) wucios-euclid-direct-rootfs-phase-3c-b
	@$(MAKE) wucios-euclid-store-root-phase-3c-c
	@$(MAKE) wucios-euclid-yocto-phase-3c-d
	@$(MAKE) wucios-euclid-openbsd-reference-phase-3c-e
	@$(MAKE) wucios-review
	@if ! git diff --exit-code; then printf '%s\n' "WuciOS idempotence check failed: safe validation modified tracked files."; exit 1; fi

wucios-clean-validation: wucios-idempotence-check

noether-check: wucios-validate

godel-check: wucios-fluff-audit

euclid-matrix: wucios-substrate-matrix

euclid-phase-2: wucios-euclid-trial-phase-2

euclid-phase-3a: wucios-euclid-buildrooms-phase-3a

euclid-phase-3b-readiness: wucios-euclid-buildrooms-phase-3b-readiness

euclid-phase-3c-a: wucios-euclid-buildrooms-phase-3c-a

euclid-phase-3c-b: wucios-euclid-direct-rootfs-phase-3c-b

euclid-phase-3c-c: wucios-euclid-store-root-phase-3c-c

euclid-phase-3c-d: wucios-euclid-yocto-phase-3c-d

euclid-phase-3c-e: wucios-euclid-openbsd-reference-phase-3c-e

euclid-build-probes: wucios-euclid-trial-phase-2

buildroom-readiness: wucios-euclid-buildrooms-phase-3a

buildroom-remediation-plan: wucios-euclid-buildrooms-phase-3b-readiness

test-authorization-matrix: wucios-euclid-buildrooms-phase-3b-readiness

buildroom-smoke-l1: wucios-euclid-buildrooms-phase-3c-a

buildroom-smoke-l2: wucios-euclid-buildrooms-phase-3c-a-smoke

buildroom-smoke-guardrails: wucios-euclid-buildrooms-phase-3c-a-guardrails

direct-rootfs-prep: wucios-euclid-direct-rootfs-phase-3c-b

direct-rootfs-scaffold: wucios-euclid-direct-rootfs-phase-3c-b-scaffold

direct-rootfs-guardrails: wucios-euclid-direct-rootfs-phase-3c-b-guardrails

store-root-prep: wucios-euclid-store-root-phase-3c-c

store-root-scaffold: wucios-euclid-store-root-phase-3c-c-scaffold

store-root-guardrails: wucios-euclid-store-root-phase-3c-c-guardrails

yocto-prep: wucios-euclid-yocto-phase-3c-d

yocto-scaffold: wucios-euclid-yocto-phase-3c-d-scaffold

yocto-guardrails: wucios-euclid-yocto-phase-3c-d-guardrails

openbsd-reference-prep: wucios-euclid-openbsd-reference-phase-3c-e

openbsd-reference-scaffold: wucios-euclid-openbsd-reference-phase-3c-e-scaffold

openbsd-reference-guardrails: wucios-euclid-openbsd-reference-phase-3c-e-guardrails

tarski-review: wucios-review

kolmogorov-budget: wucios-validate

shannon-ledger: wucios-surface-inventory

$(TARGET): $(OBJECTS)
	$(LD) -o $@ $^

build/%.o: src/%.s | check-native
	mkdir -p build
	$(AS) --64 -o $@ $<

build/%.zig.s: src/%.s
	mkdir -p build
	sed 's/OFFSET FLAT:/OFFSET /g' $< > $@

check-native:
	@if [ "$(HOST_OS)" != "Linux" ] || [ "$(HOST_ARCH)" != "x86_64" ]; then \
		echo "wuci-ji: native build/test requires Linux x86_64 with GNU as/ld."; \
		echo "host: $(HOST_OS) $(HOST_ARCH)"; \
		echo "use 'make build-linux' to cross-build an x86_64 Linux ELF with Zig."; \
		echo "run 'make test' inside x86_64 Linux, or use 'make test-linux' on Linux with qemu-user."; \
		exit 2; \
	fi

check-native-x25519: check-native
	@flags=$$(sed -n 's/^flags[[:space:]]*: //p' /proc/cpuinfo | head -n 1); \
	case " $$flags " in *" bmi2 "*) ;; *) \
		echo "wuci-ji: full native test requires BMI2 for the current X25519 helper."; \
		echo "use 'make test-linux' with qemu-user, or run on x86_64 with bmi2+avx."; \
		exit 2; \
	esac; \
	case " $$flags " in *" avx "*) ;; *) \
		echo "wuci-ji: full native test requires AVX for the current X25519 helper."; \
		echo "use 'make test-linux' with qemu-user, or run on x86_64 with bmi2+avx."; \
		exit 2; \
	esac

check-qemu-user:
	@if ! command -v $(QEMU_X86_64) >/dev/null 2>&1; then \
		echo "wuci-ji: test-linux requires Linux user-mode qemu-x86_64 on PATH."; \
		echo "macOS Homebrew qemu ships qemu-system-x86_64, not the Linux user-mode runner."; \
		echo "run tests on x86_64 Linux, or set QEMU_X86_64=/path/to/qemu-x86_64 on a Linux host."; \
		exit 2; \
	fi

check-qemu-x25519-cpu: check-qemu-user build-linux
	@$(QEMU_RUNNER) $(CROSS_TARGET) keypair >/dev/null

check-pypy:
	@if ! command -v $(PYPY) >/dev/null 2>&1; then \
		echo "wuci-ji: test-pypy requires PyPy at $(PYPY)."; \
		echo "install PyPy or run 'make test PYTHON=/path/to/pypy3'."; \
		exit 2; \
	fi

authority-root-fixture:
	mkdir -p build
	rm -f build/wuci-root.fixture.generated.txt build/wuci-release-root.fixture.generated.txt
	$(PYTHON) tools/wuci_authority_root.py emit --group-public-key $(FROST_FIXTURE_GROUP_PUBLIC_KEY) --authority build/wuci-root.fixture.generated.txt --quiet
	cmp $(AUTHORITY_ROOT) build/wuci-root.fixture.generated.txt
	$(PYTHON) tools/wuci_authority_root.py emit --group-public-key $(FROST_FIXTURE_GROUP_PUBLIC_KEY) --authority build/wuci-release-root.fixture.generated.txt --allow-open false --allow-release true --quiet
	cmp $(RELEASE_AUTHORITY_ROOT) build/wuci-release-root.fixture.generated.txt

authority-root-check: authority-root-fixture
	$(PYTHON) tools/wuci_authority_anchor.py check --authority $(AUTHORITY_ROOT) --sha256 $(AUTHORITY_ROOT_SHA256) --action open --strict-fixture-path --quiet
	$(PYTHON) tools/wuci_authority_anchor.py check --authority $(RELEASE_AUTHORITY_ROOT) --sha256 $(RELEASE_AUTHORITY_ROOT_SHA256) --action release --strict-fixture-path --quiet

authority-root-metal-check: $(TARGET)
	sha256sum -c $(AUTHORITY_ROOT_SHA256)
	sha256sum -c $(RELEASE_AUTHORITY_ROOT_SHA256)
	$(TARGET) authority-root-verify $(AUTHORITY_ROOT)
	$(TARGET) authority-root-verify $(RELEASE_AUTHORITY_ROOT)

build-linux: $(CROSS_TARGET)

$(CROSS_TARGET): $(CROSS_SOURCES)
	mkdir -p build $(ZIG_GLOBAL_CACHE_DIR) $(ZIG_LOCAL_CACHE_DIR)
	ZIG_GLOBAL_CACHE_DIR=$(abspath $(ZIG_GLOBAL_CACHE_DIR)) \
	ZIG_LOCAL_CACHE_DIR=$(abspath $(ZIG_LOCAL_CACHE_DIR)) \
	$(ZIG) cc -target $(ZIG_TARGET) -nostdlib -static -o $(CROSS_TARGET) $(CROSS_SOURCES)

ifeq ($(ZIG_TOOL_IMPL),python-compat)

$(ZIG_GATE_CONTRACT): tools/wuci_gate_contract_compat.py tools/wuci_receipt_contract.py tools/wuci_gate.py
	mkdir -p build
	printf '%s\n' '#!/bin/sh' 'set -eu' 'exec $(PYTHON) "$$(dirname "$$0")/../tools/wuci_gate_contract_compat.py" "$$@"' > $(ZIG_GATE_CONTRACT)
	chmod +x $(ZIG_GATE_CONTRACT)

$(ZIG_WARRANT): tools/wuci_frost_authorize.py
	mkdir -p build
	printf '%s\n' '#!/bin/sh' 'set -eu' 'exec $(PYTHON) "$$(dirname "$$0")/../tools/wuci_frost_authorize.py" "$$@"' > $(ZIG_WARRANT)
	chmod +x $(ZIG_WARRANT)

$(ZIG_WITNESS): tools/wuci_witness_compat.py tools/wuci_witness.py
	mkdir -p build
	printf '%s\n' '#!/bin/sh' 'set -eu' 'exec $(PYTHON) "$$(dirname "$$0")/../tools/wuci_witness_compat.py" "$$@"' > $(ZIG_WITNESS)
	chmod +x $(ZIG_WITNESS)

$(ZIG_LEDGER): tools/wuci_ledger.py
	mkdir -p build
	printf '%s\n' '#!/bin/sh' 'set -eu' 'exec $(PYTHON) "$$(dirname "$$0")/../tools/wuci_ledger.py" "$$@"' > $(ZIG_LEDGER)
	chmod +x $(ZIG_LEDGER)

else

$(ZIG_GATE_CONTRACT): tools/wuci_gate_contract.zig
	mkdir -p build $(ZIG_GLOBAL_CACHE_DIR) $(ZIG_LOCAL_CACHE_DIR)
	ZIG_GLOBAL_CACHE_DIR=$(abspath $(ZIG_GLOBAL_CACHE_DIR)) \
	ZIG_LOCAL_CACHE_DIR=$(abspath $(ZIG_LOCAL_CACHE_DIR)) \
	$(ZIG) build-exe tools/wuci_gate_contract.zig -femit-bin=$(ZIG_GATE_CONTRACT)

$(ZIG_WARRANT): tools/wuci_warrant.zig
	mkdir -p build $(ZIG_GLOBAL_CACHE_DIR) $(ZIG_LOCAL_CACHE_DIR)
	ZIG_GLOBAL_CACHE_DIR=$(abspath $(ZIG_GLOBAL_CACHE_DIR)) \
	ZIG_LOCAL_CACHE_DIR=$(abspath $(ZIG_LOCAL_CACHE_DIR)) \
	$(ZIG) build-exe tools/wuci_warrant.zig -femit-bin=$(ZIG_WARRANT)

$(ZIG_WITNESS): tools/wuci_witness.zig
	mkdir -p build $(ZIG_GLOBAL_CACHE_DIR) $(ZIG_LOCAL_CACHE_DIR)
	ZIG_GLOBAL_CACHE_DIR=$(abspath $(ZIG_GLOBAL_CACHE_DIR)) \
	ZIG_LOCAL_CACHE_DIR=$(abspath $(ZIG_LOCAL_CACHE_DIR)) \
	$(ZIG) build-exe tools/wuci_witness.zig -femit-bin=$(ZIG_WITNESS)

$(ZIG_LEDGER): tools/wuci_ledger.zig
	mkdir -p build $(ZIG_GLOBAL_CACHE_DIR) $(ZIG_LOCAL_CACHE_DIR)
	ZIG_GLOBAL_CACHE_DIR=$(abspath $(ZIG_GLOBAL_CACHE_DIR)) \
	ZIG_LOCAL_CACHE_DIR=$(abspath $(ZIG_LOCAL_CACHE_DIR)) \
	$(ZIG) build-exe tools/wuci_ledger.zig -femit-bin=$(ZIG_LEDGER)

endif

selftest: check-native $(TARGET)
	$(TARGET) selftest

asm-regression: check-native $(TARGET)
	$(TARGET) asm-regression

asm-smoke: selftest asm-regression

# Legacy static disassembly audit. Keep this opt-in; current CI support is
# defined by behavioral Gate/Witness/Ledger/HARDEN/CAGE/QCAGE/install proofs.
check-asm-immediates: check-native $(OBJECTS)
	NM=$(NM) OBJDUMP=$(OBJDUMP) $(PYTHON) tests/check_asm_immediates.py $(OBJECTS)

frost-demo: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/frost_secp256k1_workflow.py

frost-workflow: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/frost_secp256k1_workflow.py --quiet

frost-authz: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/frost_authorization_workflow.py --quiet

frost-authz-demo: check-native $(TARGET)
	mkdir -p $(FROST_AUTHZ_DEMO_DIR)
	rm -f $(FROST_AUTHZ_DEMO_DIR)/plain.txt $(FROST_AUTHZ_DEMO_DIR)/sealed.wj $(FROST_AUTHZ_DEMO_DIR)/auth-message.asm.txt $(FROST_AUTHZ_DEMO_DIR)/auth-message.tool.txt $(FROST_AUTHZ_DEMO_DIR)/auth-transcript.json $(FROST_AUTHZ_DEMO_DIR)/auth-receipt.json
	printf 'wuci warrant demo\n' > $(FROST_AUTHZ_DEMO_DIR)/plain.txt
	$(TARGET) seal-file-v2 1111111111111111111111111111111111111111111111111111111111111111 2233445566778899aabbccddeeff0011 $(FROST_AUTHZ_DEMO_DIR)/plain.txt $(FROST_AUTHZ_DEMO_DIR)/sealed.wj
	$(TARGET) warrant-message-file open $(FROST_AUTHZ_DEMO_DIR)/sealed.wj > $(FROST_AUTHZ_DEMO_DIR)/auth-message.asm.txt
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_frost_authorize.py --artifact $(FROST_AUTHZ_DEMO_DIR)/sealed.wj --action open --print-auth-message > $(FROST_AUTHZ_DEMO_DIR)/auth-message.tool.txt
	cmp $(FROST_AUTHZ_DEMO_DIR)/auth-message.asm.txt $(FROST_AUTHZ_DEMO_DIR)/auth-message.tool.txt
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_frost_authorize.py --artifact $(FROST_AUTHZ_DEMO_DIR)/sealed.wj --action open --print-transcript-manifest > $(FROST_AUTHZ_DEMO_DIR)/auth-transcript.json
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_frost_authorize.py --artifact $(FROST_AUTHZ_DEMO_DIR)/sealed.wj --action open --transcript-manifest $(FROST_AUTHZ_DEMO_DIR)/auth-transcript.json --update-transcript-manifest --receipt $(FROST_AUTHZ_DEMO_DIR)/auth-receipt.json
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_frost_authorize.py --artifact $(FROST_AUTHZ_DEMO_DIR)/sealed.wj --action open --verify-receipt $(FROST_AUTHZ_DEMO_DIR)/auth-receipt.json
	@printf 'wrote WUCI-WARRANT demo files to %s\n' "$(FROST_AUTHZ_DEMO_DIR)"

gate-boundary: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_gate_boundary.py

gate-workflow: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_gate_workflow.py --quiet

gate-policy-matrix: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_gate_policy_matrix.py --quiet

gate-receipt-contract: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_receipt_contract.py --quiet

gate-contract-zig: build-linux $(ZIG_GATE_CONTRACT)
	WUCI_JI_BIN=$(abspath $(CROSS_TARGET)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_BIN=$(abspath $(ZIG_GATE_CONTRACT)) $(PYTHON) tests/wuci_gate_contract_zig.py --quiet

gate-contract-asm: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_gate_contract_asm.py --quiet
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_gate_rooted_contract_asm.py --quiet

parser-adversarial-test: gate-contract-asm

parser-corpus-replay: check-native $(TARGET)
	mkdir -p build
	$(PYTHON) tools/wuci_corpus_replay.py --bin $(abspath $(TARGET)) --out $(PARSER_CORPUS_REPLAY) --quiet
	@printf 'WUCI parser corpus replay: %s\n' "$(PARSER_CORPUS_REPLAY)"

parser-corpus-replay-test: parser-corpus-replay
	$(PYTHON) tests/wuci_corpus_replay.py --quiet

parser-hardening-proof: parser-corpus-replay parser-corpus-replay-test
	@printf 'WUCI parser hardening proof: %s\n' "$(PARSER_CORPUS_REPLAY)"

aead-boundary-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_aead_boundary.py --quiet

secret-path-isolation-test:
	$(PYTHON) tests/wuci_secret_path_isolation.py --quiet

reproducible-build-metadata: check-native $(TARGET)
	@printf 'uname: '; uname -a
	@printf 'as: '; $(AS) --version | head -n 1
	@printf 'ld: '; $(LD) --version | head -n 1
	@printf 'python: '; $(PYTHON) --version
	@if command -v $(ZIG) >/dev/null 2>&1; then printf 'zig: '; $(ZIG) version; else printf 'zig: unavailable\n'; fi
	sha256sum $(TARGET)

release-rooted-contract: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_gate_rooted_contract_asm.py --quiet

gate-demo: check-native $(TARGET)
	mkdir -p $(GATE_DEMO_DIR)
	rm -f $(GATE_DEMO_DIR)/artifact.key $(GATE_DEMO_DIR)/plain.txt $(GATE_DEMO_DIR)/sealed.wj $(GATE_DEMO_DIR)/auth-transcript.json $(GATE_DEMO_DIR)/auth-receipt.json $(GATE_DEMO_DIR)/receipt-contract.txt $(GATE_DEMO_DIR)/opened.txt $(GATE_DEMO_DIR)/opened-copy.txt $(GATE_DEMO_DIR)/opened-asm.txt
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(GATE_DEMO_DIR)/artifact.key
	printf 'wuci gate demo\n' > $(GATE_DEMO_DIR)/plain.txt
	$(TARGET) seal-file-keyfile-v2 $(GATE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(GATE_DEMO_DIR)/plain.txt $(GATE_DEMO_DIR)/sealed.wj
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_frost_authorize.py --artifact $(GATE_DEMO_DIR)/sealed.wj --action open --print-transcript-manifest > $(GATE_DEMO_DIR)/auth-transcript.json
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_frost_authorize.py --artifact $(GATE_DEMO_DIR)/sealed.wj --action open --transcript-manifest $(GATE_DEMO_DIR)/auth-transcript.json --update-transcript-manifest --receipt $(GATE_DEMO_DIR)/auth-receipt.json
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_receipt_contract.py emit --bin $(abspath $(TARGET)) --artifact $(GATE_DEMO_DIR)/sealed.wj --action open --receipt $(GATE_DEMO_DIR)/auth-receipt.json --contract $(GATE_DEMO_DIR)/receipt-contract.txt --quiet
	$(PYTHON) tools/wuci_gate.py check --bin $(abspath $(TARGET)) --artifact $(GATE_DEMO_DIR)/sealed.wj --action open --receipt $(GATE_DEMO_DIR)/auth-receipt.json
	$(PYTHON) tools/wuci_gate.py open --bin $(abspath $(TARGET)) --artifact $(GATE_DEMO_DIR)/sealed.wj --action open --receipt $(GATE_DEMO_DIR)/auth-receipt.json --keyfile $(GATE_DEMO_DIR)/artifact.key --out $(GATE_DEMO_DIR)/opened.txt
	@printf 'wrote WUCI-GATE demo files to %s\n' "$(GATE_DEMO_DIR)"

self-release-demo: $(RELEASE_BIN)
	mkdir -p $(SELF_RELEASE_DEMO_DIR)
	rm -f \
		$(SELF_RELEASE_DEMO_DIR)/artifact.key \
		$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj \
		$(SELF_RELEASE_DEMO_DIR)/manifest.txt \
		$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt \
		$(SELF_RELEASE_DEMO_DIR)/auth-transcript.json \
		$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json \
		$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji \
		$(SELF_RELEASE_ATTESTATION)
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(SELF_RELEASE_DEMO_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(SELF_RELEASE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file open $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/warrant-message.txt
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --print-transcript-manifest > $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --transcript-manifest $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json --update-transcript-manifest --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_gate.py check --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_gate.py open --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json --keyfile $(SELF_RELEASE_DEMO_DIR)/artifact.key --out $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	cmp $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	chmod +x $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	$(RELEASE_RUNNER) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji --help >/dev/null
	@printf 'WUCI self-release demo complete\n'
	@printf 'sealed artifact: %s\n' "$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj"
	@printf 'manifest: %s\n' "$(SELF_RELEASE_DEMO_DIR)/manifest.txt"
	@printf 'warrant message: %s\n' "$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt"
	@printf 'receipt: %s\n' "$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json"
	@printf 'opened binary: %s\n' "$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji"
	@printf 'verified: byte-identical and executable\n'

self-release-bundle: self-release-demo
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) attest
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) verify
	@printf 'self-release attestation: %s\n' "$(SELF_RELEASE_ATTESTATION)"

self-release-contract-demo: $(RELEASE_BIN) $(ZIG_GATE_CONTRACT)
	mkdir -p $(SELF_RELEASE_DEMO_DIR)
	rm -f \
		$(SELF_RELEASE_DEMO_DIR)/artifact.key \
		$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj \
		$(SELF_RELEASE_DEMO_DIR)/manifest.txt \
		$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt \
		$(SELF_RELEASE_DEMO_DIR)/auth-transcript.json \
		$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json \
		$(SELF_RELEASE_CONTRACT) \
		$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji \
		$(SELF_RELEASE_ATTESTATION)
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(SELF_RELEASE_DEMO_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(SELF_RELEASE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file open $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/warrant-message.txt
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --print-transcript-manifest > $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --transcript-manifest $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json --update-transcript-manifest --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_receipt_contract.py emit --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json --contract $(SELF_RELEASE_CONTRACT) --quiet
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_GATE_CONTRACT)) verify --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json --contract $(SELF_RELEASE_CONTRACT)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_GATE_CONTRACT)) open --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json --contract $(SELF_RELEASE_CONTRACT) --keyfile $(SELF_RELEASE_DEMO_DIR)/artifact.key --out $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	cmp $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	chmod +x $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	$(RELEASE_RUNNER) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji --help >/dev/null
	@printf 'WUCI self-release contract demo complete\n'
	@printf 'sealed artifact: %s\n' "$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj"
	@printf 'manifest: %s\n' "$(SELF_RELEASE_DEMO_DIR)/manifest.txt"
	@printf 'warrant message: %s\n' "$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt"
	@printf 'receipt: %s\n' "$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json"
	@printf 'receipt contract: %s\n' "$(SELF_RELEASE_CONTRACT)"
	@printf 'opened binary: %s\n' "$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji"
	@printf 'verified: Zig flat-contract Gate, byte-identical, and executable\n'

self-release-contract-bundle: self-release-contract-demo
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_BIN=$(abspath $(ZIG_GATE_CONTRACT)) $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-bin $(abspath $(ZIG_GATE_CONTRACT)) attest
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_BIN=$(abspath $(ZIG_GATE_CONTRACT)) $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-bin $(abspath $(ZIG_GATE_CONTRACT)) verify
	@printf 'self-release contract attestation: %s\n' "$(SELF_RELEASE_ATTESTATION)"

self-release-asm-contract-demo: $(RELEASE_BIN)
	mkdir -p $(SELF_RELEASE_DEMO_DIR)
	rm -f \
		$(SELF_RELEASE_DEMO_DIR)/artifact.key \
		$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj \
		$(SELF_RELEASE_DEMO_DIR)/manifest.txt \
		$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt \
		$(SELF_RELEASE_DEMO_DIR)/auth-transcript.json \
		$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json \
		$(SELF_RELEASE_CONTRACT) \
		$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji \
		$(SELF_RELEASE_ATTESTATION)
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(SELF_RELEASE_DEMO_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(SELF_RELEASE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file open $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/warrant-message.txt
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --print-transcript-manifest > $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --transcript-manifest $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json --update-transcript-manifest --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_receipt_contract.py emit --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json --contract $(SELF_RELEASE_CONTRACT) --quiet
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) gate-contract-verify $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) open-authorized-contract $(SELF_RELEASE_DEMO_DIR)/artifact.key $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	cmp $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	chmod +x $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	$(RELEASE_RUNNER) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji --help >/dev/null
	@printf 'WUCI self-release assembly contract demo complete\n'
	@printf 'sealed artifact: %s\n' "$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj"
	@printf 'manifest: %s\n' "$(SELF_RELEASE_DEMO_DIR)/manifest.txt"
	@printf 'warrant message: %s\n' "$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt"
	@printf 'receipt: %s\n' "$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json"
	@printf 'receipt contract: %s\n' "$(SELF_RELEASE_CONTRACT)"
	@printf 'opened binary: %s\n' "$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji"
	@printf 'verified: assembly flat-contract Gate, byte-identical, and executable\n'

self-release-asm-contract-bundle: self-release-asm-contract-demo
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_MODE=asm $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-mode asm attest
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_MODE=asm $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-mode asm verify
	@printf 'self-release assembly contract attestation: %s\n' "$(SELF_RELEASE_ATTESTATION)"

self-release-rooted-demo: $(RELEASE_BIN) authority-root-check
	mkdir -p $(SELF_RELEASE_DEMO_DIR)
	rm -f \
		$(SELF_RELEASE_DEMO_DIR)/artifact.key \
		$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj \
		$(SELF_RELEASE_DEMO_DIR)/manifest.txt \
		$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt \
		$(SELF_RELEASE_DEMO_DIR)/auth-transcript.json \
		$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json \
		$(SELF_RELEASE_CONTRACT) \
		$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji \
		$(SELF_RELEASE_ATTESTATION)
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(SELF_RELEASE_DEMO_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(SELF_RELEASE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file open $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/warrant-message.txt
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --print-transcript-manifest > $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --transcript-manifest $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json --update-transcript-manifest --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_receipt_contract.py emit --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json --contract $(SELF_RELEASE_CONTRACT) --quiet
	$(PYTHON) tools/wuci_authority_anchor.py check --authority $(AUTHORITY_ROOT) --sha256 $(AUTHORITY_ROOT_SHA256) --action open --contract $(SELF_RELEASE_CONTRACT) --strict-fixture-path --quiet
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) authority-root-verify $(AUTHORITY_ROOT)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) gate-contract-verify-rooted $(AUTHORITY_ROOT) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) open-authorized-rooted $(AUTHORITY_ROOT) $(SELF_RELEASE_DEMO_DIR)/artifact.key $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	cmp $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	chmod +x $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	$(RELEASE_RUNNER) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji --help >/dev/null
	@printf 'WUCI self-release anchored contract demo complete\n'
	@printf 'sealed artifact: %s\n' "$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj"
	@printf 'manifest: %s\n' "$(SELF_RELEASE_DEMO_DIR)/manifest.txt"
	@printf 'warrant message: %s\n' "$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt"
	@printf 'receipt: %s\n' "$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json"
	@printf 'receipt contract: %s\n' "$(SELF_RELEASE_CONTRACT)"
	@printf 'authority root: %s\n' "$(AUTHORITY_ROOT)"
	@printf 'opened binary: %s\n' "$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji"
	@printf 'verified: anchored assembly rooted Gate, byte-identical, and executable\n'

self-release-rooted-bundle: self-release-rooted-demo
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_MODE=rooted-asm $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-mode rooted-asm --authority $(AUTHORITY_ROOT) attest
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_MODE=rooted-asm $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-mode rooted-asm --authority $(AUTHORITY_ROOT) verify
	@printf 'self-release anchored assembly attestation: %s\n' "$(SELF_RELEASE_ATTESTATION)"

self-release-release-contract-demo: $(RELEASE_BIN)
	mkdir -p $(SELF_RELEASE_DEMO_DIR)
	rm -f \
		$(SELF_RELEASE_DEMO_DIR)/artifact.key \
		$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj \
		$(SELF_RELEASE_DEMO_DIR)/manifest.txt \
		$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt \
		$(SELF_RELEASE_DEMO_DIR)/release-transcript.json \
		$(SELF_RELEASE_DEMO_DIR)/release-receipt.json \
		$(SELF_RELEASE_CONTRACT) \
		$(SELF_RELEASE_DEMO_DIR)/release-decision.txt
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(SELF_RELEASE_DEMO_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(SELF_RELEASE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file release $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/warrant-message.txt
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action release --print-transcript-manifest > $(SELF_RELEASE_DEMO_DIR)/release-transcript.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action release --transcript-manifest $(SELF_RELEASE_DEMO_DIR)/release-transcript.json --update-transcript-manifest --receipt $(SELF_RELEASE_DEMO_DIR)/release-receipt.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_receipt_contract.py emit --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action release --receipt $(SELF_RELEASE_DEMO_DIR)/release-receipt.json --contract $(SELF_RELEASE_CONTRACT) --quiet
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) release-authorized-contract $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT) > $(SELF_RELEASE_DEMO_DIR)/release-decision.txt
	grep -q '^authorized: true$$' $(SELF_RELEASE_DEMO_DIR)/release-decision.txt
	grep -q '^action: release$$' $(SELF_RELEASE_DEMO_DIR)/release-decision.txt
	@printf 'WUCI self-release release-contract proof complete\n'
	@printf 'sealed artifact: %s\n' "$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj"
	@printf 'manifest: %s\n' "$(SELF_RELEASE_DEMO_DIR)/manifest.txt"
	@printf 'warrant message: %s\n' "$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt"
	@printf 'receipt: %s\n' "$(SELF_RELEASE_DEMO_DIR)/release-receipt.json"
	@printf 'receipt contract: %s\n' "$(SELF_RELEASE_CONTRACT)"
	@printf 'release decision: %s\n' "$(SELF_RELEASE_DEMO_DIR)/release-decision.txt"

self-release-publish-bundle: $(RELEASE_BIN)
	mkdir -p $(SELF_RELEASE_DEMO_DIR)
	rm -f \
		$(SELF_RELEASE_DEMO_DIR)/artifact.key \
		$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj \
		$(SELF_RELEASE_DEMO_DIR)/manifest.txt \
		$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt \
		$(SELF_RELEASE_DEMO_DIR)/release-transcript.json \
		$(SELF_RELEASE_DEMO_DIR)/release-receipt.json \
		$(SELF_RELEASE_CONTRACT) \
		$(SELF_RELEASE_AUTHORITY) \
		$(SELF_RELEASE_DEMO_DIR)/release-decision.txt \
		$(SELF_RELEASE_ATTESTATION)
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(SELF_RELEASE_DEMO_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(SELF_RELEASE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file release $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/warrant-message.txt
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action release --print-transcript-manifest > $(SELF_RELEASE_DEMO_DIR)/release-transcript.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action release --transcript-manifest $(SELF_RELEASE_DEMO_DIR)/release-transcript.json --update-transcript-manifest --receipt $(SELF_RELEASE_DEMO_DIR)/release-receipt.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_receipt_contract.py emit --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action release --receipt $(SELF_RELEASE_DEMO_DIR)/release-receipt.json --contract $(SELF_RELEASE_CONTRACT) --quiet
	cp $(RELEASE_AUTHORITY_ROOT) $(SELF_RELEASE_AUTHORITY)
	$(PYTHON) tools/wuci_authority_anchor.py check --authority $(RELEASE_AUTHORITY_ROOT) --sha256 $(RELEASE_AUTHORITY_ROOT_SHA256) --action release --contract $(SELF_RELEASE_CONTRACT) --strict-fixture-path --quiet
	cmp $(RELEASE_AUTHORITY_ROOT) $(SELF_RELEASE_AUTHORITY)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) authority-root-verify $(SELF_RELEASE_AUTHORITY)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) release-authorized-rooted $(SELF_RELEASE_AUTHORITY) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT) > $(SELF_RELEASE_DEMO_DIR)/release-decision.txt
	grep -q '^authorized: true$$' $(SELF_RELEASE_DEMO_DIR)/release-decision.txt
	grep -q '^action: release$$' $(SELF_RELEASE_DEMO_DIR)/release-decision.txt
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_publish_attest.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) attest
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_publish_attest.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) verify
	@printf 'WUCI self-release publish bundle complete\n'
	@printf 'sealed artifact: %s\n' "$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj"
	@printf 'release receipt: %s\n' "$(SELF_RELEASE_DEMO_DIR)/release-receipt.json"
	@printf 'receipt contract: %s\n' "$(SELF_RELEASE_CONTRACT)"
	@printf 'authority root: %s\n' "$(SELF_RELEASE_AUTHORITY)"
	@printf 'release decision: %s\n' "$(SELF_RELEASE_DEMO_DIR)/release-decision.txt"
	@printf 'publish attestation: %s\n' "$(SELF_RELEASE_ATTESTATION)"

publish-index:
	rm -f $(WITNESS_BUNDLE_DIR)/publish-index.txt
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_witness.py index --bin $(abspath $(RELEASE_BIN)) --bundle $(WITNESS_BUNDLE_DIR)

publish-witness:
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_witness.py verify --bin $(abspath $(RELEASE_BIN)) --bundle $(WITNESS_BUNDLE_DIR)

witness-zig: $(ZIG_WITNESS)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WITNESS)) verify $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN))

witness-zig-test: $(ZIG_WITNESS)
	WUCI_WITNESS_BIN=$(abspath $(ZIG_WITNESS)) WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) $(PYTHON) tests/wuci_witness_zig.py --bundle $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN)) --quiet

witness-archive:
	rm -f $(WITNESS_ARCHIVE) $(WITNESS_ARCHIVE_SHA256)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_witness_archive.py pack --bin $(abspath $(RELEASE_BIN)) --bundle $(WITNESS_BUNDLE_DIR) --archive $(WITNESS_ARCHIVE) --sha256 $(WITNESS_ARCHIVE_SHA256)

witness-archive-verify:
	rm -rf $(WITNESS_ARCHIVE_CHECK_DIR)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_witness_archive.py verify --bin $(abspath $(RELEASE_BIN)) --archive $(WITNESS_ARCHIVE) --sha256 $(WITNESS_ARCHIVE_SHA256) --extract-dir $(WITNESS_ARCHIVE_CHECK_DIR)

witness-archive-zig-verify: $(ZIG_WITNESS)
	rm -rf $(WITNESS_ARCHIVE_CHECK_DIR)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_witness_archive.py verify --bin $(abspath $(RELEASE_BIN)) --archive $(WITNESS_ARCHIVE) --sha256 $(WITNESS_ARCHIVE_SHA256) --extract-dir $(WITNESS_ARCHIVE_CHECK_DIR) --zig-witness $(abspath $(ZIG_WITNESS))

self-release-witness-bundle: $(RELEASE_BIN) authority-root-metal-check $(ZIG_WARRANT) $(ZIG_WITNESS) $(ZIG_GATE_CONTRACT)
	mkdir -p $(WITNESS_BUNDLE_DIR) $(WITNESS_WORK_DIR)
	rm -f \
		$(WITNESS_WORK_DIR)/artifact.key \
		$(WITNESS_WORK_DIR)/release-transcript.json \
		$(WITNESS_BUNDLE_DIR)/artifact.key \
		$(WITNESS_BUNDLE_DIR)/opened-wuci-ji \
		$(WITNESS_BUNDLE_DIR)/auth-transcript.json \
		$(WITNESS_BUNDLE_DIR)/release-transcript.json \
		$(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj \
		$(WITNESS_BUNDLE_DIR)/manifest.txt \
		$(WITNESS_BUNDLE_DIR)/warrant-message.txt \
		$(WITNESS_BUNDLE_DIR)/release-receipt.json \
		$(WITNESS_BUNDLE_DIR)/receipt-contract.txt \
		$(WITNESS_BUNDLE_DIR)/authority-root.txt \
		$(WITNESS_BUNDLE_DIR)/release-decision.txt \
		$(WITNESS_BUNDLE_DIR)/publish-index.txt \
		$(WITNESS_BUNDLE_DIR)/attestation.json
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(WITNESS_WORK_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(WITNESS_WORK_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj > $(WITNESS_BUNDLE_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file release $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj > $(WITNESS_BUNDLE_DIR)/warrant-message.txt
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WARRANT)) --bin $(abspath $(RELEASE_BIN)) --artifact $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj --action release --print-transcript-manifest > $(WITNESS_WORK_DIR)/release-transcript.json
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WARRANT)) --bin $(abspath $(RELEASE_BIN)) --artifact $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj --action release --transcript-manifest $(WITNESS_WORK_DIR)/release-transcript.json --update-transcript-manifest --receipt $(WITNESS_BUNDLE_DIR)/release-receipt.json
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_GATE_CONTRACT)) emit --bin $(abspath $(RELEASE_BIN)) --artifact $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj --receipt $(WITNESS_BUNDLE_DIR)/release-receipt.json --contract $(WITNESS_BUNDLE_DIR)/receipt-contract.txt --quiet
	cp $(RELEASE_AUTHORITY_ROOT) $(WITNESS_BUNDLE_DIR)/authority-root.txt
	sha256sum -c $(RELEASE_AUTHORITY_ROOT_SHA256)
	cmp $(RELEASE_AUTHORITY_ROOT) $(WITNESS_BUNDLE_DIR)/authority-root.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) authority-root-verify $(WITNESS_BUNDLE_DIR)/authority-root.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) release-authorized-rooted $(WITNESS_BUNDLE_DIR)/authority-root.txt $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj $(WITNESS_BUNDLE_DIR)/receipt-contract.txt > $(WITNESS_BUNDLE_DIR)/release-decision.txt
	grep -q '^authorized: true$$' $(WITNESS_BUNDLE_DIR)/release-decision.txt
	grep -q '^action: release$$' $(WITNESS_BUNDLE_DIR)/release-decision.txt
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WITNESS)) index $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN))
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WITNESS)) attest $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN))
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WITNESS)) verify $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN))
	rm -f $(WITNESS_WORK_DIR)/artifact.key $(WITNESS_WORK_DIR)/release-transcript.json
	@printf 'WUCI self-release witness bundle complete\n'
	@printf 'public witness bundle: %s\n' "$(WITNESS_BUNDLE_DIR)"
	@printf 'sealed artifact: %s\n' "$(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj"
	@printf 'publish index: %s\n' "$(WITNESS_BUNDLE_DIR)/publish-index.txt"
	@printf 'witness attestation: %s\n' "$(WITNESS_BUNDLE_DIR)/attestation.json"

self-release-witness-archive: self-release-witness-bundle
	$(MAKE) witness-archive RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" WITNESS_BUNDLE_DIR=$(WITNESS_BUNDLE_DIR) WITNESS_ARCHIVE=$(WITNESS_ARCHIVE) WITNESS_ARCHIVE_SHA256=$(WITNESS_ARCHIVE_SHA256)
	$(MAKE) witness-archive-verify RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" WITNESS_ARCHIVE=$(WITNESS_ARCHIVE) WITNESS_ARCHIVE_SHA256=$(WITNESS_ARCHIVE_SHA256) WITNESS_ARCHIVE_CHECK_DIR=$(WITNESS_ARCHIVE_CHECK_DIR)

self-release-ledger-bundle: $(RELEASE_BIN) self-release-witness-bundle $(ZIG_LEDGER) $(ZIG_WITNESS)
	rm -rf $(LEDGER_DIR)
	$(abspath $(ZIG_LEDGER)) init --bin $(abspath $(RELEASE_BIN)) --ledger $(LEDGER_DIR)
	$(abspath $(ZIG_LEDGER)) append --bin $(abspath $(RELEASE_BIN)) --ledger $(LEDGER_DIR) --witness-bundle $(WITNESS_BUNDLE_DIR)
	$(abspath $(ZIG_LEDGER)) prove-inclusion --bin $(abspath $(RELEASE_BIN)) --ledger $(LEDGER_DIR) --sequence 0 --out $(LEDGER_INCLUSION_PROOF)
	$(abspath $(ZIG_LEDGER)) verify-inclusion --bin $(abspath $(RELEASE_BIN)) --entry $(LEDGER_DIR)/ledger-entry.txt --proof $(LEDGER_INCLUSION_PROOF) --head $(LEDGER_DIR)/ledger-head.txt
	$(abspath $(ZIG_LEDGER)) prove-consistency --bin $(abspath $(RELEASE_BIN)) --ledger $(LEDGER_DIR) --from-head $(LEDGER_DIR)/previous-ledger-head.txt --to-head $(LEDGER_DIR)/ledger-head.txt --out $(LEDGER_CONSISTENCY_PROOF)
	$(abspath $(ZIG_LEDGER)) verify-consistency --bin $(abspath $(RELEASE_BIN)) --proof $(LEDGER_CONSISTENCY_PROOF)
	$(abspath $(ZIG_LEDGER)) verify-history --bin $(abspath $(RELEASE_BIN)) --ledger $(LEDGER_DIR)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WITNESS)) verify $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN))
	@printf 'WUCI self-release ledger bundle complete\n'
	@printf 'ledger: %s\n' "$(LEDGER_DIR)"
	@printf 'ledger entry: %s\n' "$(LEDGER_DIR)/ledger-entry.txt"
	@printf 'ledger head: %s\n' "$(LEDGER_DIR)/ledger-head.txt"
	@printf 'inclusion proof: %s\n' "$(LEDGER_INCLUSION_PROOF)"
	@printf 'consistency proof: %s\n' "$(LEDGER_CONSISTENCY_PROOF)"

cage-policy-matrix: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_cage_policy_matrix.py --quiet

cage-bundle-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_cage_bundle.py --quiet

cage-attestation-test: cage-bundle-test

cage-ledger-entry: check-native $(TARGET) self-release-witness-bundle cage-policy-matrix
	rm -f $(CAGE_ATTESTATION) $(CAGE_LEDGER_ENTRY) $(CAGE_LEDGER_LEAF)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_cage.py attest --bin $(abspath $(TARGET)) --bundle $(WITNESS_BUNDLE_DIR) --out $(CAGE_ATTESTATION)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_cage.py verify --bin $(abspath $(TARGET)) --bundle $(WITNESS_BUNDLE_DIR) --attestation $(CAGE_ATTESTATION)
	$(PYTHON) tools/wuci_cage.py ledger-entry --attestation $(CAGE_ATTESTATION) --out $(CAGE_LEDGER_ENTRY)
	$(TARGET) ledger-leaf-file $(CAGE_LEDGER_ENTRY) > $(CAGE_LEDGER_LEAF)
	@printf 'CAGE attestation: %s\n' "$(CAGE_ATTESTATION)"
	@printf 'CAGE ledger entry: %s\n' "$(CAGE_LEDGER_ENTRY)"
	@printf 'CAGE ledger leaf: %s\n' "$(CAGE_LEDGER_LEAF)"

cage-proof: cage-ledger-entry
	rm -f $(CAGE_RUN_DENIAL)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_cage.py verify --bin $(abspath $(TARGET)) --bundle $(WITNESS_BUNDLE_DIR) --attestation $(CAGE_ATTESTATION)
	$(PYTHON) tools/wuci_cage.py deny-run --artifact $(WITNESS_BUNDLE_DIR)/wuci-ji.self.wj --out $(CAGE_RUN_DENIAL)
	@printf 'CAGE run denial: %s\n' "$(CAGE_RUN_DENIAL)"

qcage-model-test:
	$(PYTHON) tests/wuci_qcage_model.py --quiet

qcage-policy-matrix:
	$(PYTHON) tests/wuci_qcage_policy_matrix.py --quiet

qcage-crypto-inventory:
	mkdir -p build
	$(PYTHON) tools/wuci_qcage.py crypto-inventory --repo . --out $(QCAGE_CRYPTO_INVENTORY)

qcage-build-graph:
	mkdir -p build
	$(PYTHON) tools/wuci_qcage.py build-graph --repo . --out $(QCAGE_BUILD_GRAPH)

qcage-attestation-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_qcage_attestation.py --quiet

qcage-risk:
	$(PYTHON) tools/wuci_qcage.py risk --T-migrate 3 --T-trust 10 --T-CRQC 10

qcage-proof: self-release-witness-bundle cage-proof qcage-model-test qcage-policy-matrix qcage-crypto-inventory qcage-build-graph
	rm -f $(QCAGE_ATTESTATION)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_qcage.py attest \
		--bin $(abspath $(TARGET)) \
		--cage-attestation $(CAGE_ATTESTATION) \
		--witness-bundle $(WITNESS_BUNDLE_DIR) \
		--crypto-inventory $(QCAGE_CRYPTO_INVENTORY) \
		--build-graph $(QCAGE_BUILD_GRAPH) \
		--mode compat \
		--T-migrate 3 \
		--T-trust 10 \
		--T-CRQC 10 \
		--out $(QCAGE_ATTESTATION)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tools/wuci_qcage.py verify \
		--bin $(abspath $(TARGET)) \
		--attestation $(QCAGE_ATTESTATION) \
		--cage-attestation $(CAGE_ATTESTATION) \
		--witness-bundle $(WITNESS_BUNDLE_DIR) \
		--crypto-inventory $(QCAGE_CRYPTO_INVENTORY) \
		--build-graph $(QCAGE_BUILD_GRAPH)
	@printf 'QCAGE attestation: %s\n' "$(QCAGE_ATTESTATION)"

harden-policy-matrix:
	$(PYTHON) tests/wuci_hardening_policy_matrix.py --quiet

harden0-policy-matrix:
	$(PYTHON) tests/wuci_harden0_policy_matrix.py --quiet

harden-safeio-test:
	$(PYTHON) tests/wuci_safeio.py --quiet

harden0-safeio-test:
	$(PYTHON) tests/wuci_safeio.py --quiet

harden-verifier-identity-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_verifier_identity.py --quiet

harden0-verifier-identity-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_verifier_identity.py --quiet

harden-witness-symlink-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_witness_symlink_hardening.py --quiet

harden0-witness-safeio-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_witness_safeio.py --quiet

harden-fixture-quarantine-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_fixture_quarantine.py --quiet

harden0-fixture-quarantine-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_fixture_quarantine.py --quiet

harden-action-policy-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_action_policy.py --quiet

harden0-action-policy-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_action_policy.py --quiet

harden-ledger-mutation-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_ledger_mutation_hardening.py --quiet

harden0-ledger-mutation-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_ledger_mutation_hardening.py --quiet

harden-proof: harden-policy-matrix harden-safeio-test harden-verifier-identity-test harden-witness-symlink-test harden-fixture-quarantine-test harden-action-policy-test harden-ledger-mutation-test
	@printf 'WUCI-HARDEN proof complete\n'

harden0-proof: harden0-policy-matrix harden0-safeio-test harden0-verifier-identity-test harden0-witness-safeio-test harden0-fixture-quarantine-test harden0-action-policy-test harden0-ledger-mutation-test
	@printf 'WUCI-HARDEN-0 proof complete\n'

high-attestation-profile:
	$(PYTHON) tests/wuci_high_attestation_profile.py --quiet

host-capacity:
	@printf 'WUCI host logical CPUs: %s\n' "$(HOST_LOGICAL_CPUS)"
	@printf 'Use make -j%s for independent targets; shared evidence bundle targets are serialized by their dependencies.\n' "$(HOST_LOGICAL_CPUS)"

sbom-provenance: build-linux
	$(PYTHON) tools/wuci_provenance.py emit --repo . --sbom $(WUCI_SBOM) --provenance $(WUCI_PROVENANCE) --quiet
	$(PYTHON) tools/wuci_provenance.py verify --repo . --sbom $(WUCI_SBOM) --provenance $(WUCI_PROVENANCE) --quiet
	@printf 'WUCI SBOM: %s\n' "$(WUCI_SBOM)"
	@printf 'WUCI provenance: %s\n' "$(WUCI_PROVENANCE)"

sbom-provenance-test:
	$(PYTHON) tests/wuci_provenance.py --quiet

carrot-policy: check-native $(TARGET)
	$(PYTHON) tools/wuci_carrot.py validate --policy $(CARROT_POLICY) --quiet
	$(PYTHON) tools/wuci_carrot.py attest --policy $(CARROT_POLICY) --probe-bin $(abspath $(TARGET)) --out $(CARROT_ATTESTATION) --quiet
	@printf 'WUCI CARROT attestation: %s\n' "$(CARROT_ATTESTATION)"

kernel-sandbox-proof: check-native $(TARGET) carrot-policy
	$(PYTHON) tests/wuci_sandbox_enforcement.py --quiet

rust-sandbox-build:
	@if [ -z "$(RUSTC)" ]; then \
		echo "wuci-sandbox: rustc is required to build the Rust kernel wrapper."; \
		exit 2; \
	fi
	mkdir -p build
	$(RUSTC) -C opt-level=2 -o $(RUST_SANDBOX) tools/wuci_sandbox.rs

rust-sandbox-test: check-native $(TARGET) rust-sandbox-build
	$(RUST_SANDBOX) --selftest
	$(RUST_SANDBOX) --no-network -- $(abspath $(TARGET)) selftest

pq-verifier-detect:
	$(PYTHON) tools/wuci_pq_verifier.py detect --out $(PQ_VERIFIER_EVIDENCE) --quiet
	$(PYTHON) tools/wuci_pq_verifier.py verify --evidence $(PQ_VERIFIER_EVIDENCE) --quiet
	@printf 'WUCI PQ verifier evidence: %s\n' "$(PQ_VERIFIER_EVIDENCE)"

pq-verifier-fips204-build:
	@if [ -z "$(RUSTC)" ] || [ -z "$(CARGO)" ]; then \
		echo "wuci-pq-fips204-verify: rustc/cargo are required to build the FIPS 204 verifier."; \
		exit 2; \
	fi
	$(CARGO) build --manifest-path $(PQ_FIPS204_MANIFEST) --release --locked
	mkdir -p build
	cp $(PQ_FIPS204_SOURCE_BIN) $(PQ_FIPS204_BIN)
	$(PQ_FIPS204_BIN) selftest

pq-verifier-fips204-proof: pq-verifier-fips204-build
	mkdir -p $(PQ_FIPS204_KAT_DIR)
	rm -f $(PQ_FIPS204_KAT_PUBLIC_KEY) $(PQ_FIPS204_KAT_MESSAGE) $(PQ_FIPS204_KAT_SIGNATURE)
	$(PQ_FIPS204_BIN) write-kat --out-dir $(PQ_FIPS204_KAT_DIR)
	$(PYTHON) tools/wuci_pq_verifier.py attest-real \
		--verifier $(abspath $(PQ_FIPS204_BIN)) \
		--algorithm ML-DSA \
		--public-key $(PQ_FIPS204_KAT_PUBLIC_KEY) \
		--message $(PQ_FIPS204_KAT_MESSAGE) \
		--signature $(PQ_FIPS204_KAT_SIGNATURE) \
		--implementation-name wuci-pq-fips204-verify \
		--implementation-version 0.1.0-fips204-0.4.6-ml-dsa-65 \
		--out $(LOCAL_REAL_PQ_VERIFIER_EVIDENCE) \
		--quiet
	$(PYTHON) tools/wuci_pq_verifier.py pin-local-fips204 \
		--evidence $(LOCAL_REAL_PQ_VERIFIER_EVIDENCE) \
		--out $(LOCAL_PQ_VERIFIER_PINS) \
		--quiet
	$(PYTHON) tools/wuci_pq_verifier.py verify-real \
		--evidence $(LOCAL_REAL_PQ_VERIFIER_EVIDENCE) \
		--pins $(LOCAL_PQ_VERIFIER_PINS) \
		--rerun \
		--quiet
	@printf 'WUCI local FIPS 204 PQ verifier evidence: %s\n' "$(LOCAL_REAL_PQ_VERIFIER_EVIDENCE)"
	@printf 'WUCI local FIPS 204 PQ verifier pins: %s\n' "$(LOCAL_PQ_VERIFIER_PINS)"

pq-verifier-real-attest:
	@if [ -z "$(PQ_VERIFIER_BIN)" ] || [ -z "$(PQ_VERIFIER_IMPLEMENTATION)" ] || [ -z "$(PQ_VERIFIER_VERSION)" ] || [ -z "$(PQ_KAT_PUBLIC_KEY)" ] || [ -z "$(PQ_KAT_MESSAGE)" ] || [ -z "$(PQ_KAT_SIGNATURE)" ] || [ -z "$(REAL_PQ_VERIFIER_EVIDENCE)" ]; then \
		echo "wuci-ji: pq-verifier-real-attest requires PQ_VERIFIER_BIN, PQ_VERIFIER_IMPLEMENTATION, PQ_VERIFIER_VERSION, PQ_KAT_PUBLIC_KEY, PQ_KAT_MESSAGE, PQ_KAT_SIGNATURE, and REAL_PQ_VERIFIER_EVIDENCE"; \
		exit 2; \
	fi
	$(PYTHON) tools/wuci_pq_verifier.py attest-real \
		--verifier $(PQ_VERIFIER_BIN) \
		--algorithm $(PQ_VERIFIER_ALGORITHM) \
		--public-key $(PQ_KAT_PUBLIC_KEY) \
		--message $(PQ_KAT_MESSAGE) \
		--signature $(PQ_KAT_SIGNATURE) \
		--implementation-name "$(PQ_VERIFIER_IMPLEMENTATION)" \
		--implementation-version "$(PQ_VERIFIER_VERSION)" \
		--out $(REAL_PQ_VERIFIER_EVIDENCE) \
		--pins $(PQ_VERIFIER_PINS) \
		--quiet
	@printf 'WUCI real PQ verifier evidence candidate: %s\n' "$(REAL_PQ_VERIFIER_EVIDENCE)"

pq-verifier-real:
	@if [ -z "$(REAL_PQ_VERIFIER_EVIDENCE)" ]; then \
		echo "wuci-ji: pq-verifier-real requires REAL_PQ_VERIFIER_EVIDENCE=/path/to/evidence.json"; \
		exit 2; \
	fi
	$(PYTHON) tools/wuci_pq_verifier.py verify-real --evidence $(REAL_PQ_VERIFIER_EVIDENCE) --pins $(PQ_VERIFIER_PINS) --quiet
	@printf 'WUCI real PQ verifier evidence verified: %s\n' "$(REAL_PQ_VERIFIER_EVIDENCE)"

pq-verifier-test:
	$(PYTHON) tests/wuci_pq_verifier.py --quiet

production-authority-verify:
	@if [ -z "$(PRODUCTION_AUTHORITY_ROOT)" ] || [ -z "$(PRODUCTION_AUTHORITY_CEREMONY)" ] || [ -z "$(PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY)" ] || [ -z "$(PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE)" ]; then \
		echo "wuci-ji: production-authority-verify requires PRODUCTION_AUTHORITY_ROOT, PRODUCTION_AUTHORITY_CEREMONY, PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY, and PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE"; \
		exit 2; \
	fi
	$(PYTHON) tools/wuci_production_authority.py verify \
		--authority $(PRODUCTION_AUTHORITY_ROOT) \
		--ceremony $(PRODUCTION_AUTHORITY_CEREMONY) \
		--ceremony-root-key $(PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY) \
		--ceremony-signature $(PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE) \
		--quiet
	@printf 'WUCI production authority verified: %s\n' "$(PRODUCTION_AUTHORITY_ROOT)"

production-readiness-gates:
	$(PYTHON) tests/wuci_production_readiness_gates.py --quiet
	$(PYTHON) tests/wuci_production_authority.py --quiet
	$(PYTHON) tests/wuci_external_audit.py --quiet

machine-passoff-test:
	$(PYTHON) tests/machine_passoff.py --quiet

wuci-prism-test:
	$(PYTHON) tests/wuci_prism.py --quiet

wuci-progress-test:
	$(PYTHON) tests/wuci_progress.py --quiet

noxframe-launch:
	$(PYTHON) tools/wuci_black_ice.py

noxframe-launch-test:
	$(PYTHON) tests/wuci_kaiju.py --quiet
	$(PYTHON) tests/wuci_os.py --quiet
	$(PYTHON) tests/wuci_noxframe.py --quiet

wuci-kaiju-test:
	$(PYTHON) tests/wuci_kaiju.py --quiet

wuci-os-test:
	$(PYTHON) tests/wuci_os.py --quiet

noxframe-self-release: check-native $(TARGET)
	$(MAKE) self-release-bundle SELF_RELEASE_DEMO_DIR=$(NOXFRAME_SELF_RELEASE_DEMO_DIR) SELF_RELEASE_ATTESTATION=$(NOXFRAME_SELF_RELEASE_ATTESTATION)
	$(MAKE) self-release-witness-bundle WITNESS_BUNDLE_DIR=$(NOXFRAME_WITNESS_BUNDLE_DIR) WITNESS_WORK_DIR=$(NOXFRAME_WITNESS_WORK_DIR)
	$(MAKE) self-release-ledger-bundle WITNESS_BUNDLE_DIR=$(NOXFRAME_WITNESS_BUNDLE_DIR) WITNESS_WORK_DIR=$(NOXFRAME_WITNESS_WORK_DIR) LEDGER_DIR=$(NOXFRAME_LEDGER_DIR) LEDGER_INCLUSION_PROOF=$(NOXFRAME_LEDGER_INCLUSION_PROOF) LEDGER_CONSISTENCY_PROOF=$(NOXFRAME_LEDGER_CONSISTENCY_PROOF)
	@printf 'NOXFRAME self-release workspace: %s\n' "build/noxframe"
	@printf 'enter with: tools/wuci-noxframe --console --yes, then self-release shell\n'

black-ice-launch: noxframe-launch

black-ice-launch-test: noxframe-launch-test

crypto-self-audit:
	$(PYTHON) tools/wuci_crypto_audit.py emit --repo . --out $(CRYPTO_SELF_AUDIT) --quiet
	$(PYTHON) tools/wuci_crypto_audit.py verify --repo . --audit $(CRYPTO_SELF_AUDIT) --quiet
	@printf 'WUCI crypto self-audit: %s\n' "$(CRYPTO_SELF_AUDIT)"

crypto-self-audit-test:
	$(PYTHON) tests/wuci_crypto_audit.py --quiet

daylight-scorecard-test:
	$(PYTHON) tests/daylight_scorecard_gate.py --quiet

daylight-v06-peer-review-score-test:
	$(PYTHON) tests/daylight_v06_review_scoring_model.py --quiet

daylight-v06-1000-preflight-test:
	$(PYTHON) tests/daylight_v06_1000_preflight.py --quiet

daylight-v06-1000-claim-gate-test:
	$(PYTHON) tests/daylight_1000_gate.py --quiet

daylight-v06-1000-checkpoint-test:
	$(PYTHON) tests/daylight_1000_checkpoint.py --quiet

daylight-v06-authority-verifier-test:
	$(PYTHON) tests/daylight_authority.py --quiet

daylight-v06-cap-removal-test:
	$(PYTHON) tests/daylight_cap_removal.py --quiet

daylight-v06-external-review-packet-test:
	$(PYTHON) tests/daylight_v06_external_review_packet.py --quiet

daylight-v06-external-review-verifier-test:
	$(PYTHON) tests/daylight_external_review.py --quiet

daylight-v06-fail-closed-model-test:
	$(PYTHON) tests/daylight_v06_fail_closed_model.py --quiet

daylight-v06-m4-symbolic-model-test:
	$(PYTHON) tests/daylight_v06_m4_symbolic_model.py --quiet

daylight-v06-protocol-state-test:
	cd daylight-equation/rust/daylight-model && cargo test --offline daylight_v06
	cd daylight-equation/rust/daylight-crypto && cargo test --offline v6_authorized_state

wuci-daylight-bridge-test: daylight-v06-protocol-state-test
	cd daylight-equation/rust/daylight-crypto && cargo test --offline wuci_daylight
	$(PYTHON) tests/wuci_daylight_bridge.py --quiet

daylight-v06-m4-z3-proof-test:
	$(PYTHON) tests/daylight_v06_m4_z3_proof.py --quiet

daylight-v06-schema-freeze-test:
	$(PYTHON) tests/daylight_v06_schema_freeze.py --quiet

daylight-v6-provider-kem-evidence-test:
	cd daylight-equation/rust/daylight-crypto && cargo test --offline v6_provider_kem_evidence

daylight-v6-provider-private-roundtrip-test:
	cd daylight-equation/rust/daylight-crypto && cargo test --offline v6_provider_private_roundtrip

daylight-v6-provider-vector-agreement-test:
	$(PYTHON) tests/daylight_v6_provider_vector_agreement.py --quiet

daylight-v6-kat-reproduction-bundle-test:
	$(PYTHON) tests/daylight_v6_kat_reproduction_bundle.py --quiet

daylight-v6-reference-seal-open-test:
	cd daylight-equation/rust/daylight-crypto && cargo test --offline v6_reference

daylight-v6-reference-negative-corpus-test:
	cd daylight-equation/rust/daylight-crypto && cargo test --offline v6_reference_negative

daylight-v6-nightlight-battery-test:
	cd daylight-equation/rust/daylight-crypto && cargo test --offline nightlight
	$(PYTHON) tests/daylight_v6_nightlight_battery.py --quiet

daylight-v6-nightlight-deep-assessment-test:
	cd daylight-equation/rust/daylight-crypto && cargo test --offline nightlight_v6_deep
	$(PYTHON) tests/daylight_v6_nightlight_deep_assessment.py --quiet

daylight-v06-m1-cross-agreement-test:
	DAYLIGHT_V06_M1_FIXTURE=$(DAYLIGHT_V06_M1_FIXTURE) $(PYTHON) tests/daylight_v06_m1_cross_agreement.py --quiet

daylight-v06-m1-fixture-test:
	DAYLIGHT_V06_M1_FIXTURE=$(DAYLIGHT_V06_M1_FIXTURE) $(PYTHON) tests/daylight_v06_m1_fixture.py --quiet

daylight-v06-m1-independent-open-test:
	DAYLIGHT_V06_M1_FIXTURE=$(DAYLIGHT_V06_M1_FIXTURE) $(PYTHON) tests/daylight_v06_m1_independent_open.py --quiet

daylight-v06-m1-static-test:
	DAYLIGHT_V06_M1_FIXTURE=$(DAYLIGHT_V06_M1_FIXTURE) $(PYTHON) tests/daylight_v06_m1_static_vectors.py --quiet

external-audit-test:
	$(PYTHON) tests/wuci_external_audit.py --quiet

wjstar-model-test:
	$(PYTHON) tests/wuci_wjstar_model.py --quiet

wjnext-model-test:
	$(PYTHON) tests/wuci_wjnext_model.py --quiet

wjgold-model-test:
	$(PYTHON) tests/wuci_golden_lock_model.py --quiet

golden-lock-policy-matrix:
	$(PYTHON) tests/wuci_golden_lock_policy_matrix.py --quiet

verify-release-bundle: check-native $(TARGET) sbom-provenance carrot-policy rust-sandbox-test pq-verifier-detect crypto-self-audit parser-corpus-replay self-release-ledger-bundle cage-proof qcage-proof
	$(PYTHON) tools/wuci_release_bundle.py verify \
		--repo . \
		--bin $(abspath $(TARGET)) \
		--sbom $(WUCI_SBOM) \
		--provenance $(WUCI_PROVENANCE) \
		--carrot $(CARROT_ATTESTATION) \
		--pq $(PQ_VERIFIER_EVIDENCE) \
		$(if $(REAL_PQ_VERIFIER_EVIDENCE),--real-pq-evidence $(REAL_PQ_VERIFIER_EVIDENCE),) \
		--pq-pins $(PQ_VERIFIER_PINS) \
		--crypto-audit $(CRYPTO_SELF_AUDIT) \
		--parser-replay $(PARSER_CORPUS_REPLAY) \
		--production-authority-policy docs/wuci_production_authority_policy.json \
		$(if $(PRODUCTION_AUTHORITY_ROOT),--production-authority $(PRODUCTION_AUTHORITY_ROOT),) \
		$(if $(PRODUCTION_AUTHORITY_CEREMONY),--production-authority-ceremony $(PRODUCTION_AUTHORITY_CEREMONY),) \
		$(if $(PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY),--production-authority-ceremony-root-key $(PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY),) \
		$(if $(PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE),--production-authority-ceremony-signature $(PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE),) \
		$(if $(EXTERNAL_AUDIT_EVIDENCE),--external-audit-evidence $(EXTERNAL_AUDIT_EVIDENCE),) \
		$(if $(EXTERNAL_AUDIT_REPORT),--external-audit-report $(EXTERNAL_AUDIT_REPORT),) \
		$(if $(EXTERNAL_AUDIT_ROOT_KEY),--external-audit-root-key $(EXTERNAL_AUDIT_ROOT_KEY),) \
		$(if $(EXTERNAL_AUDIT_SIGNATURE),--external-audit-signature $(EXTERNAL_AUDIT_SIGNATURE),) \
		--witness-bundle $(WITNESS_BUNDLE_DIR) \
		--ledger $(LEDGER_DIR) \
		--install-manifest $(INSTALL_MANIFEST) \
		--install-signature $(INSTALL_SIGNATURE) \
		--install-root-key install/wuci-install-root.v1.pub \
		--rust-sandbox $(RUST_SANDBOX) \
		--zig-witness $(abspath $(ZIG_WITNESS)) \
		--zig-ledger $(abspath $(ZIG_LEDGER)) \
		--out $(RELEASE_BUNDLE_VERIFICATION) \
		--quiet
	@printf 'WUCI release bundle verification: %s\n' "$(RELEASE_BUNDLE_VERIFICATION)"

high-attestation-proof: high-attestation-profile host-capacity sbom-provenance sbom-provenance-test carrot-policy kernel-sandbox-proof rust-sandbox-test pq-verifier-detect pq-verifier-test pq-verifier-fips204-proof production-readiness-gates crypto-self-audit crypto-self-audit-test external-audit-test wjstar-model-test wjnext-model-test wjgold-model-test golden-lock-policy-matrix parser-hardening-proof verify-release-bundle check-qemu-x25519-cpu asm-smoke check-asm-immediates harden-policy-matrix cage-policy-matrix cage-bundle-test qcage-model-test qcage-policy-matrix gate-contract-asm test-linux
	@printf 'WUCI high-attestation proof complete\n'

install-local:
	install -d -m 0700 "$(dir $(INSTALL_ROOT_KEY))"
	install -m 0644 "install/wuci-install-root.v1.pub" "$(INSTALL_ROOT_KEY)"
	$(MAKE) install-proof INSTALL_ROOT_KEY="$(INSTALL_ROOT_KEY)" INSTALL_PREFIX="$(INSTALL_PREFIX)"
	$(MAKE) install-audit INSTALL_PREFIX="$(INSTALL_PREFIX)"

wuci-install:
	tools/wuci-install --prefix "$(INSTALL_PREFIX)"

install-key-check:
	$(PYTHON) tools/wuci_install.py trust-key-check --install-root-key $(INSTALL_ROOT_KEY)

install-manifest: check-native $(TARGET)
	$(PYTHON) tools/wuci_install.py manifest --bin $(abspath $(TARGET)) --out $(INSTALL_MANIFEST)

install-sign-current: check-native $(TARGET)
	@if [ -z "$(INSTALL_SIGNING_KEY)" ]; then \
		echo "wuci-ji: install-sign-current requires INSTALL_SIGNING_KEY=/absolute/path/to/root-signing-key"; \
		exit 2; \
	fi
	$(MAKE) install-manifest
	$(PYTHON) tools/wuci_install.py sign-manifest \
		--install-root-key install/wuci-install-root.v1.pub \
		--signing-key $(INSTALL_SIGNING_KEY) \
		--manifest $(INSTALL_MANIFEST) \
		--signature $(INSTALL_SIGNATURE)

install-verify: install-key-check
	$(PYTHON) tools/wuci_install.py verify-manifest \
		--install-root-key $(INSTALL_ROOT_KEY) \
		--bin $(abspath $(TARGET)) \
		--manifest $(INSTALL_MANIFEST) \
		--signature $(INSTALL_SIGNATURE)

install-proof: check-native $(TARGET) install-verify
	$(PYTHON) tools/wuci_install.py install \
		--install-root-key $(INSTALL_ROOT_KEY) \
		--prefix $(INSTALL_PREFIX) \
		--version $(WUCI_VERSION) \
		$(INSTALL_ALLOW_PREFIX)

install-audit:
	$(PYTHON) tools/wuci_install.py audit --prefix $(INSTALL_PREFIX)

install-test: check-native $(TARGET)
	$(PYTHON) tests/wuci_install_policy.py --quiet
	$(PYTHON) tests/wuci_install_manifest.py --quiet
	$(PYTHON) tests/wuci_install_key_copy.py --quiet
	$(PYTHON) tests/wuci_install_no_shell.py --quiet
	$(PYTHON) tests/wuci_install_audit.py --quiet
	$(PYTHON) tests/wuci_install_atomic.py --quiet
	$(PYTHON) tests/wuci_install_bootstrap.py --quiet
	$(PYTHON) tests/meridian_install.py --quiet

zp1-upstream-test:
	@test -d "$(ZP1_DIR)" || { echo "missing $(ZP1_DIR); run git submodule update --init --recursive" >&2; exit 1; }
	cd "$(ZP1_DIR)" && cargo fmt --check
	cd "$(ZP1_DIR)" && cargo test
	cd "$(ZP1_DIR)" && cargo test --features test-utils
	cd "$(ZP1_DIR)" && cargo clippy --all-targets --features test-utils -- -D warnings
	cd "$(ZP1_DIR)" && cargo doc --no-deps

zp1-wuciji-bridge-test:
	cd "$(WUCIJI_ZP1_BRIDGE_DIR)" && cargo generate-lockfile
	cd "$(WUCIJI_ZP1_BRIDGE_DIR)" && cargo test --locked

zp1-wuciji-coupling-test: zp1-upstream-test zp1-wuciji-bridge-test
	$(PYTHON) tools/check_zp1_wuciji_coupling.py

verify-self-release-bundle: $(RELEASE_BIN)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) verify

self-release-attestation-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_self_release_attestation.py --quiet

publish-attestation-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_publish_attestation.py --quiet

witness-attestation-test: check-native $(TARGET) authority-root-check
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_witness.py --quiet

witness-archive-test: check-native $(TARGET) self-release-witness-bundle
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_witness_archive.py --bundle $(WITNESS_BUNDLE_DIR) --bin $(abspath $(TARGET)) --quiet

witness-archive-zig-test: $(ZIG_WITNESS)
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) $(PYTHON) tests/wuci_witness_archive.py --bundle $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN)) --zig-witness $(abspath $(ZIG_WITNESS)) --quiet

authority-anchor-test: check-native $(TARGET) authority-root-check
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_authority_anchor.py --quiet

ledger-asm-demo: check-native $(TARGET)
	@mkdir -p $(LEDGER_DEMO_DIR)
	@printf 'schema: wuci-ledger-entry-v1\nsequence: 0\nartifact-sha256: 1111111111111111111111111111111111111111111111111111111111111111\nmanifest-sha256: 2222222222222222222222222222222222222222222222222222222222222222\nwarrant-message-sha256: 3333333333333333333333333333333333333333333333333333333333333333\nrelease-receipt-sha256: 4444444444444444444444444444444444444444444444444444444444444444\nreceipt-contract-sha256: 5555555555555555555555555555555555555555555555555555555555555555\nauthority-root-sha256: 6666666666666666666666666666666666666666666666666666666666666666\nrelease-decision-sha256: 7777777777777777777777777777777777777777777777777777777777777777\nattestation-sha256: 8888888888888888888888888888888888888888888888888888888888888888\nrelease-authority-group-public-key: $(FROST_FIXTURE_GROUP_PUBLIC_KEY)\n' > $(LEDGER_DEMO_DIR)/entry-a.txt
	@printf 'schema: wuci-ledger-entry-v1\nsequence: 1\nartifact-sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nmanifest-sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nwarrant-message-sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\nrelease-receipt-sha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\nreceipt-contract-sha256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\nauthority-root-sha256: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\nrelease-decision-sha256: 9999999999999999999999999999999999999999999999999999999999999999\nattestation-sha256: 0000000000000000000000000000000000000000000000000000000000000000\nrelease-authority-group-public-key: $(FROST_FIXTURE_GROUP_PUBLIC_KEY)\n' > $(LEDGER_DEMO_DIR)/entry-b.txt
	@set -e; \
	empty_root=$$($(TARGET) ledger-empty-root); \
	leaf_a=$$($(TARGET) ledger-leaf-file $(LEDGER_DEMO_DIR)/entry-a.txt); \
	leaf_b=$$($(TARGET) ledger-leaf-file $(LEDGER_DEMO_DIR)/entry-b.txt); \
	node_root=$$($(TARGET) ledger-node $$leaf_a $$leaf_b); \
	printf 'WUCI-LEDGER assembly demo\n'; \
	printf 'empty-root: %s\n' "$$empty_root"; \
	printf 'entry-a: %s\n' "$(LEDGER_DEMO_DIR)/entry-a.txt"; \
	printf 'leaf-a: %s\n' "$$leaf_a"; \
	printf 'entry-b: %s\n' "$(LEDGER_DEMO_DIR)/entry-b.txt"; \
	printf 'leaf-b: %s\n' "$$leaf_b"; \
	printf 'node-root: %s\n' "$$node_root"

ledger-asm-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_ledger.py --primitives-only --quiet

ledger-proof-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_ledger.py --ledger-only --quiet

ledger-zig-history: $(ZIG_LEDGER)
	$(abspath $(ZIG_LEDGER)) verify-history --bin $(abspath $(RELEASE_BIN)) --ledger $(LEDGER_DIR)

pythonless-public-verify: $(ZIG_WITNESS) $(ZIG_LEDGER)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WITNESS)) verify $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN))
	$(abspath $(ZIG_LEDGER)) verify-history --bin $(abspath $(RELEASE_BIN)) --ledger $(LEDGER_DIR)
	@printf 'WUCI Pythonless public verification complete\n'

test: check-native-x25519 $(TARGET) asm-smoke authority-root-check frost-workflow frost-authz gate-boundary gate-workflow gate-policy-matrix gate-receipt-contract parser-adversarial-test authority-anchor-test ledger-asm-test ledger-proof-test cage-policy-matrix cage-bundle-test qcage-model-test qcage-policy-matrix harden-policy-matrix harden-safeio-test secret-path-isolation-test wuci-prism-test wuci-progress-test noxframe-launch-test aead-boundary-test self-release-attestation-test publish-attestation-test
	$(PYTHON) tests/test_wuci_ji.py

test-pypy: check-pypy
	$(MAKE) test PYTHON=$(PYPY)

zig-release-proof: build-linux
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-proof

zig-release-contract-proof: build-linux $(ZIG_GATE_CONTRACT)
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-contract-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-contract-proof

zig-release-asm-contract-proof: build-linux
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-asm-contract-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-asm-contract-proof

zig-release-release-contract-proof: build-linux
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-release-contract-demo RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-release-contract-proof

zig-release-rooted-proof: zig-release-anchored-proof

zig-release-anchored-proof: build-linux authority-root-check
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-rooted-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-anchored-proof

zig-release-publish-bundle: build-linux
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-publish-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-publish-bundle

zig-release-witness-bundle: build-linux authority-root-check
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-witness-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" WITNESS_BUNDLE_DIR=build/wuci-zig-release-witness-bundle

zig-release-ledger-bundle: build-linux authority-root-check
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-ledger-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" WITNESS_BUNDLE_DIR=build/wuci-zig-release-witness-bundle WITNESS_WORK_DIR=build/wuci-zig-release-witness-bundle.work LEDGER_DIR=build/wuci-zig-ledger

zig-release-witness-archive: zig-release-witness-bundle $(ZIG_WITNESS)
	$(MAKE) witness-archive RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" WITNESS_BUNDLE_DIR=build/wuci-zig-release-witness-bundle WITNESS_ARCHIVE=build/wuci-zig-release-witness-bundle.tar WITNESS_ARCHIVE_SHA256=build/wuci-zig-release-witness-bundle.tar.sha256
	$(MAKE) witness-archive-zig-verify RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" WITNESS_ARCHIVE=build/wuci-zig-release-witness-bundle.tar WITNESS_ARCHIVE_SHA256=build/wuci-zig-release-witness-bundle.tar.sha256 WITNESS_ARCHIVE_CHECK_DIR=build/wuci-zig-release-witness-archive-check

self-release-asm-contract-proof: check-native $(TARGET)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) selftest
	$(MAKE) self-release-asm-contract-bundle RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-asm-contract-proof

self-release-rooted-proof: self-release-anchored-proof

self-release-anchored-proof: check-native $(TARGET) authority-root-check
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) selftest
	$(MAKE) self-release-rooted-bundle RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-anchored-proof

rooted-proof-display: check-native $(TARGET)
	@mkdir -p build
	@printf 'forging WUCI-ANCHOR proof tape...\n'
	@$(MAKE) --no-print-directory -s self-release-rooted-bundle RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-rooted-proof > build/wuci-rooted-proof-display.log
	@$(PYTHON) tools/wuci_root_attestation_display.py --bundle-dir build/wuci-rooted-proof --authority $(AUTHORITY_ROOT)
	@printf '\nproof log: %s\n' "build/wuci-rooted-proof-display.log"

self-release-release-contract-proof: check-native $(TARGET)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) selftest
	$(MAKE) self-release-release-contract-demo RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-release-contract-proof

selftest-linux: check-qemu-user build-linux
	$(QEMU_RUNNER) $(CROSS_TARGET) selftest

test-linux: check-qemu-x25519-cpu
	WUCI_JI_BIN=$(abspath $(CROSS_TARGET)) WUCI_JI_RUNNER="$(QEMU_RUNNER)" $(PYTHON) tests/test_wuci_ji.py

ci:
	$(MAKE) ci-native
	$(MAKE) ci-zig

ci-native:
	$(MAKE) clean
	$(MAKE) test
	$(MAKE) self-release-asm-contract-proof
	$(MAKE) self-release-anchored-proof
	$(MAKE) self-release-release-contract-proof
	$(MAKE) self-release-publish-bundle
	$(MAKE) self-release-witness-bundle
	$(MAKE) self-release-ledger-bundle
	$(MAKE) cage-proof
	$(MAKE) qcage-proof
	$(MAKE) harden0-proof
	$(MAKE) harden-proof
	$(MAKE) witness-attestation-test
	$(MAKE) self-release-witness-archive
	$(MAKE) witness-archive-test

ci-zig:
	$(MAKE) clean
	$(MAKE) build-linux
	file $(CROSS_TARGET)
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) gate-contract-zig
	$(MAKE) zig-release-proof
	$(MAKE) zig-release-contract-proof
	$(MAKE) zig-release-asm-contract-proof
	$(MAKE) zig-release-anchored-proof
	$(MAKE) zig-release-release-contract-proof
	$(MAKE) zig-release-publish-bundle
	$(MAKE) zig-release-witness-bundle
	$(MAKE) zig-release-ledger-bundle
	$(MAKE) witness-zig RELEASE_BIN=$(abspath $(CROSS_TARGET)) WITNESS_BUNDLE_DIR=build/wuci-zig-release-witness-bundle
	$(MAKE) witness-zig-test RELEASE_BIN=$(abspath $(CROSS_TARGET)) WITNESS_BUNDLE_DIR=build/wuci-zig-release-witness-bundle
	$(MAKE) zig-release-witness-archive
	$(MAKE) witness-archive-zig-test RELEASE_BIN=$(abspath $(CROSS_TARGET)) WITNESS_BUNDLE_DIR=build/wuci-zig-release-witness-bundle

clean:
	rm -rf build
	mkdir -p build/wucios
	printf '\n' > build/wucios/.gitkeep
