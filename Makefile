AS ?= as
LD ?= ld
PYTHON ?= python3
PYPY ?= .tools/bin/pypy3
NM ?= nm
OBJDUMP ?= objdump
RUSTC ?= $(shell if command -v rustc >/dev/null 2>&1; then command -v rustc; elif [ -x "$(HOME)/.cargo/bin/rustc" ]; then printf '%s\n' "$(HOME)/.cargo/bin/rustc"; fi)
CARGO ?= $(shell if command -v cargo >/dev/null 2>&1; then command -v cargo; elif [ -x "$(HOME)/.cargo/bin/cargo" ]; then printf '%s\n' "$(HOME)/.cargo/bin/cargo"; fi)
ZIG ?= zig
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

.PHONY: aead-boundary-test all asm-regression asm-smoke authority-anchor-test authority-root-check authority-root-fixture authority-root-metal-check build-linux cage-attestation-test cage-bundle-test cage-ledger-entry cage-policy-matrix cage-proof carrot-policy check-asm-immediates check-native check-native-x25519 check-pypy check-qemu-user check-qemu-x25519-cpu ci ci-native ci-zig clean crypto-self-audit crypto-self-audit-test daylight-v06-m1-fixture-test external-audit-test frost-authz frost-authz-demo frost-demo frost-workflow gate-boundary gate-contract-asm gate-contract-zig gate-demo gate-policy-matrix gate-receipt-contract gate-workflow golden-lock-policy-matrix harden-action-policy-test harden-fixture-quarantine-test harden-ledger-mutation-test harden-policy-matrix harden-proof harden-safeio-test harden-verifier-identity-test harden-witness-symlink-test harden0-action-policy-test harden0-fixture-quarantine-test harden0-policy-matrix harden0-proof harden0-safeio-test harden0-verifier-identity-test harden0-witness-safeio-test high-attestation-profile high-attestation-proof host-capacity install-audit install-key-check install-manifest install-proof install-sign-current install-test install-verify kernel-sandbox-proof ledger-asm-demo ledger-asm-test ledger-proof-test ledger-zig-history parser-adversarial-test parser-corpus-replay parser-corpus-replay-test parser-hardening-proof pq-verifier-detect pq-verifier-fips204-build pq-verifier-fips204-proof pq-verifier-real pq-verifier-real-attest pq-verifier-test production-authority-verify production-readiness-gates publish-attestation-test publish-index publish-witness pythonless-public-verify qcage-attestation-test qcage-build-graph qcage-crypto-inventory qcage-model-test qcage-policy-matrix qcage-proof qcage-risk release-rooted-contract reproducible-build-metadata rooted-proof-display rust-sandbox-build rust-sandbox-test sbom-provenance sbom-provenance-test secret-path-isolation-test self-release-anchored-proof self-release-asm-contract-bundle self-release-asm-contract-demo self-release-asm-contract-proof self-release-attestation-test self-release-bundle self-release-contract-bundle self-release-demo self-release-ledger-bundle self-release-publish-bundle self-release-release-contract-demo self-release-release-contract-proof self-release-rooted-bundle self-release-rooted-demo self-release-rooted-proof self-release-witness-archive self-release-witness-bundle test test-linux test-pypy selftest selftest-linux verify-release-bundle verify-self-release-bundle witness-archive witness-archive-test witness-archive-verify witness-archive-zig-test witness-archive-zig-verify witness-attestation-test witness-zig witness-zig-test wjgold-model-test wjnext-model-test wjstar-model-test zig-release-anchored-proof zig-release-asm-contract-proof zig-release-contract-proof zig-release-ledger-bundle zig-release-proof zig-release-publish-bundle zig-release-release-contract-proof zig-release-rooted-proof zig-release-witness-archive zig-release-witness-bundle

all: check-native $(TARGET)

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
	$(abspath $(ZIG_LEDGER)) init --ledger $(LEDGER_DIR)
	$(abspath $(ZIG_LEDGER)) append --ledger $(LEDGER_DIR) --witness-bundle $(WITNESS_BUNDLE_DIR)
	$(abspath $(ZIG_LEDGER)) prove-inclusion --ledger $(LEDGER_DIR) --sequence 0 --out $(LEDGER_INCLUSION_PROOF)
	$(abspath $(ZIG_LEDGER)) verify-inclusion --entry $(LEDGER_DIR)/ledger-entry.txt --proof $(LEDGER_INCLUSION_PROOF) --head $(LEDGER_DIR)/ledger-head.txt
	$(abspath $(ZIG_LEDGER)) prove-consistency --ledger $(LEDGER_DIR) --from-head $(LEDGER_DIR)/previous-ledger-head.txt --to-head $(LEDGER_DIR)/ledger-head.txt --out $(LEDGER_CONSISTENCY_PROOF)
	$(abspath $(ZIG_LEDGER)) verify-consistency --proof $(LEDGER_CONSISTENCY_PROOF)
	$(abspath $(ZIG_LEDGER)) verify-history --ledger $(LEDGER_DIR)
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

harden-proof: harden-policy-matrix harden-safeio-test harden-verifier-identity-test harden-witness-symlink-test harden-fixture-quarantine-test harden-action-policy-test harden-ledger-mutation-test
	@printf 'WUCI-HARDEN proof complete\n'

harden0-proof: harden0-policy-matrix harden0-safeio-test harden0-verifier-identity-test harden0-witness-safeio-test harden0-fixture-quarantine-test harden0-action-policy-test
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

crypto-self-audit:
	$(PYTHON) tools/wuci_crypto_audit.py emit --repo . --out $(CRYPTO_SELF_AUDIT) --quiet
	$(PYTHON) tools/wuci_crypto_audit.py verify --repo . --audit $(CRYPTO_SELF_AUDIT) --quiet
	@printf 'WUCI crypto self-audit: %s\n' "$(CRYPTO_SELF_AUDIT)"

crypto-self-audit-test:
	$(PYTHON) tests/wuci_crypto_audit.py --quiet

daylight-v06-m1-fixture-test:
	DAYLIGHT_V06_M1_FIXTURE=$(DAYLIGHT_V06_M1_FIXTURE) $(PYTHON) tests/daylight_v06_m1_fixture.py --quiet

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
	$(abspath $(ZIG_LEDGER)) verify-history --ledger $(LEDGER_DIR)

pythonless-public-verify: $(ZIG_WITNESS) $(ZIG_LEDGER)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(abspath $(ZIG_WITNESS)) verify $(WITNESS_BUNDLE_DIR) --bin $(abspath $(RELEASE_BIN))
	$(abspath $(ZIG_LEDGER)) verify-history --ledger $(LEDGER_DIR)
	@printf 'WUCI Pythonless public verification complete\n'

test: check-native-x25519 $(TARGET) asm-smoke authority-root-check frost-workflow frost-authz gate-boundary gate-workflow gate-policy-matrix gate-receipt-contract parser-adversarial-test authority-anchor-test ledger-asm-test ledger-proof-test cage-policy-matrix cage-bundle-test qcage-model-test qcage-policy-matrix harden-policy-matrix harden-safeio-test secret-path-isolation-test aead-boundary-test self-release-attestation-test publish-attestation-test
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
