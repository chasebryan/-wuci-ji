AS ?= as
LD ?= ld
PYTHON ?= python3
PYPY ?= .tools/bin/pypy3
NM ?= nm
OBJDUMP ?= objdump
ZIG ?= zig
QEMU_X86_64 ?= qemu-x86_64

HOST_OS := $(shell uname -s)
HOST_ARCH := $(shell uname -m)

TARGET := build/wuci-ji
ASM_SOURCES := src/main.s src/wuci-ji.s src/gate_contract.s src/sys.s src/encoding.s src/frost.s src/hmac_hkdf.s src/secp256k1_field.s src/secp256k1_point.s src/secp256k1_scalar.s src/sha256.s src/x25519.s
OBJECTS := $(patsubst src/%.s,build/%.o,$(ASM_SOURCES))
CROSS_SOURCES := $(patsubst src/%.s,build/%.zig.s,$(ASM_SOURCES))
CROSS_TARGET := build/wuci-ji-linux-x86_64
ZIG_GATE_CONTRACT := build/wuci-gate-contract
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

.PHONY: all build-linux check-asm-immediates check-native check-pypy check-qemu-user clean frost-authz frost-authz-demo frost-demo frost-workflow gate-boundary gate-contract-asm gate-contract-zig gate-demo gate-policy-matrix gate-receipt-contract gate-workflow publish-attestation-test release-rooted-contract rooted-proof-display self-release-asm-contract-bundle self-release-asm-contract-demo self-release-asm-contract-proof self-release-attestation-test self-release-bundle self-release-contract-bundle self-release-contract-demo self-release-demo self-release-publish-bundle self-release-release-contract-demo self-release-release-contract-proof self-release-rooted-bundle self-release-rooted-demo self-release-rooted-proof test test-linux test-pypy selftest selftest-linux verify-self-release-bundle zig-release-asm-contract-proof zig-release-contract-proof zig-release-proof zig-release-publish-bundle zig-release-release-contract-proof zig-release-rooted-proof

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

check-qemu-user:
	@if ! command -v $(QEMU_X86_64) >/dev/null 2>&1; then \
		echo "wuci-ji: test-linux requires Linux user-mode qemu-x86_64 on PATH."; \
		echo "macOS Homebrew qemu ships qemu-system-x86_64, not the Linux user-mode runner."; \
		echo "run tests on x86_64 Linux, or set QEMU_X86_64=/path/to/qemu-x86_64 on a Linux host."; \
		exit 2; \
	fi

check-pypy:
	@if ! command -v $(PYPY) >/dev/null 2>&1; then \
		echo "wuci-ji: test-pypy requires PyPy at $(PYPY)."; \
		echo "install PyPy or run 'make test PYTHON=/path/to/pypy3'."; \
		exit 2; \
	fi

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

selftest: check-native $(TARGET)
	$(TARGET) selftest

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

self-release-rooted-demo: $(RELEASE_BIN)
	mkdir -p $(SELF_RELEASE_DEMO_DIR)
	rm -f \
		$(SELF_RELEASE_DEMO_DIR)/artifact.key \
		$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj \
		$(SELF_RELEASE_DEMO_DIR)/manifest.txt \
		$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt \
		$(SELF_RELEASE_DEMO_DIR)/auth-transcript.json \
		$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json \
		$(SELF_RELEASE_CONTRACT) \
		$(SELF_RELEASE_AUTHORITY) \
		$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji \
		$(SELF_RELEASE_ATTESTATION)
	printf '1111111111111111111111111111111111111111111111111111111111111111\n' > $(SELF_RELEASE_DEMO_DIR)/artifact.key
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) seal-file-keyfile-v2 $(SELF_RELEASE_DEMO_DIR)/artifact.key 2233445566778899aabbccddeeff0011 $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) manifest-file $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/manifest.txt
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) warrant-message-file open $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj > $(SELF_RELEASE_DEMO_DIR)/warrant-message.txt
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --print-transcript-manifest > $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_frost_authorize.py --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --transcript-manifest $(SELF_RELEASE_DEMO_DIR)/auth-transcript.json --update-transcript-manifest --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json
	WUCI_JI_BIN=$(abspath $(RELEASE_BIN)) WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_receipt_contract.py emit --bin $(abspath $(RELEASE_BIN)) --artifact $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj --action open --receipt $(SELF_RELEASE_DEMO_DIR)/auth-receipt.json --contract $(SELF_RELEASE_CONTRACT) --quiet
	$(PYTHON) tools/wuci_authority_root.py emit --contract $(SELF_RELEASE_CONTRACT) --authority $(SELF_RELEASE_AUTHORITY) --quiet
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) authority-root-verify $(SELF_RELEASE_AUTHORITY)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) gate-contract-verify-rooted $(SELF_RELEASE_AUTHORITY) $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) open-authorized-rooted $(SELF_RELEASE_AUTHORITY) $(SELF_RELEASE_DEMO_DIR)/artifact.key $(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj $(SELF_RELEASE_CONTRACT) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	cmp $(abspath $(RELEASE_BIN)) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	chmod +x $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji
	$(RELEASE_RUNNER) $(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji --help >/dev/null
	@printf 'WUCI self-release rooted contract demo complete\n'
	@printf 'sealed artifact: %s\n' "$(SELF_RELEASE_DEMO_DIR)/wuci-ji.self.wj"
	@printf 'manifest: %s\n' "$(SELF_RELEASE_DEMO_DIR)/manifest.txt"
	@printf 'warrant message: %s\n' "$(SELF_RELEASE_DEMO_DIR)/warrant-message.txt"
	@printf 'receipt: %s\n' "$(SELF_RELEASE_DEMO_DIR)/auth-receipt.json"
	@printf 'receipt contract: %s\n' "$(SELF_RELEASE_CONTRACT)"
	@printf 'authority root: %s\n' "$(SELF_RELEASE_AUTHORITY)"
	@printf 'opened binary: %s\n' "$(SELF_RELEASE_DEMO_DIR)/opened-wuci-ji"
	@printf 'verified: assembly rooted Gate, byte-identical, and executable\n'

self-release-rooted-bundle: self-release-rooted-demo
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_MODE=rooted-asm $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-mode rooted-asm --authority $(SELF_RELEASE_AUTHORITY) attest
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" WUCI_GATE_CONTRACT_MODE=rooted-asm $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) --contract $(SELF_RELEASE_CONTRACT) --contract-mode rooted-asm --authority $(SELF_RELEASE_AUTHORITY) verify
	@printf 'self-release rooted assembly attestation: %s\n' "$(SELF_RELEASE_ATTESTATION)"

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
	$(PYTHON) tools/wuci_authority_root.py emit --contract $(SELF_RELEASE_CONTRACT) --authority $(SELF_RELEASE_AUTHORITY) --allow-open false --allow-release true --quiet
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

verify-self-release-bundle: $(RELEASE_BIN)
	WUCI_JI_RUNNER="$(RELEASE_RUNNER)" $(PYTHON) tools/wuci_self_release.py --bin $(abspath $(RELEASE_BIN)) --bundle-dir $(SELF_RELEASE_DEMO_DIR) --attestation $(SELF_RELEASE_ATTESTATION) verify

self-release-attestation-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_self_release_attestation.py --quiet

publish-attestation-test: check-native $(TARGET)
	WUCI_JI_BIN=$(abspath $(TARGET)) $(PYTHON) tests/wuci_publish_attestation.py --quiet

test: check-native $(TARGET) check-asm-immediates frost-workflow frost-authz gate-boundary gate-workflow gate-policy-matrix gate-receipt-contract gate-contract-asm self-release-attestation-test publish-attestation-test
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

zig-release-rooted-proof: build-linux
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-rooted-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-rooted-proof

zig-release-publish-bundle: build-linux
	$(RELEASE_RUNNER) $(abspath $(CROSS_TARGET)) selftest
	$(MAKE) self-release-publish-bundle RELEASE_BIN=$(abspath $(CROSS_TARGET)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-zig-release-publish-bundle

self-release-asm-contract-proof: check-native $(TARGET)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) selftest
	$(MAKE) self-release-asm-contract-bundle RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-asm-contract-proof

self-release-rooted-proof: check-native $(TARGET)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) selftest
	$(MAKE) self-release-rooted-bundle RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-rooted-proof

rooted-proof-display: check-native $(TARGET)
	@mkdir -p build
	@printf 'forging WUCI-ROOT proof tape...\n'
	@$(MAKE) --no-print-directory -s self-release-rooted-bundle RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-rooted-proof > build/wuci-rooted-proof-display.log
	@$(PYTHON) tools/wuci_root_attestation_display.py --bundle-dir build/wuci-rooted-proof
	@printf '\nproof log: %s\n' "build/wuci-rooted-proof-display.log"

self-release-release-contract-proof: check-native $(TARGET)
	$(RELEASE_RUNNER) $(abspath $(RELEASE_BIN)) selftest
	$(MAKE) self-release-release-contract-demo RELEASE_BIN=$(abspath $(RELEASE_BIN)) RELEASE_RUNNER="$(RELEASE_RUNNER)" SELF_RELEASE_DEMO_DIR=build/wuci-release-contract-proof

selftest-linux: check-qemu-user build-linux
	$(QEMU_X86_64) $(CROSS_TARGET) selftest

test-linux: check-qemu-user build-linux
	WUCI_JI_BIN=$(abspath $(CROSS_TARGET)) WUCI_JI_RUNNER=$(QEMU_X86_64) $(PYTHON) tests/test_wuci_ji.py

clean:
	rm -rf build
