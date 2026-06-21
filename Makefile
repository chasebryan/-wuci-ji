AS ?= as
LD ?= ld
PYTHON ?= python3
NM ?= nm
OBJDUMP ?= objdump
ZIG ?= zig
QEMU_X86_64 ?= qemu-x86_64

HOST_OS := $(shell uname -s)
HOST_ARCH := $(shell uname -m)

TARGET := build/wuci-ji
ASM_SOURCES := src/main.s src/wuci-ji.s src/sys.s src/encoding.s src/frost.s src/hmac_hkdf.s src/secp256k1_field.s src/secp256k1_point.s src/secp256k1_scalar.s src/sha256.s src/x25519.s
OBJECTS := $(patsubst src/%.s,build/%.o,$(ASM_SOURCES))
CROSS_SOURCES := $(patsubst src/%.s,build/%.zig.s,$(ASM_SOURCES))
CROSS_TARGET := build/wuci-ji-linux-x86_64
ZIG_TARGET ?= x86_64-linux-musl
ZIG_GLOBAL_CACHE_DIR ?= build/.zig-cache/global
ZIG_LOCAL_CACHE_DIR ?= build/.zig-cache/local
FROST_AUTHZ_DEMO_DIR ?= build/frost-authz-demo

.PHONY: all build-linux check-asm-immediates check-native check-qemu-user clean frost-authz frost-authz-demo frost-demo frost-workflow gate-boundary test test-linux selftest selftest-linux

all: check-native $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) -o $@ $^

build/%.o: src/%.s check-native
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

build-linux: $(CROSS_SOURCES)
	mkdir -p build $(ZIG_GLOBAL_CACHE_DIR) $(ZIG_LOCAL_CACHE_DIR)
	ZIG_GLOBAL_CACHE_DIR=$(abspath $(ZIG_GLOBAL_CACHE_DIR)) \
	ZIG_LOCAL_CACHE_DIR=$(abspath $(ZIG_LOCAL_CACHE_DIR)) \
	$(ZIG) cc -target $(ZIG_TARGET) -nostdlib -static -o $(CROSS_TARGET) $(CROSS_SOURCES)

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

test: check-native $(TARGET) check-asm-immediates frost-workflow frost-authz gate-boundary
	$(PYTHON) tests/test_wuci_ji.py

selftest-linux: check-qemu-user build-linux
	$(QEMU_X86_64) $(CROSS_TARGET) selftest

test-linux: check-qemu-user build-linux
	WUCI_JI_BIN=$(abspath $(CROSS_TARGET)) WUCI_JI_RUNNER=$(QEMU_X86_64) $(PYTHON) tests/test_wuci_ji.py

clean:
	rm -rf build
