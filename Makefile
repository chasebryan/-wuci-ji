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
ASM_SOURCES := src/main.s src/wuci-ji.s src/sys.s src/encoding.s src/sha256.s src/x25519.s
OBJECTS := $(patsubst src/%.s,build/%.o,$(ASM_SOURCES))
OBJECT := build/wuci-ji.o
CROSS_SOURCES := $(patsubst src/%.s,build/%.zig.s,$(ASM_SOURCES))
CROSS_TARGET := build/wuci-ji-linux-x86_64
ZIG_TARGET ?= x86_64-linux-musl
ZIG_GLOBAL_CACHE_DIR ?= build/.zig-cache/global
ZIG_LOCAL_CACHE_DIR ?= build/.zig-cache/local

.PHONY: all build-linux check-asm-immediates check-native check-qemu-user clean test test-linux selftest selftest-linux

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

check-asm-immediates: check-native $(OBJECT)
	NM=$(NM) OBJDUMP=$(OBJDUMP) $(PYTHON) tests/check_asm_immediates.py $(OBJECT)

test: check-native $(TARGET) check-asm-immediates
	$(PYTHON) tests/test_wuci_ji.py

selftest-linux: check-qemu-user build-linux
	$(QEMU_X86_64) $(CROSS_TARGET) selftest

test-linux: check-qemu-user build-linux
	WUCI_JI_BIN=$(abspath $(CROSS_TARGET)) WUCI_JI_RUNNER=$(QEMU_X86_64) $(PYTHON) tests/test_wuci_ji.py

clean:
	rm -rf build
