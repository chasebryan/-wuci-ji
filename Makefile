AS ?= as
LD ?= ld
PYTHON ?= python3

TARGET := build/wuci-ji
OBJECT := build/wuci-ji.o
SOURCE := src/wuci-ji.s

.PHONY: all clean test selftest

all: $(TARGET)

$(TARGET): $(OBJECT)
	$(LD) -o $@ $<

$(OBJECT): $(SOURCE)
	mkdir -p build
	$(AS) --64 -o $@ $<

selftest: $(TARGET)
	$(TARGET) selftest

test: $(TARGET)
	$(PYTHON) tests/test_wuci_ji.py

clean:
	rm -rf build
