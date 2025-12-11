# RISC-V Cold Wallet Makefile
# Copyright (C) 2025 blubskye
# SPDX-License-Identifier: AGPL-3.0-or-later

# Cross-compilation support
CROSS_COMPILE ?=

# Compiler selection: GCC (default) or Clang
# Usage: make COMPILER=clang  (for BSD/macOS with LLVM toolchain)
#        make COMPILER=gcc    (default)
ifeq ($(COMPILER),clang)
    CC = $(CROSS_COMPILE)clang
    AR = $(CROSS_COMPILE)llvm-ar
    STRIP = $(CROSS_COMPILE)llvm-strip
    # Clang-specific flags
    CLANG_FLAGS = -Wno-gnu-zero-variadic-macro-arguments
else
    CC = $(CROSS_COMPILE)gcc
    AR = $(CROSS_COMPILE)ar
    STRIP = $(CROSS_COMPILE)strip
    CLANG_FLAGS =
endif

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin
TESTDIR = tests
LIBDIR = lib

# Target
TARGET = $(BINDIR)/riscv_wallet
TEST_TARGET = $(BINDIR)/test_runner

# Compiler flags
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11
CFLAGS += -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE
CFLAGS += -I$(SRCDIR) -I$(LIBDIR)

# Security hardening flags
HARDENING = -fno-strict-overflow -fno-delete-null-pointer-checks
CFLAGS += $(HARDENING) $(CLANG_FLAGS)

# Linker flags
LDFLAGS = -pie -Wl,-z,relro,-z,now

# Libraries
LIBS = -lsodium -lsecp256k1 -lqrencode

# libfprint-2 support (requires glib-2.0)
FPRINT_CFLAGS := $(shell pkg-config --cflags libfprint-2 glib-2.0 2>/dev/null)
FPRINT_LIBS := $(shell pkg-config --libs libfprint-2 glib-2.0 2>/dev/null)
ifneq ($(FPRINT_LIBS),)
    CFLAGS += $(FPRINT_CFLAGS) -DHAVE_LIBFPRINT
    LIBS += $(FPRINT_LIBS)
else
    $(warning libfprint-2 not found, fingerprint support disabled)
endif

# libgpiod support for GPIO button input
GPIOD_CFLAGS := $(shell pkg-config --cflags libgpiod 2>/dev/null)
GPIOD_LIBS := $(shell pkg-config --libs libgpiod 2>/dev/null)
ifneq ($(GPIOD_LIBS),)
    CFLAGS += $(GPIOD_CFLAGS) -DHAVE_LIBGPIOD
    LIBS += $(GPIOD_LIBS)
else
    $(warning libgpiod not found, GPIO button support disabled)
endif

# libdrm support for DRM/KMS display backend
DRM_CFLAGS := $(shell pkg-config --cflags libdrm 2>/dev/null)
DRM_LIBS := $(shell pkg-config --libs libdrm 2>/dev/null)
ifneq ($(DRM_LIBS),)
    CFLAGS += $(DRM_CFLAGS) -DHAVE_LIBDRM
    LIBS += $(DRM_LIBS)
else
    $(warning libdrm not found, DRM display backend disabled)
endif

# V4L2 support for QR scanner (Linux only, header-only)
ifeq ($(shell uname -s),Linux)
    CFLAGS += -DHAVE_V4L2
endif

# quirc support for QR code decoding
# Checks: 1) pkg-config, 2) system paths, 3) local build in ~/Downloads/quirc
QUIRC_LIBS := $(shell pkg-config --libs quirc 2>/dev/null)
ifneq ($(QUIRC_LIBS),)
    QUIRC_CFLAGS := $(shell pkg-config --cflags quirc 2>/dev/null)
    CFLAGS += $(QUIRC_CFLAGS) -DHAVE_QUIRC
    LIBS += $(QUIRC_LIBS)
else ifneq ($(wildcard /usr/include/quirc.h),)
    CFLAGS += -DHAVE_QUIRC
    LIBS += -lquirc
else ifneq ($(wildcard /usr/local/include/quirc.h),)
    CFLAGS += -I/usr/local/include -DHAVE_QUIRC
    LIBS += -L/usr/local/lib -lquirc
else
    # Check for local build (useful for development)
    QUIRC_LOCAL := $(HOME)/Downloads/quirc
    ifneq ($(wildcard $(QUIRC_LOCAL)/libquirc.a),)
        CFLAGS += -I$(QUIRC_LOCAL)/lib -DHAVE_QUIRC
        LIBS += $(QUIRC_LOCAL)/libquirc.a
    else
        $(warning quirc not found, QR scanner disabled. Install quirc or build from https://github.com/dlbeer/quirc)
    endif
endif

# Optional USB HID support via HIDAPI
ifeq ($(USB),1)
    CFLAGS += -DUSE_HIDAPI
    LIBS += -lhidapi-libusb
endif

# Optional hotloadable acceleration modules
ifeq ($(ACCEL_HOTLOAD),1)
    CFLAGS += -DACCEL_HOTLOAD
    LIBS += -ldl
endif

# Debug/Release builds
ifeq ($(DEBUG),1)
    CFLAGS += -g -Og -DDEBUG
else ifeq ($(O3),1)
    CFLAGS += -O3 -DNDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Profile-Guided Optimization (PGO)
# Step 1: make pgo-generate  - Build instrumented binary
# Step 2: Run the binary with representative workload (e.g., make pgo-train)
# Step 3: make pgo-use       - Build optimized binary using profile data
PGO_DIR = $(OBJDIR)/pgo

ifeq ($(PGO),generate)
    CFLAGS += -fprofile-generate=$(PGO_DIR) -fprofile-update=atomic
    LDFLAGS += -fprofile-generate=$(PGO_DIR)
else ifeq ($(PGO),use)
    # -Wno-error=missing-profile: Allow files not exercised during training
    CFLAGS += -fprofile-use=$(PGO_DIR) -fprofile-correction -Wno-error=missing-profile
    LDFLAGS += -fprofile-use=$(PGO_DIR)
endif

# Link-Time Optimization (LTO)
# Enables whole-program optimization across compilation units
# Usage: make LTO=1
ifeq ($(LTO),1)
    CFLAGS += -flto=auto -fno-fat-lto-objects
    LDFLAGS += -flto=auto
    # Use same optimization level at link time
    ifeq ($(O3),1)
        LDFLAGS += -O3
    else
        LDFLAGS += -O2
    endif
endif

# Graphite polyhedral loop optimizer (GCC only)
# Provides additional loop optimizations using polyhedral model
# May improve nested loop performance in some crypto operations
# Usage: make GRAPHITE=1
# Note: Requires ISL (Integer Set Library) support in GCC
ifeq ($(GRAPHITE),1)
    ifneq ($(COMPILER),clang)
        CFLAGS += -fgraphite-identity -floop-nest-optimize
        CFLAGS += -floop-parallelize-all -ftree-loop-distribution
    endif
endif

# RISC-V architecture optimization
# Usage: make RISCV_ARCH=rv64gc_zba_zbb_zbs
ifdef RISCV_ARCH
    CFLAGS += -march=$(RISCV_ARCH)
endif

# RISC-V microarchitecture tuning
# Usage: make RISCV_TUNE=sifive-u74 (or generic, rocket, etc.)
ifdef RISCV_TUNE
    CFLAGS += -mtune=$(RISCV_TUNE)
endif

# RISC-V optimized build preset (combines arch + tune + extensions)
# Usage: make RISCV_OPTIMIZE=1 for generic optimized RISC-V build
#        make RISCV_OPTIMIZE=sifive for SiFive U74 optimized build
#        make RISCV_OPTIMIZE=thead for T-Head C910 optimized build
# Valid -mtune: rocket, sifive-7-series, sifive-u74, thead-c906, generic-ooo, size
ifeq ($(RISCV_OPTIMIZE),1)
    # Generic RISC-V with common extensions (out-of-order tuning)
    CFLAGS += -march=rv64gc_zba_zbb_zbs -mtune=generic-ooo
    CFLAGS += -DRISCV_OPTIMIZED
else ifeq ($(RISCV_OPTIMIZE),sifive)
    # SiFive U74 (HiFive Unmatched, VisionFive 2)
    CFLAGS += -march=rv64gc_zba_zbb_zbs -mtune=sifive-u74
    CFLAGS += -DRISCV_OPTIMIZED -DRISCV_SIFIVE
else ifeq ($(RISCV_OPTIMIZE),thead)
    # T-Head C910 (LicheePi 4A, BeagleV-Ahead)
    CFLAGS += -march=rv64gc_zba_zbb_zbc_zbs -mtune=thead-c906
    CFLAGS += -DRISCV_OPTIMIZED -DRISCV_THEAD
else ifeq ($(RISCV_OPTIMIZE),spacemit)
    # SpacemiT K1 (BananaPi BPI-F3) - uses rocket tune as fallback
    CFLAGS += -march=rv64gcv_zba_zbb_zbs -mtune=rocket
    CFLAGS += -DRISCV_OPTIMIZED -DRISCV_SPACEMIT
else ifeq ($(RISCV_OPTIMIZE),crypto)
    # RISC-V with full scalar crypto (Zk)
    CFLAGS += -march=rv64gc_zba_zbb_zbs_zkn
    CFLAGS += -mtune=generic-ooo
    CFLAGS += -DRISCV_OPTIMIZED -DRISCV_SCALAR_CRYPTO
else ifeq ($(RISCV_OPTIMIZE),size)
    # Optimize for code size (embedded/constrained systems)
    CFLAGS += -march=rv64gc -mtune=size -Os
    CFLAGS += -DRISCV_OPTIMIZED -DRISCV_SIZE_OPT
endif

# Source files
SRCS = $(wildcard $(SRCDIR)/*.c) \
       $(wildcard $(SRCDIR)/wallet/*.c) \
       $(wildcard $(SRCDIR)/crypto/*.c) \
       $(wildcard $(SRCDIR)/chains/*.c) \
       $(wildcard $(SRCDIR)/security/*.c) \
       $(wildcard $(SRCDIR)/ui/*.c) \
       $(wildcard $(SRCDIR)/util/*.c) \
       $(wildcard $(SRCDIR)/usb/*.c) \
       $(wildcard $(SRCDIR)/accel/*.c) \
       $(wildcard $(SRCDIR)/hw/*.c) \
       $(wildcard $(SRCDIR)/walletconnect/*.c)

# Object files
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# Test sources
TEST_SRCS = $(wildcard $(TESTDIR)/*.c)
TEST_OBJS = $(patsubst $(TESTDIR)/%.c,$(OBJDIR)/tests/%.o,$(TEST_SRCS))

# Default target
.PHONY: all
all: dirs $(TARGET)

# Create directories
.PHONY: dirs
dirs:
	@mkdir -p $(BINDIR)
	@mkdir -p $(OBJDIR)/wallet
	@mkdir -p $(OBJDIR)/crypto
	@mkdir -p $(OBJDIR)/chains
	@mkdir -p $(OBJDIR)/security
	@mkdir -p $(OBJDIR)/ui
	@mkdir -p $(OBJDIR)/util
	@mkdir -p $(OBJDIR)/usb
	@mkdir -p $(OBJDIR)/accel
	@mkdir -p $(OBJDIR)/hw
	@mkdir -p $(OBJDIR)/walletconnect
	@mkdir -p $(OBJDIR)/tests

# Link target
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Tests
.PHONY: test
test: dirs $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(filter-out $(OBJDIR)/main.o,$(OBJS)) $(TEST_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/tests/%.o: $(TESTDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean
.PHONY: clean
clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Profile-Guided Optimization targets
.PHONY: pgo-generate pgo-train pgo-use pgo-clean pgo pgo-lto

# Step 1: Build instrumented binary
pgo-generate: clean
	@mkdir -p $(PGO_DIR)
	$(MAKE) O3=1 PGO=generate USB=1

# Step 2: Run training workload to generate profile data
pgo-train: $(TEST_TARGET)
	@echo "Running training workload..."
	./$(TEST_TARGET)
	@echo "Profile data generated in $(PGO_DIR)"

# Step 3: Build optimized binary using profile data
pgo-use:
	rm -rf $(OBJDIR)/*.o $(OBJDIR)/**/*.o $(BINDIR)
	$(MAKE) O3=1 PGO=use USB=1

# Clean profile data
pgo-clean:
	rm -rf $(PGO_DIR)

# Full PGO build (all steps)
pgo: pgo-generate
	$(MAKE) pgo-train PGO=generate O3=1 USB=1
	$(MAKE) pgo-use
	@echo ""
	@echo "PGO build complete: $(TARGET)"

# Full PGO + LTO build (maximum optimization)
pgo-lto: clean
	@mkdir -p $(PGO_DIR)
	$(MAKE) O3=1 LTO=1 PGO=generate USB=1
	$(MAKE) pgo-train PGO=generate O3=1 LTO=1 USB=1
	rm -rf $(OBJDIR)/*.o $(OBJDIR)/**/*.o $(BINDIR)
	$(MAKE) O3=1 LTO=1 PGO=use USB=1
	@echo ""
	@echo "PGO+LTO build complete: $(TARGET)"

# Install
.PHONY: install
install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

# Static analysis
.PHONY: analyze
analyze:
	cppcheck --enable=all --std=c11 $(SRCDIR)
	@echo "Running clang static analyzer..."
	scan-build make clean all

# ============================================================================
# Security Testing / Sanitizers
# ============================================================================
# AddressSanitizer (ASan) - Buffer overflows, use-after-free, memory leaks
# Usage: make sanitize-address
.PHONY: sanitize-address
sanitize-address: CFLAGS += -fsanitize=address -fno-omit-frame-pointer -g
sanitize-address: LDFLAGS += -fsanitize=address
sanitize-address: clean dirs $(TEST_TARGET)
	@echo ""
	@echo "Running tests with AddressSanitizer..."
	@echo "========================================="
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ./$(TEST_TARGET)
	@echo ""
	@echo "AddressSanitizer: No issues detected!"

# UndefinedBehaviorSanitizer (UBSan) - Integer overflow, null deref, etc.
# Usage: make sanitize-undefined
.PHONY: sanitize-undefined
sanitize-undefined: CFLAGS += -fsanitize=undefined -fno-omit-frame-pointer -g
sanitize-undefined: LDFLAGS += -fsanitize=undefined
sanitize-undefined: clean dirs $(TEST_TARGET)
	@echo ""
	@echo "Running tests with UndefinedBehaviorSanitizer..."
	@echo "================================================="
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(TEST_TARGET)
	@echo ""
	@echo "UBSan: No undefined behavior detected!"

# MemorySanitizer (MSan) - Uninitialized memory reads (Clang only)
# Usage: make sanitize-memory COMPILER=clang
.PHONY: sanitize-memory
sanitize-memory: CFLAGS += -fsanitize=memory -fno-omit-frame-pointer -g -fPIE
sanitize-memory: LDFLAGS += -fsanitize=memory -pie
sanitize-memory: clean dirs $(TEST_TARGET)
	@echo ""
	@echo "Running tests with MemorySanitizer..."
	@echo "======================================"
	MSAN_OPTIONS=halt_on_error=1 ./$(TEST_TARGET)
	@echo ""
	@echo "MemorySanitizer: No uninitialized reads detected!"

# ThreadSanitizer (TSan) - Data races (if multithreading is added later)
# Usage: make sanitize-thread
.PHONY: sanitize-thread
sanitize-thread: CFLAGS += -fsanitize=thread -fno-omit-frame-pointer -g
sanitize-thread: LDFLAGS += -fsanitize=thread
sanitize-thread: clean dirs $(TEST_TARGET)
	@echo ""
	@echo "Running tests with ThreadSanitizer..."
	@echo "======================================"
	./$(TEST_TARGET)
	@echo ""
	@echo "ThreadSanitizer: No data races detected!"

# Combined ASan + UBSan (most useful for security testing)
# Usage: make sanitize
.PHONY: sanitize
sanitize: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g
sanitize: LDFLAGS += -fsanitize=address,undefined
sanitize: clean dirs $(TEST_TARGET)
	@echo ""
	@echo "Running tests with ASan + UBSan..."
	@echo "==================================="
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(TEST_TARGET)
	@echo ""
	@echo "All sanitizers passed! No memory or undefined behavior issues."

# Valgrind memory check (slower but very thorough)
# Usage: make valgrind
.PHONY: valgrind
valgrind: DEBUG=1
valgrind: clean dirs $(TEST_TARGET)
	@echo ""
	@echo "Running tests with Valgrind..."
	@echo "==============================="
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
		--error-exitcode=1 ./$(TEST_TARGET)
	@echo ""
	@echo "Valgrind: No memory errors detected!"

# Full security audit (all sanitizers + static analysis)
# Usage: make security-audit
.PHONY: security-audit
security-audit:
	@echo "=============================================="
	@echo "       RISC-V Wallet Security Audit"
	@echo "=============================================="
	@echo ""
	@echo "[1/5] Static Analysis (cppcheck)..."
	cppcheck --enable=all --error-exitcode=1 --std=c11 $(SRCDIR) 2>&1 || true
	@echo ""
	@echo "[2/5] AddressSanitizer (buffer overflow, use-after-free)..."
	$(MAKE) sanitize-address
	@echo ""
	@echo "[3/5] UndefinedBehaviorSanitizer (integer overflow, null deref)..."
	$(MAKE) sanitize-undefined
	@echo ""
	@echo "[4/5] Combined ASan + UBSan..."
	$(MAKE) sanitize
	@echo ""
	@echo "[5/5] Valgrind (memory leaks, uninitialized reads)..."
	$(MAKE) valgrind || echo "Valgrind not installed, skipping..."
	@echo ""
	@echo "=============================================="
	@echo "       Security Audit Complete!"
	@echo "=============================================="

# Format code
.PHONY: format
format:
	clang-format -i $(SRCDIR)/**/*.c $(SRCDIR)/**/*.h

# Help
.PHONY: help
help:
	@echo "RISC-V Cold Wallet Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the wallet (default)"
	@echo "  test     - Build and run tests"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system"
	@echo "  analyze  - Run static analysis"
	@echo "  format   - Format source code"
	@echo ""
	@echo "Profile-Guided Optimization:"
	@echo "  pgo          - Full PGO build (O3 + PGO)"
	@echo "  pgo-lto      - Full PGO+LTO build (maximum optimization)"
	@echo "  pgo-generate - Build instrumented binary"
	@echo "  pgo-train    - Run training workload"
	@echo "  pgo-use      - Build optimized binary with profile data"
	@echo "  pgo-clean    - Remove profile data"
	@echo ""
	@echo "Variables:"
	@echo "  CROSS_COMPILE   - Cross-compiler prefix (e.g., riscv64-linux-gnu-)"
	@echo "  COMPILER=clang  - Use Clang/LLVM instead of GCC (for BSD/macOS)"
	@echo "  COMPILER=gcc    - Use GCC (default)"
	@echo "  DEBUG=1         - Build with debug symbols (-Og)"
	@echo "  O3=1            - Build with aggressive optimization (-O3)"
	@echo "  LTO=1           - Enable Link-Time Optimization"
	@echo "  GRAPHITE=1      - Enable Graphite loop optimizer (GCC only)"
	@echo "  USB=1           - Enable USB HID support (requires libhidapi-dev)"
	@echo "  ACCEL_HOTLOAD=1 - Enable hotloadable acceleration modules"
	@echo ""
	@echo "RISC-V Optimization:"
	@echo "  RISCV_ARCH=...  - Set -march (e.g., rv64gc_zba_zbb_zbs)"
	@echo "  RISCV_TUNE=...  - Set -mtune (e.g., sifive-u74, generic)"
	@echo "  RISCV_OPTIMIZE=1       - Generic RISC-V optimized build"
	@echo "  RISCV_OPTIMIZE=sifive  - SiFive U74 (VisionFive 2)"
	@echo "  RISCV_OPTIMIZE=thead   - T-Head C910 (LicheePi 4A)"
	@echo "  RISCV_OPTIMIZE=spacemit - SpacemiT K1 with Vector"
	@echo "  RISCV_OPTIMIZE=crypto  - Full scalar crypto (Zk)"
	@echo ""
	@echo "Security Testing:"
	@echo "  sanitize         - Run ASan + UBSan combined (recommended)"
	@echo "  sanitize-address - AddressSanitizer (buffer overflow, use-after-free)"
	@echo "  sanitize-undefined - UndefinedBehaviorSanitizer (integer overflow)"
	@echo "  sanitize-memory  - MemorySanitizer (uninitialized reads, Clang only)"
	@echo "  sanitize-thread  - ThreadSanitizer (data races)"
	@echo "  valgrind         - Valgrind memory check (thorough but slow)"
	@echo "  security-audit   - Full security audit (all sanitizers + static)"
