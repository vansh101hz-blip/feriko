# Makefile for rtw88-macos
#
# Prerequisites:
#   Xcode Command Line Tools
#   macOS SDK (comes with Xcode)
#   IOKit headers (in SDK)
#
# Usage:
#   make              — build kext binary + rtw88ctl
#   make kext         — build kext only
#   make ctl          — build rtw88ctl only
#   make install      — copy kext to /Library/Extensions and run kextutil
#   make load         — kextload (unsigned, requires SIP disabled or AppleKextExcludeList override)
#   make unload       — kextunload
#   make clean        — remove build artifacts

# ------------------------------------------------------------------ #
# Paths                                                               #
# ------------------------------------------------------------------ #

PROJ_ROOT   := $(shell pwd)
LINUX_SRC   := $(PROJ_ROOT)/../rtw88-stable/drivers/net/wireless/realtek/rtw88
COMPAT_DIR  := $(PROJ_ROOT)/src/compat
KEXT_SRC    := $(PROJ_ROOT)/src/kext
BUILD_DIR   := $(PROJ_ROOT)/build
CTL_DIR     := $(PROJ_ROOT)/ctl

KEXT_BUNDLE := $(PROJ_ROOT)/rtw88.kext
KEXT_BIN    := $(KEXT_BUNDLE)/Contents/MacOS/rtw88

# ------------------------------------------------------------------ #
# Toolchain                                                           #
# ------------------------------------------------------------------ #

SDK         := $(shell xcrun --show-sdk-path)
MKSDK       := $(PROJ_ROOT)/MacKernelSDK
ARCH        := -arch x86_64
MINOS       := -mmacosx-version-min=11.0

CC          := xcrun clang
CXX         := xcrun clang++
LD          := xcrun clang++

KEXT_FLAGS  := -fno-exceptions -fno-rtti \
               -fno-stack-protector -mkernel \
               $(ARCH) $(MINOS) \
               -isysroot $(SDK) \
               -I$(MKSDK)/Headers \
               -I$(SDK)/System/Library/Frameworks/Kernel.framework/Headers

# Compat include path overrides ALL linux/ and net/ headers
# so the Linux driver C files find our shims instead.
COMPAT_FLAGS := \
    -I$(COMPAT_DIR) \
    -I$(COMPAT_DIR)/linux \
    -I$(PROJ_ROOT)/src/kext

# C flags for Linux driver files
DRIVER_CFLAGS := \
    $(KEXT_FLAGS) \
    $(COMPAT_FLAGS) \
    -include $(COMPAT_DIR)/rtw88_compat.h \
    -I$(LINUX_SRC) \
    -DRTW88_MACOS=1 \
    -D__KERNEL__ \
    -DCONFIG_RTW88_8822BE=1 \
    -DCONFIG_RTW88_8822CE=1 \
    -DCONFIG_RTW88_8821CE=1 \
    -DCONFIG_RTW88_8812AE=1 \
    -DCONFIG_RTW88_8814AE=1 \
    -DCONFIG_RTW88_8821AU=1 \
    -DCONFIG_RTW88_8822BU=1 \
    -DCONFIG_RTW88_8822CU=1 \
    -DCONFIG_RTW88_8812AU=1 \
    -DCONFIG_RTW88_DEBUG=1 \
    -DCONFIG_RTW88_DEBUGFS=0 \
    -Wno-implicit-function-declaration \
    -Wno-int-conversion \
    -Wno-incompatible-pointer-types \
    -Wno-unused-variable \
    -Wno-unused-function

# C++ flags for kext wrapper files (-fapple-kext only for C++)
KEXT_CXXFLAGS := \
    $(KEXT_FLAGS) \
    -fapple-kext \
    $(COMPAT_FLAGS) \
    -std=c++17 \
    -DKERNEL \
    -Wno-deprecated-declarations \
    -Wno-nullability-completeness

# ------------------------------------------------------------------ #
# Source files                                                         #
# ------------------------------------------------------------------ #

# Linux driver core C files (compiled with compat headers)
DRIVER_SRCS := \
    $(LINUX_SRC)/main.c \
    $(LINUX_SRC)/mac.c \
    $(LINUX_SRC)/phy.c \
    $(LINUX_SRC)/fw.c \
    $(LINUX_SRC)/tx.c \
    $(LINUX_SRC)/rx.c \
    $(LINUX_SRC)/sec.c \
    $(LINUX_SRC)/efuse.c \
    $(LINUX_SRC)/coex.c \
    $(LINUX_SRC)/ps.c \
    $(LINUX_SRC)/regd.c \
    $(LINUX_SRC)/bf.c \
    $(LINUX_SRC)/sar.c \
    $(LINUX_SRC)/util.c \
    $(LINUX_SRC)/pci.c \
    $(LINUX_SRC)/usb.c \
    $(LINUX_SRC)/sdio.c \
    $(LINUX_SRC)/mac80211.c

# Chip-specific C files
CHIP_SRCS := \
    $(LINUX_SRC)/rtw8822b.c \
    $(LINUX_SRC)/rtw8822b_table.c \
    $(LINUX_SRC)/rtw8822be.c \
    $(LINUX_SRC)/rtw8822bu.c \
    $(LINUX_SRC)/rtw8822c.c \
    $(LINUX_SRC)/rtw8822c_table.c \
    $(LINUX_SRC)/rtw8822ce.c \
    $(LINUX_SRC)/rtw8822cu.c \
    $(LINUX_SRC)/rtw8821c.c \
    $(LINUX_SRC)/rtw8821c_table.c \
    $(LINUX_SRC)/rtw8821ce.c \
    $(LINUX_SRC)/rtw8821cu.c \
    $(LINUX_SRC)/rtw8812a.c \
    $(LINUX_SRC)/rtw8812a_table.c \
    $(LINUX_SRC)/rtw8812au.c \
    $(LINUX_SRC)/rtw8814a.c \
    $(LINUX_SRC)/rtw8814a_table.c \
    $(LINUX_SRC)/rtw8814ae.c \
    $(LINUX_SRC)/rtw8814au.c \
    $(LINUX_SRC)/rtw8821a.c \
    $(LINUX_SRC)/rtw8821a_table.c \
    $(LINUX_SRC)/rtw8821au.c \
    $(LINUX_SRC)/rtw88xxa.c

# Compat C implementation
COMPAT_SRCS := \
    $(COMPAT_DIR)/rtw88_compat.c

# IOKit C++ wrapper
KEXT_SRCS := \
    $(KEXT_SRC)/RTW88Kext.cpp \
    $(KEXT_SRC)/RTW88PCIDevice.cpp \
    $(KEXT_SRC)/RTW88IEEE80211.cpp \
    $(KEXT_SRC)/RTW88UserClient.cpp \
    $(KEXT_SRC)/RTW88USBDevice.cpp

# ------------------------------------------------------------------ #
# Object files                                                         #
# ------------------------------------------------------------------ #

DRIVER_OBJS := $(patsubst $(LINUX_SRC)/%.c, $(BUILD_DIR)/driver/%.o, $(DRIVER_SRCS))
CHIP_OBJS   := $(patsubst $(LINUX_SRC)/%.c, $(BUILD_DIR)/driver/%.o, $(CHIP_SRCS))
COMPAT_OBJS := $(patsubst $(COMPAT_DIR)/%.c, $(BUILD_DIR)/compat/%.o, $(COMPAT_SRCS))
KEXT_OBJS   := $(patsubst $(KEXT_SRC)/%.cpp, $(BUILD_DIR)/kext/%.o, $(KEXT_SRCS))

ALL_OBJS    := $(DRIVER_OBJS) $(CHIP_OBJS) $(COMPAT_OBJS) $(KEXT_OBJS)

# ------------------------------------------------------------------ #
# Linker flags                                                         #
# ------------------------------------------------------------------ #

KEXT_LDFLAGS := \
    $(ARCH) \
    -static \
    -nostdlib \
    -Xlinker -kext \
    $(MKSDK)/Library/x86_64/libkmod.a \
    $(MKSDK)/Library/universal/libkmodc++.a \
    -F$(SDK)/System/Library/Frameworks

# ------------------------------------------------------------------ #
# Targets                                                             #
# ------------------------------------------------------------------ #

.PHONY: all kext ctl install load unload clean

all: kext ctl

kext: $(KEXT_BIN)

$(KEXT_BIN): $(ALL_OBJS) | $(KEXT_BUNDLE)/Contents/MacOS
	@echo "  LD  $@"
	$(LD) $(KEXT_LDFLAGS) -o $@ $(ALL_OBJS)
	@echo "  Kext binary built: $@"

# Compile Linux driver C files with compat flags
$(BUILD_DIR)/driver/%.o: $(LINUX_SRC)/%.c | $(BUILD_DIR)/driver
	@echo "  CC  $(notdir $<)"
	$(CC) $(DRIVER_CFLAGS) -c $< -o $@

# Compile compat C files
$(BUILD_DIR)/compat/%.o: $(COMPAT_DIR)/%.c | $(BUILD_DIR)/compat
	@echo "  CC  $(notdir $<)"
	$(CC) $(DRIVER_CFLAGS) -c $< -o $@

# Compile kext C++ files
$(BUILD_DIR)/kext/%.o: $(KEXT_SRC)/%.cpp | $(BUILD_DIR)/kext
	@echo "  CXX $(notdir $<)"
	$(CXX) $(KEXT_CXXFLAGS) -c $< -o $@

# ctl binary
ctl: $(BUILD_DIR)/rtw88ctl

$(BUILD_DIR)/rtw88ctl: $(CTL_DIR)/main.c | $(BUILD_DIR)
	@echo "  CC  rtw88ctl"
	$(CC) $(ARCH) $(MINOS) \
	    -isysroot $(SDK) \
	    -framework IOKit \
	    -framework CoreFoundation \
	    -o $@ $<
	@echo "  rtw88ctl built: $@"

# ------------------------------------------------------------------ #
# Directory creation                                                  #
# ------------------------------------------------------------------ #

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/driver:
	mkdir -p $@

$(BUILD_DIR)/compat:
	mkdir -p $@

$(BUILD_DIR)/kext:
	mkdir -p $@

$(KEXT_BUNDLE)/Contents/MacOS:
	mkdir -p $@

# ------------------------------------------------------------------ #
# Install / load                                                      #
# ------------------------------------------------------------------ #

install: kext ctl
	@echo "Installing rtw88.kext to /Library/Extensions..."
	sudo cp -R $(KEXT_BUNDLE) /Library/Extensions/
	sudo chown -R root:wheel /Library/Extensions/rtw88.kext
	sudo chmod -R 755 /Library/Extensions/rtw88.kext
	@echo "Installing rtw88ctl to /usr/local/bin..."
	sudo install -m 755 $(BUILD_DIR)/rtw88ctl /usr/local/bin/rtw88ctl
	@echo "Done. Run 'make load' or reboot to activate."

load:
	@echo "Loading rtw88.kext (requires SIP kext loading enabled)..."
	sudo kextutil -v /Library/Extensions/rtw88.kext

unload:
	@echo "Unloading rtw88.kext..."
	sudo kextunload -b com.rtw88.driver

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(KEXT_BIN)

# ------------------------------------------------------------------ #
# OpenCore injection helper                                           #
# ------------------------------------------------------------------ #
# To use with OpenCore:
#   1. Copy rtw88.kext to OC/Kexts/
#   2. Add to config.plist -> Kernel -> Add:
#      Arch: Any
#      BundlePath: rtw88.kext
#      Comment: Realtek rtw88 WiFi
#      Enabled: YES
#      ExecutablePath: Contents/MacOS/rtw88
#      MaxKernel: (empty)
#      MinKernel: 20.0.0   (macOS 11+)
#      PlistPath: Contents/Info.plist
#   3. Rebuild OC cache: sudo kextcache -i /
#
# BaseSystem / Recovery notes:
#   The kext loads via OpenCore injection before the OS, so it works
#   in BaseSystem automatically.  rtw88ctl is a standalone binary;
#   copy it to the USB installer's /usr/local/bin or run from a path.
