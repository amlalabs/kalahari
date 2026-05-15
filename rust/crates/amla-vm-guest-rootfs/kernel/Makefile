# SPDX-License-Identifier: GPL-2.0-only
# amla-guest-kernel: Minimal Guest Kernel for amla-vm MicroVMs
#
# Builds a minimal Linux kernel for direct boot by amla-kvm.
# The kernel includes virtio-mmio drivers, virtio-mem, and virtio-fs.
#
# Quick start:
#   make                       - Build for host architecture
#   make GUEST_ARCH=arm64      - Cross-build for ARM64
#   make clean                 - Remove build artifacts
#   make distclean             - Remove everything including downloaded source

# ==================== Architecture Detection ====================

# GUEST_ARCH: x86_64 | arm64 (default: host arch, translated to kernel ARCH values)
UNAME_M := $(shell uname -m)
ifneq (,$(filter aarch64 arm64,$(UNAME_M)))
  GUEST_ARCH ?= arm64
else
  GUEST_ARCH ?= x86_64
endif

# Map GUEST_ARCH to kernel ARCH value
ifeq ($(GUEST_ARCH),arm64)
  KERNEL_ARCH := arm64
else ifeq ($(GUEST_ARCH),aarch64)
  KERNEL_ARCH := arm64
else
  KERNEL_ARCH := x86
endif

# Cross-compile toolchain auto-detection (only when cross-building)
ifeq ($(KERNEL_ARCH),arm64)
  ifeq (,$(filter aarch64 arm64,$(UNAME_M)))
    CROSS_COMPILE ?= aarch64-linux-gnu-
  endif
endif
ifeq ($(KERNEL_ARCH),x86)
  ifneq (,$(filter aarch64 arm64,$(UNAME_M)))
    CROSS_COMPILE ?= x86_64-linux-gnu-
  endif
endif

# Output target: vmlinux (ELF) for x86, Image (flat binary) for arm64
ifeq ($(KERNEL_ARCH),arm64)
  KERNEL_IMAGE = $(KERNEL_BUILD_DIR)/arch/arm64/boot/Image
  KERNEL_TARGET := Image
else
  KERNEL_IMAGE = $(KERNEL_BUILD_DIR)/vmlinux
  KERNEL_TARGET := vmlinux
endif

# ==================== Paths ====================

GUEST_DIR := $(shell pwd)
BUILD_DIR := $(GUEST_DIR)/.build
KERNEL_SRC_DIR := $(BUILD_DIR)/linux
KERNEL_BUILD_DIR := $(BUILD_DIR)/linux-guest-build-$(KERNEL_ARCH)
PATCHES_DIR := $(GUEST_DIR)/patches

# ==================== Configuration ====================

KERNEL_VERSION := 7.0
KERNEL_TARBALL := linux-$(KERNEL_VERSION).tar.xz
KERNEL_MAJOR := $(firstword $(subst ., ,$(KERNEL_VERSION)))
KERNEL_URL := https://cdn.kernel.org/pub/linux/kernel/v$(KERNEL_MAJOR).x/$(KERNEL_TARBALL)
JOBS ?= $(or $(shell nproc 2>/dev/null),$(shell sysctl -n hw.ncpu 2>/dev/null),1)

# ==================== Build Artifacts ====================

# Keep VMLINUX for backwards compatibility (x86 builds still produce vmlinux)
VMLINUX := $(KERNEL_BUILD_DIR)/vmlinux

# Common make arguments for all kernel build invocations
KMAKE_ARGS := ARCH=$(KERNEL_ARCH) KBUILD_BUILD_USER=hi KBUILD_BUILD_HOST=amlalabs.com
ifneq ($(CROSS_COMPILE),)
  KMAKE_ARGS += CROSS_COMPILE=$(CROSS_COMPILE)
endif

.PHONY: all clean distclean help

all: $(KERNEL_IMAGE)

# ==================== Kernel Source ====================

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(KERNEL_TARBALL): | $(BUILD_DIR)
	@echo "[+] Downloading Linux $(KERNEL_VERSION) source..."
	wget -q --show-progress -O $@ "$(KERNEL_URL)"

$(KERNEL_SRC_DIR)/.extracted: $(BUILD_DIR)/$(KERNEL_TARBALL)
	@echo "[+] Extracting kernel source..."
	rm -rf $(KERNEL_SRC_DIR)
	tar -xf $< -C $(BUILD_DIR)
	mv $(BUILD_DIR)/linux-$(KERNEL_VERSION) $(KERNEL_SRC_DIR)
	touch $@

# ==================== Kernel Patches ====================

# The overlayfs ESTALE patch has two variants: one for kernels < 6.19 (uses
# dput(upper)) and one for >= 6.19 (uses end_creating(upper)).  Select the
# correct variant and skip the other.
OVL_ESTALE_SKIP := $(strip $(if $(shell printf '%s\n' "6.19" "$(KERNEL_VERSION)" | sort -V | head -n1 | grep -qx "6.19" && echo y),\
  0000-ovl-fix-ESTALE-for-FUSE-upper-by-using-linked-dentry.patch,\
  0000-ovl-fix-ESTALE-for-FUSE-upper-by-using-linked-dentry-mainline.patch))

# DAX pfn_to_page fix only needed on >= 6.15 (commit 38607c62b34b calls
# pfn_to_page on empty/zero DAX entries, crashing on altmap pmem).
SKIP_DAX_PFN_PATCH := $(strip $(if $(shell printf '%s\n' "6.15" "$(KERNEL_VERSION)" | sort -V | head -n1 | grep -qx "6.15" && echo y),,\
  0001-dax-check-for-empty-entries-before-pfn_to_page.patch))

$(KERNEL_SRC_DIR)/.patched: $(KERNEL_SRC_DIR)/.extracted $(wildcard $(PATCHES_DIR)/*.patch)
	@echo "[+] Applying patches (skipping $(OVL_ESTALE_SKIP) $(SKIP_DAX_PFN_PATCH) for kernel $(KERNEL_VERSION))..."
	@for patch in $(PATCHES_DIR)/*.patch; do \
		if [ -f "$$patch" ]; then \
			if [ "$$(basename $$patch)" = "$(OVL_ESTALE_SKIP)" ] || \
			   [ "$$(basename $$patch)" = "$(SKIP_DAX_PFN_PATCH)" ]; then \
				echo "    Skipping: $$(basename $$patch) (not needed for $(KERNEL_VERSION))"; \
				continue; \
			fi; \
			echo "    Applying: $$(basename $$patch)"; \
			if patch -d $(KERNEL_SRC_DIR) -p1 --forward --dry-run < "$$patch" >/dev/null 2>&1; then \
				patch -d $(KERNEL_SRC_DIR) -p1 --forward < "$$patch" || exit 1; \
			elif patch -d $(KERNEL_SRC_DIR) -p1 -R --dry-run < "$$patch" >/dev/null 2>&1; then \
				echo "      (already applied, skipping)"; \
			else \
				echo "      ERROR: patch does not apply cleanly"; exit 1; \
			fi; \
		fi; \
	done
	touch $@

# ==================== Kernel Config ====================
# Minimal microVM config: allnoconfig + 64-bit seed + virtio drivers.
# Split into shared options (all arches) + arch-specific blocks.

$(KERNEL_BUILD_DIR)/.config: $(KERNEL_SRC_DIR)/.patched $(GUEST_DIR)/Makefile
	@echo "[+] Configuring guest kernel ($(KERNEL_ARCH), minimal microVM config)..."
	mkdir -p $(KERNEL_BUILD_DIR)
	@# Start from allnoconfig with 64-bit seed (x86 allnoconfig defaults to 32-bit)
ifeq ($(KERNEL_ARCH),x86)
	echo "CONFIG_64BIT=y" > $(KERNEL_BUILD_DIR)/allno.config
else
	: > $(KERNEL_BUILD_DIR)/allno.config
endif
	$(MAKE) -C $(KERNEL_SRC_DIR) O=$(KERNEL_BUILD_DIR) $(KMAKE_ARGS) \
		KCONFIG_ALLCONFIG=$(KERNEL_BUILD_DIR)/allno.config allnoconfig
	@# ---- Shared options (all architectures) ----
	$(KERNEL_SRC_DIR)/scripts/config --file $@ \
		--enable SMP --enable HOTPLUG_CPU \
		--set-val NR_CPUS 64 \
		--enable PRINTK --enable PRINTK_TIME \
		--enable BLK_DEV \
		--enable BLOCK \
		--enable BINFMT_ELF --enable BINFMT_SCRIPT \
		--enable NO_HZ_IDLE \
		--enable VIRTIO --enable VIRTIO_MENU --enable VIRTIO_MMIO \
		--enable VIRTIO_MMIO_CMDLINE_DEVICES \
		--enable VIRTIO_BLK \
		--enable VIRTIO_CONSOLE --enable HW_RANDOM --enable HW_RANDOM_VIRTIO \
		--enable VIRTIO_BALLOON --enable PAGE_REPORTING \
		--enable COMPACTION --enable STRICT_DEVMEM \
		--enable VIRTIO_MEM \
		--enable MEMORY_HOTPLUG_DEFAULT_ONLINE \
		--enable PREEMPT_VOLUNTARY \
		--enable HIGH_RES_TIMERS \
		--enable FUSE_FS --enable VIRTIO_FS \
		--enable SPARSEMEM_VMEMMAP --enable MEMORY_HOTPLUG --enable MEMORY_HOTREMOVE \
		--enable MHP_MEMMAP_ON_MEMORY \
		--enable TRANSPARENT_HUGEPAGE \
		--enable ZONE_DEVICE --enable DAX --enable FS_DAX \
		--enable LIBNVDIMM --enable BLK_DEV_PMEM --enable VIRTIO_PMEM \
		--enable MISC_FILESYSTEMS --enable EROFS_FS \
		--enable MD --enable BLK_DEV_DM --enable DM_LINEAR \
		--enable OVERLAY_FS --enable OVERLAY_FS_REDIRECT_DIR \
		--enable TTY \
		--enable EXT4_FS \
		--enable TMPFS --enable TMPFS_XATTR --enable TMPFS_POSIX_ACL \
		--enable SHMEM --enable PROC_FS --enable SYSFS \
		--enable PROC_SYSCTL \
		--enable MEMFD_CREATE \
		--enable FUTEX \
		--enable EPOLL \
		--enable SIGNALFD \
		--enable TIMERFD \
		--enable DEVTMPFS --enable DEVTMPFS_MOUNT \
		--enable DEVPTS_FS \
		--enable NAMESPACES \
		--enable PID_NS --enable NET_NS --enable UTS_NS \
		--enable SYSVIPC --enable POSIX_MQUEUE \
		--enable IPC_NS --enable USER_NS \
		--enable CGROUPS \
		--enable CGROUP_SCHED --enable CGROUP_PIDS \
		--enable CGROUP_DEVICE --enable MEMCG \
		--enable CPUSETS --enable CGROUP_FREEZER \
		--enable SECCOMP --enable SECCOMP_FILTER \
		--enable BPF_SYSCALL --enable CGROUP_BPF \
		--enable VSOCKETS --enable VIRTIO_VSOCKETS \
		--enable KEYS \
		--enable UIO \
		--enable DEVMEM \
		--disable MODULES \
		--enable NET --enable UNIX --enable INET --enable NETDEVICES --enable VIRTIO_NET \
		--enable BRIDGE --enable VETH \
		--enable NETFILTER --enable NF_CONNTRACK \
		--enable NETFILTER_XTABLES \
		--enable IP_NF_IPTABLES --enable IP_NF_FILTER --enable IP_NF_NAT \
		--disable WIRELESS --disable WLAN \
		--disable SOUND \
		--disable USB_SUPPORT \
		--enable INPUT --enable INPUT_EVDEV \
		--enable VIRTIO_INPUT \
		--enable RTC_CLASS \
		--disable SECURITY \
		--disable AUDIT \
		--disable DEBUG_INFO
	@# ---- Architecture-specific options ----
ifeq ($(KERNEL_ARCH),x86)
	@echo "[+] Applying x86-specific config..."
	$(KERNEL_SRC_DIR)/scripts/config --file $@ \
		--enable HYPERVISOR_GUEST --enable KVM_GUEST --enable PARAVIRT \
			--enable SERIAL_8250 --enable SERIAL_8250_CONSOLE \
			--set-val SERIAL_8250_NR_UARTS 1 \
			--set-val SERIAL_8250_RUNTIME_UARTS 1 \
			--enable X86_IOPL_IOPERM \
			--disable RTC_HCTOSYS \
			--disable RTC_DRV_CMOS \
			--disable ACPI \
			--disable PCI
else ifeq ($(KERNEL_ARCH),arm64)
	@echo "[+] Applying arm64-specific config..."
	$(KERNEL_SRC_DIR)/scripts/config --file $@ \
		--enable ARM64 \
		--disable ARM64_VA_BITS_52 --enable ARM64_VA_BITS_48 \
		--enable ARCH_VIRT \
		--enable ARM_GIC_V3 \
		--enable ARM_ARCH_TIMER \
		--enable SERIAL_AMBA_PL011 --enable SERIAL_AMBA_PL011_CONSOLE \
		--enable ARM_PSCI_FW \
		--enable RTC_HCTOSYS \
		--enable RTC_DRV_PL031 \
		--disable STRICT_DEVMEM \
		--disable ACPI \
		--disable PCI
endif
	$(MAKE) -C $(KERNEL_SRC_DIR) O=$(KERNEL_BUILD_DIR) $(KMAKE_ARGS) olddefconfig

# ==================== Build ====================

$(KERNEL_IMAGE): $(KERNEL_BUILD_DIR)/.config
	@echo "[+] Building guest kernel ($(KERNEL_TARGET) for $(KERNEL_ARCH))..."
	$(MAKE) -C $(KERNEL_SRC_DIR) O=$(KERNEL_BUILD_DIR) $(KMAKE_ARGS) -j$(JOBS) $(KERNEL_TARGET)
	touch $@
	@echo "[+] Guest kernel ready: $@"

# ==================== Clean ====================

clean:
	rm -rf $(KERNEL_BUILD_DIR)

distclean:
	rm -rf $(BUILD_DIR)

# ==================== Help ====================

help:
	@echo "amla-guest-kernel: Minimal Guest Kernel for amla-vm MicroVMs"
	@echo ""
	@echo "Build:"
	@echo "  make                       Download source, configure, and build kernel"
	@echo "  make GUEST_ARCH=arm64      Cross-build for ARM64"
	@echo "  make clean                 Remove build artifacts (keeps downloaded source)"
	@echo "  make distclean             Remove everything including downloaded source"
	@echo ""
	@echo "Options:"
	@echo "  GUEST_ARCH=x86_64|arm64    Target architecture (default: host arch)"
	@echo "  CROSS_COMPILE=prefix       Cross-compiler prefix (auto-detected)"
	@echo "  JOBS=N                     Parallel build jobs (default: nproc)"
	@echo ""
	@echo "Current config:"
	@echo "  GUEST_ARCH    = $(GUEST_ARCH)"
	@echo "  KERNEL_ARCH   = $(KERNEL_ARCH)"
	@echo "  CROSS_COMPILE = $(CROSS_COMPILE)"
	@echo "  Output        = $(KERNEL_IMAGE)"
