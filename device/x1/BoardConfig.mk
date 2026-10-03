#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# BoardConfig.mk — X-ROM reference board "x1"
#
# Scope of this file (Session 1):
#   * GKI (Generic Kernel Image) + Project Treble / GSI compliance
#   * pKVM (protected KVM) + AVF (Android Virtualization Framework) enablement
#   * pvmfw partition (root of trust for protected VMs)
#   * SELinux policy directory wiring
#
# Product-level packaging (PRODUCT_*) lives in device.mk / avf.mk. Board-level
# (BOARD_*, TARGET_*) lives here. Do not mix the two layers.
#

DEVICE_PATH := vendor/xrom/device/x1
XROM_SEPOLICY_PATH := vendor/xrom/sepolicy

# ===========================================================================
# 0. X-ROM master switches
# ===========================================================================
# Defined in xrom_board_switches.mk, not here. AOSP reads product configuration
# before BoardConfig.mk, so anything assigned in this file is invisible to
# device.mk and avf.mk — and the AVF switches are needed by both halves. Both
# files include the same switches file, so there is one copy and it cannot drift.
include vendor/xrom/device/x1/xrom_board_switches.mk

# ===========================================================================
# 1. Architecture — X-ROM is 64-bit only
# ===========================================================================
# Deliberate hardening decision: no 32-bit ABI. This removes the entire
# 32-bit kernel/userspace attack surface and halves the KMI we must audit.
TARGET_ARCH := arm64
TARGET_ARCH_VARIANT := armv8-2a
TARGET_CPU_ABI := arm64-v8a
TARGET_CPU_ABI2 :=
TARGET_CPU_VARIANT := generic
TARGET_CPU_VARIANT_RUNTIME := true

# No secondary architecture on purpose.
TARGET_2ND_ARCH :=
TARGET_2ND_ARCH_VARIANT :=
TARGET_2ND_CPU_ABI :=
TARGET_2ND_CPU_ABI2 :=
TARGET_2ND_CPU_VARIANT :=

# ===========================================================================
# 2. GKI — Generic Kernel Image
# ===========================================================================
BOARD_USES_GENERIC_KERNEL_IMAGE := true
BOARD_KERNEL_IMAGE_NAME := Image
TARGET_NO_KERNEL := false

# Boot header v4: kernel cmdline moved out of the header, `androidboot.*`
# parameters moved to bootconfig. Base/offset fields were removed in v4, so we
# deliberately do not set BOARD_KERNEL_BASE / BOARD_KERNEL_OFFSET here.
BOARD_BOOT_HEADER_VERSION := 4
BOARD_MKBOOTIMG_ARGS += --header_version $(BOARD_BOOT_HEADER_VERSION)

BOARD_INCLUDE_DTB_IN_BOOTIMG := true
BOARD_KERNEL_SEPARATED_DTBO := true
BOARD_RAMDISK_USE_LZ4 := true

# Kernel command line (true kernel parameters only).
# kvm-arm.mode=protected is what turns KVM into pKVM: the host kernel is booted
# at EL2, installs a stage-2 identity map, and deprivileges itself to EL1.
# See Documentation/virt/kvm/arm/pkvm.rst in the ACK tree.
ifeq ($(XROM_ENABLE_PKVM),true)
ifeq ($(TARGET_ARCH),arm64)
BOARD_KERNEL_CMDLINE += kvm-arm.mode=protected
endif
endif

# GKI kernel config delta required by X-ROM. See device/x1/kernel/README.md for
# the two supported wiring paths (ACK source build vs. prebuilt GKI + CI check).
XROM_KERNEL_CONFIG_FRAGMENT := $(DEVICE_PATH)/kernel/gki_xrom_pkvm.fragment

# ===========================================================================
# 3. Bootconfig — how AVF learns the device can run VMs
# ===========================================================================
# `virtualizationservice` reads these through the ro.boot.hypervisor.* /
# ro.boot.pkvm.* properties that init derives from /proc/bootconfig. They are
# labelled hypervisor_prop / hypervisor_restricted_prop in AOSP sepolicy.
#
# NOTE: on production hardware these keys are the bootloader's job (it is the
# component that actually knows whether EL2 was entered). Only emit them from
# the build when the bootloader does not.
ifeq ($(XROM_ENABLE_AVF),true)
ifneq ($(XROM_BOARD_SETS_HYPERVISOR_BOOTCONFIG),true)
BOARD_BOOTCONFIG += androidboot.hypervisor.vm.supported=true
ifeq ($(XROM_ENABLE_PKVM),true)
BOARD_BOOTCONFIG += androidboot.hypervisor.protected_vm.supported=true
BOARD_BOOTCONFIG += androidboot.pkvm.enabled=1
endif
endif
endif

# ===========================================================================
# 4. pvmfw — protected VM firmware (root of trust for pVMs)
# ===========================================================================
# pvmfw is the first code executed inside a protected VM. It verifies the
# payload, derives the per-VM secret and hands control to the guest kernel.
# It lives in its own AVB-chained partition and cannot be produced by the host.
ifeq ($(XROM_TARGET_HAS_PVMFW),true)
BOARD_PVMFWIMAGE_PARTITION_SIZE := 0x00100000
BOARD_AVB_ENABLE := true

# DEVELOPMENT KEYS. Replace with per-device keys held in the X-ROM signing HSM
# before any image leaves the build lab. tracked in docs/03-integration.md.
BOARD_AVB_PVMFW_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_PVMFW_ALGORITHM := SHA256_RSA4096
BOARD_AVB_PVMFW_ROLLBACK_INDEX_LOCATION := 6
endif

# ===========================================================================
# 5. Partitions / dynamic partitions
# ===========================================================================
# XROM_DEVICE_STORAGE_PROFILE and XROM_SYSTEM_FS_TYPE come from the switches
# file above; a real board overrides them there or before including it.

ifeq ($(XROM_DEVICE_STORAGE_PROFILE),generic)
BOARD_BOOTIMAGE_PARTITION_SIZE := 0x06000000
BOARD_INIT_BOOT_IMAGE_PARTITION_SIZE := 0x00800000
BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE := 0x04000000
BOARD_DTBOIMG_PARTITION_SIZE := 0x00100000
BOARD_SUPER_PARTITION_SIZE := 9663676416
BOARD_SUPER_PARTITION_GROUPS := xrom_dynamic_partitions
BOARD_XROM_DYNAMIC_PARTITIONS_SIZE := 9659482112
BOARD_XROM_DYNAMIC_PARTITIONS_PARTITION_LIST := \
    system \
    system_ext \
    product \
    vendor \
    vendor_dlkm \
    odm
endif

BOARD_BUILD_SUPER_IMAGE_BY_DEFAULT := true
BOARD_USES_METADATA_PARTITION := true
BOARD_USES_VENDOR_DLKMIMAGE := true

BOARD_SYSTEMIMAGE_FILE_SYSTEM_TYPE := $(XROM_SYSTEM_FS_TYPE)
BOARD_SYSTEM_EXTIMAGE_FILE_SYSTEM_TYPE := $(XROM_SYSTEM_FS_TYPE)
BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE := $(XROM_SYSTEM_FS_TYPE)
BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE := $(XROM_SYSTEM_FS_TYPE)
BOARD_ODMIMAGE_FILE_SYSTEM_TYPE := $(XROM_SYSTEM_FS_TYPE)
BOARD_VENDOR_DLKMIMAGE_FILE_SYSTEM_TYPE := $(XROM_SYSTEM_FS_TYPE)

# ===========================================================================
# 6. Verified Boot
# ===========================================================================
# A security OS must not ship with AVB verification disabled (--flags 3).
# Keep flags at 0; use `fastboot --disable-verity --disable-verification`
# only on unlocked engineering units.
BOARD_AVB_ENABLE := true
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 0
BOARD_AVB_ALGORITHM := SHA256_RSA4096
BOARD_AVB_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem

BOARD_AVB_SYSTEM_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_SYSTEM_ALGORITHM := SHA256_RSA4096
BOARD_AVB_SYSTEM_ROLLBACK_INDEX := $(PLATFORM_SECURITY_PATCH_TIMESTAMP)
BOARD_AVB_SYSTEM_ROLLBACK_INDEX_LOCATION := 1

BOARD_AVB_SYSTEM_EXT_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_SYSTEM_EXT_ALGORITHM := SHA256_RSA4096
BOARD_AVB_SYSTEM_EXT_ROLLBACK_INDEX := $(PLATFORM_SECURITY_PATCH_TIMESTAMP)
BOARD_AVB_SYSTEM_EXT_ROLLBACK_INDEX_LOCATION := 2

BOARD_AVB_VENDOR_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_VENDOR_ALGORITHM := SHA256_RSA4096
BOARD_AVB_VENDOR_ROLLBACK_INDEX := $(PLATFORM_SECURITY_PATCH_TIMESTAMP)
BOARD_AVB_VENDOR_ROLLBACK_INDEX_LOCATION := 3

# ===========================================================================
# 7. Project Treble / GSI compliance
# ===========================================================================
BOARD_VNDK_VERSION := current
PRODUCT_FULL_TREBLE_OVERRIDE := true
BOARD_USES_SYSTEM_EXTIMAGE := true
BOARD_USES_PRODUCTIMAGE := true
BOARD_USES_ODMIMAGE := true

DEVICE_MANIFEST_FILE := $(DEVICE_PATH)/vintf/manifest.xml
DEVICE_MATRIX_FILE := $(DEVICE_PATH)/vintf/compatibility_matrix.xml

# Enforce VINTF at build time. A GSI must boot on this vendor image, so any
# vendor HAL that is not declared here is a build error, not a warning.
PRODUCT_ENFORCE_VINTF_MANIFEST := true

# ===========================================================================
# 8. SELinux
# ===========================================================================
# Treble layering, applied to the AVF daemon:
#   system_ext_public  -> the exported API: domain type, exec type, service
#                         type, and the xrom_avfd_client() macro. Visible to
#                         product/vendor policy and frozen with the platform API.
#   system_ext_private -> the implementation: allow rules, neverallow rules,
#                         file/service/property contexts. Invisible to vendor.
#   microdroid         -> guest-side policy baked into the Microdroid image.
SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += $(XROM_SEPOLICY_PATH)/system_ext_public
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += $(XROM_SEPOLICY_PATH)/system_ext_private

# Vendor policy is intentionally empty in Session 1: /dev/kvm, the AVF device
# tree node and the hypervisor properties are already labelled by AOSP
# (kvm_device, sysfs_dt_avf, hypervisor_prop). Adding a BOARD_SEPOLICY_DIRS
# entry with no rules would only widen the vendor attack surface.
# Uncomment when a vendor HAL needs AVF access:
# BOARD_SEPOLICY_DIRS += $(XROM_SEPOLICY_PATH)/vendor

# ===========================================================================
# 9. Build sanity checks — fail loudly, never silently
# ===========================================================================
ifeq ($(XROM_ENABLE_PKVM),true)
ifneq ($(TARGET_ARCH),arm64)
$(error X-ROM: XROM_ENABLE_PKVM=true requires TARGET_ARCH=arm64. \
    pKVM is an ARMv8-A EL2 hypervisor; x86_64 targets support AVF for \
    testing only, without protected VMs. Set XROM_ENABLE_PKVM=false.)
endif
ifeq ($(XROM_TARGET_HAS_PVMFW),false)
$(warning X-ROM: pKVM enabled without a pvmfw partition. Protected VMs will \
    boot but will have no verified payload and no persistent VM secret. \
    Acceptable for bring-up only.)
endif
endif

ifeq ($(XROM_ENABLE_AVF),true)
ifneq ($(filter $(XROM_AVF_SOURCE_ABI),ANDROID_13 ANDROID_14_PLUS),)
else
$(error X-ROM: XROM_AVF_SOURCE_ABI='$(XROM_AVF_SOURCE_ABI)' is not recognised. \
    Use ANDROID_13 or ANDROID_14_PLUS.)
endif
endif
