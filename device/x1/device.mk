#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# device.mk — X-ROM reference device "x1": product packaging.
#

# Must come first: BoardConfig.mk is read by AOSP *after* product configuration,
# so the AVF switches cannot live there and be visible here. Both sides include
# the same file. See xrom_board_switches.mk for the full ordering explanation.
include vendor/xrom/device/x1/xrom_board_switches.mk

# Inherit the AOSP arm64 baseline so that PRODUCT_* variables set by X-ROM below
# take precedence.
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)

# GSI compatibility is enforced by the Treble switches in BoardConfig.mk
# (BOARD_VNDK_VERSION, PRODUCT_ENFORCE_VINTF_MANIFEST, VINTF manifest/matrix)
# and validated by `vts_treble_*` / `gsi_release` tests in CI — not by
# inheriting a generic system product, which would fight this device tree.

# No soong_namespace is declared for vendor/xrom, so PRODUCT_SOONG_NAMESPACES is
# deliberately not set: listing a namespace without a matching soong_namespace
# module is a hard build error. Every module here is xrom_-prefixed, which is
# what actually prevents collisions.

# ---------------------------------------------------------------------------
# Identity-independent product configuration
# ---------------------------------------------------------------------------
# Product identity (PRODUCT_NAME/DEVICE/BRAND/MODEL) lives in xrom_x1.mk so
# that a second X-ROM device can inherit this file unchanged.

# Android 14 baseline. AVF's Java API (VirtualMachineManager) is API level 34;
# below that only the AIDL surface exists.
PRODUCT_SHIPPING_API_LEVEL := 34

PRODUCT_CHARACTERISTICS := nosdcard

# ---------------------------------------------------------------------------
# Build images
# ---------------------------------------------------------------------------
PRODUCT_BUILD_INIT_BOOT_IMAGE := true
PRODUCT_BUILD_VENDOR_BOOT_IMAGE := true
PRODUCT_BUILD_SUPER_PARTITION := true
PRODUCT_USE_DYNAMIC_PARTITIONS := true

# ---------------------------------------------------------------------------
# AVF / pKVM / Microdroid
# ---------------------------------------------------------------------------
$(call inherit-product, vendor/xrom/device/x1/avf.mk)

# ---------------------------------------------------------------------------
# Self-healing recovery and hybrid OTA
# ---------------------------------------------------------------------------
$(call inherit-product, vendor/xrom/device/x1/recovery.mk)

# ---------------------------------------------------------------------------
# Host-side hardening
# ---------------------------------------------------------------------------
# Do not ship a debuggable userspace. A debuggable build relaxes several AVF
# checks (DebugLevel.FULL VMs, virtualizationservice_use for untrusted_app in
# userdebug_or_eng) and therefore cannot be used to evaluate X-ROM's security
# properties. Engineering units override this via eng/userdebug lunch targets.
PRODUCT_PROPERTY_OVERRIDES += \
    ro.debuggable=0

# Refuse to boot a privileged app that requests a signature|privileged
# permission with no matching entry in a privapp-permissions allowlist. The AVF
# permissions in device/x1/permissions/xrom_avf_privapp_permissions.xml are only
# meaningful under enforcement.
PRODUCT_PROPERTY_OVERRIDES += \
    ro.control_privapp_permissions=enforce

# tools/xrom_avf_verify.sh is a HOST script run over adb, so it is deliberately
# not in PRODUCT_PACKAGES: shipping it into the image would add an executable
# that nothing on the device is allowed to run under the sepolicy in
# sepolicy/system_ext_private/.
