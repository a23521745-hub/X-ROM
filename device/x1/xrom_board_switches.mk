#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# xrom_board_switches.mk — the X-ROM AVF/pKVM control surface.
#
# ---------------------------------------------------------------------------
# WHY THIS FILE EXISTS
# ---------------------------------------------------------------------------
# AOSP reads product configuration BEFORE it reads BoardConfig.mk:
# build/make/core/envsetup.mk includes product_config.mk (which pulls in
# xrom_x1.mk -> device.mk -> avf.mk) and only then includes BoardConfig.mk.
#
# So a variable assigned in BoardConfig.mk is invisible to device.mk and avf.mk.
# These switches are needed by both halves — the board half for cmdline,
# bootconfig, partitions and sepolicy directories; the product half for
# PRODUCT_PACKAGES, product properties and the Soong config that decides which
# AVF AIDL shape the daemon compiles against. Defining them here and including
# this file from both sides is the only arrangement that works without
# duplicating them and letting the two copies drift.
#
# Every assignment uses ?= so that an outer board file, a vendor add-on or a
# command-line override (XROM_ENABLE_PKVM=false m ...) wins.
#

ifndef XROM_BOARD_SWITCHES_INCLUDED
XROM_BOARD_SWITCHES_INCLUDED := true

# Enable the Android Virtualization Framework: the com.android.virt APEX
# (virtualizationservice, virtmgr, crosvm, Microdroid images, pvmfw, the vm CLI)
# and its dependencies.
XROM_ENABLE_AVF ?= true

# Enable pKVM, i.e. protected VMs. Requires an EL2-capable bootloader and a GKI
# kernel with CONFIG_KVM. Set false for x86_64 Cuttlefish bring-up, where AVF is
# available for testing but protected VMs are not.
XROM_ENABLE_PKVM ?= true

# Which AVF AIDL source shape the native daemon compiles against.
#
#   ANDROID_13      IVirtualizationService::createVm(config, consoleFd, osLogFd).
#                   VirtualMachineAppConfig is a flat parcelable whose payload
#                   config is a direct configPath field; DebugLevel has APP_ONLY;
#                   CPU count is numCpus.
#   ANDROID_14_PLUS createVm(config, consoleOutFd, consoleInFd, osLogFd).
#                   VirtualMachineAppConfig adds name, instanceId and osName,
#                   moves the payload config into a nested Payload union, and
#                   replaces numCpus with cpuTopology.
#
# Exported to Soong by avf.mk via soong_config_set and consumed by
# xrom_avfd_abi_defaults in vendor/xrom/Android.bp. There is exactly one
# `#if XROM_AVF_ABI` in the daemon, in AvfCompat.h.
#
# `tools/xrom_preflight.py --aosp-root` checks this against the actual
# VirtualMachineAppConfig.aidl in your tree, so a wrong value is caught before
# the build rather than as a wall of compile errors.
XROM_AVF_SOURCE_ABI ?= ANDROID_14_PLUS

# Does the board have a dedicated `pvmfw` partition? pvmfw is the first code
# executed inside a protected VM: it verifies the payload and derives the per-VM
# secret. Without it a pVM still boots, but it has no verified payload and no
# persistent identity — acceptable for bring-up, not for production.
XROM_TARGET_HAS_PVMFW ?= true

# Set true when the board's bootloader already writes androidboot.hypervisor.*
# into bootconfig, which is the normal arrangement on shipping pKVM hardware:
# the bootloader is the component that actually knows whether EL2 was entered.
# Emitting the same bootconfig key from both the build and the bootloader breaks
# boot, so exactly one side must produce them.
XROM_BOARD_SETS_HYPERVISOR_BOOTCONFIG ?= false

# Storage profile consumed by BoardConfig.mk. A real board overrides this with
# its own partition sizes.
XROM_DEVICE_STORAGE_PROFILE ?= generic

# Filesystem type for the read-only partitions.
XROM_SYSTEM_FS_TYPE ?= ext4

endif  # XROM_BOARD_SWITCHES_INCLUDED
