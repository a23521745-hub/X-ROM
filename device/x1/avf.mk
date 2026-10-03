#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# avf.mk — AVF / pKVM / Microdroid product configuration for X-ROM.
#
# Included from device.mk. Everything in here is PRODUCT_* (product config),
# i.e. "what goes into the image". Board-level flags (partitions, bootconfig,
# AVB) live in BoardConfig.mk.
#
# Upstream references:
#   packages/modules/Virtualization/apex/product_packages.mk          (Android 13/14)
#   packages/modules/Virtualization/build/apex/product_packages.mk    (Android 15+)
#   system/sepolicy/private/virtualizationservice.te
#   system/sepolicy/public/te_macros  -> virtualizationservice_use()
#

ifeq ($(XROM_ENABLE_AVF),true)

# ===========================================================================
# 1. Inherit the AOSP AVF product package set
# ===========================================================================
# AOSP moved this file between releases (the Virtualization module was
# reorganised into android/ build/ microdroid/ top-level directories). Probe
# both locations so one X-ROM tree builds against Android 13 through current.
XROM_AVF_PACKAGES_MK_CURRENT := \
    packages/modules/Virtualization/build/apex/product_packages.mk
XROM_AVF_PACKAGES_MK_LEGACY := \
    packages/modules/Virtualization/apex/product_packages.mk

ifneq (,$(wildcard $(XROM_AVF_PACKAGES_MK_CURRENT)))
XROM_AVF_PACKAGES_MK := $(XROM_AVF_PACKAGES_MK_CURRENT)
else ifneq (,$(wildcard $(XROM_AVF_PACKAGES_MK_LEGACY)))
XROM_AVF_PACKAGES_MK := $(XROM_AVF_PACKAGES_MK_LEGACY)
else
XROM_AVF_PACKAGES_MK :=
endif

ifeq ($(XROM_AVF_PACKAGES_MK),)
$(error X-ROM: AVF is enabled but no Virtualization product_packages.mk was \
    found. Expected one of '$(XROM_AVF_PACKAGES_MK_CURRENT)' or \
    '$(XROM_AVF_PACKAGES_MK_LEGACY)'. Is packages/modules/Virtualization \
    present in the manifest? Set XROM_ENABLE_AVF=false to build without AVF.)
endif

# Pulls in: com.android.virt (the Virtualization APEX: virtualizationservice,
# virtmgr, crosvm, Microdroid images, pvmfw, vm CLI), com.android.compos
# (isolated compilation service) plus the fs-verity / isolated-compilation
# product properties AVF depends on.
$(call inherit-product,$(XROM_AVF_PACKAGES_MK))

$(info X-ROM: AVF product packages inherited from $(XROM_AVF_PACKAGES_MK))

# ===========================================================================
# 2. Declare the AVF system feature
# ===========================================================================
# PackageManager.FEATURE_VIRTUALIZATION_FRAMEWORK
# ("android.software.virtualization_framework") is what apps and the AVF Java
# API (VirtualMachineManager) probe to decide whether AVF exists at all; VTS
# (MicrodroidTestApp) fails with "device doesn't support avf" without it.
#
# We ship our own copy rather than relying on AOSP's features_com.android.virt
# because that module's install partition changed between releases
# (/system/etc/permissions -> /vendor/etc/permissions) and X-ROM must not
# depend on which one a given tree uses.
#
# NOTE: protected-VM support is deliberately NOT a PackageManager feature. It
# is signalled by the bootloader/bootconfig key
# androidboot.hypervisor.protected_vm.supported=true, which init exposes as
# ro.boot.hypervisor.protected_vm.supported and which virtualizationservice
# turns into the pVM capability. See section 3 of BoardConfig.mk.
PRODUCT_PACKAGES += \
    xrom_avf_features.xml

# ===========================================================================
# 3. Permissions
# ===========================================================================
# AVF is gated by restricted platform permissions. Protection levels:
#
#   android.permission.MANAGE_VIRTUAL_MACHINE
#       signature|privileged. Required to create/start/stop any VM with an app
#       config. On Android 14 it was grantable only to privileged apps; from
#       Android 15 it is available to all preinstalled apps.
#   android.permission.USE_CUSTOM_VIRTUAL_MACHINE
#       signature|privileged. Required for VirtualMachineRawConfig, for a
#       custom kernel image, and for the `configPath` form of the Microdroid
#       payload config that X-ROM uses.
#   android.permission.MANAGE_VIRTUALIZATION_STATE
#       signature|privileged. Required to set the global virtualization state
#       (e.g. suspend all VMs on thermal pressure).
#
# The native daemon itself does not consume this allowlist: it runs as uid
# system (AID 1000), and PermissionManagerService grants every permission to
# uid 0 and uid 1000. The allowlist exists for the privileged X-ROM apps that
# will sit on top of xrom_avfd in later sessions.
PRODUCT_PACKAGES += \
    xrom_avf_privapp_permissions.xml

# ===========================================================================
# 4. The X-ROM AVF stack
# ===========================================================================
PRODUCT_PACKAGES += \
    xrom_avfd \
    xrom_isolation-cpp \
    init.xrom.avf.rc \
    xrom_gki_pkvm_fragment

# Microdroid payload that runs the isolated security tasks. Ships as an APK
# containing jni/arm64-v8a/libxvault_payload.so and assets/vm_config.json.
PRODUCT_PACKAGES += \
    XVaultPayload

# ===========================================================================
# 5. Runtime configuration
# ===========================================================================
# Installed to /system_ext/etc/xrom/avf.json and validated at daemon start.
# A typed file is used instead of a wall of system properties: properties have
# no schema, no bounds checking, and every new one costs a SELinux rule.
PRODUCT_COPY_FILES += \
    vendor/xrom/services/avf/xrom_avfd/xrom_avfd_config.json:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/xrom/avf.json

# Read-only status properties. Writable runtime state (xrom.avf.*) is set by
# xrom_avfd itself, which is the only domain with set_prop on xrom_avf_prop.
PRODUCT_SYSTEM_EXT_PROPERTIES += \
    ro.xrom.avf.enabled=1 \
    ro.xrom.avf.pkvm=$(XROM_ENABLE_PKVM) \
    ro.xrom.avf.abi=$(XROM_AVF_SOURCE_ABI)

# ===========================================================================
# 6. Hand the ABI choice to Soong
# ===========================================================================
# Consumed by the soong_config_module_type in vendor/xrom/Android.bp, which
# turns it into -DXROM_AVF_ABI=<13|14> for the daemon. This is the only place
# the C++ sources learn which AVF AIDL shape they are compiling against.
$(call soong_config_set,xrom,avf_abi,$(XROM_AVF_SOURCE_ABI))

# ===========================================================================
# 7. AVF release configuration (aconfig)
# ===========================================================================
# AVF behaviour is increasingly driven by aconfig release flags read from the
# build's release configuration, not from device makefiles (for example
# RELEASE_AVF_ENABLE_EARLY_VM, RELEASE_AVF_ENABLE_NETWORK,
# RELEASE_AVF_ENABLE_DEVICE_ASSIGNMENT). X-ROM deliberately does not set them
# from a device tree: overriding another team's release config is how builds stop
# being reproducible, and each of those flags carries its own threat model. Select
# the release config at lunch time instead — see docs/03, section B.2.

# ===========================================================================
# 8. Sanity checks
# ===========================================================================
ifneq ($(TARGET_ARCH),arm64)
ifneq ($(TARGET_ARCH),x86_64)
$(error X-ROM: AVF is supported only on arm64 (with pKVM) and x86_64 \
    (non-protected, testing only). TARGET_ARCH=$(TARGET_ARCH).)
endif
ifeq ($(XROM_ENABLE_PKVM),true)
$(error X-ROM: x86_64 does not provide protected VMs. Set XROM_ENABLE_PKVM=false.)
endif
endif

# com.android.virt is a 64-bit APEX containing 64-bit binaries only.
ifeq ($(filter true,$(XROM_ENABLE_AVF)),true)
ifneq ($(TARGET_SUPPORTS_64_BIT_APPS),true)
$(warning X-ROM: AVF requires a 64-bit product configuration. Verify \
    TARGET_SUPPORTS_64_BIT_APPS is set by the inherited AOSP product.)
endif
endif

endif # XROM_ENABLE_AVF
