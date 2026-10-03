#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# recovery.mk — self-healing recovery and hybrid OTA product configuration.
#
# Kept separate from avf.mk because the two have different failure modes and different
# owners. avf.mk is about starting isolated VMs; this file is about what happens when
# the device should not have booted, when the update path is the only way forward, and
# when neither can be trusted. Merging them would make a change to one look like a
# change to the other in review.
#

# ===========================================================================
# 1. The recovery stack
# ===========================================================================
# xrom_sentineld: writes the BCB, locks the monitored directory, stages and preserves
# evidence, drops the network, reboots. Runs in the normal boot.
#
# xrom_ota_installer: the only domain in the policy that may write the vault image.
# Denied every network class, so compromising the writer does not also give an
# attacker a delivery channel.
#
# xrom_recovery_gate: runs inside the recovery image, where there is no /data and no
# daemon to ask. It is what executes the hybrid decision, and it links the same
# libxrom_recovery_core that xrom_sentineld links, so the decision made in recovery is
# byte-for-byte the decision the daemon would have previewed.
PRODUCT_PACKAGES += \
    xrom_sentineld \
    xrom_ota_installer \
    xrom_recovery_gate \
    xrom_recovery-cpp \
    init.xrom.sentinel.rc

# ===========================================================================
# 2. Recovery image contents
# ===========================================================================
# The gate has to be IN the recovery image, not merely installed to /system_ext: a
# recovery that has to reach into the system partition to find out what to do is a
# recovery that depends on the thing it is being asked to repair.
PRODUCT_PACKAGES += \
    xrom_recovery_gate_recovery

TARGET_RECOVERY_FSTAB := $(DEVICE_PATH)/recovery.fstab

# ===========================================================================
# 3. Runtime configuration
# ===========================================================================
# Installed to /system_ext/etc/xrom/sentinel.json. Same reasoning as avf.json: a typed
# file with a schema and bounds checking rather than a wall of system properties,
# because properties have no schema and every new one costs a SELinux rule.
PRODUCT_COPY_FILES += \
    vendor/xrom/services/recovery/xrom_sentineld/xrom_sentineld_config.json:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/xrom/sentinel.json

# OTA trust material: the pinned Ed25519 and RSA-4096 public keys that update.json and
# the package are verified against. A separate directory from the payload trust
# material, with its own SELinux type, because the two have different failure modes and
# different consumers — and because sepolicy denies xrom_ota_installer access to the
# payload anchors, so a compromise of the installer cannot reach them.
PRODUCT_COPY_FILES += \
    vendor/xrom/security/ota_trust/ota_trust_anchors.json:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/xrom/ota-trust/ota_trust_anchors.json

# ===========================================================================
# 4. Recovery-image properties
# ===========================================================================
# Read by the recovery gate. These are the compiled-in policy values that must NOT be
# loadable from anything fetched: a limit a server could raise is not a limit.
PRODUCT_SYSTEM_EXT_PROPERTIES += \
    ro.xrom.recovery.max_package_bytes=524288000 \
    ro.xrom.recovery.require_dual_signature=1 \
    ro.xrom.recovery.vault_device=/dev/block/by-name/xrom_vault \
    ro.xrom.recovery.vault_meta_device=/dev/block/by-name/xrom_vault_meta
