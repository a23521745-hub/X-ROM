#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#

PRODUCT_MAKEFILES := \
    $(LOCAL_DIR)/xrom_x1.mk

# Android 15+ uses the trunk-stable release-config lunch syntax
# (<product>-<release_config>-<variant>); Android 13/14 use <product>-<variant>.
# Both forms are listed so a single X-ROM tree is lunchable on either. The form
# that does not apply to your release simply does not resolve.
COMMON_LUNCH_CHOICES := \
    xrom_x1-trunk_staging-userdebug \
    xrom_x1-trunk_staging-user \
    xrom_x1-trunk_staging-eng \
    xrom_x1-userdebug \
    xrom_x1-user \
    xrom_x1-eng
