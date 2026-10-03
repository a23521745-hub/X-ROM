#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# Product makefile for the X-ROM reference device. This is what `lunch`
# resolves: it binds the product identity to the shared device configuration.
#
# lunch targets (see AndroidProducts.mk):
#   xrom_x1-userdebug / xrom_x1-user / xrom_x1-eng            Android 13/14
#   xrom_x1-trunk_staging-userdebug ...                       Android 15+
#

$(call inherit-product, vendor/xrom/device/x1/device.mk)

# Board-vendor additions that must not be published (proprietary HALs, blobs).
$(call inherit-product-if-exists, vendor/xrom/device/x1/device-vendor.mk)

PRODUCT_NAME := xrom_x1
PRODUCT_DEVICE := x1
PRODUCT_BRAND := X-ROM
PRODUCT_MODEL := X-ROM X1
PRODUCT_MANUFACTURER := X-ROM Project
