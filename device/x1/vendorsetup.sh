#!/bin/bash
#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the AOSP build environment after `source build/envsetup.sh`.
# Kept deliberately small: everything that can be checked mechanically lives in
# tools/xrom_preflight.py so it runs in CI without a build shell.

# Static AVF/pKVM checks against the source tree. Run before a multi-hour build.
function xrom_preflight() {
    local repo_root="${ANDROID_BUILD_TOP:-$(pwd)}"
    python3 "${repo_root}/vendor/xrom/tools/xrom_preflight.py" \
        --aosp-root "${repo_root}" "$@"
}

# On-device AVF verification over adb. Run after flashing.
function xrom_verify_device() {
    bash "${ANDROID_BUILD_TOP:-$(pwd)}/vendor/xrom/tools/xrom_avf_verify.sh" "$@"
}

cat <<'XROM_BANNER'
  X-ROM  ·  hardened AOSP  ·  AVF/pKVM foundation
  xrom_preflight        static checks on the source tree (run before building)
  xrom_verify_device    on-device AVF/pKVM verification over adb (after flashing)
XROM_BANNER
