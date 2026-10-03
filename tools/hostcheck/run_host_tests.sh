#!/usr/bin/env bash
#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# Runs the pure, dependency-free half of X-ROM against a system C++ compiler. No
# AOSP tree, no device, no Soong: this is what CI runs on a pull request, and what
# a contributor runs before waiting hours for `m`.
#
# Two suites, and both are the same .cpp files that the in-tree cc_test modules
# compile:
#
#   xrom_avf_core_test       VmSpec, IsolationPolicy, PayloadManifest — what
#                            decides whether a VM may be created, with what
#                            parameters, and for which payload.
#   xrom_shared_core_test    SHA-256, the wire codec and the framed vsock
#                            transport, driven over an AF_UNIX socketpair.
#
# What cannot be built here is the daemon itself: it needs libbinder, libbase,
# libcrypto and the generated AVF AIDL headers. Everything those depend on for a
# decision can be, and that is the split this script enforces.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}/.hostcheck}"

CXX="${CXX:-g++}"
CXXSTD="${CXXSTD:-c++17}"

mkdir -p "${OUT_DIR}"

echo "X-ROM host bootstrap check"
echo "  compiler : $(${CXX} --version | head -1)"
echo "  standard : ${CXXSTD}"
echo "  output   : ${OUT_DIR}"
echo

WARNINGS=(
    -Wall -Wextra -Werror
    -Wno-unused-parameter
)

echo "--- building xrom_avf_core_test ---"
${CXX} -std=${CXXSTD} -g -O0 \
    "${WARNINGS[@]}" \
    -I"${HERE}" \
    -I"${REPO_ROOT}/common/crypto" \
    -I"${REPO_ROOT}/services/avf/xrom_avfd" \
    -o "${OUT_DIR}/xrom_avf_core_test" \
    "${HERE}/hostcheck_main.cpp" \
    "${REPO_ROOT}/common/crypto/Sha256.cpp" \
    "${REPO_ROOT}/services/avf/xrom_avfd/VmSpec.cpp" \
    "${REPO_ROOT}/services/avf/xrom_avfd/IsolationPolicy.cpp" \
    "${REPO_ROOT}/services/avf/xrom_avfd/PayloadManifest.cpp" \
    "${REPO_ROOT}/services/avf/xrom_avfd/tests/VmSpec_test.cpp" \
    "${REPO_ROOT}/services/avf/xrom_avfd/tests/IsolationPolicy_test.cpp" \
    "${REPO_ROOT}/services/avf/xrom_avfd/tests/PayloadManifest_test.cpp"

echo "--- running xrom_avf_core_test ---"
"${OUT_DIR}/xrom_avf_core_test"

echo
echo "--- building xrom_shared_core_test ---"
# -pthread: VsockChannel_test trickles a frame one byte at a time from a second
# thread, which is the only way to exercise the partial-read path for real.
${CXX} -std=${CXXSTD} -g -O0 -pthread \
    "${WARNINGS[@]}" \
    -I"${HERE}" \
    -I"${REPO_ROOT}/common/crypto" \
    -I"${REPO_ROOT}/common/protocol" \
    -I"${REPO_ROOT}/common/vsock" \
    -o "${OUT_DIR}/xrom_shared_core_test" \
    "${HERE}/hostcheck_main.cpp" \
    "${REPO_ROOT}/common/crypto/Sha256.cpp" \
    "${REPO_ROOT}/common/protocol/VsockProtocol.cpp" \
    "${REPO_ROOT}/common/vsock/VsockChannel.cpp" \
    "${REPO_ROOT}/common/tests/Sha256_test.cpp" \
    "${REPO_ROOT}/common/tests/VsockProtocol_test.cpp" \
    "${REPO_ROOT}/common/tests/VsockChannel_test.cpp"

echo "--- running xrom_shared_core_test ---"
"${OUT_DIR}/xrom_shared_core_test"
