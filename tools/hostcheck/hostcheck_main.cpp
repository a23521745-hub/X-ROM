/*
 * Copyright (C) 2026 The X-ROM Project
 * SPDX-License-Identifier: Apache-2.0
 *
 * Entry point for the host bootstrap runner. Kept in its own translation unit
 * so that the test sources stay byte-for-byte identical to what AOSP's gtest
 * compiles.
 */

#include <gtest/gtest.h>

int main() { return ::mini_gtest::RunAll(); }
