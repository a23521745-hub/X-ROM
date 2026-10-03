/*
 * Copyright (C) 2026 The X-ROM Project
 * SPDX-License-Identifier: Apache-2.0
 *
 * A ~100 line stand-in for <gtest/gtest.h>, used only by
 * tools/hostcheck/run_host_tests.sh.
 *
 * Why this exists: services/avf/xrom_avfd/tests/ is the real test suite and runs
 * under AOSP's gtest via `atest xrom_avf_core_test`. But an AOSP tree is a
 * 400 GB checkout and a multi-hour build, so a contributor who has cloned X-ROM
 * and nothing else has no way to run those tests. This shim lets the *same test
 * sources* run with a system g++ in about a second.
 *
 * One test suite, two runners. Deliberately not a second copy of the assertions:
 * a duplicated suite is a suite that drifts, and a policy test that drifts is
 * worse than no test.
 *
 * Supported: TEST(), EXPECT_TRUE/FALSE/EQ/NE/GE, ADD_FAILURE(), and streaming
 * extra context with <<. Deliberately unsupported: fixtures, matchers, death
 * tests, parameterised tests. Add them here if the real suite starts using them.
 *
 * Every macro here has the same name and the same argument order as the real
 * one, so a test file compiles unchanged against either: this shim for CI on a
 * build host with no AOSP, and real gtest inside the tree. That is the whole
 * point of the file — a test that only runs under one of the two is a test that
 * stops being run.
 */

#ifndef XROM_TOOLS_HOSTCHECK_GTEST_GTEST_H_
#define XROM_TOOLS_HOSTCHECK_GTEST_GTEST_H_

#include <cstdio>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace mini_gtest {

struct Registry {
  using Test = std::pair<std::string, void (*)()>;

  static std::vector<Test>& Tests() {
    static std::vector<Test> tests;
    return tests;
  }
  static int& Checks() {
    static int checks = 0;
    return checks;
  }
  static int& Failures() {
    static int failures = 0;
    return failures;
  }
};

inline bool Register(const char* name, void (*fn)()) {
  Registry::Tests().emplace_back(name, fn);
  return true;
}

// A single expectation. Reports on destruction so that the `<< context` chained
// after the macro is included in the failure output, which is what makes the
// real suite's messages readable.
class Expectation {
 public:
  Expectation(bool failed, const char* file, int line, const char* expression)
      : failed_(failed), file_(file), line_(line), expression_(expression) {}

  Expectation(const Expectation&) = delete;
  Expectation& operator=(const Expectation&) = delete;

  template <typename T>
  Expectation& operator<<(const T& value) {
    context_ << value;
    return *this;
  }

  ~Expectation() {
    ++Registry::Checks();
    if (!failed_) {
      return;
    }
    ++Registry::Failures();
    std::printf("    FAIL %s:%d\n         %s\n", file_, line_, expression_);
    const std::string context = context_.str();
    if (!context.empty()) {
      std::printf("         %s\n", context.c_str());
    }
  }

 private:
  bool failed_;
  const char* file_;
  int line_;
  const char* expression_;
  std::ostringstream context_;
};

inline int RunAll() {
  int failed_tests = 0;
  for (const Registry::Test& test : Registry::Tests()) {
    const int failures_before = Registry::Failures();
    std::printf("[ RUN      ] %s\n", test.first.c_str());
    test.second();
    if (Registry::Failures() != failures_before) {
      ++failed_tests;
      std::printf("[  FAILED  ] %s\n", test.first.c_str());
    } else {
      std::printf("[       OK ] %s\n", test.first.c_str());
    }
  }
  std::printf("\n%zu test(s), %d check(s), %d failure(s)\n", Registry::Tests().size(),
              Registry::Checks(), Registry::Failures());
  return failed_tests == 0 ? 0 : 1;
}

}  // namespace mini_gtest

#define XROM_TEST_NAME(suite, name) suite##_##name##_body

// __attribute__((used)) keeps -Wunused-variable quiet about the registration
// flag, whose only purpose is its dynamic initialiser.
#define TEST(suite, name)                                                     \
  static void XROM_TEST_NAME(suite, name)();                                  \
  __attribute__((used)) static const bool XROM_TEST_NAME(suite, name##_reg) = \
      ::mini_gtest::Register(#suite "." #name, &XROM_TEST_NAME(suite, name)); \
  static void XROM_TEST_NAME(suite, name)()

#define EXPECT_TRUE(condition) \
  ::mini_gtest::Expectation(!(condition), __FILE__, __LINE__, "EXPECT_TRUE(" #condition ")")
#define EXPECT_FALSE(condition) \
  ::mini_gtest::Expectation((condition), __FILE__, __LINE__, "EXPECT_FALSE(" #condition ")")
#define EXPECT_EQ(lhs, rhs) \
  ::mini_gtest::Expectation(!((lhs) == (rhs)), __FILE__, __LINE__, "EXPECT_EQ(" #lhs ", " #rhs ")")
#define EXPECT_NE(lhs, rhs) \
  ::mini_gtest::Expectation(!((lhs) != (rhs)), __FILE__, __LINE__, "EXPECT_NE(" #lhs ", " #rhs ")")
#define EXPECT_GE(lhs, rhs) \
  ::mini_gtest::Expectation(!((lhs) >= (rhs)), __FILE__, __LINE__, "EXPECT_GE(" #lhs ", " #rhs ")")
#define EXPECT_LE(lhs, rhs) \
  ::mini_gtest::Expectation(!((lhs) <= (rhs)), __FILE__, __LINE__, "EXPECT_LE(" #lhs ", " #rhs ")")
#define EXPECT_GT(lhs, rhs) \
  ::mini_gtest::Expectation(!((lhs) > (rhs)), __FILE__, __LINE__, "EXPECT_GT(" #lhs ", " #rhs ")")
#define EXPECT_LT(lhs, rhs) \
  ::mini_gtest::Expectation(!((lhs) < (rhs)), __FILE__, __LINE__, "EXPECT_LT(" #lhs ", " #rhs ")")
#define ADD_FAILURE() ::mini_gtest::Expectation(true, __FILE__, __LINE__, "ADD_FAILURE()")

#endif  // XROM_TOOLS_HOSTCHECK_GTEST_GTEST_H_
