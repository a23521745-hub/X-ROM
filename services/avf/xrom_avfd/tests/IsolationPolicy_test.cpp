/*
 * Copyright (C) 2026 The X-ROM Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "IsolationPolicy.h"

#include <gtest/gtest.h>

namespace xrom::avf {
namespace {

constexpr int32_t kAidSystem = 1000;
constexpr int32_t kAidShell = 2000;

CallerIdentity MakeCaller(int32_t uid = kAidSystem, bool debuggable_build = false) {
  CallerIdentity caller;
  caller.uid = uid;
  caller.pid = 4242;
  caller.selinux_domain = "system_app";
  caller.is_debuggable_build = debuggable_build;
  return caller;
}

TaskRequest MakeRequest(TaskClass task_class = TaskClass::kAttestation) {
  TaskRequest request;
  request.task_id = "task001";
  request.task_class = task_class;
  request.input_digest.assign(kSha256DigestBytes, 0xAB);
  request.input_path = "/data/misc/xrom/inbox/task001.bin";
  request.requested_memory_mib = 0;  // take the class default
  request.request_debug = false;
  return request;
}

IsolationPolicy MakePolicy(bool protected_vm_available = true, bool allow_debuggable_vm = false) {
  return IsolationPolicy(
      IsolationPolicy::DefaultOptions(protected_vm_available, allow_debuggable_vm));
}

bool Mentions(const PolicyDecision& decision, const std::string& needle) {
  return decision.Reason().find(needle) != std::string::npos;
}

// --- Admission -------------------------------------------------------------

TEST(IsolationPolicyTest, AnAllowedRequestIsAllowed) {
  const IsolationPolicy policy = MakePolicy();
  const PolicyDecision decision = policy.Evaluate(MakeCaller(), MakeRequest(), 0, 0);
  EXPECT_TRUE(decision.allowed()) << decision.Reason();
  EXPECT_EQ(decision.rejection, Rejection::kNone);
  EXPECT_TRUE(decision.violations.empty());
}

TEST(IsolationPolicyTest, AnUnlistedUidIsDenied) {
  const IsolationPolicy policy = MakePolicy();
  for (int32_t uid : {kAidShell, 10001, 10123, -1}) {
    const PolicyDecision decision = policy.Evaluate(MakeCaller(uid), MakeRequest(), 0, 0);
    EXPECT_FALSE(decision.allowed()) << "uid " << uid << " was admitted";
    EXPECT_EQ(decision.rejection, Rejection::kDenied);
    EXPECT_TRUE(Mentions(decision, "not permitted to submit"));
  }
}

TEST(IsolationPolicyTest, RootIsRefusedOnAUserBuildButNotOnADebuggableOne) {
  const IsolationPolicy policy = MakePolicy();
  EXPECT_EQ(policy.Evaluate(MakeCaller(0, false), MakeRequest(), 0, 0).rejection,
            Rejection::kDenied);
  EXPECT_TRUE(policy.Evaluate(MakeCaller(0, true), MakeRequest(), 0, 0).allowed());
}

TEST(IsolationPolicyTest, TheAllowedUidListIsHonouredFromConfiguration) {
  PolicyOptions options = IsolationPolicy::DefaultOptions(true, false);
  options.allowed_uids = {10123};
  const IsolationPolicy policy(options);
  EXPECT_TRUE(policy.Evaluate(MakeCaller(10123), MakeRequest(), 0, 0).allowed());
  EXPECT_EQ(policy.Evaluate(MakeCaller(kAidSystem), MakeRequest(), 0, 0).rejection,
            Rejection::kDenied);
}

// --- Malformed input -------------------------------------------------------

TEST(IsolationPolicyTest, AWrongLengthDigestIsMalformed) {
  const IsolationPolicy policy = MakePolicy();
  for (size_t size : {0u, 16u, 31u, 33u, 64u}) {
    TaskRequest request = MakeRequest();
    request.input_digest.assign(size, 0xAB);
    const PolicyDecision decision = policy.Evaluate(MakeCaller(), request, 0, 0);
    EXPECT_EQ(decision.rejection, Rejection::kMalformed) << "digest size " << size;
  }
}

TEST(IsolationPolicyTest, TaskIdCharsetIsEnforced) {
  const IsolationPolicy policy = MakePolicy();
  const std::string too_long(33, 'a');
  for (const std::string& task_id : {std::string(""), std::string("TASK"), std::string("task 01"),
                                     std::string("../task"), std::string("task/01"), too_long}) {
    TaskRequest request = MakeRequest();
    request.task_id = task_id;
    EXPECT_EQ(policy.Evaluate(MakeCaller(), request, 0, 0).rejection, Rejection::kMalformed)
        << "task_id '" << task_id << "'";
  }
}

TEST(IsolationPolicyTest, MalformedBeatsDeniedInPrecedence) {
  // A programming error and a security decision must not be conflated in the
  // audit record, so the classifier is fixed: malformed wins.
  const IsolationPolicy policy = MakePolicy();
  TaskRequest request = MakeRequest();
  request.input_digest.clear();                    // malformed
  request.input_path = "/data/local/tmp/evil.bin"; // denied
  const PolicyDecision decision = policy.Evaluate(MakeCaller(kAidShell), request, 0, 0);
  EXPECT_EQ(decision.rejection, Rejection::kMalformed);
  EXPECT_GE(decision.violations.size(), 3u) << "not every problem was reported";
}

// --- Path containment ------------------------------------------------------

TEST(IsolationPolicyTest, AnInputOutsideTheInboxIsDenied) {
  const IsolationPolicy policy = MakePolicy();
  for (const char* path : {"/data/local/tmp/x.bin", "/sdcard/x.bin",
                           "/data/misc/xrom/inbox/../../etc/passwd",
                           "/data/misc/xrom/inbox", "relative.bin"}) {
    TaskRequest request = MakeRequest();
    request.input_path = path;
    const PolicyDecision decision = policy.Evaluate(MakeCaller(), request, 0, 0);
    EXPECT_EQ(decision.rejection, Rejection::kDenied) << "input_path '" << path << "'";
    EXPECT_TRUE(Mentions(decision, "input_path"));
  }
}

// --- Hypervisor availability ----------------------------------------------

TEST(IsolationPolicyTest, ClassesNeedingApVmAreRefusedWithoutOne) {
  const IsolationPolicy policy = MakePolicy(/*protected_vm_available=*/false);
  for (TaskClass task_class : {TaskClass::kIntegrityCheck, TaskClass::kAttestation,
                               TaskClass::kCryptoOperation}) {
    const PolicyDecision decision = policy.Evaluate(MakeCaller(), MakeRequest(task_class), 0, 0);
    EXPECT_EQ(decision.rejection, Rejection::kNoHypervisor) << TaskClassName(task_class);
    EXPECT_TRUE(Mentions(decision, "requires a protected VM"));
  }
}

TEST(IsolationPolicyTest, StaticAnalysisStillRunsWithoutApVm) {
  // Its input is already public to the host, so an ordinary VM still contains
  // the parser, which is the point of the class.
  const IsolationPolicy policy = MakePolicy(/*protected_vm_available=*/false);
  const PolicyDecision decision =
      policy.Evaluate(MakeCaller(), MakeRequest(TaskClass::kStaticAnalysis), 0, 0);
  EXPECT_TRUE(decision.allowed()) << decision.Reason();
  EXPECT_FALSE(policy.BuildSpec(MakeRequest(TaskClass::kStaticAnalysis)).protected_vm);
}

// --- Debuggability ---------------------------------------------------------

TEST(IsolationPolicyTest, ADebuggableVmNeedsBothTheBuildAndTheConfig) {
  TaskRequest request = MakeRequest();
  request.request_debug = true;

  EXPECT_EQ(MakePolicy(true, false).Evaluate(MakeCaller(1000, true), request, 0, 0).rejection,
            Rejection::kDenied);
  EXPECT_EQ(MakePolicy(true, true).Evaluate(MakeCaller(1000, false), request, 0, 0).rejection,
            Rejection::kDenied);
  EXPECT_TRUE(MakePolicy(true, true).Evaluate(MakeCaller(1000, true), request, 0, 0).allowed());
}

TEST(IsolationPolicyTest, ADebugRequestIsRefusedNotSilentlyDowngraded) {
  // A caller that asked for logs and a shell and quietly got neither would have
  // no way to know its debugging session was never going to work.
  const IsolationPolicy policy = MakePolicy(true, false);
  TaskRequest request = MakeRequest();
  request.request_debug = true;
  EXPECT_TRUE(Mentions(policy.Evaluate(MakeCaller(), request, 0, 0), "debuggable"));
}

// --- Resources and capacity ------------------------------------------------

TEST(IsolationPolicyTest, MemoryAboveTheClassCeilingIsDenied) {
  const IsolationPolicy policy = MakePolicy();
  TaskRequest request = MakeRequest(TaskClass::kAttestation);  // ceiling 512 MiB
  request.requested_memory_mib = 1024;
  const PolicyDecision decision = policy.Evaluate(MakeCaller(), request, 0, 0);
  EXPECT_EQ(decision.rejection, Rejection::kDenied);
  EXPECT_TRUE(Mentions(decision, "ceiling"));
}

TEST(IsolationPolicyTest, MemoryBelowTheMicrodroidFloorIsDenied) {
  const IsolationPolicy policy = MakePolicy();
  TaskRequest request = MakeRequest();
  request.requested_memory_mib = 64;
  EXPECT_EQ(policy.Evaluate(MakeCaller(), request, 0, 0).rejection, Rejection::kDenied);
}

TEST(IsolationPolicyTest, NegativeMemoryIsMalformed) {
  const IsolationPolicy policy = MakePolicy();
  TaskRequest request = MakeRequest();
  request.requested_memory_mib = -1;
  EXPECT_EQ(policy.Evaluate(MakeCaller(), request, 0, 0).rejection, Rejection::kMalformed);
}

TEST(IsolationPolicyTest, TheConcurrencyCeilingIsEnforced) {
  const IsolationPolicy policy = MakePolicy();  // max_concurrent_vms == 2
  EXPECT_TRUE(policy.Evaluate(MakeCaller(), MakeRequest(), 1, 256).allowed());
  const PolicyDecision decision = policy.Evaluate(MakeCaller(), MakeRequest(), 2, 512);
  EXPECT_EQ(decision.rejection, Rejection::kCapacity);
  EXPECT_TRUE(Mentions(decision, "permitted VMs"));
}

TEST(IsolationPolicyTest, TheMemoryBudgetIsEnforced) {
  const IsolationPolicy policy = MakePolicy();  // memory_budget_mib == 1024
  EXPECT_TRUE(policy.Evaluate(MakeCaller(), MakeRequest(), 0, 1024 - 256).allowed());
  EXPECT_EQ(policy.Evaluate(MakeCaller(), MakeRequest(), 0, 1024 - 128).rejection,
            Rejection::kCapacity);
}

// --- Spec generation -------------------------------------------------------

TEST(IsolationPolicyTest, EveryClassGeneratesASpecThatPassesValidation) {
  // The two gates are kept independent on purpose, so the property that matters
  // is that they agree: anything the policy admits must survive the validator.
  for (bool protected_vm : {true, false}) {
    for (bool debuggable : {false, true}) {
      const IsolationPolicy policy = MakePolicy(protected_vm, debuggable);
      for (TaskClass task_class : {TaskClass::kStaticAnalysis, TaskClass::kIntegrityCheck,
                                   TaskClass::kAttestation, TaskClass::kCryptoOperation}) {
        TaskRequest request = MakeRequest(task_class);
        request.request_debug = debuggable;
        if (!policy.Evaluate(MakeCaller(kAidSystem, debuggable), request, 0, 0).allowed()) {
          continue;
        }
        const VmSpec spec = policy.BuildSpec(request);
        const std::vector<std::string> problems = spec.Validate(debuggable);
        EXPECT_TRUE(problems.empty())
            << TaskClassName(task_class) << " protected=" << protected_vm
            << " debuggable=" << debuggable << " -> " << spec.ToString();
        for (const auto& problem : problems) {
          ADD_FAILURE() << "  " << problem;
        }
      }
    }
  }
}

TEST(IsolationPolicyTest, GeneratedNamesAreUniquePerTaskAndClass) {
  const IsolationPolicy policy = MakePolicy();
  TaskRequest a = MakeRequest(TaskClass::kAttestation);
  TaskRequest b = MakeRequest(TaskClass::kCryptoOperation);
  TaskRequest c = a;
  c.task_id = "task002";
  EXPECT_NE(policy.BuildSpec(a).name, policy.BuildSpec(b).name);
  EXPECT_NE(policy.BuildSpec(a).name, policy.BuildSpec(c).name);
}

TEST(IsolationPolicyTest, LogsAreOnlyKeptForADebuggableVm) {
  TaskRequest request = MakeRequest();
  EXPECT_TRUE(MakePolicy().BuildSpec(request).console_log_path.empty());
  EXPECT_TRUE(MakePolicy().BuildSpec(request).os_log_path.empty());

  request.request_debug = true;
  const VmSpec spec = MakePolicy(true, true).BuildSpec(request);
  EXPECT_FALSE(spec.console_log_path.empty());
  EXPECT_FALSE(spec.os_log_path.empty());
}

TEST(IsolationPolicyTest, BuildSpecNeverRequestsACustomKernel) {
  // customConfig stays unset in MicrodroidVmBuilder, which is what keeps
  // USE_CUSTOM_VIRTUAL_MACHINE out of the permission set X-ROM actually needs.
  const VmSpec spec = MakePolicy().BuildSpec(MakeRequest());
  EXPECT_EQ(spec.os_name, "microdroid");
  EXPECT_EQ(spec.config_path_in_apk, kConfigPathInApk);
}

}  // namespace
}  // namespace xrom::avf
