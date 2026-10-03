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

#ifndef XROM_AVF_ISOLATION_POLICY_H_
#define XROM_AVF_ISOLATION_POLICY_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "PayloadManifest.h"
#include "VmSpec.h"

namespace xrom::avf {

// ---------------------------------------------------------------------------
// The decision point for every isolation request.
//
// Three properties this class is written to have:
//
//   1. Deny by default. A PolicyDecision starts out rejected and is only
//      allowed once every check has passed. There is no code path in which a
//      request is accepted because a check was forgotten.
//   2. Total. Evaluate() reports every violation, not the first. A security
//      policy that leaks one rule at a time is a policy an attacker can probe.
//   3. Pure. No binder, no file I/O, no globals, no clock. Given the same
//      options, caller, request and counters it returns the same answer, which
//      is what makes it testable on a build host and auditable by reading it.
// ---------------------------------------------------------------------------

struct CallerIdentity {
  int32_t uid = -1;
  int32_t pid = -1;
  // SELinux domain of the caller, read from SO_PEERSEC. Advisory: it is used in
  // the audit record, never as the authorisation decision, because the daemon
  // cannot verify it as cheaply as it can verify a uid.
  std::string selinux_domain;
  bool is_debuggable_build = false;
};

struct TaskRequest {
  std::string task_id;
  TaskClass task_class = TaskClass::kStaticAnalysis;
  // SHA-256 of the input. Exactly 32 bytes; anything else is malformed.
  std::vector<uint8_t> input_digest;
  std::string input_path;
  int32_t requested_memory_mib = 0;
  bool request_debug = false;
};

// Mirrors the negative return codes documented on IXIsolationService::submitTask.
enum class Rejection : int32_t {
  kNone = 0,
  kMalformed = -1,
  kDenied = -2,
  kCapacity = -3,
  kNoHypervisor = -4,
};

struct PolicyDecision {
  Rejection rejection = Rejection::kNone;
  std::vector<std::string> violations;

  bool allowed() const { return rejection == Rejection::kNone && violations.empty(); }

  // All violations joined for logging and for IsolationTaskResult.detail.
  std::string Reason() const;
};

// Per-task-class limits, loaded from /system_ext/etc/xrom/avf.json.
struct TaskClassPolicy {
  // Name of the shared library inside the payload APK that Microdroid's
  // microdroid_launcher will exec. Must match task.command in vm_config.json.
  std::string payload_binary;
  int32_t default_vcpus = 1;
  int32_t max_vcpus = 1;
  int32_t default_memory_mib = 256;
  int32_t max_memory_mib = 512;
  CpuTopology cpu_topology = CpuTopology::kOneCpu;
  bool requires_protected_vm = true;
};

struct PolicyOptions {
  // False when AVF is absent, when the kernel came up without pKVM, or when the
  // global virtualization state is DISABLED. Read from virtualizationservice,
  // not from a system property.
  bool protected_vm_available = false;
  // Only ever true on a userdebug/eng build, and only if the operator set it.
  bool allow_debuggable_vm = false;
  int32_t max_concurrent_vms = 2;
  int64_t memory_budget_mib = 1024;
  // uids permitted to submit work at all. Defaults to AID_SYSTEM.
  std::vector<int32_t> allowed_uids = {1000};
  int64_t instance_image_bytes = 64LL * 1024 * 1024;
  std::map<TaskClass, TaskClassPolicy> classes;
};

class IsolationPolicy {
 public:
  // The X-ROM default policy. Every class requires a protected VM except
  // STATIC_ANALYSIS, which processes input that is already public to the host.
  static PolicyOptions DefaultOptions(bool protected_vm_available, bool allow_debuggable_vm);

  explicit IsolationPolicy(PolicyOptions options);

  // |active_vms| and |committed_memory_mib| are supplied by the caller so that
  // the policy stays free of mutable state and therefore free of locking.
  PolicyDecision Evaluate(const CallerIdentity& caller, const TaskRequest& request,
                          int32_t active_vms, int64_t committed_memory_mib) const;

  // Turns an already-approved request into a VmSpec. Callers must still run
  // VmSpec::Validate() on the result: the policy checks intent, the validator
  // checks the artifact, and the two are kept independent so that a bug in one
  // does not silently disable the other.
  VmSpec BuildSpec(const TaskRequest& request) const;

  // Second gate, run after the signed manifest has been verified and before the
  // VM is created.
  //
  // Evaluate() decides whether *this caller* may ask for *this class* of work.
  // This decides whether *this payload* is authorised to do it. Both have to say
  // yes, and they are separate checks because they fail for different reasons:
  // a manifest may legitimately authorise only STATIC_ANALYSIS while the policy
  // permits a caller to request CRYPTO_OPERATION, and the correct answer to that
  // combination is "not with this payload", not "you may not ask".
  //
  // The manifest is an input rather than something this class loads, so that the
  // policy core stays free of file I/O, JSON and BoringSSL and therefore testable
  // on a build host.
  PolicyDecision EvaluatePayloadTrust(const TaskRequest& request,
                                      const PayloadManifest& manifest) const;

  const PolicyOptions& options() const { return options_; }

 private:
  PolicyOptions options_;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_ISOLATION_POLICY_H_
