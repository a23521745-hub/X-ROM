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

#include <algorithm>

namespace xrom::avf {
namespace {

constexpr int32_t kAidRoot = 0;
constexpr int32_t kAidSystem = 1000;

// Install locations and the guest OS name come from VmSpec.h so that the
// validator, this policy, sepolicy/file_contexts and the Soong modules cannot
// drift apart.

constexpr int32_t kTaskIdMaxLength = 32;

bool IsTaskIdChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

std::string MakeVmName(TaskClass task_class, const std::string& task_id) {
  std::string name = "xrom_";
  name += TaskClassName(task_class);
  name += '_';
  name += task_id;
  return name;
}

const char* RejectionName(Rejection rejection) {
  switch (rejection) {
    case Rejection::kNone:
      return "allowed";
    case Rejection::kMalformed:
      return "malformed request";
    case Rejection::kDenied:
      return "denied by policy";
    case Rejection::kCapacity:
      return "capacity exhausted";
    case Rejection::kNoHypervisor:
      return "no usable hypervisor";
  }
  return "unknown";
}

}  // namespace

std::string PolicyDecision::Reason() const {
  std::string out = RejectionName(rejection);
  for (const auto& violation : violations) {
    out += "; ";
    out += violation;
  }
  return out;
}

PolicyOptions IsolationPolicy::DefaultOptions(bool protected_vm_available,
                                              bool allow_debuggable_vm) {
  PolicyOptions options;
  options.protected_vm_available = protected_vm_available;
  options.allow_debuggable_vm = allow_debuggable_vm;
  options.max_concurrent_vms = 2;
  options.memory_budget_mib = 1024;
  options.allowed_uids = {kAidSystem};
  options.instance_image_bytes = 64LL * 1024 * 1024;

  // X-Defender offline scanning. The input is data the host already has, so the
  // value of the VM here is containing the *parser*, not hiding the input. A
  // protected VM is still used whenever one is available.
  TaskClassPolicy static_analysis;
  static_analysis.payload_binary = "libxvault_payload.so";
  static_analysis.default_vcpus = 1;
  static_analysis.max_vcpus = 2;
  static_analysis.default_memory_mib = 256;
  static_analysis.max_memory_mib = 1024;
  static_analysis.cpu_topology = CpuTopology::kOneCpu;
  static_analysis.requires_protected_vm = false;
  options.classes[TaskClass::kStaticAnalysis] = static_analysis;

  // Self-healing integrity recomputation. The expected measurement is secret
  // relative to the host: an attacker who knows what a good artifact hashes to
  // can forge one.
  TaskClassPolicy integrity_check = static_analysis;
  integrity_check.max_vcpus = 1;
  integrity_check.max_memory_mib = 512;
  integrity_check.requires_protected_vm = true;
  options.classes[TaskClass::kIntegrityCheck] = integrity_check;

  TaskClassPolicy attestation = static_analysis;
  attestation.max_vcpus = 1;
  attestation.max_memory_mib = 512;
  attestation.requires_protected_vm = true;
  options.classes[TaskClass::kAttestation] = attestation;

  TaskClassPolicy crypto_operation = attestation;
  options.classes[TaskClass::kCryptoOperation] = crypto_operation;

  return options;
}

IsolationPolicy::IsolationPolicy(PolicyOptions options) : options_(std::move(options)) {}

PolicyDecision IsolationPolicy::Evaluate(const CallerIdentity& caller, const TaskRequest& request,
                                         int32_t active_vms,
                                         int64_t committed_memory_mib) const {
  PolicyDecision decision;
  bool malformed = false;
  bool denied = false;
  bool capacity = false;
  bool no_hypervisor = false;

  const auto violation = [&decision](const std::string& message) {
    decision.violations.push_back(message);
  };

  // --- 1. Who is asking ------------------------------------------------
  const bool uid_listed = std::find(options_.allowed_uids.begin(), options_.allowed_uids.end(),
                                    caller.uid) != options_.allowed_uids.end();
  // Root on a debuggable build is allowed so that `vm`-style bring-up tooling
  // works. On a user build this branch is unreachable and uid 0 is refused.
  const bool root_on_debuggable = caller.uid == kAidRoot && caller.is_debuggable_build;
  if (!uid_listed && !root_on_debuggable) {
    violation("uid " + std::to_string(caller.uid) +
              " is not permitted to submit isolation tasks");
    denied = true;
  }

  // --- 2. Task identity ------------------------------------------------
  if (request.task_id.empty()) {
    violation("task_id is empty");
    malformed = true;
  } else if (static_cast<int32_t>(request.task_id.size()) > kTaskIdMaxLength) {
    violation("task_id exceeds " + std::to_string(kTaskIdMaxLength) + " characters");
    malformed = true;
  } else if (!std::all_of(request.task_id.begin(), request.task_id.end(), IsTaskIdChar)) {
    violation("task_id contains a character outside [a-z0-9_.-]");
    malformed = true;
  }

  // --- 3. Input --------------------------------------------------------
  if (request.input_digest.size() != static_cast<size_t>(kSha256DigestBytes)) {
    violation("input_digest must be exactly " + std::to_string(kSha256DigestBytes) +
              " bytes, got " + std::to_string(request.input_digest.size()));
    malformed = true;
  }
  // A path that escapes the inbox is treated as hostile rather than as a typo.
  if (!IsPathContained(request.input_path, {kInboxRoot})) {
    violation("input_path must be a file under " + std::string(kInboxRoot) +
              " with no traversal components");
    denied = true;
  }

  // --- 4. Task class ---------------------------------------------------
  const auto class_it = options_.classes.find(request.task_class);
  if (class_it == options_.classes.end()) {
    violation(std::string("task class ") + TaskClassName(request.task_class) +
              " has no policy entry");
    denied = true;
  }

  // --- 5. Hypervisor ---------------------------------------------------
  if (class_it != options_.classes.end() && class_it->second.requires_protected_vm &&
      !options_.protected_vm_available) {
    violation(std::string("task class ") + TaskClassName(request.task_class) +
              " requires a protected VM and none is available");
    no_hypervisor = true;
  }

  // --- 6. Debuggability ------------------------------------------------
  // Explicitly refused rather than silently downgraded: a caller that asked for
  // a debuggable VM and got a non-debuggable one would otherwise have no way to
  // know that its logs and shell are not coming.
  if (request.request_debug && !(options_.allow_debuggable_vm && caller.is_debuggable_build)) {
    violation("debuggable VM requested; requires a userdebug/eng build and "
              "allow_debuggable_vm in the daemon configuration");
    denied = true;
  }

  // --- 7. Resources ----------------------------------------------------
  int32_t memory_mib = 0;
  if (class_it != options_.classes.end()) {
    const TaskClassPolicy& policy = class_it->second;
    if (request.requested_memory_mib == 0) {
      memory_mib = policy.default_memory_mib;
    } else if (request.requested_memory_mib < 0) {
      violation("requested_memory_mib must not be negative");
      malformed = true;
    } else if (request.requested_memory_mib < kMinMemoryMib) {
      violation("requested_memory_mib " + std::to_string(request.requested_memory_mib) +
                " is below the " + std::to_string(kMinMemoryMib) + " MiB Microdroid floor");
      denied = true;
    } else if (request.requested_memory_mib > policy.max_memory_mib) {
      violation("requested_memory_mib " + std::to_string(request.requested_memory_mib) +
                " exceeds the " + std::to_string(policy.max_memory_mib) +
                " MiB ceiling for " + TaskClassName(request.task_class));
      denied = true;
    } else {
      memory_mib = request.requested_memory_mib;
    }
  }

  // --- 8. Capacity -----------------------------------------------------
  if (active_vms >= options_.max_concurrent_vms) {
    violation("already running " + std::to_string(active_vms) + " of " +
              std::to_string(options_.max_concurrent_vms) + " permitted VMs");
    capacity = true;
  }
  if (committed_memory_mib + memory_mib > options_.memory_budget_mib) {
    violation("committing " + std::to_string(memory_mib) + " MiB would exceed the " +
              std::to_string(options_.memory_budget_mib) + " MiB budget (" +
              std::to_string(committed_memory_mib) + " MiB already committed)");
    capacity = true;
  }

  // Precedence: a malformed request is a programming error, a denial is a
  // security decision, and the two must not be conflated in the audit record.
  if (malformed) {
    decision.rejection = Rejection::kMalformed;
  } else if (denied) {
    decision.rejection = Rejection::kDenied;
  } else if (no_hypervisor) {
    decision.rejection = Rejection::kNoHypervisor;
  } else if (capacity) {
    decision.rejection = Rejection::kCapacity;
  }
  return decision;
}

PolicyDecision IsolationPolicy::EvaluatePayloadTrust(const TaskRequest& request,
                                                     const PayloadManifest& manifest) const {
  PolicyDecision decision;

  // A manifest that did not pass PayloadManifest::Validate() should never reach
  // here, but the policy does not rely on that: it re-checks the structural
  // minimum it depends on. The two checks are cheap and a mismatch between them
  // is exactly the kind of bug that should be loud.
  for (const std::string& problem : manifest.Validate()) {
    decision.violations.push_back("the verified payload manifest is invalid: " + problem);
  }

  const int32_t task_class = static_cast<int32_t>(request.task_class);
  if (!manifest.AllowsTaskClass(task_class)) {
    decision.violations.push_back("the payload " + manifest.payload_name +
                                  " is not signed for task class " +
                                  std::to_string(task_class));
  }

  // The manifest names the library microdroid_launcher will exec. It has to be
  // the same library the policy picked for this class, or the signed manifest is
  // authorising a different binary than the one that will actually run.
  const auto policy_entry = options_.classes.find(request.task_class);
  if (policy_entry != options_.classes.end() && !policy_entry->second.payload_binary.empty() &&
      policy_entry->second.payload_binary != manifest.payload_library) {
    decision.violations.push_back(
        "the manifest authorises " + manifest.payload_library + " but the policy for class " +
        std::to_string(task_class) + " names " + policy_entry->second.payload_binary);
  }

  if (!decision.violations.empty()) {
    decision.rejection = Rejection::kDenied;
  }
  return decision;
}

VmSpec IsolationPolicy::BuildSpec(const TaskRequest& request) const {
  static const TaskClassPolicy kUnconfigured{};
  const auto class_it = options_.classes.find(request.task_class);
  // Evaluate() rejects an unconfigured class, so this fallback is only reachable
  // from a caller that skipped the decision. It produces a spec that
  // VmSpec::Validate() will reject, which is the intended behaviour.
  const TaskClassPolicy& policy =
      (class_it != options_.classes.end()) ? class_it->second : kUnconfigured;

  VmSpec spec;
  spec.name = MakeVmName(request.task_class, request.task_id);
  spec.task_class = request.task_class;
  spec.debug_level = request.request_debug ? DebugLevel::kFull : DebugLevel::kNone;
  // Use a protected VM whenever the platform can provide one. Whether one is
  // *required* was decided in Evaluate().
  spec.protected_vm = options_.protected_vm_available;
  spec.limits.memory_mib =
      (request.requested_memory_mib > 0)
          ? std::min(request.requested_memory_mib, policy.max_memory_mib)
          : policy.default_memory_mib;
  spec.limits.vcpu_count = std::min(policy.default_vcpus, policy.max_vcpus);
  spec.limits.cpu_topology = policy.cpu_topology;
  spec.limits.instance_image_bytes = options_.instance_image_bytes;
  spec.os_name = "microdroid";
  spec.payload_apk_path = kPayloadApkPath;
  spec.payload_idsig_path = std::string(kStateRoot) + spec.name + ".idsig";
  spec.instance_image_path = std::string(kStateRoot) + spec.name + ".instance.img";
  spec.config_path_in_apk = kConfigPathInApk;

  // Logs are only kept for a debuggable VM. A production VM's console output is
  // guest data and must not be persisted on the host.
  if (spec.debug_level == DebugLevel::kFull) {
    spec.console_log_path = std::string(kStateRoot) + spec.name + ".console.log";
    spec.os_log_path = std::string(kStateRoot) + spec.name + ".os.log";
  }
  return spec;
}

}  // namespace xrom::avf
