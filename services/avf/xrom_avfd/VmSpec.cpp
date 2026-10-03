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

#include "VmSpec.h"

#include <algorithm>
#include <cctype>

namespace xrom::avf {
namespace {

// The only guest OS X-ROM ships images for. Anything else needs
// USE_CUSTOM_VIRTUAL_MACHINE and a Microdroid build X-ROM has measured.
constexpr char kAllowedOsName[] = "microdroid";

bool IsAllowedNameChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

bool HasControlOrSpaceChar(const std::string& s) {
  return std::any_of(s.begin(), s.end(), [](unsigned char c) {
    return c < 0x20 || c == 0x7f || std::isspace(c) != 0;
  });
}

bool EndsWith(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool StartsWith(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

}  // namespace

bool IsPathContained(const std::string& path, const std::vector<std::string>& allowed_roots) {
  if (path.empty() || path.front() != '/') {
    return false;
  }
  if (HasControlOrSpaceChar(path)) {
    return false;
  }
  // Reject empty components ("//") and any traversal component. Comparing whole
  // components rather than searching for ".." as a substring means a legitimate
  // name like "payload..v2.apk" is not rejected while "../../etc" still is.
  size_t start = 1;
  while (start <= path.size()) {
    size_t end = path.find('/', start);
    if (end == std::string::npos) {
      end = path.size();
    }
    const std::string component = path.substr(start, end - start);
    if (component.empty() || component == "..") {
      return false;
    }
    start = end + 1;
  }
  return std::any_of(allowed_roots.begin(), allowed_roots.end(),
                     [&path](const std::string& root) {
                       return StartsWith(root, "/") && EndsWith(root, "/") &&
                              StartsWith(path, root) && path.size() > root.size();
                     });
}

std::vector<std::string> VmSpec::Validate(bool allow_debuggable) const {
  std::vector<std::string> problems;
  const auto add = [&problems](const std::string& p) { problems.push_back(p); };

  // --- name ------------------------------------------------------------
  if (name.empty()) {
    add("vm name is empty");
  } else {
    if (!StartsWith(name, kVmNamePrefix)) {
      add("vm name must start with \"" + std::string(kVmNamePrefix) + "\"");
    }
    if (static_cast<int32_t>(name.size()) > kVmNameMaxLength) {
      add("vm name exceeds " + std::to_string(kVmNameMaxLength) + " characters");
    }
    if (std::any_of(name.begin(), name.end(),
                    [](char c) { return !IsAllowedNameChar(c); })) {
      add("vm name contains a character outside [a-z0-9_.-]");
    }
  }

  // --- isolation level -------------------------------------------------
  if (!protected_vm && task_class != TaskClass::kStaticAnalysis) {
    add(std::string("task class ") + TaskClassName(task_class) +
        " requires a protected VM; pKVM's stage-2 isolation is the only thing "
        "that keeps its input out of a compromised host kernel");
  }
  if (debug_level == DebugLevel::kFull && !allow_debuggable) {
    add("debuggable VM requested but not permitted by the daemon configuration "
        "and build variant");
  }

  // --- guest OS --------------------------------------------------------
  if (os_name != kAllowedOsName) {
    add("unsupported os_name \"" + os_name + "\"; expected \"" + kAllowedOsName + "\"");
  }

  // --- resources -------------------------------------------------------
  if (limits.memory_mib < kMinMemoryMib || limits.memory_mib > kMaxMemoryMib) {
    add("memory_mib " + std::to_string(limits.memory_mib) + " outside [" +
        std::to_string(kMinMemoryMib) + ", " + std::to_string(kMaxMemoryMib) + "]");
  }
  if (limits.vcpu_count < kMinVCpus || limits.vcpu_count > kMaxVCpus) {
    add("vcpu_count " + std::to_string(limits.vcpu_count) + " outside [" +
        std::to_string(kMinVCpus) + ", " + std::to_string(kMaxVCpus) + "]");
  }
  switch (limits.cpu_topology) {
    case CpuTopology::kOneCpu:
    case CpuTopology::kOneBigCpu:
    case CpuTopology::kMatchHostCores:
      break;
    default:
      add("cpu_topology " + std::to_string(static_cast<int32_t>(limits.cpu_topology)) +
          " is not a value X-ROM will pass to crosvm");
      break;
  }
  if (limits.instance_image_bytes <= 0) {
    add("instance_image_bytes must be positive");
  } else if (limits.instance_image_bytes > kMaxInstanceImageBytes) {
    add("instance_image_bytes exceeds the configured ceiling");
  } else if (limits.instance_image_bytes % 4096 != 0) {
    add("instance_image_bytes must be a multiple of the 4096 byte page size");
  }

  // --- paths -----------------------------------------------------------
  const std::vector<std::string> payload_roots{kPayloadApkRoot};
  const std::vector<std::string> state_roots{kStateRoot};

  if (!IsPathContained(payload_apk_path, payload_roots) || !EndsWith(payload_apk_path, ".apk")) {
    add("payload_apk_path must be a *.apk under " + std::string(kPayloadApkRoot));
  }
  if (!IsPathContained(payload_idsig_path, state_roots) || !EndsWith(payload_idsig_path, ".idsig")) {
    add("payload_idsig_path must be a *.idsig under " + std::string(kStateRoot));
  }
  if (!IsPathContained(instance_image_path, state_roots)) {
    add("instance_image_path must be under " + std::string(kStateRoot));
  }

  // Trust material may only ever come from the read-only system_ext location. A
  // spec that pointed verification at /data would let whoever controls /data
  // choose the manifest — and therefore the payload — that the daemon accepts.
  const std::vector<std::string> trust_roots{kPayloadTrustRoot};
  if (!IsPathContained(payload_manifest_path, trust_roots) ||
      !EndsWith(payload_manifest_path, ".json")) {
    add("payload_manifest_path must be a *.json under " + std::string(kPayloadTrustRoot));
  }
  if (!IsPathContained(payload_manifest_sig_path, trust_roots) ||
      !EndsWith(payload_manifest_sig_path, ".sig")) {
    add("payload_manifest_sig_path must be a *.sig under " + std::string(kPayloadTrustRoot));
  }
  if (!IsPathContained(trust_config_path, trust_roots) || !EndsWith(trust_config_path, ".json")) {
    add("trust_config_path must be a *.json under " + std::string(kPayloadTrustRoot));
  }

  // The Microdroid payload config is embedded in the APK by the android_app
  // module's asset pipeline, so it is relative and lives under assets/.
  if (!StartsWith(config_path_in_apk, "assets/") || !EndsWith(config_path_in_apk, ".json") ||
      config_path_in_apk.find("..") != std::string::npos) {
    add("config_path_in_apk must be assets/*.json with no traversal");
  }

  for (const auto& log_path : {console_log_path, os_log_path}) {
    if (!log_path.empty() && !IsPathContained(log_path, state_roots)) {
      add("log paths must be under " + std::string(kStateRoot));
    }
  }

  return problems;
}

std::string VmSpec::ToString() const {
  // Deliberately omits idsig/instance paths and any digest: this string ends up
  // in logd, which is readable by the shell on a userdebug build.
  std::string out = name;
  out += " class=";
  out += TaskClassName(task_class);
  out += " protected=";
  out += protected_vm ? "yes" : "no";
  out += " debug=";
  out += DebugLevelName(debug_level);
  out += " mem_mib=";
  out += std::to_string(limits.memory_mib);
  out += " vcpus=";
  out += std::to_string(limits.vcpu_count);
  out += " topo=";
  out += CpuTopologyName(limits.cpu_topology);
  out += " os=";
  out += os_name;
  return out;
}

const char* TaskClassName(TaskClass task_class) {
  switch (task_class) {
    case TaskClass::kStaticAnalysis:
      return "static_analysis";
    case TaskClass::kIntegrityCheck:
      return "integrity_check";
    case TaskClass::kAttestation:
      return "attestation";
    case TaskClass::kCryptoOperation:
      return "crypto_operation";
  }
  return "unknown";
}

const char* DebugLevelName(DebugLevel level) {
  switch (level) {
    case DebugLevel::kNone:
      return "none";
    case DebugLevel::kFull:
      return "full";
  }
  return "unknown";
}

const char* CpuTopologyName(CpuTopology topology) {
  switch (topology) {
    case CpuTopology::kOneCpu:
      return "one_cpu";
    case CpuTopology::kOneBigCpu:
      return "one_big_cpu";
    case CpuTopology::kMatchHostCores:
      return "match_host_cores";
  }
  return "unknown";
}

}  // namespace xrom::avf
