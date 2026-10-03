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

#include "DaemonConfig.h"

#include <algorithm>
#include <memory>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <json/json.h>

namespace xrom::avf {
namespace {

// Every reader clamps into [minimum, maximum] and falls back on a missing or
// wrongly typed key. A configuration file that asks for more than the compiled-in
// ceiling gets the ceiling, not what it asked for: this file may only ever make
// the policy stricter.
int64_t ReadInt64(const Json::Value& root, const char* key, int64_t fallback, int64_t minimum,
                  int64_t maximum) {
  const Json::Value& value = root[key];
  if (!value.isIntegral()) {
    if (!value.isNull()) {
      LOG(WARNING) << "xrom_avfd: config key \"" << key << "\" is not an integer; using "
                   << fallback;
    }
    return fallback;
  }
  const int64_t parsed = value.asInt64();
  if (parsed < minimum || parsed > maximum) {
    LOG(WARNING) << "xrom_avfd: config key \"" << key << "\" = " << parsed << " outside ["
                 << minimum << ", " << maximum << "]; clamped";
    return std::clamp(parsed, minimum, maximum);
  }
  return parsed;
}

int32_t ReadInt32(const Json::Value& root, const char* key, int32_t fallback, int32_t minimum,
                  int32_t maximum) {
  return static_cast<int32_t>(ReadInt64(root, key, fallback, minimum, maximum));
}

bool ReadBool(const Json::Value& root, const char* key, bool fallback) {
  const Json::Value& value = root[key];
  if (!value.isBool()) {
    if (!value.isNull()) {
      LOG(WARNING) << "xrom_avfd: config key \"" << key << "\" is not a boolean; using "
                   << (fallback ? "true" : "false");
    }
    return fallback;
  }
  return value.asBool();
}

}  // namespace

DaemonConfig DaemonConfig::FailSafeDefaults() {
  // The struct's own initialisers are the fail-safe set: debuggable VMs off, one
  // VM at a time, half a GiB of guest memory in total, AID_SYSTEM only.
  return DaemonConfig{};
}

DaemonConfig DaemonConfig::Load(const std::string& path, std::string* error) {
  std::string content;
  if (!android::base::ReadFileToString(path, &content)) {
    *error = "cannot read " + path;
    return FailSafeDefaults();
  }
  if (content.size() > 64 * 1024) {
    *error = path + " is larger than 64 KiB; refusing to parse";
    return FailSafeDefaults();
  }

  Json::Value root;
  Json::CharReaderBuilder builder;
  builder.settings_["collectComments"] = false;
  const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  std::string parse_errors;
  if (reader == nullptr ||
      !reader->parse(content.data(), content.data() + content.size(), &root, &parse_errors)) {
    *error = "malformed JSON in " + path + ": " + parse_errors;
    return FailSafeDefaults();
  }
  if (!root.isObject()) {
    *error = path + " must contain a single JSON object";
    return FailSafeDefaults();
  }

  DaemonConfig config = FailSafeDefaults();
  config.allow_debuggable_vm = ReadBool(root, "allow_debuggable_vm", false);
  config.max_concurrent_vms = ReadInt32(root, "max_concurrent_vms", config.max_concurrent_vms, 1,
                                        kMaxConcurrentVmsLimit);
  config.memory_budget_mib = ReadInt64(root, "memory_budget_mib", config.memory_budget_mib, 128,
                                       kMemoryBudgetLimitMib);
  config.instance_image_bytes =
      ReadInt64(root, "instance_image_bytes", config.instance_image_bytes, 4096,
                kInstanceImageLimitBytes);
  config.vm_launch_timeout_ms =
      ReadInt32(root, "vm_launch_timeout_ms", config.vm_launch_timeout_ms, 1000, kLaunchTimeoutLimitMs);
  config.task_timeout_ms =
      ReadInt32(root, "task_timeout_ms", config.task_timeout_ms, 1000, kTaskTimeoutLimitMs);

  const Json::Value& uids = root["allowed_uids"];
  if (uids.isArray() && !uids.empty()) {
    std::vector<int32_t> parsed;
    for (const Json::Value& entry : uids) {
      if (!entry.isIntegral()) {
        *error = "allowed_uids must contain only integers";
        return FailSafeDefaults();
      }
      const int64_t uid = entry.asInt64();
      // uid 0 is rejected outright. Root on a user build is a compromised host,
      // and on a debuggable build IsolationPolicy already admits it separately.
      if (uid <= 0 || uid > 65535) {
        *error = "allowed_uids contains " + std::to_string(uid) + ", which is not a valid app uid";
        return FailSafeDefaults();
      }
      parsed.push_back(static_cast<int32_t>(uid));
    }
    config.allowed_uids = std::move(parsed);
  } else if (!uids.isNull()) {
    *error = "allowed_uids must be a non-empty array";
    return FailSafeDefaults();
  }

  return config;
}

PolicyOptions DaemonConfig::ToPolicyOptions(bool protected_vm_available) const {
  // Start from the compiled-in task-class table, then apply the operator's
  // ceilings. Nothing in the JSON can add a task class or relax a per-class
  // requirement.
  PolicyOptions options =
      IsolationPolicy::DefaultOptions(protected_vm_available, allow_debuggable_vm);
  options.max_concurrent_vms = max_concurrent_vms;
  options.memory_budget_mib = memory_budget_mib;
  options.allowed_uids = allowed_uids;
  options.instance_image_bytes = instance_image_bytes;
  return options;
}

IsolationService::Tunables DaemonConfig::ToTunables(bool debuggable_build) const {
  IsolationService::Tunables tunables;
  tunables.vm_launch_timeout_ms = vm_launch_timeout_ms;
  tunables.task_timeout_ms = task_timeout_ms;
  // Debuggable VMs need both: a build that is allowed to be debugged at all, and
  // an operator decision recorded in the config file. Neither alone is enough.
  tunables.debuggable_build = debuggable_build;
  return tunables;
}

std::string DaemonConfig::ToString() const {
  std::string uids;
  for (const int32_t uid : allowed_uids) {
    if (!uids.empty()) {
      uids += ",";
    }
    uids += std::to_string(uid);
  }
  return android::base::StringPrintf(
      "allow_debuggable_vm=%d max_concurrent_vms=%d memory_budget_mib=%lld "
      "instance_image_bytes=%lld allowed_uids=[%s] vm_launch_timeout_ms=%d task_timeout_ms=%d",
      allow_debuggable_vm ? 1 : 0, max_concurrent_vms,
      static_cast<long long>(memory_budget_mib), static_cast<long long>(instance_image_bytes),
      uids.c_str(), vm_launch_timeout_ms, task_timeout_ms);
}

}  // namespace xrom::avf
