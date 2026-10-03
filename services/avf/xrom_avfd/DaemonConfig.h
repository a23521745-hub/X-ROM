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

#ifndef XROM_AVF_DAEMON_CONFIG_H_
#define XROM_AVF_DAEMON_CONFIG_H_

#include <cstdint>
#include <string>
#include <vector>

#include "IsolationPolicy.h"
#include "IsolationService.h"

namespace xrom::avf {

// Operator-tunable ceilings, loaded from /system_ext/etc/xrom/avf.json.
//
// Two things are deliberately NOT in this file:
//
//   * The per-task-class table (payload binary, per-class memory and vCPU
//     ceilings, whether a class needs a protected VM) is compiled into
//     IsolationPolicy::DefaultOptions(). Changing it should require a signed
//     image update, not an edit to a config file.
//   * Anything that describes an immutable build fact. Those are system
//     properties (ro.xrom.avf.*), because they are set by the build and never
//     read back.
//
// Everything here is a ceiling an operator may want to lower on a specific
// product, so this file may only ever make the policy stricter than the
// compiled-in defaults. Values above the compiled-in maximum are clamped, not
// honoured.
struct DaemonConfig {
  // Hard maximums, independent of what the JSON asks for.
  static constexpr int32_t kMaxConcurrentVmsLimit = 4;
  static constexpr int64_t kMemoryBudgetLimitMib = 4096;
  static constexpr int64_t kInstanceImageLimitBytes = 512LL * 1024 * 1024;
  static constexpr int32_t kLaunchTimeoutLimitMs = 120000;
  static constexpr int32_t kTaskTimeoutLimitMs = 600000;

  bool allow_debuggable_vm = false;
  int32_t max_concurrent_vms = 1;
  int64_t memory_budget_mib = 512;
  int64_t instance_image_bytes = 64LL * 1024 * 1024;
  std::vector<int32_t> allowed_uids = {1000};  // AID_SYSTEM
  int32_t vm_launch_timeout_ms = 30000;
  int32_t task_timeout_ms = 120000;

  // The values used when the config file is missing, unreadable or malformed.
  // Strictly more restrictive than anything the JSON can ask for, so a failure
  // to load configuration degrades capability rather than widening it.
  static DaemonConfig FailSafeDefaults();

  // Reads and validates |path|. On any problem returns FailSafeDefaults() and
  // sets |error|; it never returns a partially applied file.
  static DaemonConfig Load(const std::string& path, std::string* error);

  PolicyOptions ToPolicyOptions(bool protected_vm_available) const;
  IsolationService::Tunables ToTunables(bool debuggable_build) const;

  std::string ToString() const;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_DAEMON_CONFIG_H_
