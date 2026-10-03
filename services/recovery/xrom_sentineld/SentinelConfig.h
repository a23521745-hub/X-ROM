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

#ifndef XROM_SENTINELD_SENTINEL_CONFIG_H_
#define XROM_SENTINELD_SENTINEL_CONFIG_H_

#include <cstdint>
#include <string>
#include <vector>

#include "BootAttemptPolicy.h"
#include "QuarantinePlan.h"
#include "RecoveryDecision.h"

namespace xrom::sentinel {

// ---------------------------------------------------------------------------
// Operator-tunable settings, loaded from /system_ext/etc/xrom/sentinel.json.
//
// WHAT MAY AND MAY NOT BE CONFIGURED HERE
// ---------------------------------------
// This file holds ceilings, thresholds, paths and the list of uids allowed to
// report a threat. It does NOT hold anything that decides what is trusted: no key
// material, no trust anchors, no pinned digests. A configuration file on a
// writable partition that could relax a signature check would be a signature check
// that a single file write disables, so the keys stay compiled into the image and
// the recovery policy that references them stays in the recovery image too.
//
// Every value has a fail-secure default in the struct below, and the loader refuses
// to start the daemon on a malformed file rather than falling back to defaults
// silently. A daemon that boots with policy nobody chose is a daemon whose
// behaviour cannot be predicted from the shipped configuration.
// ---------------------------------------------------------------------------

struct SentinelConfig {
  // --- who may report a threat --------------------------------------------
  //
  // The sentinel writes the BCB, drops the network and reboots the device. That
  // authority is only safe if the set of callers is closed, so it is closed twice:
  // here by uid, and in sepolicy by domain. Both are needed. The uid check is what
  // the daemon can enforce on itself; the SELinux rule is what stops a process from
  // reaching the binder node at all, and survives a bug in the uid check.
  //
  // 1000 is system, which covers xrom_avfd's client path and any system component
  // that detects something. Deliberately NOT including shell on production builds:
  // an adb-reachable threat reporter is a remote reboot button.
  std::vector<uint32_t> reporter_uids = {1000};

  // Whether uid 0 (root) may report. Off by default: on a production build nothing
  // runs as root that should be reporting threats, and allowing it makes the uid
  // list decorative for anyone who gets root.
  bool allow_root_reporter = false;

  // Whether uid 2000 (shell) may report. Only ever true on a debuggable build, and
  // main.cpp forces it off otherwise regardless of what this file says.
  bool allow_shell_reporter = false;

  // --- quarantine behaviour ------------------------------------------------
  // Passed straight into BuildPlan(); see common/recovery/QuarantinePlan.h. The
  // defaults there are the ones this project argues for: a 30 second window at
  // HIGH, no window at CRITICAL, cancellation requiring an authenticated user.
  ::xrom::recovery::QuarantinePolicy quarantine;

  // --- boot-loop guard ------------------------------------------------------
  ::xrom::recovery::BootAttemptPolicy boot_attempts;

  // --- recovery decision engine ---------------------------------------------
  // Used by previewRecoveryDecision() and by the recovery gate. The pinned CIDRs
  // are weak by construction and can only push a decision toward the vault; see
  // correction #6 in docs/05.
  ::xrom::recovery::RecoveryPolicy recovery;

  // --- paths -----------------------------------------------------------------
  // The monitored directory that gets locked. Locked means the sentinel revokes
  // its own grant and records the lockdown in its state, so that restarting the
  // daemon does not quietly restore access.
  std::string monitored_dir = "/data/misc/xrom/inbox/";

  // Where the sentinel writes its own state and incident records.
  std::string state_dir = "/data/misc/xrom/sentinel/";

  // The vault IMAGE partition. Read-only to this daemon and writable by exactly one
  // domain, xrom_ota_installer. That property is enforced by a neverallow and is the
  // reason this device and the metadata device below are separate: SELinux labels
  // block devices and cannot distinguish one offset from another, so a record the
  // sentinel may write cannot live on a partition only the installer may write.
  std::string vault_block_device = "/dev/block/by-name/xrom_vault";

  // The vault METADATA partition: 64 KiB holding the VaultRecord, which is where the
  // sentinel's own boot-loop counter lives. See correction #5 in docs/05.
  std::string vault_meta_block_device = "/dev/block/by-name/xrom_vault_meta";

  // Where the record sits inside the metadata partition. Offset 0, one record.
  uint64_t vault_record_offset = 0;

  // --- integrity check -------------------------------------------------------
  // Whether to run the post-boot vault comparison on every boot. Off only for
  // bring-up; the whole point of the check is that it runs when nobody thinks to
  // run it.
  bool check_integrity_on_boot = true;

  // Whether the boot-time comparison also reads both partitions in full
  // (IntegrityDepth::kDeep). Off by default and deliberately so: it is gigabytes of
  // flash I/O on the boot path and duplicates work dm-verity already does on every
  // read. See correction #9 in docs/05.
  bool deep_integrity_on_boot = false;

  // --- network quarantine ----------------------------------------------------
  // Layers to attempt, in order. Each is attempted independently and each reports
  // its own result, so a layer that fails is recorded as a degradation rather than
  // being assumed to have worked. A silently failed network cut is an uncut
  // network. See correction #10 in docs/05.
  bool use_netd_firewall_chain = true;

  // Bring the interfaces administratively down with SIOCSIFFLAGS. Requires
  // CAP_NET_ADMIN, granted in sepolicy, and is the one layer that works when netd
  // does not — which on this kernel is an open question rather than an assumption,
  // because CONFIG_BPF_SYSCALL is off and netd uses eBPF for parts of its own
  // operation. See correction #10 in docs/05.
  bool use_interface_down = true;

  bool use_quarantine_property = true;

  // The netd OEM firewall chain index to use, 1..3. netd exposes a small number of
  // OEM chains for exactly this purpose; X-ROM claims one rather than reusing the
  // dozable/standby chains, which have their own semantics and their own owners.
  int32_t netd_oem_chain = 1;

  // --- evidence preservation ---------------------------------------------------
  // Whether to hand the incident log to a protected VM after staging it.
  //
  // DEFAULT FALSE, AND THAT IS A CONFLICT IN THE REQUIREMENTS RATHER THAN AN
  // OVERSIGHT. Moving evidence into a pVM means submitting a task through
  // IXIsolationService, and submitting a task means naming a TaskClass. There is no
  // TaskClass for evidence stashing, and TaskClass is part of the frozen isolation
  // AIDL that this project is explicitly constrained not to change. Repurposing one
  // of the classes the payload already serves would mean the evidence log is
  // processed by code that expects something else entirely, which is worse than not
  // sending it.
  //
  // So the shipped behaviour is: the evidence is staged to staging_log_path with mode
  // 0600 and its SHA-256 recorded, which is real and which survives the reboot, and
  // the pVM handoff is reported as unavailable with the reason. When the isolation
  // AIDL is next unfrozen, adding the class turns this flag on and nothing else
  // changes. See correction #14 in docs/05.
  bool stash_evidence_in_pvm = false;

  // How long to wait for the VM. The quarantine sequence is bounded overall, and a
  // VM that takes two minutes to start is worse than evidence left on /data.
  int32_t evidence_vm_timeout_ms = 8000;

  // --- reboot -------------------------------------------------------------------
  // How the device is rebooted. "recovery" goes through android::sys.powerctl, which
  // is the supported path and is what lets init shut services down in order.
  std::string reboot_target = "recovery";

  // Refuse to reboot when the battery is below this. A device that dies mid-reboot
  // with an armed BCB is a device whose next boot behaviour nobody predicted, and
  // waiting for a charger is the safer state. Zero disables the check, which is
  // what a device with no battery reporting needs.
  uint32_t min_battery_percent_for_reboot = 5;
};

struct ConfigLoadResult {
  bool ok = false;
  SentinelConfig config;
  // Every problem found, matching the convention used by IsolationPolicy,
  // PayloadManifest and the OTA manifest: a loader that leaks one error at a time
  // turns a misconfigured device into a loop of edit-reboot-read-log.
  std::vector<std::string> errors;

  std::string Describe() const;
};

// Reads and validates the configuration. |path| is a parameter rather than a
// constant so that the recovery gate and the host tools can load a different file
// without duplicating the parsing.
//
// A missing file is NOT an error: the defaults above are the shipped policy, and a
// build without the file behaves exactly as documented. A file that exists and does
// not parse IS an error, because that is a configuration somebody wrote and got
// wrong, and guessing what they meant is how a security policy ends up looser than
// intended.
ConfigLoadResult LoadConfig(const std::string& path);

// Whether a uid may report a threat under this configuration. Split out from the
// binder method so that the authorisation rule can be stated and tested in one
// place instead of being spread across a service implementation.
bool IsAuthorisedReporter(const SentinelConfig& config, uint32_t calling_uid,
                          bool debuggable_build);

}  // namespace xrom::sentinel

#endif  // XROM_SENTINELD_SENTINEL_CONFIG_H_
