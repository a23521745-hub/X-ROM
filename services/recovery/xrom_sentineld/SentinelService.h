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

#ifndef XROM_SENTINELD_SENTINEL_SERVICE_H_
#define XROM_SENTINELD_SENTINEL_SERVICE_H_

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <aidl/android/xrom/recovery/BnXRecoveryService.h>
#include <binder/IBinder.h>

#include "PlatformActions.h"
#include "SentinelConfig.h"

namespace xrom::sentinel {

// ---------------------------------------------------------------------------
// The binder service and the executor that runs a quarantine plan.
//
// THE SPLIT, AND WHY IT IS HERE AND NOT IN THE PURE CORE
// ------------------------------------------------------
// common/recovery decides what should happen: BuildPlan() turns a severity and a
// policy into an ordered list of steps, and EvaluateCancelRequest() decides whether
// a cancellation may be honoured. Both are pure and both are tested.
//
// This class does the other half — it performs the steps. That cannot be pure,
// because performing them means writing /misc, dropping the network and rebooting,
// and a function that does those things is not a function that can be called twice
// in a test.
//
// So the rule this file follows is that it contains no decision of its own. It reads
// the plan, executes each step, records what happened, and consults the pure core
// whenever a choice arises. If you find an `if` in here that decides policy rather
// than reporting a result, it belongs in common/recovery with a test next to it.
//
// WHY AN UNAUTHORISED CALLER GETS A RESULT RATHER THAN AN EXCEPTION
// -----------------------------------------------------------------
// Every method returns normally with accepted=false and a reason, instead of
// throwing a binder SecurityException. A thrown exception arrives at the caller as a
// binder death or a status code, and the attempt is then recorded only in the caller's
// own log — which is the log of the process that just tried to reboot the device. A
// returned result is written to the sentinel's log by the sentinel, in the incident
// record, where it survives the caller and survives a wipe.
// ---------------------------------------------------------------------------

class SentinelService : public ::aidl::android::xrom::recovery::BnXRecoveryService {
 public:
  SentinelService(SentinelConfig config, bool debuggable_build);

  // --- IXRecoveryService ---------------------------------------------------
  ::ndk::ScopedAStatus reportThreat(
      const ::aidl::android::xrom::recovery::ThreatReport& report,
      ::aidl::android::xrom::recovery::QuarantineOutcome* outcome) override;

  ::ndk::ScopedAStatus cancelPendingQuarantine(const std::string& cancel_token,
                                               bool user_confirmed,
                                               bool* cancelled) override;

  ::ndk::ScopedAStatus checkVaultIntegrity(
      bool deep, ::aidl::android::xrom::recovery::IntegrityReportInfo* report) override;

  ::ndk::ScopedAStatus getVaultStatus(
      ::aidl::android::xrom::recovery::VaultStatus* status) override;

  ::ndk::ScopedAStatus getBootLoopStatus(
      ::aidl::android::xrom::recovery::BootLoopStatus* status) override;

  ::ndk::ScopedAStatus previewRecoveryDecision(
      ::aidl::android::xrom::recovery::RecoveryPreview* preview) override;

  ::ndk::ScopedAStatus armRecoveryBoot(const std::string& reason, bool* armed) override;

  // --- boot-time work --------------------------------------------------------
  // Runs the post-boot integrity comparison and the boot-loop guard. Called by
  // main() before the thread pool starts, so that a device which should not have
  // come up at all does not spend its first seconds serving binder calls.
  void RunBootChecks();

  // The boot-loop decision made by RunBootChecks(), kept so that getBootLoopStatus()
  // can report it without re-deriving it — and so that a second call cannot produce
  // a different answer from the one that was acted on.
  ::xrom::recovery::BootLoopDecision boot_loop_decision() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return boot_loop_decision_;
  }

 private:
  // Performs one step of the plan. Returns true when the step succeeded. The plan's
  // own OnFailure says what to do when it does not, and that decision is made by the
  // caller rather than here so that the sequence stays readable top to bottom.
  bool ExecuteStep(const ::xrom::recovery::Step& step, const std::string& incident_id,
                   std::string* detail);

  // Whether the calling uid may report a threat. Delegates to the free function in
  // SentinelConfig so that the rule is stated once.
  bool Authorised(uint32_t calling_uid) const;

  // Writes an incident record under state_dir. Best-effort and never fatal: the
  // incident log is what makes a quarantine diagnosable afterwards, but a failure to
  // write it must not stop the response, or a full /data would disable the security
  // mechanism that exists for exactly the situations where /data is misbehaving.
  void LogIncident(const std::string& incident_id, const std::string& line) const;

  std::string NewIncidentId() const;
  std::string NewCancelToken() const;

  SentinelConfig config_;
  bool debuggable_build_;

  std::unique_ptr<BcbWriter> bcb_;
  std::unique_ptr<NetworkQuarantine> network_;
  std::unique_ptr<VaultPartition> vault_;

  // Guards the pending-quarantine state and the boot-loop decision. Held only for
  // short bookkeeping sections, never across a binder call or a reboot: a mutex held
  // while the device goes down is a mutex that can deadlock the shutdown.
  mutable std::mutex mutex_;

  struct Pending {
    bool active = false;
    std::string cancel_token;
    int64_t deadline_unix = 0;
    std::string incident_id;
    ::xrom::recovery::ThreatSeverity severity = ::xrom::recovery::ThreatSeverity::kLow;
  };
  Pending pending_;

  ::xrom::recovery::SlotSnapshot slot_snapshot_;
  ::xrom::recovery::BootLoopDecision boot_loop_decision_;
  uint32_t integrity_failures_ = 0;
  int64_t incident_counter_ = 0;
};

}  // namespace xrom::sentinel

#endif  // XROM_SENTINELD_SENTINEL_SERVICE_H_
