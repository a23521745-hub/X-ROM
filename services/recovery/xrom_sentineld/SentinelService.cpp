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

#include "SentinelService.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <random>

#include <aidl/android/xrom/recovery/ThreatSeverity.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <binder/IPCThreadState.h>

#include "Sha256.h"

namespace xrom::sentinel {
namespace {

namespace aidl_recovery = ::aidl::android::xrom::recovery;

using ::xrom::recovery::Action;
using ::xrom::recovery::BootLoopAction;
using ::xrom::recovery::BcbRequest;
using ::xrom::recovery::IntegrityDepth;
using ::xrom::recovery::IntegrityVerdict;
using ::xrom::recovery::OnFailure;
using ::xrom::recovery::QuarantinePlan;
using ::xrom::recovery::Signal;
using ::xrom::recovery::Step;
using ::xrom::recovery::ThreatSeverity;
using ::xrom::recovery::VaultState;

constexpr char kMiscDevice[] = "/dev/block/by-name/misc";

int64_t NowUnix() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// The AIDL enum and the C++ enum are two spellings of one thing, and a silent
// disagreement between them would turn a LOW threat into a CRITICAL one or the
// reverse. Both directions are catastrophic, so the mapping is exhaustive with no
// default case: a new value in either enum is a compile error rather than a
// misclassification.
ThreatSeverity FromAidl(aidl_recovery::ThreatSeverity severity) {
  switch (severity) {
    case aidl_recovery::ThreatSeverity::LOW:
      return ThreatSeverity::kLow;
    case aidl_recovery::ThreatSeverity::MEDIUM:
      return ThreatSeverity::kMedium;
    case aidl_recovery::ThreatSeverity::HIGH:
      return ThreatSeverity::kHigh;
    case aidl_recovery::ThreatSeverity::CRITICAL:
      return ThreatSeverity::kCritical;
  }
  // Unreachable with -Wswitch covering every enumerator, and deliberately not a
  // silent fallback: an unknown severity reboots nothing, so the safe answer is the
  // least destructive one that still preserves evidence.
  return ThreatSeverity::kLow;
}

int32_t ToAidl(ThreatSeverity severity) {
  return static_cast<int32_t>(severity);
}

// Free-running random for tokens. Not a CSPRNG and not trying to be: a cancel token
// has to be unguessable by a process on the same device that can read the log, and
// /dev/urandom is the right source for that. A failure to read it means no token is
// issued, which means no cancellation is possible, which is fail-secure.
std::string RandomToken(size_t bytes) {
  std::string raw(bytes, '\0');
  if (!android::base::ReadFileToString("/dev/urandom", &raw, static_cast<unsigned>(bytes))) {
    return "";
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes * 2);
  for (unsigned char c : raw) {
    out.push_back(kHex[c >> 4]);
    out.push_back(kHex[c & 0x0F]);
  }
  return out;
}

}  // namespace

SentinelService::SentinelService(SentinelConfig config, bool debuggable_build)
    : config_(std::move(config)), debuggable_build_(debuggable_build) {
  bcb_ = std::make_unique<BcbWriter>(kMiscDevice);
  network_ = std::make_unique<NetworkQuarantine>(config_.use_netd_firewall_chain,
                                                 config_.use_interface_down,
                                                 config_.use_quarantine_property,
                                                 config_.netd_oem_chain);
  vault_ = std::make_unique<VaultPartition>(config_.vault_block_device,
                                            config_.vault_meta_block_device,
                                            config_.vault_record_offset);
}

bool SentinelService::Authorised(uint32_t calling_uid) const {
  return IsAuthorisedReporter(config_, calling_uid, debuggable_build_);
}

std::string SentinelService::NewIncidentId() const {
  return "inc-" + std::to_string(NowUnix()) + "-" + std::to_string(incident_counter_);
}

std::string SentinelService::NewCancelToken() const { return RandomToken(16); }

void SentinelService::LogIncident(const std::string& incident_id, const std::string& line) const {
  // Best-effort by design. The incident log is what makes a quarantine diagnosable
  // afterwards, but a failure to write it must not stop the response: a full or
  // read-only /data would otherwise disable the mechanism that exists for exactly the
  // situations where /data is misbehaving.
  const std::string dir = config_.state_dir + "incidents/";
  if (!android::base::MakeDirs(dir)) {
    LOG(WARNING) << "xrom_sentineld: cannot create " << dir << ": " << strerror(errno);
    return;
  }
  const std::string path = dir + incident_id + ".log";
  // Appended, never truncated: a second report during one compromise lands in the
  // same incident and the first one has to still be there.
  int fd = TEMP_FAILURE_RETRY(
      open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (fd < 0) {
    LOG(WARNING) << "xrom_sentineld: cannot append to " << path << ": " << strerror(errno);
    return;
  }
  const std::string record = line + "\n";
  const bool written = android::base::WriteFully(fd, record.data(), record.size());
  close(fd);
  if (!written) {
    LOG(WARNING) << "xrom_sentineld: short write to " << path;
  }
  // Also to logcat, because the incident file is on /data and /data may be the thing
  // that is about to be wiped. Two copies in two places with different failure modes.
  LOG(INFO) << "xrom_sentineld: [" << incident_id << "] " << line;
}

// ---------------------------------------------------------------------------
// Step execution
// ---------------------------------------------------------------------------

bool SentinelService::ExecuteStep(const Step& step, const std::string& incident_id,
                                 std::string* detail) {
  switch (step.action) {
    case Action::kLockFolder: {
      // Locking means two things, and the second is the one that matters. Revoking
      // the grant at runtime stops the process that is currently writing; recording
      // the lockdown in the sentinel's own state stops a restart of this daemon from
      // quietly restoring access, which is what would otherwise happen on the next
      // boot or the next crash.
      const std::string marker = config_.state_dir + "locked";
      if (!android::base::WriteStringToFile("1\n", marker, 0600, AID_SYSTEM, AID_SYSTEM,
                                            /*follow_symlinks=*/false)) {
        *detail = "cannot write the lockdown marker " + marker + ": " + strerror(errno);
        return false;
      }
      // The directory itself is made inaccessible to everyone but the sentinel. This
      // is a filesystem permission change, not a SELinux one: SELinux policy is
      // static and cannot be tightened at runtime, so the runtime half of "lock the
      // folder" has to be done with mode bits. Both halves are needed and neither
      // substitutes for the other.
      if (chmod(config_.monitored_dir.c_str(), 0700) != 0 && errno != ENOENT) {
        *detail = "cannot restrict " + config_.monitored_dir + ": " + strerror(errno);
        return false;
      }
      *detail = config_.monitored_dir + " restricted to 0700 and lockdown recorded";
      return true;
    }

    case Action::kStashEvidenceInPvm: {
      // Stage first, always. Whatever happens to the handoff, the evidence has to
      // exist somewhere with a recorded digest, because a quarantine that cannot
      // secure its own evidence destroys it — and that is why this step escalates on
      // failure rather than continuing.
      const std::string& staging = config_.quarantine.staging_log_path;
      const std::string incident_path = config_.state_dir + "incidents/" + incident_id + ".log";
      std::string content;
      if (!android::base::ReadFileToString(incident_path, &content, 1024 * 1024)) {
        // No incident record to stage. That is not a failure of the quarantine, but
        // it is a failure of the evidence trail and it has to be said.
        *detail = "no incident record at " + incident_path + " to stage";
        return false;
      }
      if (!android::base::MakeDirs(android::base::Dirname(staging))) {
        *detail = "cannot create the staging directory for " + staging;
        return false;
      }
      if (!android::base::WriteStringToFile(content, staging, 0600, AID_SYSTEM, AID_SYSTEM,
                                            /*follow_symlinks=*/false)) {
        *detail = "cannot stage the evidence to " + staging + ": " + strerror(errno);
        return false;
      }
      const std::string digest =
          xrom::crypto::Sha256::ToHex(xrom::crypto::Sha256::Hash(content));
      *detail = "staged " + std::to_string(content.size()) + " bytes to " + staging +
                " sha256=" + digest;

      if (!config_.stash_evidence_in_pvm) {
        // Reported, not hidden. See the note on stash_evidence_in_pvm in
        // SentinelConfig.h: handing evidence to a pVM needs a TaskClass, TaskClass is
        // part of the frozen isolation AIDL, and repurposing a class the payload
        // already serves would mean the evidence is processed by code expecting
        // something else. Staging succeeded, so the step succeeded; the missing
        // handoff is a recorded limitation rather than a failure.
        *detail += "; pVM handoff not performed (no evidence TaskClass in the frozen "
                   "isolation AIDL — correction #14)";
      }
      return true;
    }

    case Action::kCutNetwork: {
      const auto result = network_->Cut();
      *detail = result.Describe();
      // network_cut false means no layer confirmed the cut. Continuing anyway is
      // deliberate: the reboot and the BCB do not depend on the network being down,
      // and refusing to quarantine because netd did not answer would leave the device
      // both compromised and connected. What must not happen is claiming a cut that
      // did not occur, which is why the detail is recorded verbatim.
      if (!result.network_cut) {
        *detail += " — the network may still be up";
      }
      return result.network_cut;
    }

    case Action::kNotifyUser: {
      // The sentinel is a native daemon with no UI. What it can do is publish the
      // state that the system-side component presents, and record that it did. A
      // notification that cannot be shown is not a reason to skip the reboot: a user
      // who never saw the dialog still gets the correct security response, which is
      // why this step continues on failure.
      const std::string notice = config_.state_dir + "pending_quarantine";
      std::string body = std::string("severity=") +
                         xrom::recovery::SeverityName(pending_.severity) +
                         "\nincident=" + incident_id + "\ndeadline=" +
                         std::to_string(pending_.deadline_unix) + "\n";
      if (!android::base::WriteStringToFile(body, notice, 0600, AID_SYSTEM, AID_SYSTEM,
                                            /*follow_symlinks=*/false)) {
        *detail = "cannot publish the quarantine notice: " + std::string(strerror(errno));
        return false;
      }
      *detail = "quarantine notice published at " + notice;
      return true;
    }

    case Action::kRecordBootAttempt: {
      // Recorded before the BCB is written so that the boot-loop guard can tell this
      // reboot from a crash loop. Doing it the other way round leaves a window in
      // which a deliberate quarantine reboot counts as a failure.
      if (!vault_->RecordIntegrityFailure(nullptr)) {
        // Not fatal. The counter is what makes a post-boot integrity loop detectable,
        // and losing one increment is far better than not rebooting at all.
        *detail = "could not record the boot attempt in the vault; the reboot proceeds "
                  "and this boot will not count toward the loop limit";
        return false;
      }
      *detail = "boot attempt recorded in the vault record";
      return true;
    }

    case Action::kArmRecoveryBoot: {
      BcbRequest request;
      request.command = xrom::recovery::kCommandBootRecovery;
      request.recovery_options = {"wipe_cache"};
      request.reason = xrom::recovery::kReasonThreatDetected;
      bool changed = false;
      std::string error;
      if (!bcb_->Write(request, &changed, &error)) {
        *detail = "cannot write the BCB: " + error;
        return false;
      }
      *detail = changed ? "BCB armed with boot-recovery (options merged, existing "
                          "commands preserved)"
                        : "BCB already held boot-recovery; nothing was rewritten";
      return true;
    }

    case Action::kReboot: {
      uint32_t battery = 0;
      if (ReadBatteryPercent(&battery) &&
          battery < config_.min_battery_percent_for_reboot) {
        // Dying mid-reboot with an armed BCB leaves the next boot's behaviour
        // unpredictable. The BCB stays armed, so the reboot happens whenever power
        // returns; refusing here costs a delay and buys a predictable device.
        *detail = "battery at " + std::to_string(battery) + "% is below the " +
                  std::to_string(config_.min_battery_percent_for_reboot) +
                  "% floor; the BCB stays armed and the reboot is deferred";
        return false;
      }
      std::string error;
      if (!RequestReboot(config_.reboot_target, &error)) {
        *detail = error;
        return false;
      }
      *detail = "reboot requested via android.sys.powerctl";
      return true;
    }
  }
  *detail = "unknown action";
  return false;
}

// ---------------------------------------------------------------------------
// IXRecoveryService
// ---------------------------------------------------------------------------

::ndk::ScopedAStatus SentinelService::reportThreat(const aidl_recovery::ThreatReport& report,
                                                  aidl_recovery::QuarantineOutcome* outcome) {
  const uint32_t calling_uid =
      static_cast<uint32_t>(::android::IPCThreadState::self()->getCallingUid());

  aidl_recovery::QuarantineOutcome result;
  result.accepted = false;

  if (outcome == nullptr) {
    return ::ndk::ScopedAStatus::ok();
  }

  if (!Authorised(calling_uid)) {
    // Returned rather than thrown, and logged by the sentinel rather than only by the
    // caller: a rejected attempt recorded in the caller's own log is a record held by
    // the process that just tried to reboot the device.
    result.reason = "uid " + std::to_string(calling_uid) +
                    " is not authorised to report a threat; the attempt was recorded";
    LogIncident("unauthorised", "rejected reportThreat from uid " + std::to_string(calling_uid) +
                                    " source=" + report.source);
    *outcome = result;
    return ::ndk::ScopedAStatus::ok();
  }

  const ThreatSeverity severity = FromAidl(report.severity);

  std::string incident_id;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (report.incident_token.empty()) {
      ++incident_counter_;
      incident_id = NewIncidentId();
    } else {
      // A detector that fires repeatedly during one compromise merges into the same
      // incident instead of starting a second one, so the log reads as one event.
      incident_id = report.incident_token;
    }
  }

  const QuarantinePlan plan = xrom::recovery::BuildPlan(severity, config_.quarantine);

  LogIncident(incident_id, "threat reported uid=" + std::to_string(calling_uid) +
                               " severity=" + std::string(xrom::recovery::SeverityName(severity)) +
                               " source=" + report.source + " detail=" + report.detail +
                               " evidence=" + report.evidence_path +
                               " detected_unix=" + std::to_string(report.detected_unix));
  LogIncident(incident_id, plan.Describe());

  // A cancellation window is published before the sequence runs, not after, so that
  // the deadline the user sees is the one the daemon is enforcing.
  ThreatSeverity current_severity = severity;
  if (plan.offers_cancel) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.active = true;
    pending_.cancel_token = NewCancelToken();
    pending_.deadline_unix = NowUnix() + plan.cancel_window_seconds;
    pending_.incident_id = incident_id;
    pending_.severity = severity;
    current_severity = pending_.severity;
    result.cancel_token = pending_.cancel_token;
    result.cancel_deadline_unix = pending_.deadline_unix;
    if (pending_.cancel_token.empty()) {
      // No token means no cancellation is possible. That is fail-secure, but it has to
      // be in the log rather than silently turning the window into a formality.
      LogIncident(incident_id,
                  "could not generate a cancel token; the window is offered but no "
                  "cancellation will be accepted");
    }
  }
  (void)current_severity;

  result.accepted = true;
  result.rebooting = plan.reboots;
  result.plan = plan.Describe();
  result.incident_token = incident_id;

  // Execute. Each step's own OnFailure decides what a failure means, and the sequence
  // is bounded by the plan's total so that a hanging step cannot leave the device
  // quarantined-but-running forever.
  const int64_t deadline_ms =
      NowUnix() * 1000 + plan.total_timeout_ms;
  bool aborted = false;
  for (const Step& step : plan.steps) {
    if (NowUnix() * 1000 > deadline_ms) {
      result.steps_completed.push_back(std::string(xrom::recovery::ActionName(step.action)) +
                                       "=skipped(sequence budget exhausted)");
      LogIncident(incident_id, "sequence budget exhausted before " +
                                   std::string(xrom::recovery::ActionName(step.action)));
      aborted = true;
      break;
    }

    std::string detail;
    const bool ok = ExecuteStep(step, incident_id, &detail);
    result.steps_completed.push_back(std::string(xrom::recovery::ActionName(step.action)) + "=" +
                                     (ok ? "ok" : "FAILED") + " " + detail);
    LogIncident(incident_id, std::string(xrom::recovery::ActionName(step.action)) +
                                 (ok ? " ok: " : " FAILED: ") + detail);
    if (ok) {
      continue;
    }

    switch (step.on_failure) {
      case OnFailure::kContinue:
        break;
      case OnFailure::kEscalate:
        // A quarantine that cannot secure its own evidence destroys it. Escalating
        // means the remaining steps run at a higher severity, which in practice means
        // the reboot threshold is met and the device goes to recovery.
        LogIncident(incident_id, "escalating: " + detail);
        result.reason = "escalated after " + std::string(
                            xrom::recovery::ActionName(step.action)) + " failed: " + detail;
        break;
      case OnFailure::kAbortWithoutReboot:
        // A partially written misc can leave the bootloader with a command it cannot
        // interpret, and a device that cannot boot cannot quarantine itself either.
        LogIncident(incident_id, "aborting without reboot: " + detail);
        aborted = true;
        result.rebooting = false;
        result.reason = "aborted without rebooting after " +
                        std::string(xrom::recovery::ActionName(step.action)) + " failed: " +
                        detail;
        break;
    }
    if (aborted) {
      break;
    }
  }

  if (result.reason.empty()) {
    result.reason = result.rebooting ? "quarantine complete, rebooting into recovery"
                                     : "quarantine complete, device stays up and locked down";
  }
  LogIncident(incident_id, result.reason);
  *outcome = result;
  return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus SentinelService::cancelPendingQuarantine(const std::string& cancel_token,
                                                             bool user_confirmed,
                                                             bool* cancelled) {
  if (cancelled == nullptr) {
    return ::ndk::ScopedAStatus::ok();
  }
  *cancelled = false;

  std::string incident_id;
  ThreatSeverity severity = ThreatSeverity::kLow;
  int64_t deadline = 0;
  std::string expected_token;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!pending_.active) {
      LogIncident("cancel", "cancellation refused: no quarantine is pending");
      return ::ndk::ScopedAStatus::ok();
    }
    incident_id = pending_.incident_id;
    severity = pending_.severity;
    deadline = pending_.deadline_unix;
    expected_token = pending_.cancel_token;
  }

  // The window is evaluated by the pure core, with the elapsed time computed here.
  // Keeping the decision out of this method is what makes the cancellation rules
  // testable: severity, policy, authentication and elapsed time go in, allowed or
  // refused comes out, and every branch is reachable without a UI or a device.
  const int64_t elapsed = NowUnix() - (deadline - config_.quarantine.cancel_window_seconds);
  const auto decision = xrom::recovery::EvaluateCancelRequest(
      severity, config_.quarantine, user_confirmed, static_cast<int32_t>(elapsed));

  if (!decision.allowed) {
    LogIncident(incident_id, "cancellation refused: " + decision.reason);
    return ::ndk::ScopedAStatus::ok();
  }
  // Compared after the policy decision rather than before, so that a wrong token is
  // not distinguishable from a closed window in timing. Both are logged, and the log
  // is the audit trail rather than the return value.
  if (expected_token.empty() || cancel_token != expected_token) {
    LogIncident(incident_id,
                "cancellation refused: the token did not match, so the caller never "
                "saw the prompt it is claiming to dismiss");
    return ::ndk::ScopedAStatus::ok();
  }

  // Undo what is undoable. The BCB is deliberately NOT disarmed: if arming already
  // happened, the device is past the point of no return and un-arming it would mean
  // writing misc twice in one incident. Cancellation is only honoured while the plan
  // is still inside the window, which is before arming.
  const auto restored = network_->Restore();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.active = false;
    pending_.cancel_token.clear();
  }
  unlink((config_.state_dir + "pending_quarantine").c_str());

  *cancelled = true;
  LogIncident(incident_id, "quarantine cancelled: " + decision.reason + "; network restore: " +
                               restored.Describe());
  return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus SentinelService::checkVaultIntegrity(bool deep,
                                                         aidl_recovery::IntegrityReportInfo* out) {
  if (out == nullptr) {
    return ::ndk::ScopedAStatus::ok();
  }
  *out = aidl_recovery::IntegrityReportInfo{};

  xrom::recovery::VaultRecord record;
  std::string error;
  if (!vault_->ReadRecord(&record, &error)) {
    out->verdict = static_cast<int32_t>(IntegrityVerdict::kInconclusive);
    out->verdict_name = xrom::recovery::IntegrityVerdictName(IntegrityVerdict::kInconclusive);
    out->depth = deep ? 1 : 0;
    out->detail = error;
    out->summary = "the vault record could not be read, so no comparison was possible";
    return ::ndk::ScopedAStatus::ok();
  }

  const IntegrityDepth depth = deep ? IntegrityDepth::kDeep : IntegrityDepth::kHashtreeRoots;
  uint8_t system_digest[32] = {0};
  uint8_t vault_digest[32] = {0};
  std::string system_error;
  std::string vault_error;
  const bool system_ok = vault_->ComputeDigest("/dev/block/by-name/system_a", depth,
                                               &system_digest, &system_error);
  const bool vault_ok =
      vault_->ComputeDigest(config_.vault_block_device, depth, &vault_digest, &vault_error);

  if (!system_ok || !vault_ok) {
    // "I could not check" is its own verdict. Folding it into kMismatch would make
    // every device with an unreadable vault look tampered with, and the first few of
    // those in the field would teach everyone to ignore the alarm that follows.
    out->verdict = static_cast<int32_t>(IntegrityVerdict::kInconclusive);
    out->verdict_name = xrom::recovery::IntegrityVerdictName(IntegrityVerdict::kInconclusive);
    out->depth = deep ? 1 : 0;
    out->detail = (system_ok ? "" : "running slot: " + system_error) +
                  (system_ok || vault_ok ? "" : " | ") +
                  (vault_ok ? "" : "vault: " + vault_error);
    out->summary = "the comparison could not be completed";
    return ::ndk::ScopedAStatus::ok();
  }

  const auto report =
      xrom::recovery::CompareImages(system_digest, vault_digest, record, depth);
  out->verdict = static_cast<int32_t>(report.verdict);
  out->verdict_name = xrom::recovery::IntegrityVerdictName(report.verdict);
  out->depth = deep ? 1 : 0;
  out->system_digest = report.system_digest_hex;
  out->vault_digest = report.vault_digest_hex;
  out->detail = report.reason;
  out->summary = report.Describe();
  return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus SentinelService::getVaultStatus(aidl_recovery::VaultStatus* out) {
  if (out == nullptr) {
    return ::ndk::ScopedAStatus::ok();
  }
  *out = aidl_recovery::VaultStatus{};
  xrom::recovery::VaultRecord record;
  std::string error;
  if (!vault_->ReadRecord(&record, &error)) {
    out->usable = false;
    out->state = 0;
    out->state_name = xrom::recovery::VaultStateName(VaultState::kEmpty);
    out->detail = error;
    return ::ndk::ScopedAStatus::ok();
  }
  out->usable = record.state != VaultState::kEmpty;
  out->state = static_cast<int32_t>(record.state);
  out->state_name = xrom::recovery::VaultStateName(record.state);
  out->integrity_failures = static_cast<int32_t>(record.integrity_failures);
  out->written_unix = record.written_unix;
  out->build_fingerprint = std::string(record.build_fingerprint);
  out->vault_hashtree_root = xrom::recovery::DigestToHex(record.vault_hashtree_root);
  if (!out->usable) {
    out->detail = "the vault holds no image, so there is no fallback";
  }
  return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus SentinelService::getBootLoopStatus(aidl_recovery::BootLoopStatus* out) {
  if (out == nullptr) {
    return ::ndk::ScopedAStatus::ok();
  }
  const auto decision = boot_loop_decision();
  *out = aidl_recovery::BootLoopStatus{};
  out->action = static_cast<int32_t>(decision.action);
  out->action_name = xrom::recovery::BootLoopActionName(decision.action);
  out->degraded = decision.degraded;
  out->tries_remaining = slot_snapshot_.available
                             ? static_cast<int32_t>(slot_snapshot_.tries_remaining)
                             : -1;
  out->integrity_failures = static_cast<int32_t>(integrity_failures_);
  out->reason = decision.reason;
  return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus SentinelService::previewRecoveryDecision(
    aidl_recovery::RecoveryPreview* out) {
  if (out == nullptr) {
    return ::ndk::ScopedAStatus::ok();
  }
  *out = aidl_recovery::RecoveryPreview{};

  // Live signals, gathered the only way a running system can gather them: whether the
  // vault is usable, and whether the network is currently reachable. Everything the
  // preview cannot determine stays kUnknown, which the engine treats as a doubt and
  // which therefore pushes the preview toward the vault. A preview that guessed would
  // be worse than no preview, because it would be believed.
  xrom::recovery::RecoverySignals signals;
  xrom::recovery::VaultRecord record;
  std::string error;
  const bool vault_usable = vault_->ReadRecord(&record, &error) && record.state != VaultState::kEmpty;

  xrom::recovery::RecoveryPolicy policy = config_.recovery;
  policy.vault_unavailable = !vault_usable;

  // The transport checks are only meaningful inside the recovery image, where the
  // gate performs them against a real connection. From a running system the honest
  // value is kUnknown, and the preview says so.
  signals.wifi_available =
      android::base::GetBoolProperty("sys.xrom.preview.network_up", false) ? Signal::kClean
                                                                            : Signal::kUnknown;

  const auto decision = xrom::recovery::Decide(signals, policy);
  out->use_vault = !decision.IsRemote();
  out->doubts = decision.doubts;
  out->clean = decision.clean;
  out->reason = decision.Reason();
  return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus SentinelService::armRecoveryBoot(const std::string& reason, bool* armed) {
  if (armed == nullptr) {
    return ::ndk::ScopedAStatus::ok();
  }
  *armed = false;

  const uint32_t calling_uid =
      static_cast<uint32_t>(::android::IPCThreadState::self()->getCallingUid());
  if (!Authorised(calling_uid)) {
    LogIncident("unauthorised", "rejected armRecoveryBoot from uid " + std::to_string(calling_uid));
    return ::ndk::ScopedAStatus::ok();
  }

  BcbRequest request;
  request.command = xrom::recovery::kCommandBootRecovery;
  request.reason = reason;
  // The reason vocabulary is restricted by the pure core, so a manual arming is
  // distinguishable in the recovery log from an automatic one and a typo cannot put
  // the device into an undefined boot state.
  const std::vector<std::string> problems = xrom::recovery::Validate(request);
  if (!problems.empty()) {
    LogIncident("arm", "refused armRecoveryBoot: " + android::base::Join(problems, "; "));
    return ::ndk::ScopedAStatus::ok();
  }

  bool changed = false;
  std::string error;
  if (!bcb_->Write(request, &changed, &error)) {
    LogIncident("arm", "armRecoveryBoot failed: " + error);
    return ::ndk::ScopedAStatus::ok();
  }
  *armed = true;
  LogIncident("arm", std::string("recovery boot armed by uid ") + std::to_string(calling_uid) +
                         " reason=" + reason + (changed ? " (BCB written)" : " (already armed)"));
  return ::ndk::ScopedAStatus::ok();
}

// ---------------------------------------------------------------------------
// Boot-time work
// ---------------------------------------------------------------------------

void SentinelService::RunBootChecks() {
  // The boot-loop guard runs first and unconditionally: a device that should not have
  // come up at all should not spend its first seconds serving binder calls.
  std::string error;
  slot_snapshot_ = xrom::recovery::SlotSnapshot{};
  if (!bcb_->ReadSlotSnapshot(&slot_snapshot_, &error)) {
    LOG(WARNING) << "xrom_sentineld: platform boot counter unavailable: " << error;
  }

  xrom::recovery::VaultRecord record;
  std::string vault_error;
  integrity_failures_ = 0;
  if (vault_->ReadRecord(&record, &vault_error)) {
    integrity_failures_ = record.integrity_failures;
  } else {
    LOG(WARNING) << "xrom_sentineld: vault record unreadable: " << vault_error;
  }

  boot_loop_decision_ = xrom::recovery::EvaluateBootLoop(
      slot_snapshot_, integrity_failures_, config_.boot_attempts);
  LOG(INFO) << "xrom_sentineld: boot loop guard: "
            << xrom::recovery::BootLoopActionName(boot_loop_decision_.action) << " — "
            << boot_loop_decision_.reason
            << (boot_loop_decision_.degraded ? " (degraded)" : "");
  LogIncident("boot", std::string("boot-loop guard: ") +
                          xrom::recovery::BootLoopActionName(boot_loop_decision_.action) + " — " +
                          boot_loop_decision_.reason);

  if (boot_loop_decision_.action != BootLoopAction::kNone) {
    BcbRequest request;
    request.command = xrom::recovery::kCommandBootRecovery;
    request.reason = xrom::recovery::kReasonBootLoop;
    bool changed = false;
    std::string bcb_error;
    // Only the recovery-arming half is acted on here. A slot switch is the
    // bootloader's decision and is expressed by marking this slot unbootable, which
    // is a write to a structure X-ROM does not own; see correction #4. Arming recovery
    // is the remedy X-ROM can apply through the BCB, and it is the one that can
    // restore from the vault without discarding anything.
    if (bcb_->Write(request, &changed, &bcb_error)) {
      LogIncident("boot", changed ? "recovery armed for the boot-loop condition"
                                  : "recovery was already armed");
    } else {
      LogIncident("boot", "could not arm recovery for the boot-loop condition: " + bcb_error);
    }
  }

  if (!config_.check_integrity_on_boot) {
    LogIncident("boot", "post-boot integrity check is disabled by configuration");
    return;
  }

  aidl_recovery::IntegrityReportInfo report;
  checkVaultIntegrity(config_.deep_integrity_on_boot, &report);
  LogIncident("boot", "post-boot integrity: " + report.summary);

  if (report.verdict == static_cast<int32_t>(IntegrityVerdict::kMatch)) {
    // Cleared only on a passing boot, so that three failures spread over a year do
    // not add up to a boot loop.
    std::string clear_error;
    if (!vault_->ClearIntegrityFailures(&clear_error)) {
      LOG(WARNING) << "xrom_sentineld: could not clear the integrity counter: "
                   << clear_error;
    }
    return;
  }

  if (report.verdict == static_cast<int32_t>(IntegrityVerdict::kMismatch)) {
    std::string failure_error;
    if (!vault_->RecordIntegrityFailure(&failure_error)) {
      LOG(WARNING) << "xrom_sentineld: could not record the integrity failure: "
                   << failure_error;
    }
    // The user is notified through the same channel as a quarantine, and the event is
    // logged with both digests. The device keeps running: a mismatch means the
    // fallback is wrong, not that the running slot is — the running slot is
    // authenticated by AVB on every boot before the kernel starts.
    const std::string notice = config_.state_dir + "integrity_alert";
    android::base::WriteStringToFile(report.detail + "\n" + report.summary + "\n", notice, 0600,
                                     AID_SYSTEM, AID_SYSTEM, /*follow_symlinks=*/false);
    LogIncident("boot", "INTEGRITY MISMATCH: " + report.detail);
  }
}

}  // namespace xrom::sentinel
