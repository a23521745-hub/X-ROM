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

#ifndef XROM_RECOVERY_QUARANTINE_PLAN_H_
#define XROM_RECOVERY_QUARANTINE_PLAN_H_

#include <cstdint>
#include <string>
#include <vector>

namespace xrom::recovery {

// ---------------------------------------------------------------------------
// What happens between "a threat was detected" and "the device reboots".
//
// THE PROBLEM THIS SOLVES IS ORDERING, NOT CHOICE
// -----------------------------------------------
// Quarantine is a sequence of side effects on a system that may already be
// compromised. Order matters because each step changes what the later steps can
// rely on:
//
//   * the evidence has to be moved somewhere the compromised system cannot edit
//     BEFORE the network is cut, or a hostile process sees the cut coming and has
//     a window to exfiltrate or destroy it;
//   * the network has to be cut BEFORE the reboot is armed, or the window between
//     "decided" and "gone" is a window in which remote commands still arrive;
//   * the BCB has to be written LAST, because writing it is the point of no return
//     — from that moment the next reboot goes to recovery whatever else happens,
//     including a crash halfway through the remaining steps.
//
// So the plan is a fixed ordered list produced from a severity and a policy, and
// every step declares what to do if it fails. A step that cannot complete must not
// silently vanish: either the sequence continues with a recorded degradation, or
// the whole quarantine escalates. Which one is a property of the step, not of the
// caller's mood.
//
// WHY THIS IS A PURE FUNCTION
// ---------------------------
// The daemon that executes this runs on a device that is, by hypothesis, in a bad
// state. The plan itself is computed from a severity and a policy struct, with no
// clock, no binder and no file I/O, so every branch — including the ones that only
// fire during an incident — can be executed in a test on a build host. Incident
// code that has never run is incident code that has never been debugged.
// ---------------------------------------------------------------------------

enum class ThreatSeverity : int32_t {
  // An anomaly that is worth recording and worth locking down, but not worth
  // interrupting the user for. No reboot.
  kLow = 0,
  // Evidence of tampering that could not be confirmed. Lock down, preserve
  // evidence, reboot to recovery for a full integrity pass.
  kMedium = 1,
  // Confirmed tampering with a measured artifact, or a payload whose measurement
  // did not match its signed manifest.
  kHigh = 2,
  // Active compromise: a running component is doing something only an attacker
  // would want. No user interaction is offered, because the UI may itself be the
  // compromised component.
  kCritical = 3,
};

const char* SeverityName(ThreatSeverity severity);

enum class Action : int32_t {
  // Refuse further writes to the monitored directory by revoking the grant at
  // runtime and by marking it in the sentinel's own state, so that a restart of
  // the daemon does not quietly restore access.
  kLockFolder = 0,
  // Move the encrypted incident log into the protected VM's storage, where the
  // host cannot read or edit it. AVmPayload_getEncryptedStoragePath() is the
  // mechanism; the host may delete that storage but cannot read it.
  kStashEvidenceInPvm = 1,
  // Drop every network path. Done through netd's firewall chain, which is
  // nftables in the kernel: userspace sets the policy, the kernel enforces it.
  // This is not a kernel patch, and it is not eBPF — CONFIG_BPF_SYSCALL stays off.
  kCutNetwork = 2,
  // Show the user what is happening and, if policy allows, offer a cancel.
  kNotifyUser = 3,
  // Write the BCB. Last, and the point of no return.
  kArmRecoveryBoot = 4,
  // Trigger the reboot.
  kReboot = 5,
  // Record that a boot attempt is pending, so that the boot-loop guard knows this
  // reboot was deliberate and does not count it as a failure.
  kRecordBootAttempt = 6,
};

const char* ActionName(Action action);

// What to do when a step cannot complete.
enum class OnFailure : int32_t {
  // Note it and continue. For steps whose absence degrades the response without
  // making it wrong — the user notification, for instance.
  kContinue = 0,
  // The remaining steps cannot be trusted without this one, so stop and escalate
  // the severity. Used for evidence preservation: a quarantine that cannot secure
  // its own evidence is a quarantine that destroys it.
  kEscalate = 1,
  // Stop the sequence and do not reboot. Used when arming the recovery boot would
  // be worse than staying up — for example when the BCB write itself failed, since
  // a partially written misc is a device that may not boot at all.
  kAbortWithoutReboot = 2,
};

const char* OnFailureName(OnFailure on_failure);

struct Step {
  Action action = Action::kLockFolder;
  // Upper bound on how long this step may take. The whole sequence is bounded, so
  // a step that hangs cannot leave the device quarantined-but-running forever.
  int32_t timeout_ms = 5000;
  OnFailure on_failure = OnFailure::kContinue;
  // Human-readable purpose, carried into the incident log.
  std::string rationale;
};

struct QuarantinePolicy {
  // Length of the window in which the user may cancel the reboot.
  int32_t cancel_window_seconds = 30;

  // Cancelling requires the device to be unlocked and the cancellation to come
  // from the keyguard-authenticated user. Without this, any process that can draw
  // a dialog — or any attacker holding the device — can dismiss a security
  // response by tapping a button.
  bool cancel_requires_authentication = true;

  // At kCritical there is no window at all, whatever cancel_window_seconds says.
  //
  // This is the one place where this file disagrees with the obvious reading of
  // the requirement, and the reason is worth stating plainly: the UI is part of
  // the system under suspicion. A dialog that says "threat detected, tap to
  // cancel" is a control surface handed to whatever compromised the device, and at
  // kCritical that is exactly the component we least trust. An operator who wants
  // a window at kCritical can set this to true; the default is that they should
  // not want one.
  bool allow_cancel_at_critical = false;

  // kHigh and above reboot. Below that the device stays up, locked down and
  // logging, because interrupting a user for an unconfirmed anomaly trains them to
  // dismiss the real one.
  ThreatSeverity reboot_threshold = ThreatSeverity::kHigh;

  // Bound on the whole sequence. If the steps cannot complete in this time the
  // sequence is abandoned at whatever step it reached and the failure is recorded.
  int32_t total_budget_ms = 30000;

  // Where the encrypted incident log is written before it is moved into the pVM.
  // A path under the sentinel's own data directory; it must not be a path the
  // compromised component can already write.
  std::string staging_log_path = "/data/misc/xrom/sentinel/incident.log.enc";
};

struct QuarantinePlan {
  std::vector<Step> steps;
  ThreatSeverity severity = ThreatSeverity::kLow;

  // True when the plan ends in a reboot.
  bool reboots = false;

  // True when a cancellation window is offered anywhere in the plan.
  bool offers_cancel = false;
  int32_t cancel_window_seconds = 0;

  // Sum of the step timeouts, clamped to the policy budget. Used by the executor
  // to decide how long to wait in total rather than trusting each step to respect
  // its own.
  int32_t total_timeout_ms = 0;

  std::string Describe() const;
};

// Builds the plan. Deterministic: the same severity and policy always produce the
// same steps in the same order, which is what makes the ordering testable.
QuarantinePlan BuildPlan(ThreatSeverity severity, const QuarantinePolicy& policy);

// Whether a cancellation request may be honoured.
//
// |authenticated| is whether the cancellation came from a keyguard-authenticated
// user. |elapsed_seconds| is how far into the window the request arrived. Both are
// inputs rather than things this function looks up, so that the decision can be
// tested without a UI, a clock or a device.
struct CancelDecision {
  bool allowed = false;
  std::string reason;
};

CancelDecision EvaluateCancelRequest(ThreatSeverity severity, const QuarantinePolicy& policy,
                                     bool authenticated, int32_t elapsed_seconds);

}  // namespace xrom::recovery

#endif  // XROM_RECOVERY_QUARANTINE_PLAN_H_
