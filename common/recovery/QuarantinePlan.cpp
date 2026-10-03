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

#include "QuarantinePlan.h"

namespace xrom::recovery {
namespace {

Step Make(Action action, int32_t timeout_ms, OnFailure on_failure, const char* rationale) {
  Step step;
  step.action = action;
  step.timeout_ms = timeout_ms;
  step.on_failure = on_failure;
  step.rationale = rationale;
  return step;
}

}  // namespace

const char* SeverityName(ThreatSeverity severity) {
  switch (severity) {
    case ThreatSeverity::kLow:
      return "low";
    case ThreatSeverity::kMedium:
      return "medium";
    case ThreatSeverity::kHigh:
      return "high";
    case ThreatSeverity::kCritical:
      return "critical";
  }
  return "invalid";
}

const char* ActionName(Action action) {
  switch (action) {
    case Action::kLockFolder:
      return "lock-folder";
    case Action::kStashEvidenceInPvm:
      return "stash-evidence-in-pvm";
    case Action::kCutNetwork:
      return "cut-network";
    case Action::kNotifyUser:
      return "notify-user";
    case Action::kArmRecoveryBoot:
      return "arm-recovery-boot";
    case Action::kReboot:
      return "reboot";
    case Action::kRecordBootAttempt:
      return "record-boot-attempt";
  }
  return "invalid";
}

const char* OnFailureName(OnFailure on_failure) {
  switch (on_failure) {
    case OnFailure::kContinue:
      return "continue";
    case OnFailure::kEscalate:
      return "escalate";
    case OnFailure::kAbortWithoutReboot:
      return "abort-without-reboot";
  }
  return "invalid";
}

std::string QuarantinePlan::Describe() const {
  std::string out = std::string("quarantine(") + SeverityName(severity) + "): ";
  for (size_t i = 0; i < steps.size(); ++i) {
    if (i != 0) {
      out += " -> ";
    }
    out += ActionName(steps[i].action);
  }
  out += reboots ? " [reboots]" : " [stays up]";
  if (offers_cancel) {
    out += " [cancel window " + std::to_string(cancel_window_seconds) + "s]";
  }
  return out;
}

QuarantinePlan BuildPlan(ThreatSeverity severity, const QuarantinePolicy& policy) {
  QuarantinePlan plan;
  plan.severity = severity;

  // --- always, at every severity -------------------------------------------
  //
  // Locking first and preserving evidence second is the order that matters. Once
  // the monitored directory is locked, a hostile process can no longer add to or
  // alter what is about to be moved; and moving it before the network is cut means
  // the cut itself cannot be used as a signal to destroy the evidence.
  plan.steps.push_back(Make(Action::kLockFolder, 2000, OnFailure::kContinue,
                            "stop the monitored directory from changing while the "
                            "incident is being recorded"));
  plan.steps.push_back(
      Make(Action::kStashEvidenceInPvm, 8000, OnFailure::kEscalate,
           "move the encrypted incident log where the host cannot read or edit it; "
           "a quarantine that cannot secure its own evidence destroys it"));

  // The network goes down before anything is armed, so that the interval between
  // "decided" and "rebooted" is not an interval in which remote commands arrive.
  plan.steps.push_back(Make(Action::kCutNetwork, 3000, OnFailure::kContinue,
                            "cut every network path before the reboot is armed"));

  // --- the user-facing part, which depends on severity ----------------------
  const bool reboot = severity >= policy.reboot_threshold;
  plan.reboots = reboot;

  if (reboot) {
    // At kCritical there is no dialog. The UI is part of the system under
    // suspicion, and offering a cancel button hands a control surface to whatever
    // compromised it. See allow_cancel_at_critical in the header.
    const bool critical = severity == ThreatSeverity::kCritical;
    const bool window =
        policy.cancel_window_seconds > 0 && (!critical || policy.allow_cancel_at_critical);

    plan.offers_cancel = window;
    plan.cancel_window_seconds = window ? policy.cancel_window_seconds : 0;

    if (window) {
      // The notification is deliberately NOT a step that blocks for the whole
      // window: the executor shows it, then waits, so that the wait is one
      // cancellable period rather than a step whose timeout has to equal the
      // window. A step that fails here must not stop the reboot: a user who never
      // saw the dialog still gets the correct security response.
      plan.steps.push_back(Make(Action::kNotifyUser, 2000, OnFailure::kContinue,
                                "tell the user what is happening and, if policy "
                                "allows, offer a cancellation window"));
    }

    // Recorded before the BCB is written, so that the boot-loop guard can tell a
    // deliberate quarantine reboot from a crash loop. Writing the BCB first and
    // recording afterwards would leave a window in which the reboot counts as a
    // failure and pushes the device closer to the loop threshold.
    plan.steps.push_back(Make(Action::kRecordBootAttempt, 1000, OnFailure::kContinue,
                              "mark this reboot as deliberate so the boot-loop "
                              "guard does not count it as a failure"));

    // Arming is the point of no return, which is why it is second to last and why
    // its failure aborts without rebooting: a partially written misc partition can
    // leave the bootloader with a command it cannot interpret, and a device that
    // cannot boot cannot quarantine itself either.
    plan.steps.push_back(Make(Action::kArmRecoveryBoot, 5000, OnFailure::kAbortWithoutReboot,
                              "write the BCB; from here the next reboot goes to "
                              "recovery whatever else happens"));
    plan.steps.push_back(Make(Action::kReboot, 5000, OnFailure::kContinue,
                              "hand the device to the bootloader"));
  } else {
    // Below the reboot threshold the device stays up, locked down and logging.
    // The user is still told, because a silent lockdown that the operator cannot
    // explain is indistinguishable from a bug.
    plan.steps.push_back(Make(Action::kNotifyUser, 2000, OnFailure::kContinue,
                              "record and report the anomaly without interrupting "
                              "the user's session"));
  }

  int64_t total = 0;
  for (const Step& step : plan.steps) {
    total += step.timeout_ms;
  }
  if (plan.offers_cancel) {
    total += static_cast<int64_t>(plan.cancel_window_seconds) * 1000;
  }
  plan.total_timeout_ms =
      static_cast<int32_t>(total > policy.total_budget_ms ? policy.total_budget_ms : total);
  return plan;
}

CancelDecision EvaluateCancelRequest(ThreatSeverity severity, const QuarantinePolicy& policy,
                                     bool authenticated, int32_t elapsed_seconds) {
  CancelDecision decision;

  if (severity == ThreatSeverity::kCritical && !policy.allow_cancel_at_critical) {
    decision.allowed = false;
    decision.reason =
        "the threat is critical and the UI is part of the system under suspicion; "
        "no cancellation is offered at this severity";
    return decision;
  }
  if (severity < policy.reboot_threshold) {
    // Nothing to cancel: the plan never armed a reboot.
    decision.allowed = false;
    decision.reason = "this severity does not reboot, so there is nothing to cancel";
    return decision;
  }
  if (policy.cancel_window_seconds <= 0) {
    decision.allowed = false;
    decision.reason = "the cancel window is disabled by policy";
    return decision;
  }
  if (elapsed_seconds < 0 || elapsed_seconds >= policy.cancel_window_seconds) {
    decision.allowed = false;
    decision.reason = "the " + std::to_string(policy.cancel_window_seconds) +
                      " second window has closed";
    return decision;
  }
  if (policy.cancel_requires_authentication && !authenticated) {
    decision.allowed = false;
    decision.reason =
        "the cancellation did not come from a keyguard-authenticated user; an "
        "unauthenticated dialog dismissal must not be able to stop a security "
        "response";
    return decision;
  }

  decision.allowed = true;
  decision.reason = "cancelled by an authenticated user " + std::to_string(elapsed_seconds) +
                    "s into a " + std::to_string(policy.cancel_window_seconds) + "s window";
  return decision;
}

}  // namespace xrom::recovery
