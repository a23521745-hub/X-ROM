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

// Tests for common/recovery/QuarantinePlan.cpp.
//
// What is being asserted here is ORDER, and order is the part of quarantine that
// cannot be tested on a device. Each step changes what the later steps can rely
// on: the monitored directory has to stop changing before the evidence is moved,
// the evidence has to be somewhere the host cannot edit before the network is cut,
// and the network has to be down before the reboot is armed, because the interval
// between "decided" and "gone" is otherwise an interval in which remote commands
// still arrive. Arming the BCB is last-but-one for the opposite reason: it is the
// point of no return, and every step after it has to be one that is safe to skip.
//
// The cancellation tests assert a decision this project takes that differs from
// the obvious reading of the requirement: at kCritical there is no dialog. The UI
// is part of the system under suspicion, and a button that dismisses a security
// response is a control surface handed to whatever compromised it.

#include "QuarantinePlan.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace {

using ::xrom::recovery::Action;
using ::xrom::recovery::BuildPlan;
using ::xrom::recovery::EvaluateCancelRequest;
using ::xrom::recovery::OnFailure;
using ::xrom::recovery::QuarantinePolicy;
using ::xrom::recovery::ThreatSeverity;

// Index of |action| in the plan, or -1 when it is absent.
int IndexOf(const std::vector<::xrom::recovery::Step>& steps, Action action) {
  for (size_t i = 0; i < steps.size(); ++i) {
    if (steps[i].action == action) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

}  // namespace

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

TEST(QuarantinePlan, LocksBeforeItPreservesEvidence) {
  const auto plan = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{});
  const int lock = IndexOf(plan.steps, Action::kLockFolder);
  const int stash = IndexOf(plan.steps, Action::kStashEvidenceInPvm);
  EXPECT_GE(lock, 0);
  EXPECT_GE(stash, 0);
  EXPECT_LT(lock, stash);
}

TEST(QuarantinePlan, PreservesEvidenceBeforeItCutsTheNetwork) {
  // The cut is a visible signal that something is wrong. A hostile process that
  // sees it coming has a window to destroy what was never moved.
  const auto plan = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{});
  EXPECT_LT(IndexOf(plan.steps, Action::kStashEvidenceInPvm),
            IndexOf(plan.steps, Action::kCutNetwork));
}

TEST(QuarantinePlan, CutsTheNetworkBeforeArmingTheRecoveryBoot) {
  const auto plan = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{});
  EXPECT_LT(IndexOf(plan.steps, Action::kCutNetwork),
            IndexOf(plan.steps, Action::kArmRecoveryBoot));
}

TEST(QuarantinePlan, RecordsTheBootAttemptBeforeArmingTheBcb) {
  // Otherwise there is a window in which a deliberate quarantine reboot counts as
  // a boot failure and pushes the device toward the boot-loop threshold.
  const auto plan = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{});
  EXPECT_LT(IndexOf(plan.steps, Action::kRecordBootAttempt),
            IndexOf(plan.steps, Action::kArmRecoveryBoot));
}

TEST(QuarantinePlan, ArmingTheBcbIsFollowedOnlyByTheReboot) {
  const auto plan = BuildPlan(ThreatSeverity::kCritical, QuarantinePolicy{});
  const int arm = IndexOf(plan.steps, Action::kArmRecoveryBoot);
  EXPECT_GE(arm, 0);
  EXPECT_EQ(arm, static_cast<int>(plan.steps.size()) - 2);
  EXPECT_EQ(plan.steps.back().action, Action::kReboot);
}

TEST(QuarantinePlan, FirstThreeStepsAreTheSameAtEverySeverity) {
  const std::vector<ThreatSeverity> severities = {
      ThreatSeverity::kLow, ThreatSeverity::kMedium, ThreatSeverity::kHigh,
      ThreatSeverity::kCritical};
  for (ThreatSeverity severity : severities) {
    const auto plan = BuildPlan(severity, QuarantinePolicy{});
    EXPECT_EQ(plan.steps[0].action, Action::kLockFolder);
    EXPECT_EQ(plan.steps[1].action, Action::kStashEvidenceInPvm);
    EXPECT_EQ(plan.steps[2].action, Action::kCutNetwork);
  }
}

// ---------------------------------------------------------------------------
// Failure behaviour
// ---------------------------------------------------------------------------

TEST(QuarantinePlan, LosingTheEvidenceEscalatesRatherThanContinuing) {
  // A quarantine that cannot secure its own evidence destroys it, and going on to
  // reboot as though nothing happened leaves no record that it did.
  const auto plan = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{});
  EXPECT_EQ(plan.steps[1].on_failure, OnFailure::kEscalate);
}

TEST(QuarantinePlan, AFailedBcbWriteDoesNotReboot) {
  // A partially written misc can leave the bootloader with a command it cannot
  // interpret. A device that cannot boot cannot quarantine itself either, so the
  // honest response to a failed arming is to stop and stay up.
  const auto plan = BuildPlan(ThreatSeverity::kCritical, QuarantinePolicy{});
  const int arm = IndexOf(plan.steps, Action::kArmRecoveryBoot);
  EXPECT_EQ(plan.steps[arm].on_failure, OnFailure::kAbortWithoutReboot);
}

TEST(QuarantinePlan, AFailedNetworkCutDoesNotStopTheQuarantine) {
  // The network cut is defence in depth on a device that is about to reboot into
  // recovery anyway. Refusing to quarantine because netd did not answer would be
  // a strict downgrade.
  const auto plan = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{});
  EXPECT_EQ(plan.steps[2].on_failure, OnFailure::kContinue);
}

TEST(QuarantinePlan, EveryStepHasAPositiveTimeoutAndTheTotalIsBounded) {
  QuarantinePolicy policy;
  policy.total_budget_ms = 12000;
  const auto plan = BuildPlan(ThreatSeverity::kHigh, policy);
  int64_t sum = 0;
  for (const auto& step : plan.steps) {
    EXPECT_GT(step.timeout_ms, 0);
    sum += step.timeout_ms;
  }
  // The window is part of the total, so the budget has to cover it too.
  sum += static_cast<int64_t>(plan.cancel_window_seconds) * 1000;
  EXPECT_LE(plan.total_timeout_ms, policy.total_budget_ms);
  EXPECT_LT(plan.total_timeout_ms, sum);
}

// ---------------------------------------------------------------------------
// Severity thresholds
// ---------------------------------------------------------------------------

TEST(QuarantinePlan, BelowTheThresholdTheDeviceStaysUp) {
  const auto low = BuildPlan(ThreatSeverity::kLow, QuarantinePolicy{});
  const auto medium = BuildPlan(ThreatSeverity::kMedium, QuarantinePolicy{});
  EXPECT_FALSE(low.reboots);
  EXPECT_FALSE(medium.reboots);
  EXPECT_EQ(IndexOf(low.steps, Action::kArmRecoveryBoot), -1);
  EXPECT_EQ(IndexOf(medium.steps, Action::kReboot), -1);
  // The user is still told: a silent lockdown the operator cannot explain is
  // indistinguishable from a bug.
  EXPECT_GE(IndexOf(medium.steps, Action::kNotifyUser), 0);
}

TEST(QuarantinePlan, AtAndAboveTheThresholdTheDeviceReboots) {
  EXPECT_TRUE(BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{}).reboots);
  EXPECT_TRUE(BuildPlan(ThreatSeverity::kCritical, QuarantinePolicy{}).reboots);
}

TEST(QuarantinePlan, TheRebootThresholdIsPolicyNotAConstant) {
  QuarantinePolicy cautious;
  cautious.reboot_threshold = ThreatSeverity::kMedium;
  EXPECT_TRUE(BuildPlan(ThreatSeverity::kMedium, cautious).reboots);

  QuarantinePolicy relaxed;
  relaxed.reboot_threshold = ThreatSeverity::kCritical;
  EXPECT_FALSE(BuildPlan(ThreatSeverity::kHigh, relaxed).reboots);
  EXPECT_TRUE(BuildPlan(ThreatSeverity::kCritical, relaxed).reboots);
}

// ---------------------------------------------------------------------------
// The cancellation window
// ---------------------------------------------------------------------------

TEST(QuarantinePlan, CriticalSeverityGetsNoCancelWindowByDefault) {
  const auto plan = BuildPlan(ThreatSeverity::kCritical, QuarantinePolicy{});
  EXPECT_TRUE(plan.reboots);
  EXPECT_FALSE(plan.offers_cancel);
  EXPECT_EQ(plan.cancel_window_seconds, 0);
  EXPECT_EQ(IndexOf(plan.steps, Action::kNotifyUser), -1);
}

TEST(QuarantinePlan, HighSeverityGetsTheWindowByDefault) {
  const auto plan = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{});
  EXPECT_TRUE(plan.offers_cancel);
  EXPECT_EQ(plan.cancel_window_seconds, 30);
  EXPECT_GE(IndexOf(plan.steps, Action::kNotifyUser), 0);
}

TEST(QuarantinePlan, AnOperatorCanTurnTheWindowOffEntirely) {
  QuarantinePolicy policy;
  policy.cancel_window_seconds = 0;
  const auto plan = BuildPlan(ThreatSeverity::kHigh, policy);
  EXPECT_FALSE(plan.offers_cancel);
  EXPECT_TRUE(plan.reboots);
  // With the window gone there is nothing to notify about, so the step is absent
  // rather than present-and-useless.
  EXPECT_EQ(IndexOf(plan.steps, Action::kNotifyUser), -1);
}

TEST(QuarantinePlan, CriticalCanOptIntoAWindowButHasToSaySo) {
  QuarantinePolicy policy;
  policy.allow_cancel_at_critical = true;
  const auto plan = BuildPlan(ThreatSeverity::kCritical, policy);
  EXPECT_TRUE(plan.offers_cancel);
  EXPECT_EQ(plan.cancel_window_seconds, 30);
}

// ---------------------------------------------------------------------------
// EvaluateCancelRequest
// ---------------------------------------------------------------------------

TEST(QuarantineCancel, AuthenticatedUserInsideTheWindowMayCancel) {
  const QuarantinePolicy policy;
  const auto decision =
      EvaluateCancelRequest(ThreatSeverity::kHigh, policy, /*authenticated=*/true, 5);
  EXPECT_TRUE(decision.allowed);
  EXPECT_TRUE(decision.reason.find("authenticated") != std::string::npos);
}

TEST(QuarantineCancel, AnUnauthenticatedDismissalMayNotCancel) {
  // Any process that can draw a dialog could otherwise stop a security response
  // by tapping a button.
  const QuarantinePolicy policy;
  const auto decision =
      EvaluateCancelRequest(ThreatSeverity::kHigh, policy, /*authenticated=*/false, 5);
  EXPECT_FALSE(decision.allowed);
  EXPECT_TRUE(decision.reason.find("keyguard-authenticated") != std::string::npos);
}

TEST(QuarantineCancel, AfterTheWindowClosesItCannotBeCancelled) {
  const QuarantinePolicy policy;  // 30 seconds
  EXPECT_TRUE(
      EvaluateCancelRequest(ThreatSeverity::kHigh, policy, true, 29).allowed);
  EXPECT_FALSE(
      EvaluateCancelRequest(ThreatSeverity::kHigh, policy, true, 30).allowed);
  EXPECT_FALSE(
      EvaluateCancelRequest(ThreatSeverity::kHigh, policy, true, 9999).allowed);
  EXPECT_FALSE(
      EvaluateCancelRequest(ThreatSeverity::kHigh, policy, true, -1).allowed);
}

TEST(QuarantineCancel, CriticalIsNeverCancellableUnlessPolicyInsists) {
  const QuarantinePolicy policy;
  const auto refused =
      EvaluateCancelRequest(ThreatSeverity::kCritical, policy, true, 0);
  EXPECT_FALSE(refused.allowed);
  EXPECT_TRUE(refused.reason.find("critical") != std::string::npos);

  QuarantinePolicy insistent;
  insistent.allow_cancel_at_critical = true;
  EXPECT_TRUE(EvaluateCancelRequest(ThreatSeverity::kCritical, insistent, true, 0).allowed);
}

TEST(QuarantineCancel, ASeverityThatNeverRebootedHasNothingToCancel) {
  const QuarantinePolicy policy;
  const auto decision =
      EvaluateCancelRequest(ThreatSeverity::kMedium, policy, true, 0);
  EXPECT_FALSE(decision.allowed);
  EXPECT_TRUE(decision.reason.find("does not reboot") != std::string::npos);
}

TEST(QuarantineCancel, ADisabledWindowRefusesEvenAnAuthenticatedRequest) {
  QuarantinePolicy policy;
  policy.cancel_window_seconds = 0;
  const auto decision =
      EvaluateCancelRequest(ThreatSeverity::kHigh, policy, true, 0);
  EXPECT_FALSE(decision.allowed);
  EXPECT_TRUE(decision.reason.find("disabled") != std::string::npos);
}

TEST(QuarantineCancel, AuthenticationCanBeWaivedButOnlyByPolicy) {
  QuarantinePolicy policy;
  policy.cancel_requires_authentication = false;
  EXPECT_TRUE(EvaluateCancelRequest(ThreatSeverity::kHigh, policy, false, 5).allowed);
}

// ---------------------------------------------------------------------------
// Determinism and description
// ---------------------------------------------------------------------------

TEST(QuarantinePlan, TheSameInputsProduceTheSamePlan) {
  // Incident code runs once, on a device that is already in a bad state. If the
  // plan depended on anything other than its arguments it could not be reasoned
  // about afterwards from the log alone.
  const QuarantinePolicy policy;
  const auto a = BuildPlan(ThreatSeverity::kHigh, policy);
  const auto b = BuildPlan(ThreatSeverity::kHigh, policy);
  EXPECT_EQ(a.Describe(), b.Describe());
  EXPECT_EQ(a.steps.size(), b.steps.size());
  EXPECT_EQ(a.total_timeout_ms, b.total_timeout_ms);
}

TEST(QuarantinePlan, DescribeNamesEveryStepAndTheOutcome) {
  const auto description = BuildPlan(ThreatSeverity::kHigh, QuarantinePolicy{}).Describe();
  EXPECT_TRUE(description.find("quarantine(high)") != std::string::npos);
  EXPECT_TRUE(description.find("lock-folder") != std::string::npos);
  EXPECT_TRUE(description.find("stash-evidence-in-pvm") != std::string::npos);
  EXPECT_TRUE(description.find("cut-network") != std::string::npos);
  EXPECT_TRUE(description.find("arm-recovery-boot") != std::string::npos);
  EXPECT_TRUE(description.find("[reboots]") != std::string::npos);
  EXPECT_TRUE(description.find("cancel window 30s") != std::string::npos);
}

TEST(QuarantinePlan, EveryEnumValueHasADistinctPrintableName) {
  // Names that go into an incident log read on a device that may be wiped
  // afterwards. A missing case would print "invalid" and hide which step ran.
  const std::vector<Action> actions = {
      Action::kLockFolder,          Action::kStashEvidenceInPvm, Action::kCutNetwork,
      Action::kNotifyUser,          Action::kArmRecoveryBoot,    Action::kReboot,
      Action::kRecordBootAttempt};
  for (Action action : actions) {
    EXPECT_NE(std::string(xrom::recovery::ActionName(action)), "invalid");
  }
  const std::vector<ThreatSeverity> severities = {
      ThreatSeverity::kLow, ThreatSeverity::kMedium, ThreatSeverity::kHigh,
      ThreatSeverity::kCritical};
  for (ThreatSeverity severity : severities) {
    EXPECT_NE(std::string(xrom::recovery::SeverityName(severity)), "invalid");
  }
  EXPECT_NE(std::string(xrom::recovery::OnFailureName(OnFailure::kContinue)), "invalid");
  EXPECT_NE(std::string(xrom::recovery::OnFailureName(OnFailure::kEscalate)), "invalid");
  EXPECT_NE(std::string(xrom::recovery::OnFailureName(OnFailure::kAbortWithoutReboot)),
            "invalid");
}
