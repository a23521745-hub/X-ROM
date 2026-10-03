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

// Tests for common/recovery/BootAttemptPolicy.cpp.
//
// The thing being asserted here is that two failure classes get two counters, and
// that X-ROM only owns one of them.
//
// tries_remaining is the platform's counter: the bootloader decrements it before
// each attempt and resets it after a successful boot, and it counts boots that
// never reached userspace. It lives in bootloader_control inside the slot_suffix
// field of misc, in a region the bootloader, recovery and uncrypt share at offsets
// that are agreed across AOSP and are not configurable. X-ROM reads it and never
// writes it — the last test in this file asserts exactly that, so the invariant is
// something a test fails on rather than something a comment asks for.
//
// integrity_failures is X-ROM's counter and it covers the case the platform
// counter structurally cannot see: a device that boots perfectly, reaches
// userspace, discovers its /system does not match its vault, and reboots into the
// same state. From the bootloader's point of view every one of those boots
// succeeded, so tries_remaining never moves and the device loops forever.

#include "BootAttemptPolicy.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace {

using ::xrom::recovery::BootAttemptPolicy;
using ::xrom::recovery::BootLoopAction;
using ::xrom::recovery::EvaluateBootLoop;
using ::xrom::recovery::SlotSnapshot;

// A slot the bootloader is happy with: plenty of tries left, other slot bootable,
// recovery attempts available.
SlotSnapshot HealthySlot() {
  SlotSnapshot slot;
  slot.available = true;
  slot.slot_index = 0;
  slot.tries_remaining = 7;
  slot.successful_boot = false;
  slot.verity_corrupted = false;
  slot.priority = 15;
  slot.recovery_tries_remaining = 3;
  slot.other_slot_bootable = true;
  return slot;
}

}  // namespace

// ---------------------------------------------------------------------------
// Nothing is wrong
// ---------------------------------------------------------------------------

TEST(BootAttemptPolicy, AHealthyBootDoesNothing) {
  const auto decision = EvaluateBootLoop(HealthySlot(), 0, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kNone));
  EXPECT_FALSE(decision.degraded);
  EXPECT_TRUE(decision.reason.find("tries_remaining=7") != std::string::npos);
}

TEST(BootAttemptPolicy, AConfirmedGoodSlotIsNotSecondGuessed) {
  // successful_boot means the bootloader has already been told this slot works and
  // has reset tries_remaining. Consulting the counter in that state would be
  // meaningless, and acting on it would arm recovery against a slot the platform
  // has just vouched for.
  SlotSnapshot slot = HealthySlot();
  slot.successful_boot = true;
  slot.tries_remaining = 0;
  const auto decision = EvaluateBootLoop(slot, 0, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kNone));
}

TEST(BootAttemptPolicy, IntegrityFailuresBelowTheLimitDoNothing) {
  const auto decision = EvaluateBootLoop(HealthySlot(), 2, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kNone));
  EXPECT_TRUE(decision.reason.find("integrity_failures=2 of 3") != std::string::npos);
}

// ---------------------------------------------------------------------------
// X-ROM's own counter: boots that reached userspace and failed
// ---------------------------------------------------------------------------

TEST(BootAttemptPolicy, ThreePostBootIntegrityFailuresArmRecovery) {
  const auto decision = EvaluateBootLoop(HealthySlot(), 3, BootAttemptPolicy{});
  EXPECT_TRUE(decision.action != BootLoopAction::kNone);
  EXPECT_TRUE(decision.reason.find("post-boot integrity failed on 3 consecutive boots") !=
              std::string::npos);
  // Recovery first, with the slot switch held in reserve: recovery can restore
  // from the vault without discarding anything, while a slot switch abandons the
  // current image and may land on an equally broken one.
  EXPECT_EQ(static_cast<int>(decision.action),
            static_cast<int>(BootLoopAction::kArmRecoveryThenSwitchSlot));
}

TEST(BootAttemptPolicy, MoreFailuresThanTheLimitStillArmRecoveryOnce) {
  const auto decision = EvaluateBootLoop(HealthySlot(), 17, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action),
            static_cast<int>(BootLoopAction::kArmRecoveryThenSwitchSlot));
}

TEST(BootAttemptPolicy, WithNoOtherSlotOnlyRecoveryIsArmed) {
  SlotSnapshot slot = HealthySlot();
  slot.other_slot_bootable = false;
  const auto decision = EvaluateBootLoop(slot, 3, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kArmRecovery));
  EXPECT_TRUE(decision.reason.find("no other slot is available") != std::string::npos);
}

TEST(BootAttemptPolicy, TheLimitIsPolicyNotAConstant) {
  BootAttemptPolicy strict;
  strict.max_integrity_failures = 1;
  EXPECT_NE(static_cast<int>(EvaluateBootLoop(HealthySlot(), 1, strict).action),
            static_cast<int>(BootLoopAction::kNone));

  BootAttemptPolicy lenient;
  lenient.max_integrity_failures = 5;
  EXPECT_EQ(static_cast<int>(EvaluateBootLoop(HealthySlot(), 4, lenient).action),
            static_cast<int>(BootLoopAction::kNone));
}

// ---------------------------------------------------------------------------
// The platform's counter: boots that never reached userspace
// ---------------------------------------------------------------------------

TEST(BootAttemptPolicy, TheBootloaderRunningOutOfTriesSwitchesSlotFirst) {
  // Only the platform counter has fired. Recovery entered from a slot the
  // bootloader has already given up on is recovery entered with an unreliable view
  // of the device, and the bootloader is going to switch anyway.
  SlotSnapshot slot = HealthySlot();
  slot.tries_remaining = 1;  // at the floor
  const auto decision = EvaluateBootLoop(slot, 0, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kSwitchSlot));
  EXPECT_TRUE(decision.reason.find("only the bootloader's own counter is exhausted") !=
              std::string::npos);
}

TEST(BootAttemptPolicy, TheTriesFloorIsNotZero) {
  // At zero the bootloader has already marked the slot unbootable and is falling
  // back. Waiting for zero means X-ROM never gets to say anything about a slot
  // that is dying, which is the entire window in which the vault is useful.
  BootAttemptPolicy policy;
  EXPECT_GE(policy.tries_remaining_floor, 1u);
  SlotSnapshot slot = HealthySlot();
  slot.tries_remaining = 2;
  EXPECT_EQ(static_cast<int>(EvaluateBootLoop(slot, 0, policy).action),
            static_cast<int>(BootLoopAction::kNone));
  slot.tries_remaining = 1;
  EXPECT_NE(static_cast<int>(EvaluateBootLoop(slot, 0, policy).action),
            static_cast<int>(BootLoopAction::kNone));
}

TEST(BootAttemptPolicy, WhenBothCountersFireRecoveryIsArmedWithTheSwitchInReserve) {
  SlotSnapshot slot = HealthySlot();
  slot.tries_remaining = 0;
  const auto decision = EvaluateBootLoop(slot, 3, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action),
            static_cast<int>(BootLoopAction::kArmRecoveryThenSwitchSlot));
  EXPECT_TRUE(decision.reason.find("post-boot integrity failed") != std::string::npos);
  EXPECT_TRUE(decision.reason.find("tries left on this slot") != std::string::npos);
}

TEST(BootAttemptPolicy, AnUnreadableMiscStillActsOnXromsOwnCounter) {
  // Failing to act because /misc could not be read is how a device loops forever.
  // The response is still armed; the decision is marked degraded so the log says
  // that half the evidence was missing.
  SlotSnapshot slot;  // available == false
  const auto decision = EvaluateBootLoop(slot, 3, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kArmRecovery));
  EXPECT_TRUE(decision.degraded);
  EXPECT_TRUE(decision.reason.find("could not be read") != std::string::npos);
}

TEST(BootAttemptPolicy, AnUnreadableMiscWithNoFailuresIsDegradedButQuiet) {
  SlotSnapshot slot;
  const auto decision = EvaluateBootLoop(slot, 0, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kNone));
  EXPECT_TRUE(decision.degraded);
}

// ---------------------------------------------------------------------------
// dm-verity
// ---------------------------------------------------------------------------

TEST(BootAttemptPolicy, VerityCorruptionCountsAsAnExhaustedCounter) {
  // Not a guess: the kernel's own verification of a block it was asked to read
  // failed. That is the same class of fact as three of X-ROM's comparisons
  // disagreeing, and one report is enough.
  SlotSnapshot slot = HealthySlot();
  slot.verity_corrupted = true;
  const auto decision = EvaluateBootLoop(slot, 0, BootAttemptPolicy{});
  EXPECT_NE(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kNone));
  EXPECT_TRUE(decision.reason.find("dm-verity reported corruption") != std::string::npos);
}

TEST(BootAttemptPolicy, VerityCorruptionCanBeExcludedByPolicy) {
  SlotSnapshot slot = HealthySlot();
  slot.verity_corrupted = true;
  BootAttemptPolicy policy;
  policy.verity_corruption_counts = false;
  EXPECT_EQ(static_cast<int>(EvaluateBootLoop(slot, 0, policy).action),
            static_cast<int>(BootLoopAction::kNone));
}

TEST(BootAttemptPolicy, VerityCorruptionOnAConfirmedGoodSlotIsNotCounted) {
  // A stale flag on a slot the bootloader has since vouched for would otherwise
  // arm recovery on every boot forever.
  SlotSnapshot slot = HealthySlot();
  slot.verity_corrupted = true;
  slot.successful_boot = true;
  EXPECT_EQ(static_cast<int>(EvaluateBootLoop(slot, 0, BootAttemptPolicy{}).action),
            static_cast<int>(BootLoopAction::kNone));
}

// ---------------------------------------------------------------------------
// When neither remedy is available
// ---------------------------------------------------------------------------

TEST(BootAttemptPolicy, ExhaustedRecoveryTriesSwitchSlotInstead) {
  // Recovery the bootloader will not honour is worse than no recovery: the device
  // comes back up in the same state and the failure has been consumed invisibly.
  SlotSnapshot slot = HealthySlot();
  slot.recovery_tries_remaining = 0;
  const auto decision = EvaluateBootLoop(slot, 3, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kSwitchSlot));
  EXPECT_TRUE(decision.reason.find("recovery attempts are exhausted") != std::string::npos);
}

TEST(BootAttemptPolicy, WithNoRecoveryTriesAndNoOtherSlotTheConditionIsReportedNotHidden) {
  SlotSnapshot slot = HealthySlot();
  slot.recovery_tries_remaining = 0;
  slot.other_slot_bootable = false;
  const auto decision = EvaluateBootLoop(slot, 3, BootAttemptPolicy{});
  // kNone, but with a reason that says both remedies were considered and
  // rejected. Silently returning kNone would hide the fact that the device is out
  // of options, which is the one thing an operator has to know.
  EXPECT_EQ(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kNone));
  EXPECT_TRUE(decision.reason.find("no automatic remedy is available") != std::string::npos);
}

TEST(BootAttemptPolicy, IgnoringRecoveryTriesIsPossibleButNotTheDefault) {
  SlotSnapshot slot = HealthySlot();
  slot.recovery_tries_remaining = 0;
  BootAttemptPolicy policy;
  EXPECT_TRUE(policy.respect_recovery_tries);
  policy.respect_recovery_tries = false;
  const auto decision = EvaluateBootLoop(slot, 3, policy);
  EXPECT_EQ(static_cast<int>(decision.action),
            static_cast<int>(BootLoopAction::kArmRecoveryThenSwitchSlot));
}

TEST(BootAttemptPolicy, ARequiredBootableOtherSlotIsTheDefault) {
  // Arming a slot switch on a device with one usable slot turns a bad boot into no
  // boot.
  BootAttemptPolicy policy;
  EXPECT_TRUE(policy.require_bootable_other_slot);
  SlotSnapshot slot = HealthySlot();
  slot.other_slot_bootable = false;
  slot.tries_remaining = 1;
  const auto decision = EvaluateBootLoop(slot, 0, policy);
  EXPECT_NE(static_cast<int>(decision.action), static_cast<int>(BootLoopAction::kSwitchSlot));
}

// ---------------------------------------------------------------------------
// The ownership invariant
// ---------------------------------------------------------------------------

TEST(BootAttemptPolicy, XromNeverWritesThePlatformBootCounter) {
  // X-ROM writes /misc: the BCB at offset 0 is how a recovery boot is armed. What
  // it never writes is bootloader_control.slot_info[].tries_remaining at offset
  // 2048, or anything in the system space at offset 32768 — those bytes belong to
  // the bootloader, recovery and uncrypt, at offsets that are agreed across the
  // platform and are not configurable. A X-ROM counter parked there is a collision
  // waiting for the next AOSP feature that uses the same region.
  //
  // Asserted as a test rather than left as a comment so that the next change to
  // this file has to confront it.
  EXPECT_FALSE(xrom::recovery::XromMayWritePlatformBootCounter());
}

TEST(BootAttemptPolicy, XromsOwnCounterLivesInTheVaultRecordNotInMisc) {
  // The counterpart to the test above: integrity_failures is a field of
  // VaultRecord, which is on the xrom_vault partition and is written by the OTA
  // installer and the sentinel. Nothing in the boot-loop decision reaches into
  // misc for it, which is what keeps the two counters from being confused with
  // each other in the code as well as in the design.
  const auto decision = EvaluateBootLoop(HealthySlot(), 3, BootAttemptPolicy{});
  EXPECT_TRUE(decision.reason.find("post-boot integrity") != std::string::npos);
  EXPECT_TRUE(decision.reason.find("misc") == std::string::npos);
}

TEST(BootAttemptPolicy, EveryActionHasADistinctPrintableName) {
  const std::vector<BootLoopAction> actions = {
      BootLoopAction::kNone, BootLoopAction::kArmRecovery, BootLoopAction::kSwitchSlot,
      BootLoopAction::kArmRecoveryThenSwitchSlot};
  for (BootLoopAction action : actions) {
    EXPECT_NE(std::string(xrom::recovery::BootLoopActionName(action)), "invalid");
  }
  EXPECT_NE(std::string(xrom::recovery::BootLoopActionName(BootLoopAction::kArmRecovery)),
            std::string(xrom::recovery::BootLoopActionName(BootLoopAction::kSwitchSlot)));
}

TEST(BootAttemptPolicy, TheSameInputsProduceTheSameDecision) {
  const auto a = EvaluateBootLoop(HealthySlot(), 3, BootAttemptPolicy{});
  const auto b = EvaluateBootLoop(HealthySlot(), 3, BootAttemptPolicy{});
  EXPECT_EQ(static_cast<int>(a.action), static_cast<int>(b.action));
  EXPECT_EQ(a.reason, b.reason);
  EXPECT_EQ(a.degraded, b.degraded);
}
