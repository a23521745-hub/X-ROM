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

#include "BootAttemptPolicy.h"

namespace xrom::recovery {

const char* BootLoopActionName(BootLoopAction action) {
  switch (action) {
    case BootLoopAction::kNone:
      return "none";
    case BootLoopAction::kArmRecovery:
      return "arm-recovery";
    case BootLoopAction::kSwitchSlot:
      return "switch-slot";
    case BootLoopAction::kArmRecoveryThenSwitchSlot:
      return "arm-recovery-then-switch-slot";
  }
  return "invalid";
}

BootLoopDecision EvaluateBootLoop(const SlotSnapshot& slot, uint32_t integrity_failures,
                                  const BootAttemptPolicy& policy) {
  BootLoopDecision decision;

  // --- X-ROM's own counter: boots that reached userspace and failed -----------
  //
  // This is checked first, and independently of whether the platform counter could
  // be read. A post-boot integrity failure is confirmed evidence about the running
  // image, and refusing to act on it because /misc was unreadable would leave a
  // device looping between "boot fine, find the image is wrong, reboot" forever.
  const bool integrity_exhausted = integrity_failures >= policy.max_integrity_failures;

  // A single dm-verity corruption report is treated as an exhausted counter,
  // because it is not a guess: the kernel's own verification of a block it was
  // asked to read failed. That is the same class of fact as three of our own
  // comparisons disagreeing.
  const bool verity_failed = policy.verity_corruption_counts && slot.available &&
                             slot.verity_corrupted && !slot.successful_boot;

  // --- the platform counter: boots that never reached userspace ---------------
  bool tries_exhausted = false;
  if (slot.available) {
    // successful_boot means the bootloader has already been told this slot works
    // and has reset tries_remaining to its maximum. Comparing against the floor in
    // that state would be meaningless, so the counter is only consulted when the
    // slot has not been confirmed good.
    tries_exhausted = !slot.successful_boot && slot.tries_remaining <= policy.tries_remaining_floor;
  }

  if (!integrity_exhausted && !verity_failed && !tries_exhausted) {
    decision.action = BootLoopAction::kNone;
    if (!slot.available) {
      decision.degraded = true;
      decision.reason =
          "no failure condition is met, but the platform boot counter could not be "
          "read, so this decision rests on X-ROM's own counter alone";
    } else {
      decision.reason = "tries_remaining=" + std::to_string(slot.tries_remaining) +
                        ", integrity_failures=" + std::to_string(integrity_failures) +
                        " of " + std::to_string(policy.max_integrity_failures);
    }
    return decision;
  }

  // --- something has to be done; decide what ----------------------------------
  //
  // Recovery is the first resort and the slot switch the second, because recovery
  // can restore from the vault without discarding anything, while a slot switch
  // abandons the current image and, on a device whose two slots were updated
  // together, may land on an equally broken one.
  const bool can_switch = !policy.require_bootable_other_slot ||
                          (slot.available && slot.other_slot_bootable);

  // Recovery that the bootloader will not honour is worse than no recovery: the
  // device comes back up in the same state and the failure has now been consumed
  // invisibly. So when recovery_tries_remaining is spent, skip straight to the
  // slot switch if there is one, and say why.
  const bool recovery_blocked =
      policy.respect_recovery_tries && slot.available && slot.recovery_tries_remaining == 0;

  std::string evidence;
  if (integrity_exhausted) {
    evidence += "post-boot integrity failed on " + std::to_string(integrity_failures) +
                " consecutive boots (limit " + std::to_string(policy.max_integrity_failures) + ")";
  }
  if (verity_failed) {
    evidence += evidence.empty() ? "" : "; ";
    evidence += "dm-verity reported corruption on a slot the bootloader has not "
                "confirmed good";
  }
  if (tries_exhausted) {
    evidence += evidence.empty() ? "" : "; ";
    evidence += "the bootloader has " + std::to_string(slot.tries_remaining) +
                " tries left on this slot (floor " +
                std::to_string(policy.tries_remaining_floor) + ")";
  }

  if (recovery_blocked && can_switch) {
    decision.action = BootLoopAction::kSwitchSlot;
    decision.reason = evidence + "; recovery attempts are exhausted so the other "
                                 "slot is tried instead";
    return decision;
  }
  if (recovery_blocked && !can_switch) {
    // Neither remedy is available. The device keeps booting and the situation is
    // reported, because there is no third option and silently choosing kNone would
    // hide the fact that both were considered and rejected.
    decision.action = BootLoopAction::kNone;
    decision.reason = evidence + "; recovery attempts are exhausted and no other "
                                 "slot is bootable, so no automatic remedy is "
                                 "available and the condition is reported instead";
    return decision;
  }

  if (!slot.available) {
    // The platform counter could not be read. X-ROM's own counter still fired, so
    // the response is still armed; the decision is recorded as degraded because
    // the slot-switch half of it cannot be evaluated without knowing whether the
    // other slot boots.
    decision.action = BootLoopAction::kArmRecovery;
    decision.degraded = true;
    decision.reason = evidence + "; the platform boot counter could not be read, so "
                                 "only recovery is armed and no slot switch is "
                                 "attempted";
    return decision;
  }

  // tries_exhausted on its own — the bootloader is about to give up on this slot —
  // is the one case where switching first is right, because the bootloader is going
  // to switch anyway and recovery entered from a dying slot is recovery entered
  // with an unreliable view of the device. When X-ROM's own integrity counter also
  // fired, recovery is armed with the switch held in reserve.
  if (tries_exhausted && !integrity_exhausted && !verity_failed && can_switch) {
    decision.action = BootLoopAction::kSwitchSlot;
    decision.reason = evidence + "; only the bootloader's own counter is exhausted, "
                                 "so the slot is switched rather than recovery being "
                                 "armed against an image the bootloader has already "
                                 "given up on";
    return decision;
  }

  decision.action =
      can_switch ? BootLoopAction::kArmRecoveryThenSwitchSlot : BootLoopAction::kArmRecovery;
  decision.reason = evidence;
  decision.reason += can_switch ? "; recovery is armed with the other slot held in reserve"
                                : "; recovery is armed and no other slot is available";
  return decision;
}

bool XromMayWritePlatformBootCounter() {
  // Always false, and deliberately so.
  //
  // X-ROM writes /misc: the BCB at offset 0 is how a recovery boot is armed, and
  // that write is performed by the sentinel through libbootloader_message. What it
  // never writes is bootloader_control.slot_info[].tries_remaining at offset 2048,
  // or anything in the system space at offset 32768. Those bytes are owned by the
  // bootloader, by recovery and by uncrypt, at offsets that are agreed across the
  // platform and are not configurable; a X-ROM counter there would collide with
  // the next AOSP feature that uses the same region.
  //
  // This is a function rather than a constant so that the invariant can be asserted
  // in a test and grepped for in review, instead of living only in a comment that
  // the next change might not read.
  return false;
}

}  // namespace xrom::recovery
