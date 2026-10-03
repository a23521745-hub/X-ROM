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

#ifndef XROM_RECOVERY_BOOT_ATTEMPT_POLICY_H_
#define XROM_RECOVERY_BOOT_ATTEMPT_POLICY_H_

#include <cstdint>
#include <string>

namespace xrom::recovery {

// ---------------------------------------------------------------------------
// "Three failed boots trigger recovery" — and the reason it needs two counters.
//
// THE COUNTER ALREADY EXISTS, AND IT IS NOT OURS TO REINVENT
// ----------------------------------------------------------
// A/B Android already maintains a boot-attempt counter, in
// bootloader_control.slot_info[slot].tries_remaining, stored inside the
// slot_suffix field of bootloader_message_ab at offset 2048 of /misc. The
// bootloader decrements it before each attempt and resets it after a successful
// boot; when it reaches zero the bootloader marks the slot unbootable and falls
// back to the other one. That machinery is platform code, is exercised on every
// device that ships A/B updates, and is the thing the recovery image and
// update_engine already cooperate with.
//
// Writing our own counter into /misc would therefore be worse than redundant. The
// region past the 2 KiB BCB is shared by bootloader, recovery and uncrypt at
// offsets they agree on and that are not configurable; SYSTEM_SPACE_OFFSET_IN_MISC
// (32 KiB, 32 KiB long) is reserved for AOSP features such as
// misc_virtual_ab_message. A X-ROM counter parked anywhere in there is a collision
// waiting for a platform update to land on it. So this file reads the platform's
// counter instead of maintaining one, and adds exactly the part the platform does
// not cover.
//
// WHAT THE PLATFORM COUNTER CANNOT SEE
// ------------------------------------
// tries_remaining counts boots that failed at the bootloader's level: no kernel,
// no init, a slot that never reached userspace. It says nothing about a device
// that boots perfectly and then fails a post-boot integrity check, because from
// the bootloader's point of view that boot succeeded. A device that comes up,
// discovers its /system does not match its vault, and reboots into the same state
// will loop forever with tries_remaining untouched.
//
// So there are two failure classes and they need two counters:
//
//   * tries_remaining — did not reach userspace. Owned by the bootloader, read
//     here, never written by X-ROM.
//   * integrity_failures — reached userspace and failed the post-boot check. Owned
//     by X-ROM, stored in the vault record, incremented by the sentinel.
//
// Either one reaching its limit arms recovery. Keeping them separate is what makes
// the incident log able to say which kind of failure is happening, and keeping the
// first one read-only is what stops X-ROM from fighting the bootloader over the
// same bytes.
// ---------------------------------------------------------------------------

// The platform's view of the current slot, read from bootloader_control.
struct SlotSnapshot {
  // False when /misc could not be read or did not contain a valid
  // bootloader_control (no magic, bad CRC, non-A/B device). Every decision below
  // degrades to "do not trust this counter" rather than to "assume it is fine".
  bool available = false;

  uint32_t slot_index = 0;
  uint32_t tries_remaining = 0;
  bool successful_boot = false;
  bool verity_corrupted = false;
  uint32_t priority = 0;

  // recovery_tries_remaining from the same structure: how many times recovery
  // itself may be entered before the bootloader stops offering it. A recovery loop
  // is as bad as a boot loop and this is the platform's guard against it, so the
  // decision engine has to look at it before arming recovery a fourth time.
  uint32_t recovery_tries_remaining = 0;

  // Whether the other slot is bootable, i.e. whether falling back is even an
  // option. Arming a slot switch on a device with one usable slot turns a bad boot
  // into no boot.
  bool other_slot_bootable = false;
};

struct BootAttemptPolicy {
  // X-ROM's own limit on post-boot integrity failures.
  uint32_t max_integrity_failures = 3;

  // Arm recovery when the platform counter is at or below this many tries left.
  // Not zero: at zero the bootloader has already given up on the slot and is
  // switching away from it, so waiting for zero means X-ROM never gets to say
  // anything about a slot that is dying.
  uint32_t tries_remaining_floor = 1;

  // dm-verity reporting corruption is a confirmed integrity failure that did not
  // come from X-ROM's own check, and it is treated as one.
  bool verity_corruption_counts = true;

  // Refuse to arm recovery when the platform has run out of recovery attempts,
  // because the bootloader would ignore it and the device would come back up in the
  // same state with the failure now invisible.
  bool respect_recovery_tries = true;

  // Refuse to switch slots when the other slot is not bootable.
  bool require_bootable_other_slot = true;
};

enum class BootLoopAction : int32_t {
  // Nothing to do: this boot is healthy as far as boot-loop accounting goes.
  kNone = 0,
  // Write boot-recovery into the BCB.
  kArmRecovery = 1,
  // Ask the bootloader to try the other slot, by marking this one unbootable.
  kSwitchSlot = 2,
  // Both: try recovery, and if recovery cannot fix it, fall back.
  kArmRecoveryThenSwitchSlot = 3,
};

const char* BootLoopActionName(BootLoopAction action);

struct BootLoopDecision {
  BootLoopAction action = BootLoopAction::kNone;
  std::string reason;

  // True when the decision was made without a trustworthy platform counter. The
  // action is still taken — failing to act because /misc could not be read is how
  // a device loops forever — but the log has to record that half the evidence was
  // missing.
  bool degraded = false;
};

// Decides what to do at the start of a boot, given the platform's slot state and
// X-ROM's own integrity-failure count from the vault record.
//
// |integrity_failures| is the sentinel's counter, i.e. how many consecutive boots
// reached userspace and then failed the post-boot comparison. It is passed in
// rather than read here so that the policy stays testable and the storage stays the
// vault record's business.
BootLoopDecision EvaluateBootLoop(const SlotSnapshot& slot, uint32_t integrity_failures,
                                  const BootAttemptPolicy& policy);

// Whether the sentinel may write to /misc for boot-loop accounting at all. Always
// false: the platform counter is read-only to X-ROM, and the answer being a
// function rather than a constant is so that the invariant is stated in one place
// and can be asserted in a test instead of living in a comment.
bool XromMayWritePlatformBootCounter();

}  // namespace xrom::recovery

#endif  // XROM_RECOVERY_BOOT_ATTEMPT_POLICY_H_
