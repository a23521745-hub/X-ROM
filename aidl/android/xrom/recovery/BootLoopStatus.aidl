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

package android.xrom.recovery;

/** What the boot-loop guard concluded at the start of this boot. */
parcelable BootLoopStatus {
    /** xrom::recovery::BootLoopAction as an int: 0 none, 1 arm-recovery,
     * 2 switch-slot, 3 arm-recovery-then-switch-slot. */
    int action = 0;

    /** The action as a name. */
    String action_name = "";

    /** True when the decision was made without a trustworthy platform counter,
     * i.e. /misc could not be read or held no valid bootloader_control. The action
     * is still taken — failing to act because /misc was unreadable is how a device
     * loops forever — but the log records that half the evidence was missing. */
    boolean degraded = false;

    /** The bootloader's own tries_remaining for the current slot, or -1 when it
     * could not be read. */
    int tries_remaining = -1;

    /** X-ROM's own count of post-boot integrity failures on this slot. */
    int integrity_failures = 0;

    /** Why. Always populated, including when the action is "none", because a boot
     * loop guard that stays silent when it decides to do nothing cannot be
     * distinguished from one that never ran. */
    String reason = "";
}
