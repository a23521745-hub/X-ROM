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

import android.xrom.recovery.BootLoopStatus;
import android.xrom.recovery.IntegrityReportInfo;
import android.xrom.recovery.QuarantineOutcome;
import android.xrom.recovery.RecoveryPreview;
import android.xrom.recovery.ThreatReport;
import android.xrom.recovery.VaultStatus;

/**
 * X-ROM's self-healing recovery service.
 *
 * WHAT THIS SERVICE IS ALLOWED TO DO, AND WHAT IT IS NOT
 * ------------------------------------------------------
 * It writes the bootloader control block in /misc, it locks a monitored directory,
 * it moves encrypted evidence into the protected VM's storage, it drops the
 * network through netd's firewall chain, and it reboots the device. That is a very
 * large amount of authority, so the interface is small, the caller set is closed,
 * and every method records what it did.
 *
 * It does NOT decide what counts as a threat. Detection belongs to whoever is
 * looking — xrom_avfd for payloads, the boot-time integrity check for images, an
 * operator for everything else — and this service acts on the severity it is given.
 * The split is what keeps the authority in one place and the judgement in another,
 * so that a bug in a detector produces a logged report rather than a silent policy
 * change.
 *
 * It also does not touch the AVF isolation service. IXIsolationService and the
 * vsock data plane are unchanged by this interface; the only interaction is that
 * the sentinel asks for a VM to hold evidence, through the same binder interface
 * every other client uses, and is subject to the same IsolationPolicy as them.
 *
 * Platform-internal, CPP backend only, no stability annotation and no VINTF entry:
 * it is not a vendor HAL and it crosses no Treble boundary.
 */
interface IXRecoveryService {
    /**
     * Report a threat and let the sentinel respond to it.
     *
     * Returns synchronously with what the sentinel decided and did, before any
     * reboot. The caller is expected to log the outcome itself: a caller that only
     * learns the outcome from the recovery image learns it after a wipe.
     *
     * Authorised callers are checked by uid and by SELinux; an unauthorised caller
     * gets accepted=false and a reason, not an exception, so that the attempt
     * itself is recorded rather than lost in a binder death.
     */
    QuarantineOutcome reportThreat(in ThreatReport report);

    /**
     * Cancel a pending quarantine reboot.
     *
     * |cancel_token| is the one-time token returned by reportThreat. |user_confirmed|
     * asserts that a keyguard-authenticated human dismissed the prompt.
     *
     * The trust boundary here is worth stating plainly rather than hiding: the
     * sentinel cannot itself see the keyguard, so "was it really the user" is
     * delegated to a system-uid caller that can — which is the same delegation
     * every security prompt in Android already makes. What the token adds is that a
     * system-uid component which never saw the prompt cannot dismiss it. Both halves
     * are required: the uid check alone would let any system component cancel any
     * quarantine, and the token alone would let a non-UI process that happened to
     * read the log pretend to be a user.
     *
     * Returns false when the window has closed, the token does not match, the
     * severity does not permit cancellation, or the caller is not authorised. The
     * attempt is logged either way, including successful ones.
     */
    boolean cancelPendingQuarantine(in String cancel_token, boolean user_confirmed);

    /**
     * Compare the running slot against the vault.
     *
     * |deep| selects SHA-256 over every byte of both partitions instead of
     * comparing the AVB hashtree roots. The deep form is gigabytes of flash I/O and
     * duplicates work dm-verity already does on every read, so it is opt-in: the
     * cheap comparison is the one that gates boot, and the deep one is for
     * explaining a mismatch the cheap one already found.
     */
    IntegrityReportInfo checkVaultIntegrity(boolean deep);

    /** The state of the xrom_vault partition. */
    VaultStatus getVaultStatus();

    /** What the boot-loop guard concluded at the start of this boot. */
    BootLoopStatus getBootLoopStatus();

    /**
     * Run the hybrid decision engine against live signals without acting on the
     * result. See RecoveryPreview for why this exists.
     */
    RecoveryPreview previewRecoveryDecision();

    /**
     * Arm a recovery boot without a threat report.
     *
     * For an operator and for tests, and restricted accordingly: the caller must be
     * the system uid and |reason| must be one of the recorded X-ROM recovery
     * reasons, so that a manual arming is distinguishable in the recovery log from
     * an automatic one. Returns false rather than throwing when refused.
     *
     * Uses the same append semantics as every other BCB write in this project: a
     * queued command from uncrypt or update_engine survives, and an unchanged BCB is
     * not rewritten.
     */
    boolean armRecoveryBoot(in String reason);
}
