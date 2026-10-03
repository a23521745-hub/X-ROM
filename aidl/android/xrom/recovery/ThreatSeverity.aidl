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

/**
 * How bad the thing that was just detected is.
 *
 * The numeric values MUST match xrom::recovery::ThreatSeverity in
 * common/recovery/QuarantinePlan.h. There is a test asserting the mapping, because
 * a silent disagreement between an AIDL enum and the C++ enum it feeds would make
 * a LOW threat arrive as CRITICAL or the reverse, and both are catastrophic in
 * opposite directions.
 *
 * The severity decides two things and only two: whether the device reboots into
 * recovery, and whether the user is offered a chance to stop it. Everything else
 * about the response — lock the folder, preserve the evidence, cut the network —
 * happens at every severity, because a response that only fires when the threat is
 * already severe is a response that never gets practised.
 */
enum ThreatSeverity {
    /**
     * An anomaly worth recording and worth locking down, but not worth
     * interrupting the user for. No reboot.
     */
    LOW = 0,

    /** Evidence of tampering that could not be confirmed. Lock down, preserve the
     * evidence, reboot to recovery for a full integrity pass. */
    MEDIUM = 1,

    /** Confirmed tampering with a measured artifact, or a payload whose
     * measurement did not match its signed manifest. */
    HIGH = 2,

    /**
     * Active compromise: a running component is doing something only an attacker
     * would want.
     *
     * At this severity no cancellation is offered, by default and on purpose. The
     * UI is part of the system under suspicion, and a dialog offering a way to
     * dismiss a security response is a control surface handed to whatever
     * compromised the device. An operator who wants a window here can set
     * allow_cancel_at_critical in the sentinel's configuration; the default is that
     * they should not want one.
     */
    CRITICAL = 3,
}
