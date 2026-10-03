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

import android.xrom.recovery.ThreatSeverity;

/**
 * A detection, as submitted to the sentinel by whatever noticed it.
 *
 * The sentinel does not re-derive the severity from the detail string and it does
 * not ask the caller to justify itself: it acts on the severity and records
 * everything else. That is a deliberate trust decision. The set of callers is
 * closed by SELinux and by a uid check in the daemon, so the interesting question
 * is never "is this caller telling the truth" but "what did it see", and the answer
 * to that has to survive into a log on a device that is about to be wiped.
 */
parcelable ThreatReport {
    /** How bad it is. Decides reboot and cancellation; see ThreatSeverity. */
    ThreatSeverity severity = ThreatSeverity.LOW;

    /**
     * Which component detected it, e.g. "xrom_avfd", "xrom_sentineld.boot_check",
     * "xrom_recovery_gate". Free text, length-limited by the daemon, and recorded
     * verbatim: a report that cannot say who made it cannot be triaged after the
     * fact.
     */
    String source = "";

    /** What was observed. Also free text, also recorded verbatim. */
    String detail = "";

    /**
     * Path to the evidence the detector produced, if any. The sentinel copies it
     * into its own staging directory and then into the protected VM's encrypted
     * storage; it never reads it as structured data and never trusts the path to
     * be inside any particular directory, because the whole point is that the
     * detector may be reporting on a directory the sentinel itself has locked.
     */
    String evidence_path = "";

    /** When the detector saw it, in seconds since the epoch. Zero means "the
     * detector had no clock", which the sentinel records rather than substituting
     * its own time — a detection time invented by the responder is worse than an
     * absent one. */
    long detected_unix = 0;

    /**
     * A one-time token the caller received from a previous reportThreat call, or
     * empty. Presenting it makes the new report merge into the same incident
     * instead of starting a second one, which is what a detector that fires
     * repeatedly during a single compromise needs.
     */
    String incident_token = "";
}
