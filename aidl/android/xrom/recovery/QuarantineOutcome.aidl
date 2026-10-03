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
 * What the sentinel did about a ThreatReport.
 *
 * Returned synchronously, before any reboot, so that the caller can log its own
 * view of the incident. A caller that only learns the outcome from the recovery
 * image learns it after a wipe.
 */
parcelable QuarantineOutcome {
    /** The report was accepted and acted on. False means the sentinel refused it,
     * and reason says why — most often because the caller is not authorised. */
    boolean accepted = false;

    /** The plan this report produced, as one human-readable line. Mirrors
     * xrom::recovery::QuarantinePlan::Describe() and is what goes into the log. */
    String plan = "";

    /** True when the plan ends in a reboot into recovery. */
    boolean rebooting = false;

    /**
     * Seconds since the epoch after which a cancellation will no longer be
     * honoured. Zero when no cancellation window was offered, which is the case at
     * CRITICAL severity by default and at any severity that does not reboot.
     */
    long cancel_deadline_unix = 0;

    /**
     * One-time token required by cancelPendingQuarantine. Deliberately not
     * derivable from anything the caller already knows: a system-uid component
     * that never saw the prompt must not be able to dismiss it.
     */
    String cancel_token = "";

    /** Which steps of the plan completed, in order. A step that failed is present
     * with its failure appended, so the log shows the whole sequence rather than
     * stopping at the first problem. */
    String[] steps_completed = new String[0];

    /** The incident token for follow-up reports. */
    String incident_token = "";

    /** Why the report was refused, or a summary of what was done. */
    String reason = "";
}
