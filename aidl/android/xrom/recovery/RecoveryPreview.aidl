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
 * What the hybrid decision engine would choose right now, without choosing it.
 *
 * Exists because the decision is made in the recovery image, where there is no
 * shell, no logcat and no way to ask. Being able to run the same engine on a
 * healthy device — with the same pinned CIDRs, the same policy and live signal
 * values — is the only way to find out before an incident whether a given network
 * would be trusted or refused.
 */
parcelable RecoveryPreview {
    /** True when the engine would install from xrom_vault. */
    boolean use_vault = true;

    /** Every signal that was not clean, with its name and value. */
    String[] doubts = new String[0];

    /** Every signal that was checked and passed. Recorded because "it used the
     * vault" after eleven clean checks and one doubt is a different incident from
     * "it used the vault" with nothing checked at all. */
    String[] clean = new String[0];

    /** One line for the log. */
    String reason = "";
}
