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
 * The result of comparing the running slot against the vault.
 *
 * The verdict is three-valued and the third value is the one that matters most.
 * "match" and "mismatch" are answers; "inconclusive" means the comparison could not
 * be completed, and folding it into "mismatch" would make every device with an
 * unreadable vault look tampered with. The first few of those in the field would
 * teach everyone to ignore the alarm that follows.
 */
parcelable IntegrityReportInfo {
    /** xrom::recovery::IntegrityVerdict as an int: 0 match, 1 mismatch,
     * 2 inconclusive. */
    int verdict = 2;

    /** The verdict as a name. */
    String verdict_name = "";

    /** xrom::recovery::IntegrityDepth as an int: 0 compared the AVB hashtree roots,
     * 1 compared SHA-256 over every byte of both partitions. The report says which
     * one ran, because a cheap check that passed reads exactly like a thorough one
     * that passed unless the depth is recorded. */
    int depth = 0;

    /** Digest of the running slot, lowercase hex. Empty when it could not be read. */
    String system_digest = "";

    /** Digest of the vault, lowercase hex. Empty when it could not be read. */
    String vault_digest = "";

    /** Which side moved, or why the comparison could not be made. This is the field
     * that decides the remedy: restore FROM the vault, rewrite the vault, or go to
     * recovery because neither copy is known good. */
    String detail = "";

    /** One line for the log, mirroring IntegrityReport::Describe(). */
    String summary = "";
}
