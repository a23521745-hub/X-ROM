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

/** The state of the xrom_vault partition as the sentinel understands it. */
parcelable VaultStatus {
    /** True when a vault record parsed and validated. False means the partition is
     * absent, unreadable, erased or holds a record this build cannot parse — and
     * the recovery decision engine treats all of those as "there is no fallback". */
    boolean usable = false;

    /** xrom::recovery::VaultState as an int: 0 empty, 1 written, 2 verified,
     * 3 mismatch, 4 rolled-back. */
    int state = 0;

    /** The same value as a name, for logs and for a UI that should not have to
     * duplicate the enum. */
    String state_name = "";

    /** Consecutive boots that reached userspace and then failed the post-boot
     * integrity comparison. This is X-ROM's own boot-loop counter; the
     * bootloader's tries_remaining is a different counter covering a different
     * failure class, and BootLoopStatus reports that one. */
    int integrity_failures = 0;

    /** When the image in the vault was written, in seconds since the epoch. */
    long written_unix = 0;

    /** ro.build.fingerprint of the image in the vault. */
    String build_fingerprint = "";

    /** vbmeta hashtree root of the image in the vault, lowercase hex. Empty when
     * the vault is not usable. */
    String vault_hashtree_root = "";

    /** Why the vault is not usable, when it is not. */
    String detail = "";
}
