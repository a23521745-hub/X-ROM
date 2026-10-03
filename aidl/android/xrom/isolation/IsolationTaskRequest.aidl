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
package android.xrom.isolation;

import android.xrom.isolation.TaskClass;

/**
 * A request to run one isolated task.
 *
 * The request carries a *digest* of the work rather than the work itself. The
 * input is written to a file the daemon owns, the digest is what gets measured
 * and logged, and the payload inside the VM re-derives the digest from the file
 * descriptor it is handed and refuses to proceed on a mismatch. Sending the
 * bytes over binder twice would double the surface for a confused deputy.
 */
parcelable IsolationTaskRequest {
    /** Caller-chosen identifier, unique per caller. [a-z0-9_.-]{1,64}. */
    String taskId;

    /** What kind of work this is. Determines payload, limits and pVM need. */
    TaskClass taskClass;

    /** SHA-256 of the input artifact. Must be exactly 32 bytes. */
    byte[] inputDigest;

    /**
     * Path to the input artifact. Must be inside a directory the caller is
     * already allowed to read; the daemon re-opens it and never trusts the
     * caller's file descriptor, so a swapped-after-open file is caught by the
     * digest check rather than being executed.
     */
    String inputPath;

    /** Requested guest RAM in MiB. Clamped to the task class ceiling. */
    int requestedMemoryMib;

    /**
     * Ask for a debuggable VM. Denied unless the build is userdebug/eng AND
     * allow_debuggable_vm is true in /system_ext/etc/xrom/avf.json. A
     * DebugLevel.FULL VM exposes a guest adb shell and full kernel logs, which
     * is incompatible with the confidentiality guarantees the task classes
     * exist to provide.
     */
    boolean requestDebug;
}
