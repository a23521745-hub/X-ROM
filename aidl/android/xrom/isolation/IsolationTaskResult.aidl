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

import android.xrom.isolation.AttestationLevel;
import android.xrom.isolation.TaskState;

/** Outcome of a submitted isolation task. */
parcelable IsolationTaskResult {
    /** Echoes IsolationTaskRequest.taskId. */
    String taskId;

    /** Terminal or current state. */
    TaskState state;

    /** Payload exit code, or -1 if the payload never reported one. */
    int exitCode;

    /**
     * SHA-256 of the output artifact as computed *inside* the VM. The daemon
     * recomputes it over the bytes the VM returned and fails the task on a
     * mismatch: a VM that was tampered with in flight must not be able to hand
     * back a result that looks internally consistent.
     *
     * Empty when the payload never reported a result — a DENIED or FAILED task
     * has no output to digest, and filling this with zeroes would make "no
     * output" and "output that hashes to zero" indistinguishable.
     */
    byte[] outputDigest;

    /** Human-readable reason. Populated for DENIED, FAILED and CANCELLED. */
    String detail;

    /** CID the VM held while running, or -1 if it never got one. */
    int cid;

    // -----------------------------------------------------------------------
    // Provenance. Everything below is filled in only for a COMPLETED task, and
    // only from a kTaskResult frame whose digest the daemon recomputed itself.
    //
    // The point of carrying the measurements back to the caller is that a digest
    // on its own is not evidence: outputDigest says "these bytes", and these
    // fields say which payload, which configuration and which VM instance
    // produced them. A consumer that caches or forwards a result can pin all of
    // it, and a consumer that only wanted the bytes can ignore them.
    // -----------------------------------------------------------------------

    /** How strongly this result is backed. See AttestationLevel. */
    AttestationLevel attestationLevel;

    /** Number of output bytes the payload reported sending. */
    int outputLength;

    /**
     * SHA-256 of the payload library, measured by the guest over /proc/self/exe
     * inside the VM. Compared by the daemon against payload_lib_sha256 in the
     * signed manifest before any input was released; reported here so the caller
     * can see what it was compared against.
     */
    byte[] payloadLibDigest;

    /**
     * SHA-256 of assets/vm_config.json as the guest sees it after extraction from
     * the verified APK. Checked against the manifest the same way.
     */
    byte[] vmConfigDigest;

    /**
     * SHA-256 over the whole unzipped APK contents directory, computed by the
     * guest. The host cannot recompute this one from the APK without unzipping
     * it, so it is recorded rather than enforced: it is identical in kGuestHello
     * and in kTaskResult, which ties a result to the directory state that
     * produced it and makes a modified extraction visible in the audit trail.
     */
    byte[] apkContentsDigest;

    /**
     * The instance binding from kTaskResult: a SHA-256 over a secret that only
     * this VM instance can obtain, mixed with the request nonce and the output
     * digest. Empty when attestationLevel is MEASUREMENT_ONLY.
     *
     * The daemon cannot verify this value and does not claim to. It is published
     * so that two results from two VM instances can be told apart, and so that a
     * replayed result can be recognised by anything that has seen the original.
     */
    byte[] instanceBinding;

    /** The nonce the host generated for this task, echoed back by the payload. */
    byte[] nonce;

    /** payload_name from the verified manifest, e.g. "xvault". */
    String payloadName;

    /** key_id of the trust anchor whose signature authorised the manifest. */
    String manifestKeyId;

    /** security_version from the verified manifest, for anti-rollback auditing. */
    int manifestSecurityVersion;
}
