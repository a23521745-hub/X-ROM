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

/**
 * The kind of work a caller is asking X-ROM to run inside a protected VM.
 *
 * This is not a label for the caller's convenience. IsolationPolicy maps each
 * class onto a fixed payload binary, a memory ceiling and a protected-VM
 * requirement, so adding a value here is a security decision that needs a
 * matching entry in /system_ext/etc/xrom/avf.json.
 */
@Backing(type="int")
enum TaskClass {
    /** Static analysis of an untrusted input (X-Defender offline scanning). */
    STATIC_ANALYSIS = 0,

    /** Verified recomputation of a measured artifact (self-healing integrity). */
    INTEGRITY_CHECK = 1,

    /** Handling of key material or remote attestation. Requires a pVM. */
    ATTESTATION = 2,

    /** A cryptographic operation on secret input. Requires a pVM. */
    CRYPTO_OPERATION = 3,
}
