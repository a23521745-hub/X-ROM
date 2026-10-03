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

/** Lifecycle of a submitted isolation task. */
@Backing(type="int")
enum TaskState {
    /** Accepted by the daemon, no VM allocated yet. */
    PENDING = 0,
    /** VM configuration built, createVm()/start() in flight. */
    VM_STARTING = 1,
    /** Microdroid is up and the payload has been launched. */
    RUNNING = 2,
    /** Payload reported success and the VM has been torn down. */
    SUCCEEDED = 3,
    /** Payload failed, VM died, or the result could not be verified. */
    FAILED = 4,
    /** Rejected by IsolationPolicy before any VM was created. */
    DENIED = 5,
    /** Cancelled by the caller. */
    CANCELLED = 6,
}
