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

import android.xrom.isolation.IIsolationTaskCallback;
import android.xrom.isolation.IsolationTaskRequest;
import android.xrom.isolation.IsolationTaskResult;

/**
 * X-ROM's entry point for running work inside an isolated Microdroid VM.
 *
 * Registered as android.xrom.isolation.IXIsolationService/xrom_isolation and
 * labelled xrom_avf_service in service_contexts. Reachability is granted
 * per-domain by xrom_avfd_client(); untrusted apps cannot resolve the name at
 * all, and the daemon re-checks the caller's uid before accepting work.
 *
 * Callers never see a VirtualMachineConfig, a CID or a file descriptor for VM
 * state. Everything AVF-shaped is confined to the daemon, which is the point:
 * the number of processes that can express "boot me a VM with these options"
 * on an X-ROM device is one.
 */
interface IXIsolationService {
    /** servicemanager instance name. */
    const String INSTANCE = "xrom_isolation";

    /**
     * Submit a task. Returns a monotonically increasing sequence number, or a
     * negative value on rejection:
     *   -1  malformed request (see IsolationPolicy for what counts)
     *   -2  denied by policy
     *   -3  at the concurrency or memory-budget ceiling
     *   -4  no usable hypervisor (AVF absent, or protected VMs unavailable and
     *       the task class requires one)
     *
     * Rejection is synchronous and cheap; nothing is allocated until the call
     * returns a non-negative sequence number.
     */
    long submitTask(in IsolationTaskRequest request, in IIsolationTaskCallback callback);

    /**
     * Current or terminal result for a task. Returns a result with state DENIED
     * and a detail string if the sequence number is unknown to this caller —
     * tasks are not enumerable across uids.
     */
    IsolationTaskResult getResult(long sequence);

    /**
     * Stop a task and tear its VM down immediately, as if the power had been
     * pulled. The guest is not notified and gets no chance to flush.
     */
    void cancelTask(long sequence);

    /**
     * Whether a protected VM can be booted right now. False when AVF is absent,
     * when the kernel came up without pKVM, or when the global virtualization
     * state has been set to DISABLED. Callers that need ATTESTATION or
     * CRYPTO_OPERATION should check this before queueing work.
     */
    boolean isProtectedVmAvailable();

    /** Number of VMs currently allocated. Bounded by the daemon config. */
    int getActiveVmCount();
}
