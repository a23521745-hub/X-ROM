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

import android.xrom.isolation.IsolationTaskResult;
import android.xrom.isolation.TaskState;

/**
 * Progress notifications for a submitted task.
 *
 * oneway, so a slow or wedged caller cannot stall the daemon's worker thread —
 * a client that stops draining binder is a denial-of-service vector, and an
 * isolation service must not have one.
 */
oneway interface IIsolationTaskCallback {
    /** Emitted on every TaskState transition, in order. */
    void onStateChanged(String taskId, in TaskState state);

    /**
     * Emitted exactly once, when the task reaches SUCCEEDED, FAILED, DENIED or
     * CANCELLED. The daemon drops its reference to the callback afterwards; the
     * caller must not expect further traffic and must not re-register it.
     */
    void onCompleted(in IsolationTaskResult result);
}
