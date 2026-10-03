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

#ifndef XROM_AVF_ISOLATION_SERVICE_H_
#define XROM_AVF_ISOLATION_SERVICE_H_

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <aidl/android/xrom/isolation/BnXIsolationService.h>
#include <utils/StrongPointer.h>

#include "AvfController.h"
#include "IsolationPolicy.h"
#include "PayloadManifest.h"
#include "PayloadVerifier.h"
#include "VsockChannel.h"

namespace xrom::avf {

namespace aidl_xrom = ::aidl::android::xrom::isolation;

// Implementation of android.xrom.isolation.IXIsolationService.
//
// Binder threads never boot a VM. submitTask() checks the request against
// IsolationPolicy, records it, and returns a sequence number; a bounded pool of
// worker threads does the AVF work. A Microdroid boot takes hundreds of
// milliseconds, and a binder thread blocked that long is a denial-of-service
// handle handed to every permitted caller.
class IsolationService : public aidl_xrom::BnXIsolationService {
 public:
  struct Tunables {
    // How long to wait for the guest payload to report ready.
    int32_t vm_launch_timeout_ms = 30000;
    // How long to wait for the payload to finish once ready.
    int32_t task_timeout_ms = 120000;
    // How long to wait for the guest's kGuestHello after it reports ready. Short
    // on purpose: the payload sends it immediately on accept, so a delay here
    // means the guest is wedged, not slow.
    int32_t hello_timeout_ms = 10000;
    // Bytes per kTaskInput / kTaskOutput frame. 64 KiB keeps a frame inside the
    // vsock buffer so neither side has to reassemble a split frame.
    int32_t transfer_chunk_bytes = 64 * 1024;
    // True only on a userdebug/eng build.
    bool debuggable_build = false;
  };

  IsolationService(AvfController* controller, IsolationPolicy policy, Tunables tunables);
  ~IsolationService() override;

  IsolationService(const IsolationService&) = delete;
  IsolationService& operator=(const IsolationService&) = delete;

  // Starts the worker pool. Called once, after construction, before the service
  // is registered with servicemanager.
  void Start();

  // Stops the worker pool and tears down every running VM. Called from the
  // daemon's shutdown path so that a SIGTERM cannot leave an orphaned pVM
  // holding guest memory.
  void Shutdown();

  // --- IXIsolationService ----------------------------------------------
  ::android::binder::Status submitTask(const aidl_xrom::IsolationTaskRequest& request,
                                       const ::android::sp<aidl_xrom::IIsolationTaskCallback>& callback,
                                       int64_t* out_sequence) override;
  ::android::binder::Status getResult(int64_t sequence,
                                      aidl_xrom::IsolationTaskResult* out_result) override;
  ::android::binder::Status cancelTask(int64_t sequence) override;
  ::android::binder::Status isProtectedVmAvailable(bool* out_available) override;
  ::android::binder::Status getActiveVmCount(int32_t* out_count) override;

 private:
  struct WorkItem {
    int64_t sequence = 0;
    TaskRequest request;
    CallerIdentity caller;
    ::android::sp<aidl_xrom::IIsolationTaskCallback> callback;
    // Memory reserved for this task at admission time, released when it ends.
    int64_t reserved_memory_mib = 0;
  };

  struct Record {
    aidl_xrom::IsolationTaskResult result;
    int32_t owner_uid = -1;
    bool cancelled = false;
    bool running = false;
    std::string vm_name;
  };

  void WorkerMain();
  void RunTask(const WorkItem& item);

  // --- the data plane ----------------------------------------------------
  //
  // Everything that happens over the vsock between "the VM is up" and "the task
  // has a verified result". Kept out of RunTask because RunTask's job is the VM
  // lifecycle and admission bookkeeping, and because this function has one
  // clearly stated contract: it either returns a result whose every digest the
  // host recomputed itself, or it returns a reason why not. There is no partial
  // success and no path that leaves |ok| true with an unverified digest.
  struct DataPlaneOutcome {
    bool ok = false;
    std::string error;

    // True once the guest identified itself, whether or not it was accepted.
    bool hello_received = false;
    vsock::GuestHello hello;

    bool result_received = false;
    vsock::TaskResult task_result;

    std::vector<uint8_t> output;

    // The level the host is willing to assert, after clamping what the guest
    // claimed down to what the host could corroborate.
    aidl_xrom::AttestationLevel attestation = aidl_xrom::AttestationLevel::MEASUREMENT_ONLY;
  };

  DataPlaneOutcome RunDataExchange(const WorkItem& item, const AvfController::VmHandle& handle,
                                   const VerifiedPayload& verified,
                                   std::chrono::steady_clock::time_point deadline);

  // Returns the concurrency slot and the memory reservation taken in submitTask.
  // Called on every exit path from WorkerMain, including cancellation.
  void ReleaseSlot(const WorkItem& item);

  bool IsCancelled(int64_t sequence) const;

  void SetState(const WorkItem& item, aidl_xrom::TaskState state);
  void Complete(const WorkItem& item, const aidl_xrom::IsolationTaskResult& result);
  void UpdateRecord(int64_t sequence,
                    const std::function<void(aidl_xrom::IsolationTaskResult*)>& mutate);

  // Reads /proc/<pid>/attr/current for the audit record. Best effort: a failure
  // here must never fail a request, and the value is never used for a decision.
  static std::string PeerSelinuxDomain(int32_t pid);

  AvfController* const controller_;
  const IsolationPolicy policy_;
  const Tunables tunables_;

  // Signature and measurement verification of the payload. Loaded lazily on the
  // first task from the trust config named in the VmSpec, so that a daemon whose
  // trust material is missing reports the reason on every task instead of
  // refusing to start and leaving the operator with an init restart loop.
  PayloadVerifier verifier_;

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<WorkItem> queue_;
  std::map<int64_t, Record> records_;
  std::vector<std::thread> workers_;
  std::atomic<bool> shutdown_{false};
  int64_t next_sequence_ GUARDED_BY(mutex_) = 1;
  int32_t active_vms_ GUARDED_BY(mutex_) = 0;
  int64_t committed_memory_mib_ GUARDED_BY(mutex_) = 0;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_ISOLATION_SERVICE_H_
