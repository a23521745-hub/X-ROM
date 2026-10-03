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

#ifndef XROM_AVF_VM_LIFECYCLE_OBSERVER_H_
#define XROM_AVF_VM_LIFECYCLE_OBSERVER_H_

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>

#include <aidl/android/system/virtualizationservice/BnVirtualMachineCallback.h>
#include <aidl/android/system/virtualizationcommon/DeathReason.h>
#include <aidl/android/system/virtualizationcommon/ErrorCode.h>

namespace xrom::avf {

// Implementation of android.system.virtualizationservice.IVirtualMachineCallback.
//
// CPP-backend Bn signature convention, stated here because getting it wrong is
// otherwise a wall of "marked override but does not override": `in` primitives
// arrive by value, `in` parcelables and enums arrive by const reference, and
// every method returns ::android::binder::Status. The interface is `oneway`, so
// these are called on a binder thread and must not block on the daemon's own
// locks for long.
class VmLifecycleObserver
    : public ::aidl::android::system::virtualizationservice::BnVirtualMachineCallback {
 public:
  enum class Phase : int32_t {
    kCreated = 0,
    kPayloadStarted = 1,
    kPayloadReady = 2,
    kPayloadFinished = 3,
    kError = 4,
    kDied = 5,
  };

  // --- IVirtualMachineCallback -----------------------------------------
  ::android::binder::Status onPayloadStarted(int32_t cid) override;
  ::android::binder::Status onPayloadReady(int32_t cid) override;
  ::android::binder::Status onPayloadFinished(int32_t cid, int32_t exit_code) override;
  ::android::binder::Status onError(
      int32_t cid,
      const ::aidl::android::system::virtualizationcommon::ErrorCode& error_code,
      const std::u16string& message) override;
  ::android::binder::Status onDied(
      int32_t cid,
      const ::aidl::android::system::virtualizationcommon::DeathReason& reason) override;

  // --- Daemon-side view ------------------------------------------------
  // Blocks until microdroid_launcher has started the payload, the VM fails, or
  // the timeout expires.
  //
  // "Started" means the pVM booted, pvmfw verified the payload and
  // microdroid_launcher exec'd our code. It is the weaker of the two signals and
  // the right one to wait for when nothing is going to be sent to the guest.
  //
  // Returns false on timeout — the caller must then stop the VM, because a
  // Microdroid that never starts its payload is holding guest RAM and a CID.
  bool WaitForPayloadLaunched(std::chrono::milliseconds timeout);

  // Blocks until the payload calls AVmPayload_notifyPayloadReady(), the VM
  // reaches a terminal phase, or the timeout expires.
  //
  // Session 1 deliberately did not wait for this, on the reasoning that a
  // run-once payload never signals readiness. That reasoning was correct for a
  // payload that only exits, and wrong for the data plane: the X-Vault payload
  // now binds and listens on the control port BEFORE notifying, so readiness
  // means "a connectVsock will find a listener" rather than "a service is up".
  // Waiting for it removes the race in which the host connects to a port nothing
  // is listening on yet and gets ECONNREFUSED from a VM that was about to work.
  //
  // Returns false if the payload finished, errored or died without ever becoming
  // ready, which the caller must treat as a failed task and not as a timeout to
  // retry.
  bool WaitForPayloadReady(std::chrono::milliseconds timeout);

  // True once onPayloadReady has been observed, without blocking.
  bool payload_ready() const;

  // Blocks until the VM reaches a terminal phase (finished, error, died) or the
  // timeout expires.
  bool WaitForTerminal(std::chrono::milliseconds timeout);

  Phase phase() const;
  bool failed() const;
  int32_t exit_code() const;
  int32_t cid() const;

  // Human-readable cause for IsolationTaskResult.detail. Error codes and death
  // reasons are rendered numerically: the enumerators differ between AVF
  // releases, and a log that says "reason 4" is still actionable, whereas a log
  // that names a constant which no longer exists is actively misleading.
  std::string failure_detail() const;

  static const char* PhaseName(Phase phase);

 private:
  void EnterPhase(Phase phase);

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  Phase phase_ = Phase::kCreated;
  // Tracked separately from phase_ because Phase is ordered and kPayloadFinished
  // sorts above kPayloadReady: a payload that exits without ever notifying would
  // otherwise satisfy a `phase_ >= kPayloadReady` test.
  bool payload_ready_ = false;
  int32_t cid_ = -1;
  int32_t exit_code_ = -1;
  std::string detail_;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_VM_LIFECYCLE_OBSERVER_H_
