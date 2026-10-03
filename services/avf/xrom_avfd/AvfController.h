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

#ifndef XROM_AVF_AVF_CONTROLLER_H_
#define XROM_AVF_AVF_CONTROLLER_H_

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

#include <aidl/android/system/virtualizationservice/IVirtualMachine.h>
#include <aidl/android/system/virtualizationservice/IVirtualizationService.h>
#include <android-base/thread_annotations.h>
#include <utils/StrongPointer.h>

#include "MicrodroidVmBuilder.h"
#include "VmLifecycleObserver.h"
#include "VmSpec.h"

namespace xrom::avf {

namespace aidl_vs = ::aidl::android::system::virtualizationservice;

// Client side of android.system.virtualizationservice.IVirtualizationService.
//
// Owns the whole AVF conversation: binding to the service, keeping the idsig for
// the payload APK current, allocating VM instance ids, and driving
// createVm() -> registerCallback() -> start() -> stop(). Nothing above this
// class sees an AIDL type.
class AvfController {
 public:
  // A running VM. Holding the last reference to IVirtualMachine is what keeps it
  // alive: AVF shuts a VM down when every binder handle to it is dropped, which
  // is how it avoids leaking a VM whose owner was killed. So the lifetime of
  // this struct *is* the lifetime of the VM, and it must be released explicitly.
  struct VmHandle {
    android::sp<aidl_vs::IVirtualMachine> vm;
    android::sp<VmLifecycleObserver> observer;
    int32_t cid = -1;
    std::string name;

    bool valid() const { return vm != nullptr; }
    void Clear() {
      vm = nullptr;
      observer = nullptr;
      cid = -1;
      name.clear();
    }
  };

  AvfController();
  ~AvfController();

  AvfController(const AvfController&) = delete;
  AvfController& operator=(const AvfController&) = delete;

  // Binds to virtualizationservice, waiting up to |timeout|. xrom_avfd starts in
  // init class core, and the com.android.virt APEX service is not guaranteed to
  // be registered yet, so this retries rather than assuming ordering.
  bool Connect(std::chrono::milliseconds timeout);

  // True when the service is reachable and the platform reports that protected
  // VMs can actually be booted. Read from ro.boot.hypervisor.* rather than from
  // an AIDL capability method, because which method exists varies by release
  // while the bootconfig-derived property does not.
  bool IsProtectedVmAvailable();

  // Creates or refreshes the APK Signature Scheme v4 digest file for the payload
  // APK. Microdroid will not boot without it: it is what lets the guest verify
  // the payload it was handed. Idempotent — virtualizationservice skips the work
  // when the idsig already matches the APK.
  bool EnsureIdsig(const VmSpec& spec, std::string* error);

  // Asks AVF for a fresh VM instance id. Android 14+ only; on Android 13 the
  // instance id is not part of the app config and this returns a zeroed value.
  bool AllocateInstanceId(InstanceId* out, std::string* error);

  // createVm + registerCallback + start, then waits for microdroid_launcher to
  // start the payload. On any failure the VM is stopped and |handle| is left invalid, so a
  // caller cannot accidentally leak a half-started VM.
  bool StartVm(const VmSpec& spec, const InstanceId& instance_id, bool allow_debuggable,
               std::chrono::milliseconds launch_timeout, VmHandle* handle, std::string* error);

  // Opens the host end of a vsock connection to a port the guest is listening
  // on, and returns a connected file descriptor. The caller owns it and must
  // close it (VsockChannel does, on destruction).
  //
  // AVF proxies this through crosvm: the host side is an ordinary AF_UNIX-like
  // stream socket, not an AF_VSOCK socket, which is why nothing here needs a
  // guest CID. That also means the descriptor behaves like a normal stream —
  // partial writes, EAGAIN, orderly close — and VsockChannel is written against
  // exactly those semantics.
  //
  // Call this only after VmLifecycleObserver::WaitForPayloadReady() has returned
  // true. Connecting earlier races the guest's bind() and fails with an error
  // that looks like a broken VM rather than a premature connect.
  bool ConnectVsock(const VmHandle& handle, int32_t port, int* fd_out, std::string* error);

  // Stops the VM immediately and drops the handle. Equivalent to pulling the
  // plug: the guest gets no notification and no chance to flush.
  void StopVm(VmHandle* handle);

 private:
  // Returns the cached proxy, binding on first use and rebinding after the
  // service dies. Returns null if virtualizationservice is not registered.
  android::sp<aidl_vs::IVirtualizationService> Service();

  // Called by ServiceDeathRecipient. Clears the cached proxy so the next
  // Service() call rebinds.
  void OnServiceDied();

  class ServiceDeathRecipient;

  mutable std::mutex mutex_;
  android::sp<aidl_vs::IVirtualizationService> service_ GUARDED_BY(mutex_);
  android::sp<ServiceDeathRecipient> death_recipient_;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_AVF_CONTROLLER_H_
