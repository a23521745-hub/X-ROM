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

#include "AvfController.h"

#include <fcntl.h>

#include <array>
#include <optional>
#include <thread>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include <cstring>
#include <binder/IServiceManager.h>
#include <binder/ParcelFileDescriptor.h>

#include "AvfCompat.h"

namespace xrom::avf {
namespace {

using ::android::base::unique_fd;
using ::android::binder::Status;
using ::android::os::ParcelFileDescriptor;
using ::android::sp;

std::string Describe(const Status& status) {
  return std::string(status.toString8());
}

// Opens a log sink for a debuggable VM. Returns nullopt when logging is off,
// which is the normal case: a production VM's console output is guest data and
// X-ROM does not persist it on the host.
std::optional<ParcelFileDescriptor> OpenLogSink(const std::string& path) {
  if (path.empty()) {
    return std::nullopt;
  }
  const int fd =
      TEMP_FAILURE_RETRY(open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                              0600));
  if (fd < 0) {
    PLOG(ERROR) << "xrom_avfd: cannot open a VM log sink; continuing without it";
    return std::nullopt;
  }
  return ParcelFileDescriptor(unique_fd(fd));
}

}  // namespace

// ---------------------------------------------------------------------------
// ServiceDeathRecipient
// ---------------------------------------------------------------------------
// Holds its own mutex and a detachable owner pointer. The binder driver keeps a
// reference to this recipient for as long as the link is live, so it can outlive
// the controller; without Detach() a late binderDied() would dereference freed
// memory.
class AvfController::ServiceDeathRecipient : public ::android::IBinder::DeathRecipient {
 public:
  explicit ServiceDeathRecipient(AvfController* owner) : owner_(owner) {}

  void binderDied(const ::android::wp<::android::IBinder>& /*who*/) override {
    AvfController* owner = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      owner = owner_;
    }
    if (owner != nullptr) {
      owner->OnServiceDied();
    }
  }

  void Detach() {
    std::lock_guard<std::mutex> lock(mutex_);
    owner_ = nullptr;
  }

 private:
  std::mutex mutex_;
  AvfController* owner_ GUARDED_BY(mutex_);
};

// ---------------------------------------------------------------------------
// AvfController
// ---------------------------------------------------------------------------
AvfController::AvfController() = default;

AvfController::~AvfController() {
  if (death_recipient_ != nullptr) {
    death_recipient_->Detach();
  }
}

void AvfController::OnServiceDied() {
  LOG(ERROR) << "xrom_avfd: virtualizationservice died; any running VM is gone with it";
  std::lock_guard<std::mutex> lock(mutex_);
  service_ = nullptr;
}

sp<aidl_vs::IVirtualizationService> AvfController::Service() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (service_ != nullptr) {
    return service_;
  }

  const sp<::android::IBinder> binder = ::android::defaultServiceManager()->checkService(
      ::android::String16(XROM_AVF_SERVICE_INSTANCE));
  if (binder == nullptr) {
    return nullptr;
  }
  sp<aidl_vs::IVirtualizationService> service =
      ::android::interface_cast<aidl_vs::IVirtualizationService>(binder);
  if (service == nullptr) {
    LOG(ERROR) << "xrom_avfd: binder resolved but does not implement IVirtualizationService";
    return nullptr;
  }

  if (death_recipient_ == nullptr) {
    death_recipient_ = new ServiceDeathRecipient(this);
  }
  if (binder->linkToDeath(death_recipient_, /*cookie=*/0) != ::android::NO_ERROR) {
    // Not fatal: the only consequence is that a service restart is discovered on
    // the next failed call instead of immediately.
    LOG(WARNING) << "xrom_avfd: linkToDeath on virtualizationservice failed";
  }
  service_ = service;
  return service_;
}

bool AvfController::Connect(std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (true) {
    if (Service() != nullptr) {
      LOG(INFO) << "xrom_avfd: bound to virtualizationservice";
      return true;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      LOG(ERROR) << "xrom_avfd: virtualizationservice never appeared. Is com.android.virt "
                    "installed and is the kernel built with CONFIG_KVM?";
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

bool AvfController::IsProtectedVmAvailable() {
  if (Service() == nullptr) {
    return false;
  }
  // Both keys originate in bootconfig (androidboot.hypervisor.protected_vm.supported
  // and androidboot.pkvm.enabled) and are exposed by init as ro.boot.*. Which one
  // a given bootloader publishes is a platform detail, so accept either.
  if (android::base::GetProperty("ro.boot.hypervisor.protected_vm.supported", "") == "true") {
    return true;
  }
  const std::string pkvm = android::base::GetProperty("ro.boot.pkvm.enabled", "");
  return pkvm == "1" || pkvm == "true";
}

bool AvfController::EnsureIdsig(const VmSpec& spec, std::string* error) {
  sp<aidl_vs::IVirtualizationService> service = Service();
  if (service == nullptr) {
    *error = "virtualizationservice is not available";
    return false;
  }

  unique_fd apk_fd = MicrodroidVmBuilder::OpenNoFollow(spec.payload_apk_path, /*writable=*/false);
  if (!apk_fd.ok()) {
    *error = "payload apk could not be opened read-only";
    return false;
  }

  // Created if absent, updated if the APK changed. The file must be opened
  // read-write; AVF writes the digest tree into it.
  unique_fd idsig_fd(TEMP_FAILURE_RETRY(open(spec.payload_idsig_path.c_str(),
                                             O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600)));
  if (!idsig_fd.ok()) {
    *error = "idsig file could not be created or opened";
    return false;
  }

  const Status status = service->createOrUpdateIdsigFile(ParcelFileDescriptor(std::move(apk_fd)),
                                                         ParcelFileDescriptor(std::move(idsig_fd)));
  if (!status.isOk()) {
    *error = "createOrUpdateIdsigFile failed: " + Describe(status);
    return false;
  }
  return true;
}

bool AvfController::AllocateInstanceId(InstanceId* out, std::string* error) {
  out->fill(0);

#if XROM_AVF_ABI >= 14
  sp<aidl_vs::IVirtualizationService> service = Service();
  if (service == nullptr) {
    *error = "virtualizationservice is not available";
    return false;
  }
  std::array<uint8_t, kInstanceIdBytes> allocated{};
  const Status status = service->allocateInstanceId(&allocated);
  if (!status.isOk()) {
    *error = "allocateInstanceId failed: " + Describe(status);
    return false;
  }
  *out = allocated;
#else
  // Android 13 has no instance id in VirtualMachineAppConfig; VM identity is
  // derived from the payload and config alone. Report success with a zeroed
  // value, which MicrodroidVmBuilder ignores on this ABI.
  (void)error;
#endif
  return true;
}

bool AvfController::StartVm(const VmSpec& spec, const InstanceId& instance_id,
                            bool allow_debuggable, std::chrono::milliseconds launch_timeout,
                            VmHandle* handle, std::string* error) {
  handle->Clear();

  sp<aidl_vs::IVirtualizationService> service = Service();
  if (service == nullptr) {
    *error = "virtualizationservice is not available";
    return false;
  }

  const MicrodroidVmBuilder::Result built =
      MicrodroidVmBuilder::Build(spec, instance_id, allow_debuggable);
  if (!built.ok) {
    *error = built.error;
    return false;
  }

  const std::optional<ParcelFileDescriptor> console_out = OpenLogSink(spec.console_log_path);
  // X-ROM never drives the guest console interactively, so there is no input fd
  // on any ABI. Passing it explicitly rather than omitting it is what turns a
  // future arity change into a compile error instead of a silent default.
  const std::optional<ParcelFileDescriptor> console_in = std::nullopt;
  const std::optional<ParcelFileDescriptor> os_log = OpenLogSink(spec.os_log_path);

  sp<aidl_vs::IVirtualMachine> vm;
#if XROM_AVF_ABI >= 14
  Status status = service->createVm(built.config, console_out, console_in, os_log, &vm);
#else
  Status status = service->createVm(built.config, console_out, os_log, &vm);
#endif
  if (!status.isOk() || vm == nullptr) {
    *error = "createVm failed: " + (status.isOk() ? std::string("null VM returned")
                                                   : Describe(status));
    return false;
  }

  sp<VmLifecycleObserver> observer = new VmLifecycleObserver();
  status = vm->registerCallback(observer);
  if (!status.isOk()) {
    *error = "registerCallback failed: " + Describe(status);
    // Dropping |vm| is enough: AVF shuts the VM down when the last binder handle
    // goes away, which is exactly what happens when this function returns.
    return false;
  }

  status = vm->start();
  if (!status.isOk()) {
    *error = "start failed: " + Describe(status);
    return false;
  }

  if (!observer->WaitForPayloadLaunched(launch_timeout)) {
    *error = "payload never started: " + observer->failure_detail();
    vm->stop();
    return false;
  }

  int32_t cid = -1;
  if (vm->getCid(&cid).isOk()) {
    LOG(INFO) << "xrom_avfd: " << spec.name << " ready on cid=" << cid;
  } else {
    cid = observer->cid();
  }

  handle->vm = vm;
  handle->observer = observer;
  handle->cid = cid;
  handle->name = spec.name;
  return true;
}

bool AvfController::ConnectVsock(const VmHandle& handle, int32_t port, int* fd_out,
                                 std::string* error) {
  if (fd_out == nullptr || error == nullptr) {
    return false;
  }
  *fd_out = -1;
  if (!handle.valid()) {
    *error = "the VM handle is not valid; cannot connect a vsock";
    return false;
  }
  if (port <= 0) {
    *error = "vsock port " + std::to_string(port) + " is not usable";
    return false;
  }

  ParcelFileDescriptor pfd;
  const Status status = handle.vm->connectVsock(port, &pfd);
  if (!status.isOk()) {
    *error = "IVirtualMachine::connectVsock(" + std::to_string(port) + ") failed: " +
             status.getDescription();
    return false;
  }

  // dup() rather than ParcelFileDescriptor::release(): the accessor exists on
  // some binder backends and not others, and X-ROM builds against AVF AIDL from
  // Android 13 through current. dup() costs one descriptor and works everywhere.
  const int fd = ::dup(pfd.get());
  if (fd < 0) {
    *error = std::string("cannot take ownership of the vsock descriptor: ") + strerror(errno);
    return false;
  }
  *fd_out = fd;
  LOG(INFO) << "xrom_avfd: connected to " << handle.name << " vsock port " << port;
  return true;
}

void AvfController::StopVm(VmHandle* handle) {
  if (handle == nullptr) {
    return;
  }
  if (handle->valid()) {
    const Status status = handle->vm->stop();
    if (!status.isOk()) {
      LOG(WARNING) << "xrom_avfd: stop() on " << handle->name << " reported "
                   << Describe(status);
    }
  }
  // Clearing drops the last IVirtualMachine reference, which is what actually
  // releases the CID and the guest memory.
  handle->Clear();
}

}  // namespace xrom::avf
