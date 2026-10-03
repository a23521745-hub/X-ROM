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

// xrom_avfd — X-ROM's AVF orchestration daemon.
//
// Boots isolated Microdroid VMs through android.system.virtualizationservice and
// exposes them as android.xrom.isolation.IXIsolationService. Started by init from
// /system_ext/etc/init/init.xrom.avf.rc as uid system, confined by
// sepolicy/system_ext_private/xrom_avfd.te.

#include <unistd.h>

#include <chrono>
#include <csignal>
#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/signal_action.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <utils/StrongPointer.h>

#include "AvfCompat.h"
#include "AvfController.h"
#include "DaemonConfig.h"
#include "IsolationService.h"

namespace {

constexpr char kConfigPath[] = "/system_ext/etc/xrom/avf.json";
constexpr char kServiceName[] = "android.xrom.isolation.IXIsolationService/xrom_isolation";

// Binds to virtualizationservice for up to this long. xrom_avfd is in init class
// core and the com.android.virt APEX service is not guaranteed to be registered
// yet, so this is a wait, not a race.
constexpr int kAvfConnectTimeoutSeconds = 30;

}  // namespace

int main(int argc, char** argv) {
  android::base::InitLogging(argv);
  LOG(INFO) << "xrom_avfd: starting, compiled against AVF AIDL ABI " << XROM_AVF_ABI;

  const bool debuggable_build = android::base::GetBoolProperty("ro.debuggable", false);
  if (debuggable_build) {
    LOG(WARNING) << "xrom_avfd: ro.debuggable=1. Debuggable builds relax AVF checks and expose "
                    "guest logs; they cannot be used to evaluate X-ROM's isolation properties.";
  }

  std::string config_error;
  const xrom::avf::DaemonConfig config = xrom::avf::DaemonConfig::Load(kConfigPath, &config_error);
  if (!config_error.empty()) {
    // Fail closed: the fail-safe configuration is strictly more restrictive than
    // anything the JSON could have asked for.
    LOG(ERROR) << "xrom_avfd: " << config_error << "; using fail-safe defaults";
  }
  LOG(INFO) << "xrom_avfd: config " << config.ToString();

  xrom::avf::AvfController controller;
  if (!controller.Connect(std::chrono::seconds(kAvfConnectTimeoutSeconds))) {
    // Keep running rather than exiting. A daemon that is absent produces binder
    // "service not found" errors in its clients, which look like a client bug; a
    // daemon that is present and answers "no hypervisor" produces an actionable
    // denial. Both are honest, only one is debuggable.
    LOG(ERROR) << "xrom_avfd: virtualizationservice did not appear. Is the com.android.virt APEX "
                  "installed, and is CONFIG_KVM enabled in the running kernel?";
  }

  const bool protected_vm_available = controller.IsProtectedVmAvailable();
  LOG(INFO) << "xrom_avfd: protected VM support = " << (protected_vm_available ? "yes" : "no");
  android::base::SetProperty("xrom.avf.protected_vm_available", protected_vm_available ? "1" : "0");

  // init sends SIGTERM and then SIGKILL. On SIGTERM we exit without a shutdown
  // sequence, which is safe by construction rather than by care: AVF keeps a VM
  // alive only while some client holds an IVirtualMachine binder handle, so the
  // moment this process dies every VM it started is torn down by
  // virtualizationservice. There is no orphaned pVM to clean up, and doing less
  // work in a signal handler is the safer choice.
  android::base::SignalAction sigterm(SIGTERM, [](int signal_number) {
    LOG(INFO) << "xrom_avfd: received signal " << signal_number
              << "; exiting and letting AVF reclaim the VMs";
    _exit(0);
  });

  android::sp<xrom::avf::IsolationService> service = new xrom::avf::IsolationService(
      &controller, config.ToPolicyOptions(protected_vm_available),
      config.ToTunables(debuggable_build));
  service->Start();

  const android::sp<android::ProcessState> process = android::ProcessState::self();
  // Four binder threads: submitTask, getResult, cancelTask and the state queries
  // are all short. None of them boot a VM; the worker pool does that.
  process->setThreadPoolMaxThreadCount(4);
  process->startThreadPool();

  const android::status_t registered =
      android::defaultServiceManager()->addService(android::String16(kServiceName), service);
  if (registered != android::NO_ERROR) {
    LOG(ERROR) << "xrom_avfd: addService(" << kServiceName << ") failed with " << registered;
    service->Shutdown();
    return 1;
  }

  android::base::SetProperty("xrom.avf.ready", "1");
  LOG(INFO) << "xrom_avfd: registered " << kServiceName;

  process->joinThreadPool();

  service->Shutdown();
  LOG(INFO) << "xrom_avfd: exiting";
  return 0;
}
