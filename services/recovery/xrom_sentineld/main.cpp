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

// xrom_sentineld — X-ROM's self-healing recovery daemon.
//
// Exposes android.xrom.recovery.IXRecoveryService/xrom_recovery. Started by init from
// /system_ext/etc/init/init.xrom.sentinel.rc as uid system, confined by
// sepolicy/system_ext_private/xrom_sentineld.te.
//
// WHAT IT DOES AND WHAT IT DELIBERATELY DOES NOT
// ----------------------------------------------
// It writes the bootloader control block in /misc, locks a monitored directory,
// stages and preserves incident evidence, drops the network, and reboots the device.
// It does not decide what counts as a threat — detection belongs to whoever is
// looking, and this daemon acts on the severity it is given.
//
// It does not touch the AVF isolation service. IXIsolationService and the vsock data
// plane are unchanged; see correction #3 in docs/05 for why the recovery authority
// lives in a separate daemon and a separate binder interface rather than being added
// to the one that starts VMs.

#include <unistd.h>

#include <csignal>
#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/signal_action.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <utils/StrongPointer.h>

#include "SentinelConfig.h"
#include "SentinelService.h"

namespace {

constexpr char kConfigPath[] = "/system_ext/etc/xrom/sentinel.json";
constexpr char kServiceName[] = "android.xrom.recovery.IXRecoveryService/xrom_recovery";

}  // namespace

int main(int argc, char** argv) {
  android::base::InitLogging(argv);
  LOG(INFO) << "xrom_sentineld: starting";

  const bool debuggable_build = android::base::GetBoolProperty("ro.debuggable", false);
  if (debuggable_build) {
    LOG(WARNING) << "xrom_sentineld: ro.debuggable=1. Root and shell may report threats "
                    "if the configuration allows it, and the cancel window is easier to "
                    "exercise. This is intended on a bring-up build and unacceptable on "
                    "a release one.";
  }

  // A configuration that exists and does not parse stops the daemon. Falling back to
  // defaults would mean the device runs a policy nobody chose and the log does not
  // mention it, which is worse than a daemon that refuses to start.
  //
  // A configuration that does not exist is NOT an error: the defaults in
  // SentinelConfig are the shipped policy and are documented as such.
  const auto loaded = xrom::sentinel::LoadConfig(kConfigPath);
  if (!loaded.ok) {
    LOG(ERROR) << "xrom_sentineld: " << loaded.Describe();
    LOG(ERROR) << "xrom_sentineld: refusing to start. Fix or remove " << kConfigPath;
    return 1;
  }
  LOG(INFO) << "xrom_sentineld: " << loaded.Describe();

  const auto& config = loaded.config;
  LOG(INFO) << "xrom_sentineld: quarantine="
            << (config.quarantine.cancel_window_seconds > 0
                    ? std::to_string(config.quarantine.cancel_window_seconds) + "s window"
                    : "no cancel window")
            << ", cancel_at_critical="
            << (config.quarantine.allow_cancel_at_critical ? "ALLOWED" : "refused")
            << ", reboot_threshold="
            << xrom::recovery::SeverityName(config.quarantine.reboot_threshold)
            << ", integrity_limit=" << config.boot_attempts.max_integrity_failures
            << ", deep_integrity_on_boot="
            << (config.deep_integrity_on_boot ? "yes" : "no")
            << ", network_layers=" << (config.use_netd_firewall_chain ? "netd " : "")
            << (config.use_interface_down ? "ioctl " : "")
            << (config.use_quarantine_property ? "property" : "");

  if (config.stash_evidence_in_pvm) {
    // Warned about loudly rather than failing: the handoff cannot succeed until the
    // isolation AIDL has a TaskClass for evidence stashing, and it is part of the
    // frozen interface this project is constrained not to change. See correction #14.
    LOG(WARNING) << "xrom_sentineld: stash_evidence_in_pvm is enabled but no evidence "
                    "TaskClass exists in the frozen isolation AIDL; evidence will be "
                    "staged on /data and the handoff reported as unavailable";
  }

  auto service = android::sp<xrom::sentinel::SentinelService>::make(config, debuggable_build);

  // Boot-time work runs before the thread pool starts, so that a device which should
  // not have come up at all does not spend its first seconds serving binder calls, and
  // so that the boot-loop decision is already made and recorded by the time anything
  // can ask about it.
  service->RunBootChecks();

  const auto status = android::defaultServiceManager()->addService(
      android::String16(kServiceName), service);
  if (status != android::OK) {
    LOG(ERROR) << "xrom_sentineld: could not register " << kServiceName << " (status "
               << status << "). A daemon that cannot be reached cannot quarantine "
                  "anything, so it does not stay up pretending to.";
    return 1;
  }
  LOG(INFO) << "xrom_sentineld: published " << kServiceName;

  // Rebooting is not an exceptional condition for this daemon; it is the last step of
  // a plan. Ignoring SIGTERM during shutdown is deliberate — init sends it to every
  // service, and being killed halfway through arming a BCB is how a device ends up
  // with a partially written misc. The service is marked `shutdown critical` in the
  // rc file for the same reason, and both halves are needed: the rc entry keeps init
  // from killing it early, and the handler covers the case where something else
  // signals it.
  struct sigaction action {};
  action.sa_handler = SIG_IGN;
  sigaction(SIGTERM, &action, nullptr);

  android::ProcessState::self()->setThreadPoolMaxThreadCount(2);
  android::ProcessState::self()->startThreadPool();
  android::IPCThreadState::self()->joinThreadPool(/*exitOnFdClose=*/true);

  LOG(INFO) << "xrom_sentineld: binder thread pool exited";
  return 0;
}
