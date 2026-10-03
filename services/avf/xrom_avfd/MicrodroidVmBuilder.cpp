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

#include "MicrodroidVmBuilder.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include <android-base/logging.h>
#include <binder/ParcelFileDescriptor.h>

#include "AvfCompat.h"

namespace aidl_vs = ::aidl::android::system::virtualizationservice;

namespace xrom::avf {
namespace {

using ::android::os::ParcelFileDescriptor;

// VmSpec::Validate() restricts the VM name to [a-z0-9_.-] and the OS name to a
// fixed allowlist, so widening to UTF-16 by zero-extension is lossless here.
// This is an invariant of the validator, not a general-purpose conversion.
std::u16string ToUtf16(const std::string& ascii) {
  return std::u16string(ascii.begin(), ascii.end());
}

aidl_vs::VirtualMachineAppConfig::DebugLevel MapDebugLevel(DebugLevel level) {
  switch (level) {
    case DebugLevel::kNone:
      return aidl_vs::VirtualMachineAppConfig::DebugLevel::NONE;
    case DebugLevel::kFull:
      return aidl_vs::VirtualMachineAppConfig::DebugLevel::FULL;
  }
  // Unreachable; the switch is exhaustive and Validate() rejects other values.
  return aidl_vs::VirtualMachineAppConfig::DebugLevel::NONE;
}

#if XROM_AVF_ABI >= 14
aidl_vs::CpuTopology MapCpuTopology(CpuTopology topology) {
  switch (topology) {
    case CpuTopology::kOneCpu:
      return aidl_vs::CpuTopology::ONE_CPU;
    case CpuTopology::kOneBigCpu:
      return aidl_vs::CpuTopology::ONE_BIG_CPU;
    case CpuTopology::kMatchHostCores:
      return aidl_vs::CpuTopology::MATCH_HOST_CORES;
  }
  return aidl_vs::CpuTopology::ONE_CPU;
}
#endif

// Creates the per-VM instance image if it does not exist, otherwise reopens it.
//
// Reopening matters: instance.img holds the per-instance state that AVF binds
// to the VM's derived secret. Deleting it between runs would silently change
// the VM's identity and invalidate anything the payload sealed on a previous
// boot. Deleting it is an explicit operator action, not a side effect of a
// restart.
bool EnsureInstanceImage(const std::string& path, int64_t size_bytes, android::base::unique_fd* out,
                         std::string* error) {
  int fd = TEMP_FAILURE_RETRY(
      open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (fd < 0) {
    if (errno != EEXIST) {
      *error = "cannot create instance image: " + std::string(strerror(errno));
      return false;
    }
    fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC));
    if (fd < 0) {
      *error = "cannot reopen instance image: " + std::string(strerror(errno));
      return false;
    }
    struct stat st {};
    if (fstat(fd, &st) != 0) {
      *error = "cannot stat instance image: " + std::string(strerror(errno));
      close(fd);
      return false;
    }
    if (static_cast<int64_t>(st.st_size) != size_bytes) {
      *error = "instance image is " + std::to_string(st.st_size) + " bytes but the policy asked for " +
               std::to_string(size_bytes);
      close(fd);
      return false;
    }
  } else if (ftruncate(fd, size_bytes) != 0) {
    *error = "cannot size instance image: " + std::string(strerror(errno));
    close(fd);
    return false;
  }
  out->reset(fd);
  return true;
}

}  // namespace

android::base::unique_fd MicrodroidVmBuilder::OpenNoFollow(const std::string& path, bool writable) {
  const int flags = (writable ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC;
  const int fd = TEMP_FAILURE_RETRY(open(path.c_str(), flags));
  if (fd < 0) {
    PLOG(ERROR) << "xrom_avfd: open failed for a VM input file";
  }
  return android::base::unique_fd(fd);
}

MicrodroidVmBuilder::Result MicrodroidVmBuilder::Build(const VmSpec& spec,
                                                       const InstanceId& instance_id,
                                                       bool allow_debuggable) {
  Result result;

  // Belt and braces. IsolationPolicy has already approved the intent behind this
  // spec; the validator checks the artifact. Keeping the two independent means a
  // bug in either one still leaves a gate standing.
  const std::vector<std::string> problems = spec.Validate(allow_debuggable);
  if (!problems.empty()) {
    result.error = "spec rejected by validation:";
    for (const auto& problem : problems) {
      result.error += " [" + problem + "]";
    }
    LOG(ERROR) << "xrom_avfd: " << result.error;
    return result;
  }

  // The payload APK lives on a read-only verified partition and is passed as a
  // file descriptor; AVF never receives the path.
  android::base::unique_fd apk_fd = OpenNoFollow(spec.payload_apk_path, /*writable=*/false);
  if (!apk_fd.ok()) {
    result.error = "payload apk could not be opened";
    return result;
  }

  android::base::unique_fd idsig_fd = OpenNoFollow(spec.payload_idsig_path, /*writable=*/false);
  if (!idsig_fd.ok()) {
    result.error = "idsig could not be opened; AvfController::EnsureIdsig must run first";
    return result;
  }

  android::base::unique_fd instance_fd;
  if (!EnsureInstanceImage(spec.instance_image_path, spec.limits.instance_image_bytes, &instance_fd,
                           &result.error)) {
    return result;
  }

  aidl_vs::VirtualMachineAppConfig app;
  app.apk = ParcelFileDescriptor(std::move(apk_fd));
  app.idsig = ParcelFileDescriptor(std::move(idsig_fd));
  app.instanceImage = ParcelFileDescriptor(std::move(instance_fd));
  app.extraIdsigs = {};
  app.debugLevel = MapDebugLevel(spec.debug_level);
  app.protectedVm = spec.protected_vm;
  app.memoryMib = spec.limits.memory_mib;

#if XROM_AVF_ABI >= 14
  app.name = ToUtf16(spec.name);
  app.instanceId = instance_id;
  app.osName = spec.os_name;
  app.cpuTopology = MapCpuTopology(spec.limits.cpu_topology);
  app.payload.set<XROM_UNION_TAG(aidl_vs::VirtualMachineAppConfig::Payload, configPath, ConfigPath)>(
      spec.config_path_in_apk);
  // customConfig stays nullopt. Setting it would request a custom kernel image,
  // device assignment or a gdb port, all of which need
  // USE_CUSTOM_VIRTUAL_MACHINE and all of which would weaken the measurement
  // pvmfw takes of the guest.
  app.customConfig = std::nullopt;
  app.encryptedStorageImage = std::nullopt;
#else   // Android 13
  (void)instance_id;
  app.configPath = spec.config_path_in_apk;
  app.numCpus = spec.limits.vcpu_count;
  app.cpuAffinity = std::nullopt;
  app.taskProfiles = {};
#endif  // XROM_AVF_ABI

  // VirtualMachineConfig is a union of appConfig and rawConfig. rawConfig is the
  // low-level "boot this kernel with these disks" form; it bypasses Microdroid
  // and pvmfw's payload verification entirely, so X-ROM never constructs it.
  result.config.set<XROM_UNION_TAG(aidl_vs::VirtualMachineConfig, appConfig, AppConfig)>(
      std::move(app));
  result.ok = true;
  return result;
}

}  // namespace xrom::avf
