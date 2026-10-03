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

#ifndef XROM_AVF_MICRODROID_VM_BUILDER_H_
#define XROM_AVF_MICRODROID_VM_BUILDER_H_

#include <string>

#include <aidl/android/system/virtualizationservice/VirtualMachineConfig.h>
#include <android-base/unique_fd.h>

#include "VmSpec.h"

namespace xrom::avf {

// ---------------------------------------------------------------------------
// The ONLY file in X-ROM that constructs AVF AIDL types.
//
// That constraint is the reason this class exists. When the AVF interface moves
// — a field renamed, a union re-tagged, an arity change — exactly one
// translation unit has to be updated, and the rest of the daemon keeps working
// against VmSpec, which is plain C++ with no generated headers at all.
// ---------------------------------------------------------------------------

class MicrodroidVmBuilder {
 public:
  struct Result {
    bool ok = false;
    // Empty when ok. Never contains a path or digest that would be useful to an
    // attacker reading logd; it names the field that failed and why.
    std::string error;

    // Owns every file descriptor it references, wrapped in
    // android::os::ParcelFileDescriptor. They stay open for as long as this
    // config lives, which must be at least until createVm() has returned:
    // virtualizationservice clones the descriptors into crosvm's table and
    // builds the composite disk image out of /proc/self/fd/N paths, so closing
    // them early yields a VM that boots and then cannot find its own partitions.
    ::aidl::android::system::virtualizationservice::VirtualMachineConfig config;
  };

  // Validates |spec|, opens every file it references, and produces a
  // VirtualMachineConfig ready for IVirtualizationService::createVm().
  //
  // |allow_debuggable| comes from the daemon configuration and build variant,
  // never from the request that triggered the build.
  //
  // |instance_id| is only used on Android 14+, where AVF derives VM identity
  // from it. Ignored on Android 13.
  static Result Build(const VmSpec& spec, const InstanceId& instance_id, bool allow_debuggable);

  // Opens |path| read-only with O_NOFOLLOW. Exposed for the idsig path, which
  // the controller has to hand to createOrUpdateIdsigFile() separately.
  static android::base::unique_fd OpenNoFollow(const std::string& path, bool writable);
};

}  // namespace xrom::avf

#endif  // XROM_AVF_MICRODROID_VM_BUILDER_H_
