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

#ifndef XROM_AVF_VM_SPEC_H_
#define XROM_AVF_VM_SPEC_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace xrom::avf {

// The 64-byte VM instance id AVF uses to derive VM identity (Android 14+;
// VirtualMachineAppConfig.instanceId, allocated by
// IVirtualizationService::allocateInstanceId()). It is kept out of VmSpec
// because it is runtime state owned by the daemon, not part of the request.
inline constexpr size_t kInstanceIdBytes = 64;
using InstanceId = std::array<uint8_t, kInstanceIdBytes>;


// ---------------------------------------------------------------------------
// Platform-independent description of a Microdroid VM.
//
// This translation unit has no Android dependencies on purpose. Everything here
// is plain C++17 so that it compiles and runs on a build host with no AOSP tree
// attached — see tools/hostcheck/. The mapping onto
// android::system::virtualizationservice types happens in exactly one place,
// MicrodroidVmBuilder.cpp, which is the only file in the daemon that has to
// change when the AVF AIDL moves.
// ---------------------------------------------------------------------------

// Mirrors VirtualMachineAppConfig::DebugLevel.
//
// Android 13 also defines APP_ONLY between NONE and FULL. X-ROM does not use it:
// "app logs but no shell" is a distinction without a security difference, since
// the app payload is the thing being isolated and its logs can carry secrets.
enum class DebugLevel : int32_t {
  kNone = 0,
  kFull = 1,
};

// Mirrors android.system.virtualizationservice.CpuTopology. Only the subset
// X-ROM will actually request is enumerated; the builder rejects anything else
// rather than passing an unknown value through to crosvm.
enum class CpuTopology : int32_t {
  kOneCpu = 0,
  kOneBigCpu = 1,
  kMatchHostCores = 2,
};

// Mirrors android.xrom.isolation.TaskClass. Kept as a separate enum so that the
// pure layer does not depend on generated AIDL headers.
enum class TaskClass : int32_t {
  kStaticAnalysis = 0,
  kIntegrityCheck = 1,
  kAttestation = 2,
  kCryptoOperation = 3,
};

// Hard ceilings. A VM that cannot be described within these is a bug in the
// caller or in the daemon config, not something to negotiate at runtime.
inline constexpr int32_t kVmNameMaxLength = 64;
inline constexpr char kVmNamePrefix[] = "xrom_";
inline constexpr int32_t kMinMemoryMib = 128;
inline constexpr int32_t kMaxMemoryMib = 4096;
inline constexpr int32_t kMinVCpus = 1;
inline constexpr int32_t kMaxVCpus = 8;
inline constexpr int64_t kMaxInstanceImageBytes = 8LL * 1024 * 1024 * 1024;
inline constexpr int32_t kSha256DigestBytes = 32;

// ---------------------------------------------------------------------------
// Install locations, declared once.
//
// The validator (VmSpec.cpp), the policy (IsolationPolicy.cpp), the SELinux
// file_contexts and the Soong modules all have to agree on these, so they are
// defined here and nowhere else. tools/xrom_preflight.py cross-checks this
// header against sepolicy/system_ext_private/file_contexts.
// ---------------------------------------------------------------------------

// The payload APK, installed by the android_app module XVaultPayload with
// system_ext_specific: true. Labelled xrom_vault_payload_file.
inline constexpr char kPayloadApkRoot[] = "/system_ext/app/XVaultPayload/";
inline constexpr char kPayloadApkPath[] = "/system_ext/app/XVaultPayload/XVaultPayload.apk";

// Per-VM mutable state. Labelled xrom_avfd_data_file, mode 0700.
inline constexpr char kStateRoot[] = "/data/misc/xrom/avf/";

// The only directory a caller may point a task at. Labelled xrom_avfd_data_file.
inline constexpr char kInboxRoot[] = "/data/misc/xrom/inbox/";

// The Microdroid payload config, embedded in the APK's assets by the android_app
// module's asset pipeline.
inline constexpr char kConfigPathInApk[] = "assets/vm_config.json";

// ---------------------------------------------------------------------------
// Payload trust material. Read-only to the daemon (SELinux label
// xrom_payload_trust_file) and shipped as part of the system_ext image, so an
// attacker who compromises /data still cannot install a trust anchor or a
// manifest that the daemon will accept.
//
// The manifest and its detached signature are separate files on purpose: the
// signature covers the exact bytes of the manifest, so there is no
// canonicalisation step whose implementation could disagree between the signing
// tool and the verifier.
// ---------------------------------------------------------------------------
inline constexpr char kPayloadTrustRoot[] = "/system_ext/etc/xrom/trust/";
inline constexpr char kDefaultTrustConfigPath[] =
    "/system_ext/etc/xrom/trust/trust_anchors.json";
inline constexpr char kDefaultManifestPath[] =
    "/system_ext/etc/xrom/trust/xrom_payload_manifest.json";
inline constexpr char kDefaultManifestSignaturePath[] =
    "/system_ext/etc/xrom/trust/xrom_payload_manifest.sig";

struct ResourceLimits {
  int32_t memory_mib = 0;
  int32_t vcpu_count = 1;
  CpuTopology cpu_topology = CpuTopology::kOneCpu;
  int64_t instance_image_bytes = 0;
};

struct VmSpec {
  // VM name. Used as a filename component by virtualizationservice, so it is
  // restricted to a conservative character set and must carry the X-ROM prefix.
  std::string name;

  TaskClass task_class = TaskClass::kStaticAnalysis;

  DebugLevel debug_level = DebugLevel::kNone;

  // A protected VM is the only configuration in which pKVM's stage-2 isolation
  // applies. false means "ordinary KVM", where the host kernel can read guest
  // memory — which is a legitimate thing to want for testing and an illegitimate
  // thing to want for anything else.
  bool protected_vm = true;

  ResourceLimits limits;

  // Guest OS. "microdroid" is the only value that does not require
  // USE_CUSTOM_VIRTUAL_MACHINE and the only one X-ROM ships images for.
  std::string os_name = "microdroid";

  // Absolute paths, all opened by the daemon and passed to AVF as file
  // descriptors.
  std::string payload_apk_path;
  std::string payload_idsig_path;
  std::string instance_image_path;

  // Signed manifest describing the payload, and the pinned trust anchors that
  // authorise it. Defaults are the shipped locations; they are validated to sit
  // under kPayloadTrustRoot so that a caller cannot redirect verification to a
  // manifest of their own choosing.
  std::string payload_manifest_path = kDefaultManifestPath;
  std::string payload_manifest_sig_path = kDefaultManifestSignaturePath;
  std::string trust_config_path = kDefaultTrustConfigPath;

  // Path of the Microdroid payload config *inside* the APK. Must live under
  // assets/ — that is where the android_app module puts it — and must be
  // relative, with no leading slash.
  std::string config_path_in_apk;

  // Where VM console and OS logs are written. Empty means discard.
  std::string console_log_path;
  std::string os_log_path;

  // Validates the whole spec. Returns every problem found, not just the first:
  // a caller fixing one violation at a time against a security policy is a
  // caller who is guessing at the policy. An empty result means the spec is
  // acceptable.
  //
  // allow_debuggable comes from the daemon configuration and the build variant,
  // never from the request.
  std::vector<std::string> Validate(bool allow_debuggable) const;

  // Single-line rendering for logs. Never includes digests or paths that could
  // carry user data.
  std::string ToString() const;
};

// True if |path| is absolute, contains no traversal or empty components, has no
// control characters or trailing whitespace, and begins with one of
// |allowed_roots|. This is a lexical check: it does not touch the filesystem,
// and it is not a substitute for O_NOFOLLOW at open time. Both are needed.
bool IsPathContained(const std::string& path, const std::vector<std::string>& allowed_roots);

const char* TaskClassName(TaskClass task_class);
const char* DebugLevelName(DebugLevel level);
const char* CpuTopologyName(CpuTopology topology);

}  // namespace xrom::avf

#endif  // XROM_AVF_VM_SPEC_H_
