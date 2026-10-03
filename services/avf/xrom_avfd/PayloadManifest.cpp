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

#include "PayloadManifest.h"

#include <algorithm>

namespace xrom::avf {
namespace {

using ::xrom::crypto::Sha256;
using ::xrom::crypto::Sha256Digest;

constexpr int32_t kMaxAllowedTaskClasses = 16;

bool IsZero(const Sha256Digest& digest) {
  return std::all_of(digest.begin(), digest.end(), [](uint8_t b) { return b == 0; });
}

// A bare file name with an extension, and nothing that could escape a directory.
//
// The characters forbidden here are the ones that turn a file name into a path or
// a traversal: separators, a leading dot, a ".." component and control bytes. A
// single extension dot is required, not merely allowed — the real values are
// "XVaultPayload.apk" and "libxvault_payload.so".
bool IsPlainFilename(const std::string& name) {
  if (name.empty() || name.size() > 128) {
    return false;
  }
  if (name[0] == '.') {
    return false;  // ".", ".." and every hidden file
  }
  if (name.find("..") != std::string::npos) {
    return false;
  }
  return std::none_of(name.begin(), name.end(), [](char c) {
    return c == '/' || c == '\\' || c < 0x20 || c == 0x7f || c == ':' || c == '*';
  });
}

}  // namespace

std::vector<std::string> PayloadManifest::Validate() const {
  std::vector<std::string> problems;
  const auto add = [&problems](const std::string& p) { problems.push_back(p); };

  if (manifest_version != kManifestVersion) {
    add("manifest_version " + std::to_string(manifest_version) + " != " +
        std::to_string(kManifestVersion));
  }
  if (payload_name.empty() || payload_name.size() > 64) {
    add("payload_name must be 1..64 characters");
  }
  // A plain filename, not a path: a manifest that could name a directory would be
  // able to point the daemon at an APK outside the verified payload location.
  if (!IsPlainFilename(payload_apk_filename)) {
    add("payload_apk_filename must be a plain file name with no separators or traversal");
  }
  if (!IsPlainFilename(payload_library)) {
    add("payload_library must be a plain file name with no separators or traversal");
  }
  if (signature_algorithm != kAlgorithmEd25519 &&
      signature_algorithm != kAlgorithmRsa4096Sha256) {
    add("signature_algorithm must be " + std::string(kAlgorithmEd25519) + " or " +
        std::string(kAlgorithmRsa4096Sha256));
  }
  if (key_id.empty() || key_id.size() > 64) {
    add("key_id must be 1..64 characters");
  }
  if (IsZero(apk_sha256)) {
    add("apk_sha256 is all zeroes, which is not a plausible digest of a signed APK");
  }
  if (IsZero(vm_config_sha256)) {
    add("vm_config_sha256 is all zeroes");
  }
  if (IsZero(payload_lib_sha256)) {
    add("payload_lib_sha256 is all zeroes");
  }
  if (allowed_task_classes.empty()) {
    add("allowed_task_classes is empty: a payload authorised for nothing cannot run anything");
  } else if (static_cast<int32_t>(allowed_task_classes.size()) > kMaxAllowedTaskClasses) {
    add("allowed_task_classes has more than " + std::to_string(kMaxAllowedTaskClasses) +
        " entries");
  } else {
    std::vector<int32_t> sorted = allowed_task_classes;
    std::sort(sorted.begin(), sorted.end());
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
      add("allowed_task_classes contains a duplicate");
    }
    for (const int32_t value : sorted) {
      if (value < 0 || value > 3) {
        add("allowed_task_classes contains " + std::to_string(value) +
            ", which is not a TaskClass");
        break;
      }
    }
  }
  if (security_version < 0) {
    add("security_version must not be negative");
  }
  if (issued_at_unix <= 0 || not_after_unix <= 0) {
    add("issued_at_unix and not_after_unix must be positive UNIX timestamps");
  } else if (not_after_unix <= issued_at_unix) {
    add("not_after_unix must be after issued_at_unix");
  }
  return problems;
}

bool PayloadManifest::AllowsTaskClass(int32_t task_class) const {
  return std::find(allowed_task_classes.begin(), allowed_task_classes.end(), task_class) !=
         allowed_task_classes.end();
}

bool PayloadManifest::IsExpired(int64_t now_unix) const {
  return now_unix >= not_after_unix;
}

bool PayloadManifest::IsNotYetValid(int64_t now_unix) const {
  return now_unix < issued_at_unix;
}

std::string PayloadManifest::ToString() const {
  const auto shorten = [](const Sha256Digest& digest) {
    return Sha256::ToHex(digest).substr(0, 12);
  };
  std::string classes;
  for (const int32_t value : allowed_task_classes) {
    if (!classes.empty()) {
      classes += ",";
    }
    classes += std::to_string(value);
  }
  // The file names are included alongside their digests because they are the
  // part an operator can act on: "lib=libxvault_payload.so:8c45ce4e5a5c" can be
  // compared against task.command in vm_config.json at a glance, where a bare
  // digest has to be looked up first.
  return payload_name + " v" + std::to_string(manifest_version) + " apk=" + payload_apk_filename +
         ":" + shorten(apk_sha256) + " lib=" + payload_library + ":" +
         shorten(payload_lib_sha256) + " cfg=" + shorten(vm_config_sha256) + " algo=" +
         signature_algorithm + " key=" + key_id + " secver=" + std::to_string(security_version) +
         " classes=[" + classes + "]";
}

}  // namespace xrom::avf
