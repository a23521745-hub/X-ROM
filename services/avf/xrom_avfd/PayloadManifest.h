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

#ifndef XROM_AVF_PAYLOAD_MANIFEST_H_
#define XROM_AVF_PAYLOAD_MANIFEST_H_

#include <cstdint>
#include <string>
#include <vector>

#include "Sha256.h"

namespace xrom::avf {

// ---------------------------------------------------------------------------
// The signed description of what X-ROM is willing to let a pVM execute.
//
// WHY X-ROM SIGNS ITS OWN MANIFEST WHEN AVF ALREADY VERIFIES THE PAYLOAD
// ---------------------------------------------------------------------
// AVF does verify the payload: pvmfw checks the APK's fs-verity digest tree
// (the .idsig) and measures it into the VM identity, and the whole chain is
// rooted in AVB. That is real and it is not enough on its own, because it
// answers "was this APK tampered with?" and not "did X-ROM choose this APK?".
// The certificate an APK is signed with on a self-built ROM is the platform
// certificate, which every system component shares. So a payload that was built
// by the same tree, signed with the same key and installed to the same partition
// verifies perfectly under AVF — including one X-ROM never intended to ship.
//
// This manifest adds a second, independent trust anchor: an X-ROM signing key
// that is not the platform key, and a pinned SHA-256 of the exact APK bytes.
// The daemon verifies it BEFORE handing anything to AVF, so a payload whose
// manifest does not verify is never offered to the hypervisor at all.
//
// Pure struct + validation only. JSON parsing and signature verification need
// BoringSSL and libjsoncpp and live in PayloadVerifier; keeping them apart means
// the validation rules are testable on a build host.
// ---------------------------------------------------------------------------

// Signature schemes the verifier accepts. Both are required by the X-ROM signing
// policy: Ed25519 for speed and a small signature, RSA-4096/SHA-256 for
// environments whose HSM cannot export an Ed25519 key.
inline constexpr char kAlgorithmEd25519[] = "ED25519";
inline constexpr char kAlgorithmRsa4096Sha256[] = "RSA4096_SHA256";

// Bumped on any incompatible change to the manifest structure.
inline constexpr int32_t kManifestVersion = 1;

struct PayloadManifest {
  int32_t manifest_version = 0;

  // Human-readable identity, used in logs and to name the trust anchor entry.
  std::string payload_name;

  // File name of the APK inside the payload directory. Not a path: the directory
  // comes from VmSpec.h so that the manifest cannot redirect the daemon.
  std::string payload_apk_filename;

  // SHA-256 of the exact APK bytes. The daemon recomputes this over the file it
  // is about to open and refuses on mismatch, which is what makes a swapped or
  // rebuilt APK detectable even though AVF would still boot it.
  ::xrom::crypto::Sha256Digest apk_sha256{};

  // Name of the shared library microdroid_launcher will exec, e.g.
  // "libxvault_payload.so". Must equal task.command in vm_config.json; the
  // preflight checks the three against each other.
  std::string payload_library;

  // SHA-256 of assets/vm_config.json as it appears inside the APK. The guest
  // measures the same file from AVmPayload_getApkContentsPath() and reports it in
  // kGuestHello; the host compares. Two independent measurements of the same
  // artifact have to agree, which is the point.
  ::xrom::crypto::Sha256Digest vm_config_sha256{};

  // SHA-256 of the payload library as the guest sees it, i.e. uncompressed and
  // page-aligned inside the APK. Also cross-checked against kGuestHello.
  ::xrom::crypto::Sha256Digest payload_lib_sha256{};

  // Task classes this payload is authorised to serve. A class absent from this
  // list is refused even if IsolationPolicy would otherwise allow it, so a
  // payload cannot be talked into doing work it was not signed for.
  std::vector<int32_t> allowed_task_classes;

  // Anti-rollback. A manifest with a lower value than the one recorded in the
  // trust anchor is refused, so a validly signed older manifest cannot be
  // replayed after a security fix.
  int32_t security_version = 0;

  std::string signature_algorithm;

  // Selects the entry in trust_anchors.json. Pinning the key by id rather than
  // trusting whatever key verifies is what stops an attacker from adding their
  // own anchor.
  std::string key_id;

  int64_t issued_at_unix = 0;
  int64_t not_after_unix = 0;

  // Structural validation. Returns every problem, matching IsolationPolicy's
  // convention: a policy that leaks one rule at a time can be probed.
  std::vector<std::string> Validate() const;

  bool AllowsTaskClass(int32_t task_class) const;
  bool IsExpired(int64_t now_unix) const;
  bool IsNotYetValid(int64_t now_unix) const;

  // Single line for logs. Digests are rendered as the first 12 hex characters:
  // enough to correlate two log lines, not enough to be a lookup aid.
  std::string ToString() const;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_PAYLOAD_MANIFEST_H_
