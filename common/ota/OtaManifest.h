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

#ifndef XROM_OTA_OTA_MANIFEST_H_
#define XROM_OTA_OTA_MANIFEST_H_

#include <cstdint>
#include <string>
#include <vector>

namespace xrom::ota {

// ---------------------------------------------------------------------------
// update.json: what a recovery that has decided to trust the network is allowed
// to download, and how big it is allowed to be.
//
// THE MANIFEST IS THE SIZE GATE, AND THAT IS THE WHOLE POINT OF HAVING ONE
// ------------------------------------------------------------------------
// A recovery image running on a device with no OS underneath it has very little
// room to be wrong. Downloading an artifact of unbounded size into a partition of
// bounded size is the classic way to turn a network path into a brick: the
// download succeeds, the write fails halfway, and the device now has neither its
// old image nor a new one. So the manifest declares the package size before
// anything is fetched, the declared size is checked against a hard ceiling, and
// the actual byte count is checked against the declaration as the download
// proceeds. A package that says 400 MB and arrives as 900 MB is rejected at 400 MB,
// not at the end.
//
// The ceiling defaults to 500 MiB. That is a policy value, not a property of the
// format, and it lives in OtaVerifier so that it can be tightened per device.
//
// SIGNATURES ARE DETACHED, AND THE SIGNED BYTES ARE THE FILE'S BYTES
// ------------------------------------------------------------------
// The signature fields are deliberately not part of this struct. Putting a
// signature inside the document it signs forces a canonicalisation step — decide
// which fields are covered, in what order, with what whitespace — and every such
// decision is a place where the signer and the verifier can agree to disagree
// without either one being obviously broken. This project already learned that
// lesson once: the payload manifest is signed over its exact serialised bytes with
// no canonicalisation at all, and the OTA manifest does the same. update.json is
// accompanied by update.json.ed25519.sig and update.json.rsa4096.sig, and both
// cover byte-for-byte what is on the wire.
// ---------------------------------------------------------------------------

constexpr uint32_t kOtaManifestVersion = 1;
constexpr size_t kMaxFingerprintLength = 128;
constexpr size_t kMaxUrlLength = 512;
constexpr size_t kMaxKeyIdLength = 64;

// The default hard ceiling on a downloaded package. 500 MiB, matching the
// requirement that an oversized declaration falls back to the vault instead of
// being attempted.
constexpr uint64_t kDefaultMaxPackageBytes = 500ull * 1024ull * 1024ull;

struct OtaManifest {
  uint32_t manifest_version = kOtaManifestVersion;

  // Where to fetch the package. Must be https: a plaintext URL means the manifest
  // itself may have arrived over a path an attacker controls, and every signature
  // in the world does not help if the bytes fetched are not the bytes signed. The
  // host must be a name rather than an IP literal so that certificate pinning has
  // something to pin against; see OtaVerifier for how the resolved address is
  // additionally constrained.
  std::string package_url;

  // SHA-256 of the package exactly as it is fetched, lowercase hex, 64 characters.
  // Checked before the package is handed to anything else, so that a truncated or
  // substituted download cannot reach the installer.
  std::string package_sha256;

  // Declared size in bytes. Enforced twice: against the ceiling before the
  // download starts, and against the running byte count during it.
  uint64_t package_bytes = 0;

  // Monotonic anti-rollback counter for the OTA line. A package whose
  // security_version is lower than the one already installed is refused even if
  // its signature is valid, because a valid signature on an old image is exactly
  // what a downgrade attack presents.
  uint32_t security_version = 0;

  // ro.build.fingerprint of the image this package produces, and of the image it
  // expects to be applied to. The target is checked against the running build
  // before anything is written: an incremental package applied to the wrong base
  // produces an image that boots to nothing.
  std::string build_fingerprint;
  std::string target_fingerprint;

  // vbmeta hashtree root digest the resulting system image is expected to have,
  // lowercase hex. This is what gets recorded in the vault, and comparing it
  // against the digest the installer actually produced is how a package that
  // verified, installed, and still built the wrong image gets caught.
  std::string expected_hashtree_root_sha256;

  // Refuse to start an install below this charge. An OTA that dies at 3% battery
  // is a device that needs a charger and a recovery image, and the manifest is the
  // right place to state the requirement because it is signed and therefore cannot
  // be relaxed by whoever is serving it.
  uint32_t min_battery_percent = 0;

  int64_t issued_at_unix = 0;
  int64_t not_after_unix = 0;

  // Whether this package may be written to the vault as well as to the running
  // slot. False means it is a fix-up package intended only for the slot, and the
  // installer must not treat it as a fallback image. Defaulting to true matches
  // the hybrid design; the field exists so that a future package type can opt out
  // without a format change.
  bool updates_vault = true;

  // Serialises to the exact bytes that are signed. Field order and whitespace are
  // part of the artifact: changing them invalidates every signature already issued,
  // which is the point.
  std::string Serialize() const;
};

struct OtaManifestValidation {
  bool ok = false;
  // Every problem found, not just the first. A manifest served over a network the
  // recovery engine has already decided to distrust is likely to be wrong in more
  // than one way, and a log that reports one defect at a time turns diagnosis into
  // a loop of fix-rebuild-retry.
  std::vector<std::string> errors;

  std::string Describe() const;
};

OtaManifestValidation Validate(const OtaManifest& manifest);

// Checks the declared size against a ceiling. Split out from Validate because the
// ceiling is policy and Validate is format: a manifest can be perfectly
// well-formed and still be too large for this device to accept.
struct SizeDecision {
  bool accepted = false;
  std::string reason;
};
SizeDecision DecidePackageSize(uint64_t declared_bytes, uint64_t max_bytes);

bool IsLowercaseHex64(const std::string& value);

}  // namespace xrom::ota

#endif  // XROM_OTA_OTA_MANIFEST_H_
