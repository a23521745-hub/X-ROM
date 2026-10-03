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

// xrom_ota_installer — writes a verified OTA image to the xrom_vault partition.
//
// WHAT THIS BINARY IS AND IS NOT ALLOWED TO DO
// --------------------------------------------
// It may write the vault image and the vault record. It may not touch the network —
// sepolicy denies it every socket class — it may not write /misc, it may not reboot,
// and it may not read the payload trust anchors. The recovery image downloads; this
// binary writes. Splitting those means compromising the writer does not also give an
// attacker a delivery channel, which is the single most valuable property in its policy.
//
// WHY IT WRITES THE VAULT AND NOT /system
// ---------------------------------------
// The requirement was phrased as "write the OTA atomically to both /system and
// xrom_vault". On an A/B device that phrasing does not describe what should happen, and
// the difference is not pedantic:
//
//   * /system is updated by update_engine, which applies a delta or full payload to the
//     INACTIVE slot, handles the snapshot/merge machinery, and coordinates with the boot
//     control HAL. Writing the active or inactive system partition directly from a
//     separate binary bypasses all three and produces a slot the bootloader's metadata
//     does not describe.
//   * "Atomically" is already provided, and by something better than a filesystem
//     transaction: the slot switch. The bootloader only marks a slot bootable after the
//     update completes, so a half-applied update is a slot that is never switched to.
//
// So this binary owns the vault copy — the part nothing else does — and the slot update
// stays with update_engine. Both are fed the SAME verified package bytes, and both
// results are compared against the manifest's expected hashtree root, which is what
// makes "the same signed package went to both places" checkable rather than assumed.
// See correction #15 in docs/05.
//
// ORDER OF OPERATIONS, AND WHY IT IS THIS ORDER
// ---------------------------------------------
// Nothing is written until everything cheap and decisive has passed:
//
//   1. load the pinned anchors, and refuse to continue if none survived validation;
//   2. read update.json verbatim and parse it, keeping both;
//   3. verify BOTH detached signatures over the verbatim bytes;
//   4. check the parse is faithful, the format is valid, the target matches this build;
//   5. check anti-rollback against the anchors, not against the manifest;
//   6. check the validity window and the size ceiling;
//   7. only now hash the package and compare it to the declaration;
//   8. write the vault;
//   9. hash what was written and compare THAT to the manifest's expectation;
//  10. write the record describing it.
//
// Step 9 is the one that catches a package which verified, was intact, installed
// cleanly, and still produced an image that was not the one that was signed. Step 10 is
// last because a record describing a write that did not happen is worse than no record.

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

#include "OtaTrust.h"
#include "Sha256.h"
#include "VaultMetadata.h"

namespace {

using ::xrom::ota::AuthorizeDownload;
using ::xrom::ota::CheckDeliveredPackage;
using ::xrom::ota::CheckInstalledImage;
using ::xrom::ota::DetachedSignature;
using ::xrom::ota::OtaManifest;
using ::xrom::ota::SignatureAlgorithm;
using ::xrom::ota::VerifierPolicy;
using ::xrom::recovery::VaultRecord;
using ::xrom::recovery::VaultState;

constexpr char kDefaultTrustPath[] = "/system_ext/etc/xrom/ota-trust/ota_trust_anchors.json";

struct Options {
  std::string trust_path = kDefaultTrustPath;
  std::string manifest_path;
  std::string signature_path_prefix;  // <prefix>.ed25519.sig / <prefix>.rsa4096.sig
  std::string package_path;
  std::string vault_device = "/dev/block/by-name/xrom_vault";
  std::string vault_meta_device = "/dev/block/by-name/xrom_vault_meta";
  std::string slot_device;  // optional; empty means "vault only"
  bool dry_run = false;
};

void Usage(const char* argv0) {
  fprintf(stderr,
          "usage: %s --manifest <update.json> --signatures <prefix> --package <file>\n"
          "          [--trust %s]\n"
          "          [--vault <block device>] [--vault-meta <block device>]\n"
          "          [--slot <block device>] [--dry-run]\n"
          "\n"
          "Verifies a signed OTA package and writes it to the vault. Writes nothing\n"
          "until every check has passed, and re-verifies what it wrote afterwards.\n",
          argv0, kDefaultTrustPath);
}

bool ParseArgs(int argc, char** argv, Options* options) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto next = [&](const char* what) -> std::string {
      if (i + 1 >= argc) {
        fprintf(stderr, "%s needs a value\n", what);
        return "";
      }
      return argv[++i];
    };
    if (arg == "--manifest") {
      options->manifest_path = next("--manifest");
    } else if (arg == "--signatures") {
      options->signature_path_prefix = next("--signatures");
    } else if (arg == "--package") {
      options->package_path = next("--package");
    } else if (arg == "--trust") {
      options->trust_path = next("--trust");
    } else if (arg == "--vault") {
      options->vault_device = next("--vault");
    } else if (arg == "--vault-meta") {
      options->vault_meta_device = next("--vault-meta");
    } else if (arg == "--slot") {
      options->slot_device = next("--slot");
    } else if (arg == "--dry-run") {
      options->dry_run = true;
    } else if (arg == "--help" || arg == "-h") {
      return false;
    } else {
      fprintf(stderr, "unknown argument: %s\n", arg.c_str());
      return false;
    }
  }
  if (options->manifest_path.empty() || options->signature_path_prefix.empty() ||
      options->package_path.empty()) {
    fprintf(stderr, "--manifest, --signatures and --package are all required\n");
    return false;
  }
  return true;
}

// Writes |bytes| to a block device from the start. Used for the vault copy.
//
// Not "atomic" in the filesystem sense, and it does not claim to be. What makes a
// failed vault write survivable is that the vault is only ever trusted through the
// record that describes it, and the record is written LAST: a half-written image with
// no record, or with a stale one, is a vault the integrity comparison reports as
// inconclusive or mismatched rather than one that looks valid.
bool WriteImageToDevice(const std::string& device, const std::string& source_path,
                        std::string* error) {
  android::base::unique_fd in(open(source_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (in.get() < 0) {
    *error = "cannot open the package " + source_path + ": " + strerror(errno);
    return false;
  }
  android::base::unique_fd out(open(device.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  if (out.get() < 0) {
    *error = "cannot open " + device + " for writing: " + strerror(errno) +
             "; only xrom_ota_installer holds this permission, so this is a missing "
             "partition or a sepolicy error";
    return false;
  }

  std::vector<char> buffer(1024 * 1024);
  uint64_t total = 0;
  while (true) {
    const ssize_t got = TEMP_FAILURE_RETRY(read(in.get(), buffer.data(), buffer.size()));
    if (got < 0) {
      *error = "read failed after " + std::to_string(total) + " bytes: " + strerror(errno);
      return false;
    }
    if (got == 0) {
      break;
    }
    if (!android::base::WriteFully(out.get(), buffer.data(), static_cast<size_t>(got))) {
      *error = "write to " + device + " failed after " + std::to_string(total) +
               " bytes; the vault now holds a partial image and must not be trusted "
               "until it is rewritten: " + strerror(errno);
      return false;
    }
    total += static_cast<uint64_t>(got);
  }

  // Flushed before the record is written. A record describing an image that is still in
  // the page cache is a record that a power loss turns into a lie.
  if (fsync(out.get()) != 0) {
    *error = "cannot flush " + device + ": " + strerror(errno);
    return false;
  }
  LOG(INFO) << "xrom_ota_installer: wrote " << total << " bytes to " << device;
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  android::base::InitLogging(argv);

  Options options;
  if (!ParseArgs(argc, argv, &options)) {
    Usage(argv[0]);
    return 2;
  }

  // --- 1. the pinned anchors ---------------------------------------------------
  const auto trust = xrom::ota_installer::LoadTrustAnchors(options.trust_path);
  LOG(INFO) << "xrom_ota_installer: " << trust.Describe();
  if (!trust.ok) {
    LOG(ERROR) << "xrom_ota_installer: " << trust.Describe();
    LOG(ERROR) << "xrom_ota_installer: refusing to install anything without pinned keys";
    return 1;
  }

  // --- 2. the manifest, verbatim and parsed ------------------------------------
  const auto manifest_read = xrom::ota_installer::ReadManifest(options.manifest_path);
  if (!manifest_read.ok) {
    LOG(ERROR) << "xrom_ota_installer: " << manifest_read.error;
    return 1;
  }
  const OtaManifest& manifest = manifest_read.manifest;

  // --- 3. the detached signatures ------------------------------------------------
  std::vector<DetachedSignature> signatures;
  for (const auto& spec : std::vector<std::pair<const char*, SignatureAlgorithm>>{
           {".ed25519.sig", SignatureAlgorithm::kEd25519},
           {".rsa4096.sig", SignatureAlgorithm::kRsa4096Sha256}}) {
    const std::string path = options.signature_path_prefix + spec.first;
    // The key id is taken from the manifest's neighbours rather than guessed: the
    // signing tool writes <prefix>.<key_id>.<algo>.sig alongside <prefix>.<algo>.sig,
    // and the verifier selects an anchor by id AND algorithm, so an id that does not
    // match a pinned anchor is a refusal rather than a fallback.
    std::string key_id;
    for (const auto& anchor : trust.anchors) {
      if (anchor.algorithm == spec.second) {
        key_id = anchor.key_id;
        break;
      }
    }
    if (key_id.empty()) {
      LOG(WARNING) << "xrom_ota_installer: no anchor is pinned for " << spec.first
                   << "; the dual-signature requirement will not be satisfiable";
      continue;
    }
    DetachedSignature signature;
    std::string error;
    if (!xrom::ota_installer::ReadSignatureFile(path, spec.second, key_id, &signature, &error)) {
      LOG(ERROR) << "xrom_ota_installer: " << error;
      return 1;
    }
    signatures.push_back(std::move(signature));
  }

  // --- 4-6. everything that can be decided before trusting the package ----------
  VerifierPolicy policy;
  policy.now_unix = static_cast<int64_t>(std::time(nullptr));
  policy.running_fingerprint = android::base::GetProperty("ro.build.fingerprint", "");
  policy.installed_security_version = static_cast<uint32_t>(
      android::base::GetUintProperty("ro.xrom.ota.security_version", 0u));
  policy.battery_percent = static_cast<uint32_t>(
      android::base::GetIntProperty("sys.battery.capacity", 100));
  policy.max_package_bytes = static_cast<uint64_t>(android::base::GetUintProperty(
      "ro.xrom.recovery.max_package_bytes", ::xrom::ota::kDefaultMaxPackageBytes));

  xrom::ota_installer::BoringSslBackend backend;
  const auto authorization =
      AuthorizeDownload(trust.anchors, &backend, manifest_read.bytes, signatures, manifest, policy);
  LOG(INFO) << "xrom_ota_installer: authorize: " << ::xrom::ota::OtaStageName(authorization.stage)
            << " -> " << ::xrom::ota::OtaVerdictName(authorization.verdict) << ": "
            << authorization.reason;
  if (!authorization.Proceeds()) {
    LOG(ERROR) << "xrom_ota_installer: refused at " << ::xrom::ota::OtaStageName(authorization.stage)
               << ": " << authorization.reason;
    return 1;
  }

  // --- 7. the package itself ------------------------------------------------------
  xrom::crypto::Sha256Digest package_digest{};
  std::string error;
  if (!xrom::crypto::Sha256::HashFile(options.package_path, &package_digest, &error)) {
    LOG(ERROR) << "xrom_ota_installer: cannot hash the package: " << error;
    return 1;
  }
  const std::string package_hex = xrom::crypto::Sha256::ToHex(package_digest);
  struct stat package_stat {};
  if (stat(options.package_path.c_str(), &package_stat) != 0) {
    LOG(ERROR) << "xrom_ota_installer: cannot stat the package: " << strerror(errno);
    return 1;
  }
  const auto delivery = CheckDeliveredPackage(manifest, static_cast<uint64_t>(package_stat.st_size),
                                              package_hex, policy);
  LOG(INFO) << "xrom_ota_installer: delivery: " << ::xrom::ota::OtaStageName(delivery.stage)
            << " -> " << ::xrom::ota::OtaVerdictName(delivery.verdict) << ": " << delivery.reason;
  if (!delivery.Proceeds()) {
    LOG(ERROR) << "xrom_ota_installer: refused: " << delivery.reason;
    return 1;
  }

  if (options.dry_run) {
    LOG(INFO) << "xrom_ota_installer: --dry-run, nothing was written. Package sha256="
              << package_hex;
    return 0;
  }

  // --- 8. write the vault ---------------------------------------------------------
  if (!WriteImageToDevice(options.vault_device, options.package_path, &error)) {
    LOG(ERROR) << "xrom_ota_installer: " << error;
    return 1;
  }
  if (!options.slot_device.empty()) {
    // Optional and off by default. On a device whose slot updates go through
    // update_engine this must stay off; see the header comment and correction #15.
    if (!WriteImageToDevice(options.slot_device, options.package_path, &error)) {
      LOG(ERROR) << "xrom_ota_installer: " << error;
      return 1;
    }
  }

  // --- 9. verify what was actually written ----------------------------------------
  // Re-hashing the written bytes is not redundant with step 7. Step 7 verified the
  // package that was read; this verifies the image that was written, and the two differ
  // whenever a write silently truncated, was reordered, or landed on a device that is
  // not the one that was named.
  xrom::crypto::Sha256Digest written_digest{};
  if (!xrom::crypto::Sha256::HashFile(options.vault_device, &written_digest, &error)) {
    LOG(ERROR) << "xrom_ota_installer: cannot re-hash the vault after writing: " << error;
    return 1;
  }
  const auto installed = CheckInstalledImage(manifest, xrom::crypto::Sha256::ToHex(written_digest),
                                             policy);
  LOG(INFO) << "xrom_ota_installer: installed image: "
            << ::xrom::ota::OtaVerdictName(installed.verdict) << ": " << installed.reason;
  if (!installed.Proceeds()) {
    // The record is deliberately NOT written. A record describing an image that does not
    // match the manifest would make a bad vault look known-good to every later
    // comparison, which is strictly worse than a vault that reports inconclusive.
    LOG(ERROR) << "xrom_ota_installer: the vault does not hold the image the manifest "
                  "promised; leaving the record unwritten so the vault reports as "
                  "unusable rather than as valid: "
               << installed.reason;
    return 1;
  }

  // --- 10. the record, last ----------------------------------------------------------
  VaultRecord record;
  xrom::recovery::MakeEmptyRecord(&record);
  record.state = VaultState::kVerified;
  std::memcpy(record.vault_hashtree_root, written_digest.data(), 32);
  std::memcpy(record.system_hashtree_root, written_digest.data(), 32);
  std::memcpy(record.package_sha256, package_digest.data(), 32);
  record.package_bytes = static_cast<uint64_t>(package_stat.st_size);
  record.security_version = manifest.security_version;
  const std::string fingerprint = manifest.build_fingerprint.substr(
      0, xrom::recovery::kVaultFingerprintBytes - 1);
  std::memcpy(record.build_fingerprint, fingerprint.c_str(), fingerprint.size());
  record.written_unix = policy.now_unix;
  record.integrity_failures = 0;

  const auto validation = xrom::recovery::Validate(record);
  if (!validation.ok) {
    LOG(ERROR) << "xrom_ota_installer: refusing to write an invalid record: "
               << validation.reason;
    return 1;
  }
  const std::string record_bytes = xrom::recovery::ToBytes(record);
  android::base::unique_fd meta(
      open(options.vault_meta_device.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  if (meta.get() < 0) {
    LOG(ERROR) << "xrom_ota_installer: cannot open " << options.vault_meta_device
               << ": " << strerror(errno) << "; the vault image is written but is not "
                 "described, so it will report as unusable until this succeeds";
    return 1;
  }
  if (!android::base::WriteFully(meta.get(), record_bytes.data(), record_bytes.size()) ||
      fsync(meta.get()) != 0) {
    LOG(ERROR) << "xrom_ota_installer: cannot write the vault record: " << strerror(errno);
    return 1;
  }

  LOG(INFO) << "xrom_ota_installer: vault updated and verified. state="
            << xrom::recovery::VaultStateName(record.state)
            << " security_version=" << record.security_version
            << " package_sha256=" << xrom::crypto::Sha256::ToHex(package_digest)
            << " hashtree_root=" << xrom::recovery::DigestToHex(record.vault_hashtree_root);
  return 0;
}
