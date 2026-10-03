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

// Tests for services/avf/xrom_avfd/PayloadManifest.cpp — the structural rules a
// signed manifest has to satisfy before the daemon will act on it.
//
// Signature verification is not tested here: it needs BoringSSL and runs in the
// AOSP build. What is tested is every rule that decides whether a *validly
// signed* manifest is still acceptable, because a signature proves authorship and
// not sense. The end-to-end signing format is covered by
// tools/tests/payload_signing_roundtrip.sh, which drives the real openssl.

#include "PayloadManifest.h"

#include <string>

#include "Sha256.h"
#include "gtest/gtest.h"

namespace {

using ::xrom::avf::kAlgorithmEd25519;
using ::xrom::avf::kAlgorithmRsa4096Sha256;
using ::xrom::avf::kManifestVersion;
using ::xrom::avf::PayloadManifest;
using ::xrom::crypto::Sha256;

// A manifest that satisfies every rule. Each test breaks exactly one field, so a
// failure names the rule that stopped working rather than a pile of them.
PayloadManifest Valid() {
  PayloadManifest manifest;
  manifest.manifest_version = kManifestVersion;
  manifest.payload_name = "xvault";
  manifest.payload_apk_filename = "XVaultPayload.apk";
  manifest.payload_library = "libxvault_payload.so";
  manifest.apk_sha256 = Sha256::Hash("apk bytes");
  manifest.vm_config_sha256 = Sha256::Hash("config bytes");
  manifest.payload_lib_sha256 = Sha256::Hash("library bytes");
  manifest.allowed_task_classes = {0, 1};
  manifest.security_version = 1;
  manifest.signature_algorithm = kAlgorithmEd25519;
  manifest.key_id = "xrom-payload-root-01";
  manifest.issued_at_unix = 1700000000;
  manifest.not_after_unix = 1800000000;
  return manifest;
}

// Joins the violations so that a failure message shows all of them.
std::string Joined(const PayloadManifest& manifest) {
  std::string out;
  for (const std::string& problem : manifest.Validate()) {
    out += "[" + problem + "] ";
  }
  return out;
}

bool HasViolationAbout(const PayloadManifest& manifest, const std::string& needle) {
  for (const std::string& problem : manifest.Validate()) {
    if (problem.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace

TEST(PayloadManifest, AWellFormedManifestValidates) {
  const PayloadManifest manifest = Valid();
  EXPECT_TRUE(manifest.Validate().empty()) << Joined(manifest);
  EXPECT_TRUE(manifest.AllowsTaskClass(0));
  EXPECT_TRUE(manifest.AllowsTaskClass(1));
  EXPECT_FALSE(manifest.AllowsTaskClass(2));
  EXPECT_FALSE(manifest.AllowsTaskClass(3));
  EXPECT_FALSE(manifest.IsExpired(1750000000));
  EXPECT_FALSE(manifest.IsNotYetValid(1750000000));
}

TEST(PayloadManifest, BothSupportedAlgorithmsAreAccepted) {
  PayloadManifest ed25519 = Valid();
  ed25519.signature_algorithm = kAlgorithmEd25519;
  EXPECT_TRUE(ed25519.Validate().empty()) << Joined(ed25519);

  PayloadManifest rsa = Valid();
  rsa.signature_algorithm = kAlgorithmRsa4096Sha256;
  EXPECT_TRUE(rsa.Validate().empty()) << Joined(rsa);

  // A third scheme would mean a second verification path, and a second path is a
  // second chance to get one of them wrong.
  PayloadManifest other = Valid();
  other.signature_algorithm = "ECDSA_P256_SHA256";
  EXPECT_TRUE(HasViolationAbout(other, "signature_algorithm"));
  PayloadManifest empty = Valid();
  empty.signature_algorithm = "";
  EXPECT_TRUE(HasViolationAbout(empty, "signature_algorithm"));
}

TEST(PayloadManifest, VersionMustMatch) {
  PayloadManifest manifest = Valid();
  manifest.manifest_version = kManifestVersion + 1;
  EXPECT_TRUE(HasViolationAbout(manifest, "manifest_version"));
  manifest.manifest_version = 0;
  EXPECT_TRUE(HasViolationAbout(manifest, "manifest_version"));
}

TEST(PayloadManifest, FilenamesMayNotEscapeTheirDirectory) {
  // The manifest names a file, not a path. If it could name a directory, a
  // signed manifest would be enough to point the daemon at an APK somewhere else
  // on the device — the signature would be valid and the payload would not be the
  // one that was measured.
  for (const char* name : {"/etc/passwd", "../XVaultPayload.apk", "sub/dir/payload.apk",
                           "..", ".", "a\\b.apk", ".hidden.apk", "a..b.apk"}) {
    PayloadManifest manifest = Valid();
    manifest.payload_apk_filename = name;
    EXPECT_TRUE(HasViolationAbout(manifest, "payload_apk_filename")) << name;
  }
  // The extension dot is required, not merely permitted.
  PayloadManifest valid = Valid();
  valid.payload_apk_filename = "XVaultPayload.apk";
  EXPECT_TRUE(valid.Validate().empty()) << Joined(valid);

  PayloadManifest empty = Valid();
  empty.payload_apk_filename = "";
  EXPECT_TRUE(HasViolationAbout(empty, "payload_apk_filename"));

  PayloadManifest long_name = Valid();
  long_name.payload_library = std::string(129, 'x');
  EXPECT_TRUE(HasViolationAbout(long_name, "payload_library"));
}

TEST(PayloadManifest, ZeroDigestsAreRejected) {
  // An all-zero digest is what an unfilled field looks like. Accepting it would
  // let a manifest that forgot to pin the APK compare equal to nothing at all.
  PayloadManifest manifest = Valid();
  manifest.apk_sha256.fill(0);
  EXPECT_TRUE(HasViolationAbout(manifest, "apk_sha256"));

  manifest = Valid();
  manifest.vm_config_sha256.fill(0);
  EXPECT_TRUE(HasViolationAbout(manifest, "vm_config_sha256"));

  manifest = Valid();
  manifest.payload_lib_sha256.fill(0);
  EXPECT_TRUE(HasViolationAbout(manifest, "payload_lib_sha256"));
}

TEST(PayloadManifest, TaskClassListMustBeUsable) {
  PayloadManifest empty = Valid();
  empty.allowed_task_classes.clear();
  EXPECT_TRUE(HasViolationAbout(empty, "allowed_task_classes"))
      << "a payload authorised for nothing must not be accepted silently";

  PayloadManifest duplicated = Valid();
  duplicated.allowed_task_classes = {0, 0, 1};
  EXPECT_TRUE(HasViolationAbout(duplicated, "duplicate"));

  PayloadManifest out_of_range = Valid();
  out_of_range.allowed_task_classes = {0, 4};
  EXPECT_TRUE(HasViolationAbout(out_of_range, "not a TaskClass"));

  PayloadManifest negative = Valid();
  negative.allowed_task_classes = {-1};
  EXPECT_TRUE(HasViolationAbout(negative, "not a TaskClass"));

  PayloadManifest too_many = Valid();
  too_many.allowed_task_classes.clear();
  for (int32_t i = 0; i < 17; ++i) {
    too_many.allowed_task_classes.push_back(i % 4);
  }
  EXPECT_TRUE(HasViolationAbout(too_many, "more than"));

  PayloadManifest all_four = Valid();
  all_four.allowed_task_classes = {0, 1, 2, 3};
  EXPECT_TRUE(all_four.Validate().empty()) << Joined(all_four);
}

TEST(PayloadManifest, ValidityWindowIsChecked) {
  const PayloadManifest manifest = Valid();
  EXPECT_TRUE(manifest.IsNotYetValid(1699999999));
  EXPECT_FALSE(manifest.IsNotYetValid(1700000000));
  EXPECT_FALSE(manifest.IsExpired(1799999999));
  EXPECT_TRUE(manifest.IsExpired(1800000000));

  PayloadManifest inverted = Valid();
  inverted.not_after_unix = inverted.issued_at_unix - 1;
  EXPECT_TRUE(HasViolationAbout(inverted, "not_after_unix"));

  PayloadManifest zeroed = Valid();
  zeroed.issued_at_unix = 0;
  EXPECT_TRUE(HasViolationAbout(zeroed, "issued_at_unix"));

  PayloadManifest negative = Valid();
  negative.not_after_unix = -1;
  EXPECT_TRUE(HasViolationAbout(negative, "issued_at_unix"));
}

TEST(PayloadManifest, IdentityFieldsAreBounded) {
  PayloadManifest manifest = Valid();
  manifest.payload_name = "";
  EXPECT_TRUE(HasViolationAbout(manifest, "payload_name"));

  manifest = Valid();
  manifest.payload_name = std::string(65, 'n');
  EXPECT_TRUE(HasViolationAbout(manifest, "payload_name"));

  manifest = Valid();
  manifest.key_id = "";
  EXPECT_TRUE(HasViolationAbout(manifest, "key_id"));

  manifest = Valid();
  manifest.security_version = -1;
  EXPECT_TRUE(HasViolationAbout(manifest, "security_version"));
}

TEST(PayloadManifest, EveryProblemIsReportedNotJustTheFirst) {
  // A validator that leaks one rule at a time can be probed: fix the reported
  // problem, resubmit, learn the next rule. Reporting all of them at once removes
  // that channel and saves an operator several round trips.
  PayloadManifest manifest;
  const size_t problems = manifest.Validate().size();
  EXPECT_GE(problems, 8u);

  manifest = Valid();
  manifest.manifest_version = 99;
  manifest.payload_name = "";
  manifest.apk_sha256.fill(0);
  manifest.allowed_task_classes.clear();
  EXPECT_GE(manifest.Validate().size(), 4u);
}

TEST(PayloadManifest, ToStringOmitsFullDigests) {
  // This string goes to logd, which the shell can read on a userdebug build.
  // Twelve hex characters correlate two log lines; sixty-four would hand over the
  // value outright.
  const PayloadManifest manifest = Valid();
  const std::string rendered = manifest.ToString();
  EXPECT_NE(rendered.find("xvault"), std::string::npos);
  EXPECT_NE(rendered.find("xrom-payload-root-01"), std::string::npos);
  EXPECT_NE(rendered.find("libxvault_payload.so"), std::string::npos) << rendered;
  EXPECT_EQ(rendered.find(Sha256::ToHex(manifest.apk_sha256)), std::string::npos);
  EXPECT_EQ(rendered.find(Sha256::ToHex(manifest.payload_lib_sha256)), std::string::npos);
}
