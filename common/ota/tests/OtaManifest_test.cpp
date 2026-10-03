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

// Tests for common/ota/OtaManifest.cpp.
//
// The URL tests matter more than they look. update.json arrives from a network the
// recovery engine has only provisionally decided to trust, and the package_url in
// it is handed to a downloader that is not the same code as the validator. Any
// input on which two URL parsers can disagree about what the host is becomes a way
// to make the validator approve one host and the downloader fetch another. So the
// authority is checked structurally and the ambiguous forms are rejected outright
// rather than parsed: userinfo, IP literals, bare names, non-standard ports.
//
// The serialisation tests assert that Serialize() is deterministic and that its
// field order is fixed, because the detached signature covers exactly those bytes.
// tools/xrom_sign_ota.py produces the same string, and
// tools/tests/ota_signing_roundtrip.sh fails if the two ever diverge — a signer
// and a verifier that disagree about whitespace produce signatures that are valid
// over bytes nobody ever sends.

#include "OtaManifest.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace {

using ::xrom::ota::DecidePackageSize;
using ::xrom::ota::IsLowercaseHex64;
using ::xrom::ota::kDefaultMaxPackageBytes;
using ::xrom::ota::OtaManifest;

OtaManifest Valid() {
  OtaManifest manifest;
  manifest.package_url = "https://update.xrom.example/releases/x1/ota-0008.zip";
  manifest.package_sha256 = "0f3a9c1d4e5b6a7988a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60";
  manifest.package_bytes = 268435456;  // 256 MiB
  manifest.security_version = 8;
  manifest.build_fingerprint = "X-ROM/x1/16/AP1A.000000.008/8:user/release-keys";
  manifest.target_fingerprint = "X-ROM/x1/16/AP1A.000000.007/7:user/release-keys";
  manifest.expected_hashtree_root_sha256 =
      "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
  manifest.min_battery_percent = 30;
  manifest.issued_at_unix = 1767225600;   // 2026-01-01T00:00:00Z
  manifest.not_after_unix = 1774915200;   // 2026-03-31T00:00:00Z
  manifest.updates_vault = true;
  return manifest;
}

bool Fails(const std::string& message_contains, const OtaManifest& manifest) {
  const auto validation = xrom::ota::Validate(manifest);
  if (validation.ok) {
    return false;
  }
  for (const std::string& error : validation.errors) {
    if (error.find(message_contains) != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// The baseline
// ---------------------------------------------------------------------------

TEST(OtaManifest, ACompleteManifestIsValid) {
  const auto validation = xrom::ota::Validate(Valid());
  EXPECT_TRUE(validation.ok);
  EXPECT_EQ(validation.errors.size(), 0u);
  EXPECT_EQ(validation.Describe(), "valid");
}

TEST(OtaManifest, TheDefaultSizeCeilingIsFiveHundredMebibytes) {
  EXPECT_EQ(kDefaultMaxPackageBytes, 500ull * 1024 * 1024);
  EXPECT_TRUE(xrom::ota::Validate(Valid()).ok);
  // The valid manifest sits comfortably under it.
  EXPECT_LT(Valid().package_bytes, kDefaultMaxPackageBytes);
}

// ---------------------------------------------------------------------------
// Serialisation: the bytes that get signed
// ---------------------------------------------------------------------------

TEST(OtaManifest, SerializeIsDeterministicAndFieldOrderIsFixed) {
  const OtaManifest manifest = Valid();
  const std::string a = manifest.Serialize();
  const std::string b = manifest.Serialize();
  EXPECT_EQ(a, b);

  // The signature covers these bytes, so the order is part of the artifact and
  // cannot drift. Each key must appear, in this order.
  const std::vector<std::string> order = {
      "\"manifest_version\"", "\"package_url\"",           "\"package_sha256\"",
      "\"package_bytes\"",    "\"security_version\"",      "\"build_fingerprint\"",
      "\"target_fingerprint\"", "\"expected_hashtree_root_sha256\"",
      "\"min_battery_percent\"", "\"issued_at_unix\"",     "\"not_after_unix\"",
      "\"updates_vault\""};
  size_t previous = 0;
  for (const std::string& key : order) {
    const size_t at = a.find(key);
    EXPECT_TRUE(at != std::string::npos);
    EXPECT_GT(at, previous);
    previous = at;
  }
}

TEST(OtaManifest, SerializeIsIndentedJsonThatEndsWithANewline) {
  const std::string out = Valid().Serialize();
  EXPECT_EQ(out.substr(0, 2), "{\n");
  EXPECT_EQ(out.substr(out.size() - 2), "}\n");
  EXPECT_TRUE(out.find("\n  \"package_url\": ") != std::string::npos);
  EXPECT_TRUE(out.find("\"updates_vault\": true") != std::string::npos);
}

TEST(OtaManifest, EveryFieldChangeChangesTheSerialisedBytes) {
  // If a field could change without changing the signed bytes, the signature would
  // not cover it. Each mutation is applied to a copy and the result compared.
  const std::string baseline = Valid().Serialize();
  const std::vector<OtaManifest> mutations = [] {
    std::vector<OtaManifest> out;
    OtaManifest m = Valid();
    m.package_url = "https://update.xrom.example/releases/x1/ota-0009.zip";
    out.push_back(m);
    m = Valid();
    m.package_bytes = 268435457;
    out.push_back(m);
    m = Valid();
    m.security_version = 9;
    out.push_back(m);
    m = Valid();
    m.min_battery_percent = 31;
    out.push_back(m);
    m = Valid();
    m.updates_vault = false;
    out.push_back(m);
    m = Valid();
    m.not_after_unix = 1774915201;
    out.push_back(m);
    m = Valid();
    m.build_fingerprint = Valid().build_fingerprint + "x";
    out.push_back(m);
    m = Valid();
    m.package_sha256 = Valid().expected_hashtree_root_sha256;
    out.push_back(m);
    return out;
  }();
  for (const OtaManifest& mutation : mutations) {
    EXPECT_NE(mutation.Serialize(), baseline);
  }
}

TEST(OtaManifest, SerializeEscapesTheCharactersJsonRequires) {
  OtaManifest manifest = Valid();
  manifest.build_fingerprint = "a\"b\\c\nd\te";
  const std::string out = manifest.Serialize();
  EXPECT_TRUE(out.find("a\\\"b\\\\c\\nd\\te") != std::string::npos);
  // A raw newline inside a string literal would break the JSON and, more
  // importantly, would make the signed bytes different from what a parser reads.
  EXPECT_EQ(out.find("\nd"), std::string::npos);
}

// ---------------------------------------------------------------------------
// The URL: where two parsers disagreeing becomes an attack
// ---------------------------------------------------------------------------

TEST(OtaManifest, RejectsAPlaintextUrl) {
  OtaManifest manifest = Valid();
  manifest.package_url = "http://update.xrom.example/releases/x1/ota-0008.zip";
  EXPECT_TRUE(Fails("https://", manifest));
}

TEST(OtaManifest, RejectsUserinfoBecauseItMakesTheRealHostAmbiguous) {
  // A validator reading the whole authority as a host approves a URL whose real
  // host is evil.example. Rejecting is cheaper than parsing, and parsing is the
  // thing two implementations disagree about.
  OtaManifest manifest = Valid();
  manifest.package_url = "https://update.xrom.example@evil.example/ota.zip";
  EXPECT_TRUE(Fails("userinfo", manifest));
}

TEST(OtaManifest, RejectsAnIpLiteralHost) {
  // A pinned certificate has a subject name to match against; an address does not.
  OtaManifest manifest = Valid();
  manifest.package_url = "https://140.82.121.4/releases/x1/ota-0008.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));
}

TEST(OtaManifest, RejectsAnAllNumericFinalLabel) {
  // Not just IPv4: "host.123" is not a hostname anyone should be fetching from,
  // and the rule that rejects the address is the same rule that rejects it.
  OtaManifest manifest = Valid();
  manifest.package_url = "https://update.xrom.123/ota.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));

  manifest = Valid();
  manifest.package_url = "https://10.0.0.1/ota.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));
}

TEST(OtaManifest, AcceptsAHostnameWhoseEarlyLabelsAreNumeric) {
  // "3cdn.example" is a perfectly ordinary CDN hostname. Only the final label
  // has to be non-numeric, or a legitimate host would be rejected.
  OtaManifest manifest = Valid();
  manifest.package_url = "https://x1.3cdn.update7.xrom.example/ota.zip";
  EXPECT_TRUE(xrom::ota::Validate(manifest).ok);
}

TEST(OtaManifest, RejectsABareHostname) {
  // "update" on its own resolves through whatever search domain the network
  // happens to hand out, which in recovery is the network under suspicion.
  OtaManifest manifest = Valid();
  manifest.package_url = "https://update/ota.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));
}

TEST(OtaManifest, RejectsANonStandardPort) {
  OtaManifest manifest = Valid();
  manifest.package_url = "https://update.xrom.example:8443/ota.zip";
  EXPECT_TRUE(Fails("port 443", manifest));
}

TEST(OtaManifest, AcceptsAnExplicitPort443) {
  OtaManifest manifest = Valid();
  manifest.package_url = "https://update.xrom.example:443/releases/ota.zip";
  EXPECT_TRUE(xrom::ota::Validate(manifest).ok);
}

TEST(OtaManifest, RejectsTraversalAndAMissingPath) {
  OtaManifest manifest = Valid();
  manifest.package_url = "https://update.xrom.example/releases/../../etc/passwd";
  EXPECT_TRUE(Fails("..", manifest));

  manifest = Valid();
  manifest.package_url = "https://update.xrom.example";
  EXPECT_TRUE(Fails("must include a path", manifest));
}

TEST(OtaManifest, RejectsAnEmptyAndAnOverlongUrl) {
  OtaManifest manifest = Valid();
  manifest.package_url = "";
  EXPECT_TRUE(Fails("must not be empty", manifest));

  manifest = Valid();
  manifest.package_url = "https://update.xrom.example/" + std::string(600, 'a');
  EXPECT_TRUE(Fails("characters", manifest));
}

TEST(OtaManifest, RejectsHostnamesWithEmptyOrOverlongLabels) {
  OtaManifest manifest = Valid();
  manifest.package_url = "https://update..xrom.example/ota.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));

  manifest = Valid();
  manifest.package_url = "https://-update.xrom.example/ota.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));

  manifest = Valid();
  manifest.package_url = "https://update-.xrom.example/ota.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));

  manifest = Valid();
  manifest.package_url = "https://" + std::string(70, 'a') + ".example/ota.zip";
  EXPECT_TRUE(Fails("dotted hostname", manifest));
}

// ---------------------------------------------------------------------------
// The digests and the size
// ---------------------------------------------------------------------------

TEST(OtaManifest, RejectsDigestsThatAreNotSixtyFourLowercaseHexCharacters) {
  const std::vector<std::string> bad = {
      "",
      "0f3a9c1d",
      "0F3A9C1D4E5B6A7988A0B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E5F60",  // uppercase
      "0f3a9c1d4e5b6a7988a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6g",  // 'g'
      "0f3a9c1d4e5b6a7988a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f600", // 65
      "0f3a9c1d4e5b6a7988a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6",   // 63
  };
  for (const std::string& digest : bad) {
    EXPECT_FALSE(IsLowercaseHex64(digest));
    OtaManifest manifest = Valid();
    manifest.package_sha256 = digest;
    EXPECT_TRUE(Fails("package_sha256", manifest));
    manifest = Valid();
    manifest.expected_hashtree_root_sha256 = digest;
    EXPECT_TRUE(Fails("expected_hashtree_root_sha256", manifest));
  }
}

TEST(OtaManifest, IsLowercaseHex64AcceptsExactlyWhatItSays) {
  EXPECT_TRUE(IsLowercaseHex64(Valid().package_sha256));
  EXPECT_TRUE(IsLowercaseHex64(std::string(64, '0')));
  EXPECT_TRUE(IsLowercaseHex64(std::string(32, 'a') + std::string(32, '9')));
}

TEST(OtaManifest, RejectsAManifestThatDoesNotDeclareASize) {
  // A manifest without a declared size cannot be size-gated, and an ungated
  // download is how a recovery image fills a partition it cannot finish writing.
  OtaManifest manifest = Valid();
  manifest.package_bytes = 0;
  EXPECT_TRUE(Fails("non-zero", manifest));
}

TEST(OtaManifest, TheSizeCeilingIsCheckedSeparatelyFromTheFormat) {
  // A manifest can be perfectly well formed and still be too large for this
  // device to accept, which is why the ceiling is policy and not validation.
  OtaManifest huge = Valid();
  huge.package_bytes = 6ull * 1024 * 1024 * 1024;
  EXPECT_TRUE(xrom::ota::Validate(huge).ok);

  const auto decision = DecidePackageSize(huge.package_bytes, kDefaultMaxPackageBytes);
  EXPECT_FALSE(decision.accepted);
  EXPECT_TRUE(decision.reason.find("falling back to the vault") != std::string::npos);
}

TEST(OtaManifest, DecidePackageSizeAcceptsWhatFits) {
  const auto decision = DecidePackageSize(268435456, kDefaultMaxPackageBytes);
  EXPECT_TRUE(decision.accepted);
  EXPECT_TRUE(decision.reason.find("within") != std::string::npos);
}

TEST(OtaManifest, DecidePackageSizeTreatsAZeroCeilingAsDisablingNetworkInstalls) {
  // Not as "allow anything". A ceiling of zero is a configuration that says this
  // device never installs from the network, and reading it the other way round
  // would be the single worst possible default.
  const auto decision = DecidePackageSize(1, 0);
  EXPECT_FALSE(decision.accepted);
  EXPECT_TRUE(decision.reason.find("disables network installs") != std::string::npos);
}

TEST(OtaManifest, DecidePackageSizeRejectsAnUndeclaredSize) {
  EXPECT_FALSE(DecidePackageSize(0, kDefaultMaxPackageBytes).accepted);
}

TEST(OtaManifest, TheCeilingIsInclusiveAtExactlyTheLimit) {
  EXPECT_TRUE(DecidePackageSize(kDefaultMaxPackageBytes, kDefaultMaxPackageBytes).accepted);
  EXPECT_FALSE(DecidePackageSize(kDefaultMaxPackageBytes + 1, kDefaultMaxPackageBytes).accepted);
}

// ---------------------------------------------------------------------------
// Fingerprints, counters, window
// ---------------------------------------------------------------------------

TEST(OtaManifest, RejectsAManifestWhoseTargetIsItsOwnOutput) {
  // Somebody filled both fields in without thinking, and the anti-rollback check
  // that depends on them is then meaningless.
  OtaManifest manifest = Valid();
  manifest.target_fingerprint = manifest.build_fingerprint;
  EXPECT_TRUE(Fails("must differ", manifest));
}

TEST(OtaManifest, RejectsEmptyOrOverlongFingerprints) {
  OtaManifest manifest = Valid();
  manifest.build_fingerprint = "";
  EXPECT_TRUE(Fails("build_fingerprint", manifest));

  manifest = Valid();
  manifest.target_fingerprint = std::string(200, 'x');
  EXPECT_TRUE(Fails("target_fingerprint", manifest));
}

TEST(OtaManifest, RejectsAValidityWindowThatIsNotAWindow) {
  OtaManifest manifest = Valid();
  manifest.not_after_unix = manifest.issued_at_unix;
  EXPECT_TRUE(Fails("must be after", manifest));

  manifest = Valid();
  manifest.not_after_unix = manifest.issued_at_unix - 1;
  EXPECT_TRUE(Fails("must be after", manifest));

  manifest = Valid();
  manifest.issued_at_unix = 0;
  EXPECT_TRUE(Fails("issued_at_unix must be positive", manifest));

  manifest = Valid();
  manifest.not_after_unix = -5;
  EXPECT_TRUE(Fails("not_after_unix must be positive", manifest));
}

TEST(OtaManifest, RejectsAValidityWindowLongerThanAYear) {
  // A manifest that stays valid for a decade is a manifest that can be replayed
  // for a decade. The signing tool caps the window; the verifier refuses one that
  // did not come from the signing tool.
  OtaManifest manifest = Valid();
  manifest.not_after_unix = manifest.issued_at_unix + 400 * 24 * 3600;
  EXPECT_TRUE(Fails("366 days", manifest));

  manifest = Valid();
  manifest.not_after_unix = manifest.issued_at_unix + 366 * 24 * 3600;
  EXPECT_TRUE(xrom::ota::Validate(manifest).ok);
}

TEST(OtaManifest, RejectsABatteryRequirementAboveFullCharge) {
  OtaManifest manifest = Valid();
  manifest.min_battery_percent = 101;
  EXPECT_TRUE(Fails("0..100", manifest));
}

TEST(OtaManifest, RejectsAnUnknownManifestVersion) {
  OtaManifest manifest = Valid();
  manifest.manifest_version = 2;
  EXPECT_TRUE(Fails("manifest_version", manifest));
}

TEST(OtaManifest, ReportsEveryProblemNotJustTheFirst) {
  // A manifest served over a network the recovery engine has already decided to
  // distrust is likely to be wrong in more than one way. A validator that leaks
  // one rule at a time turns diagnosis into a loop of fix-rebuild-retry, and can
  // be probed by whoever is serving it.
  OtaManifest manifest;
  manifest.manifest_version = 99;
  manifest.package_url = "http://1.2.3.4";
  manifest.package_sha256 = "nope";
  manifest.expected_hashtree_root_sha256 = "nope";
  manifest.package_bytes = 0;
  manifest.build_fingerprint = "";
  manifest.target_fingerprint = "";
  manifest.min_battery_percent = 200;
  manifest.issued_at_unix = 0;
  manifest.not_after_unix = 0;

  const auto validation = xrom::ota::Validate(manifest);
  EXPECT_FALSE(validation.ok);
  EXPECT_GE(validation.errors.size(), 8u);
  EXPECT_TRUE(validation.Describe().find("invalid (") != std::string::npos);
}
