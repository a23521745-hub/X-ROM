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

// Tests for common/recovery/BcbMessage.cpp.
//
// The layout assertions in this file are checked against the published AOSP
// definition of bootloader_message (bootable/recovery/bootloader_message/include/
// bootloader_message/bootloader_message.h), not against this project's copy of it.
// That is the only reason they are worth having: a struct that is 2048 bytes
// because we made it 2048 bytes proves nothing, while a struct that is 2048 bytes
// with command at 0, status at 32, recovery at 64, stage at 832 and reserved at
// 864 is the struct the bootloader reads.
//
// The behavioural tests concentrate on the two properties that make writing the
// BCB safe rather than merely possible:
//
//   * APPEND, never replace. The recovery field is a shared channel. uncrypt,
//     RecoverySystem, update_engine and the A/B slot logic all queue commands in
//     it, and a pending command from any of them is meaningful. Rendering by
//     memset-and-write would silently discard a queued wipe or an interrupted OTA
//     and the device would then do the wrong thing at the next reboot with no
//     record of what was lost.
//   * REFUSE, never truncate. A truncated recovery option is a different option.
//     A field that does not fit is an error the caller has to see, not a shorter
//     string it does not.

#include "BcbMessage.h"

#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace {

using ::xrom::recovery::BcbImage;
using ::xrom::recovery::BcbRequest;
using ::xrom::recovery::BootloaderMessage;

// A misc partition that already holds a queued command, as it would mid-OTA.
BootloaderMessage ExistingWithQueuedOptions() {
  BootloaderMessage message{};
  std::memcpy(message.command, "boot-recovery", 13);
  const std::string field =
      "recovery\n--wipe_cache\n--prompt_and_wipe_data\n--update_package=/data/ota.zip\n";
  std::memcpy(message.recovery, field.data(), field.size());
  std::memcpy(message.stage, "2/5", 3);
  return message;
}

BcbRequest ThreatRequest() {
  BcbRequest request;
  request.command = xrom::recovery::kCommandBootRecovery;
  request.recovery_options = {"wipe_cache"};
  request.reason = xrom::recovery::kReasonThreatDetected;
  return request;
}

bool RenderOk(const BcbRequest& request, const BootloaderMessage& existing, BcbImage* image,
              std::vector<std::string>* errors) {
  return xrom::recovery::Render(request, existing, image, errors);
}

}  // namespace

// ---------------------------------------------------------------------------
// Layout. If any of these fail, the bootloader and X-ROM disagree about where
// misc's fields are, and nothing else in this file matters.
// ---------------------------------------------------------------------------

TEST(BcbMessage, StructIsExactlyOneBcbLong) {
  EXPECT_EQ(sizeof(BootloaderMessage), 2048u);
  EXPECT_EQ(alignof(BootloaderMessage), 1u);
}

TEST(BcbMessage, FieldOffsetsMatchTheAospLayout) {
  EXPECT_EQ(offsetof(BootloaderMessage, command), 0u);
  EXPECT_EQ(offsetof(BootloaderMessage, status), 32u);
  EXPECT_EQ(offsetof(BootloaderMessage, recovery), 64u);
  EXPECT_EQ(offsetof(BootloaderMessage, stage), 832u);
  EXPECT_EQ(offsetof(BootloaderMessage, reserved), 864u);
  EXPECT_EQ(sizeof(BootloaderMessage().command), 32u);
  EXPECT_EQ(sizeof(BootloaderMessage().status), 32u);
  EXPECT_EQ(sizeof(BootloaderMessage().recovery), 768u);
  EXPECT_EQ(sizeof(BootloaderMessage().stage), 32u);
  EXPECT_EQ(sizeof(BootloaderMessage().reserved), 1184u);
}

TEST(BcbMessage, MiscRegionMapIsSelfConsistent) {
  // The BCB occupies the first 2 KiB and nothing else may start inside it.
  EXPECT_EQ(xrom::recovery::kBcbOffsetInMisc + sizeof(BootloaderMessage),
            xrom::recovery::kVendorSpaceOffsetInMisc);
  // wipe_package sits between the vendor region and the system region.
  EXPECT_GT(xrom::recovery::kWipePackageOffsetInMisc,
            xrom::recovery::kVendorSpaceOffsetInMisc);
  EXPECT_LT(xrom::recovery::kWipePackageOffsetInMisc,
            xrom::recovery::kSystemSpaceOffsetInMisc);
  // The system space is the last region and ends exactly at the partition size.
  EXPECT_EQ(xrom::recovery::kSystemSpaceOffsetInMisc + xrom::recovery::kSystemSpaceSizeInMisc,
            xrom::recovery::kMiscSize);
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

TEST(BcbMessage, ToBytesIsExactlyOneBcbAndRoundTrips) {
  const BootloaderMessage original = ExistingWithQueuedOptions();
  const std::vector<uint8_t> bytes = xrom::recovery::ToBytes(original);
  EXPECT_EQ(bytes.size(), sizeof(BootloaderMessage));

  BootloaderMessage restored{};
  EXPECT_TRUE(xrom::recovery::FromBytes(bytes.data(), bytes.size(), &restored));
  EXPECT_EQ(std::memcmp(&original, &restored, sizeof(original)), 0);
}

TEST(BcbMessage, FromBytesRejectsAShortBuffer) {
  // A short read from a block device is a real failure mode, and accepting it
  // would leave the tail of the struct holding whatever was on the stack.
  const std::vector<uint8_t> bytes(sizeof(BootloaderMessage) - 1, 0);
  BootloaderMessage restored{};
  EXPECT_FALSE(xrom::recovery::FromBytes(bytes.data(), bytes.size(), &restored));
  EXPECT_FALSE(xrom::recovery::FromBytes(nullptr, sizeof(BootloaderMessage), &restored));
}

TEST(BcbMessage, FromBytesAcceptsALargerPartitionImage) {
  // misc is 64 KiB and the BCB is 2 KiB of it. Reading the whole partition and
  // taking the first BCB is the normal path.
  const BootloaderMessage original = ExistingWithQueuedOptions();
  std::vector<uint8_t> bytes(xrom::recovery::kMiscSize, 0xFF);
  const std::vector<uint8_t> bcb = xrom::recovery::ToBytes(original);
  std::memcpy(bytes.data(), bcb.data(), bcb.size());

  BootloaderMessage restored{};
  EXPECT_TRUE(xrom::recovery::FromBytes(bytes.data(), bytes.size(), &restored));
  EXPECT_TRUE(xrom::recovery::RequestsRecovery(restored));
  EXPECT_EQ(xrom::recovery::XromReason(restored), "");
}

// ---------------------------------------------------------------------------
// Append semantics — the property that keeps a queued OTA alive
// ---------------------------------------------------------------------------

TEST(BcbMessage, RenderPreservesOptionsAlreadyQueuedInMisc) {
  const BootloaderMessage existing = ExistingWithQueuedOptions();
  BcbImage image;
  std::vector<std::string> errors;
  EXPECT_TRUE(RenderOk(ThreatRequest(), existing, &image, &errors));
  EXPECT_TRUE(errors.empty());

  const std::vector<std::string> options =
      xrom::recovery::ParseRecoveryOptions(image.message);
  // All three queued options survive, in their original order...
  EXPECT_EQ(options.size(), 4u);
  EXPECT_EQ(options[0], "wipe_cache");
  EXPECT_EQ(options[1], "prompt_and_wipe_data");
  EXPECT_EQ(options[2], "update_package=/data/ota.zip");
  // ...and X-ROM's own reason is appended rather than substituted.
  EXPECT_EQ(options[3], "xrom-reason=threat-detected");
}

TEST(BcbMessage, RenderPreservesStageAndCommandWhenNotSpecified) {
  const BootloaderMessage existing = ExistingWithQueuedOptions();
  BcbRequest request;
  request.command = "";  // leave the bootloader's instruction alone
  request.recovery_options = {"xrom-quarantine"};

  BcbImage image;
  std::vector<std::string> errors;
  EXPECT_TRUE(RenderOk(request, existing, &image, &errors));
  EXPECT_TRUE(xrom::recovery::RequestsRecovery(image.message));
  EXPECT_EQ(std::string(image.message.stage, 3), "2/5");
}

TEST(BcbMessage, RenderIsIdempotentAndReportsNoChangeTheSecondTime) {
  // Rendering the same request twice must not rewrite misc. Flash has a finite
  // erase budget, and on some controllers an interrupted write to misc is not
  // recoverable — so "nothing to write" has to be detectable before the write.
  const BootloaderMessage existing = ExistingWithQueuedOptions();
  BcbImage first;
  std::vector<std::string> errors;
  EXPECT_TRUE(RenderOk(ThreatRequest(), existing, &first, &errors));
  EXPECT_TRUE(first.changed);

  BcbImage second;
  errors.clear();
  EXPECT_TRUE(RenderOk(ThreatRequest(), first.message, &second, &errors));
  EXPECT_FALSE(second.changed);
  EXPECT_EQ(std::memcmp(&first.message, &second.message, sizeof(BootloaderMessage)), 0);
}

TEST(BcbMessage, RenderReplacesAnOlderXromReason) {
  // Two --xrom-reason flags would make the field ambiguous to anything reading
  // it, so the most recent trigger wins.
  BootloaderMessage existing = ExistingWithQueuedOptions();
  BcbImage first;
  std::vector<std::string> errors;
  EXPECT_TRUE(RenderOk(ThreatRequest(), existing, &first, &errors));
  EXPECT_EQ(xrom::recovery::XromReason(first.message), "threat-detected");

  BcbRequest second_request;
  second_request.recovery_options = {"wipe_cache"};
  second_request.reason = xrom::recovery::kReasonIntegrityMismatch;
  BcbImage second;
  errors.clear();
  EXPECT_TRUE(RenderOk(second_request, first.message, &second, &errors));
  EXPECT_EQ(xrom::recovery::XromReason(second.message), "integrity-mismatch");

  size_t reasons = 0;
  for (const std::string& option : xrom::recovery::ParseRecoveryOptions(second.message)) {
    if (option.rfind("xrom-reason=", 0) == 0) {
      ++reasons;
    }
  }
  EXPECT_EQ(reasons, 1u);
  // The uncrypt option queued before all of this is still there.
  EXPECT_TRUE(xrom::recovery::ParseRecoveryOptions(second.message)[2] ==
              "update_package=/data/ota.zip");
}

TEST(BcbMessage, RenderRefusesToTruncateAFieldThatDoesNotFit) {
  BootloaderMessage existing{};
  BcbRequest request;
  // Exactly 32 options — the count Validate allows — each long enough that the
  // merged field is many times the 768 bytes available. Legal as far as the
  // request format is concerned and impossible as far as the partition is.
  for (int i = 0; i < 32; ++i) {
    request.recovery_options.push_back("option_" + std::to_string(i) + "_" +
                                       std::string(180, 'x'));
  }
  EXPECT_EQ(request.recovery_options.size(), 32u);
  EXPECT_TRUE(xrom::recovery::Validate(request).empty());

  BcbImage image;
  std::vector<std::string> errors;
  EXPECT_FALSE(RenderOk(request, existing, &image, &errors));
  EXPECT_EQ(errors.size(), 1u);
  EXPECT_TRUE(errors[0].find("does not fit in 768") != std::string::npos);
}

TEST(BcbMessage, RenderLeavesTheOutputUntouchedWhenItRefuses) {
  // A partial BCB is worse than no BCB: the caller has to be able to look at
  // |image| after a failure and know it was never written to.
  BootloaderMessage existing = ExistingWithQueuedOptions();
  BcbRequest request;
  request.command = "boot-somewhere-else";

  BcbImage image;
  image.message = existing;
  image.changed = false;
  std::vector<std::string> errors;
  EXPECT_FALSE(RenderOk(request, existing, &image, &errors));
  EXPECT_EQ(std::memcmp(&image.message, &existing, sizeof(existing)), 0);
  EXPECT_FALSE(image.changed);
}

// ---------------------------------------------------------------------------
// Validation: the recovery field is a command line, so the alphabet is narrow
// ---------------------------------------------------------------------------

TEST(BcbMessage, ValidateRejectsOptionsThatWouldInjectASecondOption) {
  const std::vector<std::string> bad = {
      "wipe_cache\n--prompt_and_wipe_data",  // newline splits into two options
      "wipe cache",                          // space splits on a command line
      "--wipe_cache",                        // callers must not pass the dashes
      "wipe_cache\r",                        // control byte
      "wipe;rm -rf /data",                   // shell metacharacter
      std::string(201, 'a'),                 // over the length cap
      "",                                    // empty
  };
  for (const std::string& option : bad) {
    BcbRequest request;
    request.recovery_options = {option};
    EXPECT_EQ(xrom::recovery::Validate(request).size(), 1u);
  }
}

TEST(BcbMessage, ValidateAcceptsTheCharactersARealOptionNeeds) {
  BcbRequest request;
  request.recovery_options = {
      "update_package=/cache/ota.zip",
      "xrom-reason=threat-detected",
      "locale=tr_TR",
      "sideload",
      "debug+verbose",
      "path@host:1234/a.b_c",
  };
  EXPECT_TRUE(xrom::recovery::Validate(request).empty());
}

TEST(BcbMessage, ValidateRejectsAnUnknownCommandAndAnUnknownReason) {
  BcbRequest request;
  request.command = "boot-recoveryy";
  request.reason = "because-i-said-so";
  const std::vector<std::string> problems = xrom::recovery::Validate(request);
  // Both are reported, not just the first: a validator that leaks one rule at a
  // time can be probed by whoever is submitting requests.
  EXPECT_EQ(problems.size(), 2u);
}

TEST(BcbMessage, ValidateRejectsAMalformedStage) {
  const std::vector<std::string> bad = {"/5", "2/", "2", "a/b", "2/5/7",
                                        "2/555555555555", " / "};
  for (const std::string& stage : bad) {
    BcbRequest request;
    request.stage = stage;
    EXPECT_EQ(xrom::recovery::Validate(request).size(), 1u);
  }
  BcbRequest good;
  good.stage = "2/5";
  EXPECT_TRUE(xrom::recovery::Validate(good).empty());
}

TEST(BcbMessage, ValidateRejectsMoreOptionsThanTheFieldCouldEverHold) {
  BcbRequest request;
  for (int i = 0; i < 33; ++i) {
    request.recovery_options.push_back("opt" + std::to_string(i));
  }
  EXPECT_EQ(xrom::recovery::Validate(request).size(), 1u);
}

// ---------------------------------------------------------------------------
// The failure mode that is easy to get wrong and impossible to notice on a
// working device: an empty command leaves the bootloader's instruction alone, so
// rendering onto a blank misc arms nothing.
// ---------------------------------------------------------------------------

TEST(BcbMessage, EmptyCommandOntoBlankMiscDoesNotArmRecovery) {
  BootloaderMessage existing{};  // erased-ish misc: no command at all
  BcbRequest request;
  request.command = "";
  request.recovery_options = {"wipe_cache"};
  request.reason = xrom::recovery::kReasonThreatDetected;

  BcbImage image;
  std::vector<std::string> errors;
  EXPECT_TRUE(RenderOk(request, existing, &image, &errors));
  EXPECT_FALSE(xrom::recovery::RequestsRecovery(image.message));
  // The options are there but the bootloader will never look at them.
  EXPECT_EQ(xrom::recovery::ParseRecoveryOptions(image.message).size(), 2u);
}

TEST(BcbMessage, RequestsRecoveryIsTrueOnlyForBootRecovery) {
  BootloaderMessage message{};
  EXPECT_FALSE(xrom::recovery::RequestsRecovery(message));

  std::memcpy(message.command, "boot-recovery", 13);
  EXPECT_TRUE(xrom::recovery::RequestsRecovery(message));

  std::memset(message.command, 0, sizeof(message.command));
  std::memcpy(message.command, "boot-fastboot", 13);
  EXPECT_FALSE(xrom::recovery::RequestsRecovery(message));

  std::memset(message.command, 0, sizeof(message.command));
  std::memcpy(message.command, "bootonce-bootloader", 19);
  EXPECT_FALSE(xrom::recovery::RequestsRecovery(message));
}

TEST(BcbMessage, ParseRecoveryOptionsIgnoresTheHeaderAndBlankLines) {
  BootloaderMessage message{};
  const std::string field = "recovery\n--wipe_cache\n\n--sideload\n";
  std::memcpy(message.recovery, field.data(), field.size());
  const std::vector<std::string> options = xrom::recovery::ParseRecoveryOptions(message);
  EXPECT_EQ(options.size(), 2u);
  EXPECT_EQ(options[0], "wipe_cache");
  EXPECT_EQ(options[1], "sideload");
}

TEST(BcbMessage, RecoveryFieldAlwaysStartsWithTheHeaderRecoveryParses) {
  // A recovery field without the "recovery" marker is ignored by recovery, which
  // makes a missing header a silent no-op: the worst failure mode for a
  // security-triggered reboot, because everything looks like it worked.
  BcbRequest request;
  request.recovery_options = {"wipe_cache"};
  BcbImage image;
  std::vector<std::string> errors;
  EXPECT_TRUE(RenderOk(request, BootloaderMessage{}, &image, &errors));
  EXPECT_EQ(std::string(image.message.recovery, 9), "recovery\n");
}
