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

#ifndef XROM_RECOVERY_BCB_MESSAGE_H_
#define XROM_RECOVERY_BCB_MESSAGE_H_

#include <cstdint>
#include <string>
#include <vector>

namespace xrom::recovery {

// ---------------------------------------------------------------------------
// The Bootloader Control Block: the 2 KiB structure at offset 0 of the misc
// partition through which Linux, the bootloader and recovery talk to each other.
//
// WHY THIS FILE IS A PURE DATA STRUCTURE AND NOT A BLOCK-DEVICE WRITER
// -------------------------------------------------------------------
// Getting this layout wrong bricks the device: the bootloader reads misc before
// the kernel starts, so there is no recovery from a misaligned field and no log
// to read afterwards. That makes it exactly the kind of code that must be
// testable on a build host, with assertions, rather than on a device, once.
//
// The bytes this file produces are handed to AOSP's libbootloader_message, which
// owns opening misc and doing the read-modify-write. X-ROM does not write the
// block device itself — see the comment on RecoveryOptions below for why that
// matters and is not just tidiness.
//
// Layout and field sizes are from AOSP
// bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message.h
// and are fixed by every bootloader ever shipped. Do not "clean up" this struct.
// ---------------------------------------------------------------------------

// misc partition map, from the AOSP header. These offsets are admitted by the
// bootloader, recovery and uncrypt, so they are not configurable without
// changing all three.
inline constexpr uint64_t kBcbOffsetInMisc = 0;               // bootloader_message
inline constexpr uint64_t kVendorSpaceOffsetInMisc = 2 * 1024;
inline constexpr uint64_t kWipePackageOffsetInMisc = 16 * 1024;  // uncrypt / recovery
inline constexpr uint64_t kSystemSpaceOffsetInMisc = 32 * 1024;  // AOSP features
inline constexpr uint64_t kSystemSpaceSizeInMisc = 32 * 1024;
inline constexpr uint64_t kMiscSize = 64 * 1024;

// Wire struct. Byte-for-byte what AOSP and every bootloader expect.
struct BootloaderMessage {
  char command[32];     // "boot-recovery", "boot-fastboot", "bootonce-bootloader", ...
  char status[32];      // deprecated since Froyo; AOSP still zeroes it
  char recovery[768];   // recovery command line: "recovery\n" then one option per line
  char stage[32];       // "n/m" for multi-stage packages
  char reserved[1184];  // grew from 224 so the struct rounds to exactly 2048
} __attribute__((packed));

static_assert(sizeof(BootloaderMessage) == 2048,
              "bootloader_message size changes break A/B devices");
static_assert(alignof(BootloaderMessage) == 1, "bootloader_message must not be padded");

// Command values. Only the ones X-ROM will ever write are listed; an unknown
// command is rejected by Validate() rather than passed through, because a typo
// here is a device that boots into an undefined state.
inline constexpr char kCommandBootRecovery[] = "boot-recovery";
inline constexpr char kCommandBootFastboot[] = "boot-fastboot";
inline constexpr char kCommandBootonceBootloader[] = "bootonce-bootloader";

// The first line of the recovery field. Recovery's parser requires it; a
// recovery field without it is ignored, which is a silent no-op — the worst
// possible failure mode for a security-triggered reboot.
inline constexpr char kRecoveryHeaderLine[] = "recovery";

// Reasons X-ROM records in the recovery options. Recovery itself ignores
// unknown --xrom-* flags, so these are for the log and for the recovery gate,
// not for AOSP's installer.
inline constexpr char kReasonThreatDetected[] = "threat-detected";
inline constexpr char kReasonBootLoop[] = "boot-loop";
inline constexpr char kReasonIntegrityMismatch[] = "integrity-mismatch";
inline constexpr char kReasonOperatorRequest[] = "operator-request";

// Friendly form of the BCB. std::string/vector instead of fixed char buffers, so
// that the length rules are enforced in one place instead of at every call site.
struct BcbRequest {
  std::string command = kCommandBootRecovery;

  // Recovery command-line options, one per entry, WITHOUT the leading "--". They
  // are appended to whatever recovery options are already in misc rather than
  // replacing them — see the note on AppendSemantics.
  std::vector<std::string> recovery_options;

  // Optional "n/m" progress marker. Empty leaves the field untouched.
  std::string stage;

  // X-ROM's own reason, recorded as --xrom-reason=<value>. Kept as a separate
  // field rather than free text so that Validate() can restrict the vocabulary:
  // a reason string ends up in recovery logs that survive a wipe.
  std::string reason;
};

// Result of rendering a request onto an existing BCB.
struct BcbImage {
  BootloaderMessage message{};

  // True when the rendered image differs from the one it was rendered onto.
  // Writing an unchanged BCB is not harmless: it costs a flash erase cycle on a
  // partition with a finite write budget, and on some controllers an interrupted
  // write to misc is unrecoverable.
  bool changed = false;
};

// Validates a request. Returns every problem, matching the convention used by
// IsolationPolicy and PayloadManifest: a validator that leaks one rule at a time
// can be probed by an attacker who can submit requests.
std::vector<std::string> Validate(const BcbRequest& request);

// Renders |request| onto |existing|, which is the BCB currently in misc.
//
// APPEND SEMANTICS, AND WHY THEY ARE NOT OPTIONAL
// ------------------------------------------------
// The recovery field is a shared channel. uncrypt, RecoverySystem, update_engine
// and A/B slot logic all write to it, and a pending command from any of them is
// meaningful. Rendering a request by memset-ing the struct and writing our own
// options would silently discard a queued wipe or an interrupted OTA, and the
// device would then do the wrong thing at the next reboot with no record of what
// was lost.
//
// So this function preserves command/stage when the request does not set them,
// and merges recovery options: existing ones stay, new ones are appended if not
// already present. That is also what AOSP's write_bootloader_message() does, and
// doing it here means the merge can be tested — libbootloader_message cannot be
// unit tested without a misc partition.
//
// Returns false with |errors| populated if the request fails Validate(), or if
// the merged result would not fit in the 768-byte recovery field. In that case
// |out| is left untouched: a partial BCB is worse than no BCB.
bool Render(const BcbRequest& request, const BootloaderMessage& existing, BcbImage* out,
            std::vector<std::string>* errors);

// Parses the recovery field back into options. Used by the recovery gate to find
// out why it was woken up, and by tests.
std::vector<std::string> ParseRecoveryOptions(const BootloaderMessage& message);

// True when the BCB currently asks for recovery. The bootloader's own test is a
// string comparison on the command field; this matches it.
bool RequestsRecovery(const BootloaderMessage& message);

// Extracts --xrom-reason= if present, else empty.
std::string XromReason(const BootloaderMessage& message);

// Serialises a BCB to the exact 2048 bytes that go to misc offset 0.
std::vector<uint8_t> ToBytes(const BootloaderMessage& message);

// Parses 2048 bytes from misc. Returns false on a short buffer.
bool FromBytes(const uint8_t* data, size_t size, BootloaderMessage* out);

}  // namespace xrom::recovery

#endif  // XROM_RECOVERY_BCB_MESSAGE_H_
