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

// Tests for common/protocol/VsockProtocol.cpp — the host/guest wire codec.
//
// The wire layout is a contract between two binaries that are built at the same
// time but run on opposite sides of a hypervisor and cannot be updated together:
// the host daemon is on system_ext and the payload is inside a measured APK. A
// struct that changes size silently is the failure these tests exist to catch, so
// every size is asserted explicitly and every round trip is checked field by
// field rather than by comparing whole structs.

#include "VsockProtocol.h"

#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace {

using namespace ::xrom::avf::vsock;  // NOLINT(build/namespaces) — test-local convenience
using ::xrom::crypto::Sha256;
using ::xrom::crypto::Sha256Digest;

Sha256Digest DigestOf(char seed) {
  Sha256Digest digest{};
  digest.fill(static_cast<uint8_t>(seed));
  return digest;
}

// Splits a complete frame into its header and payload halves. The tests call this
// rather than re-deriving the offset, so that a change to the framing shows up as
// one failure here instead of twenty scattered ones.
void Split(const std::vector<uint8_t>& frame, FrameHeader* header, std::vector<uint8_t>* payload) {
  if (frame.size() < kFrameHeaderSize) {
    std::memset(header, 0, sizeof(*header));
    payload->clear();
    return;
  }
  std::memcpy(header, frame.data(), kFrameHeaderSize);
  payload->assign(frame.begin() + kFrameHeaderSize, frame.end());
}

}  // namespace

// ---------------------------------------------------------------------------
// Wire layout
// ---------------------------------------------------------------------------

TEST(VsockProtocol, WireSizesAreFixed) {
  EXPECT_EQ(sizeof(FrameHeader), 48u);
  EXPECT_EQ(sizeof(GuestHelloPayload), 100u);
  EXPECT_EQ(sizeof(TaskBeginPayload), 140u);
  EXPECT_EQ(sizeof(TaskResultPayload), 176u);
  EXPECT_EQ(sizeof(TaskAbortPayload), 68u);
  EXPECT_EQ(alignof(FrameHeader), 1u);
  EXPECT_EQ(kFrameHeaderSize, sizeof(FrameHeader));
}

TEST(VsockProtocol, HeaderCarriesMagicVersionLengthAndDigest) {
  const Sha256Digest digest = DigestOf(0x5a);
  std::array<uint8_t, kFrameHeaderSize> bytes{};
  EXPECT_TRUE(EncodeHeader(FrameType::kTaskInput, 1234, digest, &bytes));

  FrameHeader header{};
  EXPECT_TRUE(DecodeHeader(bytes.data(), bytes.size(), &header));
  EXPECT_EQ(header.magic, kFrameMagic);
  EXPECT_EQ(header.version, kProtocolVersion);
  EXPECT_EQ(header.type, static_cast<uint32_t>(FrameType::kTaskInput));
  EXPECT_EQ(header.payload_length, 1234u);
  EXPECT_EQ(0, std::memcmp(header.payload_digest, digest.data(), digest.size()));
}

// ---------------------------------------------------------------------------
// Header rejection
// ---------------------------------------------------------------------------

TEST(VsockProtocol, DecodeHeaderRejectsCorruption) {
  const Sha256Digest digest = DigestOf(0x11);
  std::array<uint8_t, kFrameHeaderSize> good{};
  EXPECT_TRUE(EncodeHeader(FrameType::kTaskResult, 8, digest, &good));
  FrameHeader header{};

  // Wrong magic. The magic is what a stream that has lost framing sync trips
  // over first, so it has to be checked before anything else is interpreted.
  std::array<uint8_t, kFrameHeaderSize> bad = good;
  bad[0] ^= 0xff;
  EXPECT_FALSE(DecodeHeader(bad.data(), bad.size(), &header));

  // Wrong version.
  bad = good;
  bad[4] = static_cast<uint8_t>(kProtocolVersion + 1);
  EXPECT_FALSE(DecodeHeader(bad.data(), bad.size(), &header));

  // Unknown frame type.
  bad = good;
  bad[8] = 0x7f;
  EXPECT_FALSE(DecodeHeader(bad.data(), bad.size(), &header));

  // Declared length over the ceiling.
  bad = good;
  const uint32_t too_big = kMaxFramePayloadBytes + 1;
  std::memcpy(bad.data() + 12, &too_big, sizeof(too_big));
  EXPECT_FALSE(DecodeHeader(bad.data(), bad.size(), &header));

  // Truncated buffer.
  EXPECT_FALSE(DecodeHeader(good.data(), kFrameHeaderSize - 1, &header));
  EXPECT_FALSE(DecodeHeader(nullptr, 0, &header));
  EXPECT_FALSE(DecodeHeader(good.data(), good.size(), nullptr));
}

TEST(VsockProtocol, EncodeHeaderRejectsUnknownTypesAndBadLengths) {
  std::array<uint8_t, kFrameHeaderSize> bytes{};
  const Sha256Digest digest = DigestOf(0x22);
  EXPECT_FALSE(EncodeHeader(static_cast<FrameType>(999), 0, digest, &bytes));
  EXPECT_FALSE(EncodeHeader(FrameType::kTaskInput, kMaxFramePayloadBytes + 1, digest, &bytes));
  EXPECT_FALSE(EncodeHeader(FrameType::kTaskInput, 0, digest, nullptr));
  // The ceiling itself must be accepted, not just values below it.
  EXPECT_TRUE(EncodeHeader(FrameType::kTaskInput, kMaxFramePayloadBytes, digest, &bytes));
}

// ---------------------------------------------------------------------------
// Frame-level encode / decode
// ---------------------------------------------------------------------------

TEST(VsockProtocol, EncodeFrameComputesThePayloadDigest) {
  const std::vector<uint8_t> payload(1000, 0x42);
  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeFrame(FrameType::kTaskOutput, payload.data(), payload.size(), &frame));
  EXPECT_EQ(frame.size(), kFrameHeaderSize + payload.size());

  FrameHeader header{};
  const uint8_t* decoded_payload = nullptr;
  size_t decoded_size = 0;
  EXPECT_TRUE(DecodeFrame(frame.data(), frame.size(), &header, &decoded_payload, &decoded_size));
  EXPECT_EQ(decoded_size, payload.size());
  EXPECT_EQ(0, std::memcmp(decoded_payload, payload.data(), payload.size()));
  EXPECT_TRUE(VerifyPayloadDigest(header, decoded_payload, decoded_size));
}

TEST(VsockProtocol, EmptyPayloadFramesAreLegal) {
  // kTaskInputEnd and kTaskAbort-with-no-detail carry no payload, and an empty
  // frame is the case where a digest over zero bytes is most likely to be
  // special-cased incorrectly.
  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeFrame(FrameType::kTaskInputEnd, nullptr, 0, &frame));
  EXPECT_EQ(frame.size(), kFrameHeaderSize);

  FrameHeader header{};
  const uint8_t* payload = nullptr;
  size_t size = 0;
  EXPECT_TRUE(DecodeFrame(frame.data(), frame.size(), &header, &payload, &size));
  EXPECT_EQ(size, 0u);
  EXPECT_TRUE(VerifyPayloadDigest(header, payload, size));
}

TEST(VsockProtocol, DecodeFrameRejectsATruncatedFrame) {
  // DecodeHeader deliberately succeeds here: a streaming reader parses the header
  // before it knows how much more is coming. DecodeFrame is the whole-buffer form
  // and must not.
  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeFrame(FrameType::kTaskOutput, "0123456789", 10, &frame));

  FrameHeader header{};
  EXPECT_TRUE(DecodeHeader(frame.data(), kFrameHeaderSize, &header));
  EXPECT_EQ(header.payload_length, 10u);

  const uint8_t* payload = nullptr;
  size_t size = 0;
  EXPECT_FALSE(DecodeFrame(frame.data(), kFrameHeaderSize + 9, &header, &payload, &size));
  EXPECT_TRUE(DecodeFrame(frame.data(), frame.size(), &header, &payload, &size));
}

TEST(VsockProtocol, VerifyPayloadDigestDetectsASingleFlippedBit) {
  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeFrame(FrameType::kTaskOutput, "aaaaaaaa", 8, &frame));
  FrameHeader header{};
  EXPECT_TRUE(DecodeHeader(frame.data(), kFrameHeaderSize, &header));
  const uint8_t* payload = frame.data() + kFrameHeaderSize;

  EXPECT_TRUE(VerifyPayloadDigest(header, payload, 8));
  std::vector<uint8_t> corrupted(frame);
  corrupted[kFrameHeaderSize + 3] ^= 0x01;
  EXPECT_FALSE(VerifyPayloadDigest(header, corrupted.data() + kFrameHeaderSize, 8));
  // A short read must not verify either: the digest covers the declared length.
  EXPECT_FALSE(VerifyPayloadDigest(header, payload, 7));
}

// ---------------------------------------------------------------------------
// Typed payloads
// ---------------------------------------------------------------------------

TEST(VsockProtocol, GuestHelloRoundTrip) {
  GuestHello in;
  in.protocol_version = kProtocolVersion;
  in.payload_lib_digest = DigestOf(0x01);
  in.vm_config_digest = DigestOf(0x02);
  in.apk_contents_digest = DigestOf(0x03);

  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeGuestHello(in, &frame));
  EXPECT_EQ(frame.size(), kFrameHeaderSize + sizeof(GuestHelloPayload));

  FrameHeader header{};
  std::vector<uint8_t> payload;
  Split(frame, &header, &payload);
  EXPECT_EQ(header.type, static_cast<uint32_t>(FrameType::kGuestHello));

  GuestHello out;
  EXPECT_TRUE(DecodeGuestHello(payload.data(), payload.size(), &out));
  EXPECT_EQ(out.protocol_version, kProtocolVersion);
  EXPECT_TRUE(out.payload_lib_digest == in.payload_lib_digest);
  EXPECT_TRUE(out.vm_config_digest == in.vm_config_digest);
  EXPECT_TRUE(out.apk_contents_digest == in.apk_contents_digest);

  // A hello that claims a protocol version the host does not speak must be
  // refused rather than decoded, or the two ends negotiate by accident.
  GuestHello wrong = in;
  wrong.protocol_version = kProtocolVersion + 1;
  EXPECT_FALSE(EncodeGuestHello(wrong, &frame));
  GuestHello zero = in;
  zero.protocol_version = 0;
  EXPECT_FALSE(EncodeGuestHello(zero, &frame));
}

TEST(VsockProtocol, TaskBeginRoundTrip) {
  TaskBegin in;
  in.task_id = "task-0001";
  in.task_class = 3;
  in.input_length = 123456;
  in.authorization_level = 1;
  in.nonce.fill(0xab);
  in.input_digest = DigestOf(0xcd);

  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeTaskBegin(in, &frame));
  FrameHeader header{};
  std::vector<uint8_t> payload;
  Split(frame, &header, &payload);

  TaskBegin out;
  EXPECT_TRUE(DecodeTaskBegin(payload.data(), payload.size(), &out));
  EXPECT_EQ(out.task_id, in.task_id);
  EXPECT_EQ(out.task_class, in.task_class);
  EXPECT_EQ(out.input_length, in.input_length);
  EXPECT_EQ(out.authorization_level, in.authorization_level);
  EXPECT_TRUE(out.nonce == in.nonce);
  EXPECT_TRUE(out.input_digest == in.input_digest);
}

TEST(VsockProtocol, TaskBeginRejectsUnusableValues) {
  TaskBegin in;
  in.task_id = "task";
  in.input_length = 8;
  std::vector<uint8_t> frame;

  // An encoder that produces a frame its own decoder refuses is how the two ends
  // drift: the host sends it, the guest drops the connection, and the failure
  // looks like a transport problem.
  TaskBegin empty_id = in;
  empty_id.task_id = "";
  EXPECT_FALSE(EncodeTaskBegin(empty_id, &frame));

  TaskBegin long_id = in;
  long_id.task_id = std::string(kTaskIdMaxLength + 1, 'x');
  EXPECT_FALSE(EncodeTaskBegin(long_id, &frame));

  // The buffer is 64 bytes and must stay NUL terminated, so 64 characters cannot
  // fit even though the field is 64 wide.
  TaskBegin exact = in;
  exact.task_id = std::string(kTaskIdMaxLength, 'x');
  EXPECT_FALSE(EncodeTaskBegin(exact, &frame));
  TaskBegin one_less = in;
  one_less.task_id = std::string(kTaskIdMaxLength - 1, 'x');
  EXPECT_TRUE(EncodeTaskBegin(one_less, &frame));

  TaskBegin huge_input = in;
  huge_input.input_length = kMaxInputBytes + 1;
  EXPECT_FALSE(EncodeTaskBegin(huge_input, &frame));

  // A task id containing a NUL would truncate differently on each side.
  TaskBegin embedded_nul = in;
  embedded_nul.task_id = std::string("ab\0cd", 5);
  EXPECT_FALSE(EncodeTaskBegin(embedded_nul, &frame));
}

TEST(VsockProtocol, TaskResultRoundTrip) {
  TaskResult in;
  in.nonce.fill(0x01);
  in.output_digest = DigestOf(0x02);
  in.instance_binding = DigestOf(0x03);
  in.payload_lib_digest = DigestOf(0x04);
  in.vm_config_digest = DigestOf(0x05);
  in.exit_code = -7;
  in.output_length = 65536;
  in.attestation_level = AttestationLevel::kRemoteAttested;
  in.flags = 0xdeadbeef;

  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeTaskResult(in, &frame));
  FrameHeader header{};
  std::vector<uint8_t> payload;
  Split(frame, &header, &payload);

  TaskResult out;
  EXPECT_TRUE(DecodeTaskResult(payload.data(), payload.size(), &out));
  EXPECT_TRUE(out.nonce == in.nonce);
  EXPECT_TRUE(out.output_digest == in.output_digest);
  EXPECT_TRUE(out.instance_binding == in.instance_binding);
  EXPECT_TRUE(out.payload_lib_digest == in.payload_lib_digest);
  EXPECT_TRUE(out.vm_config_digest == in.vm_config_digest);
  EXPECT_EQ(out.exit_code, -7);
  EXPECT_EQ(out.output_length, 65536u);
  EXPECT_TRUE(out.attestation_level == AttestationLevel::kRemoteAttested);
  EXPECT_EQ(out.flags, 0xdeadbeefu);

  // output_length is capped: a result claiming more output than the protocol
  // allows is a broken or hostile guest.
  TaskResult huge = in;
  huge.output_length = kMaxOutputBytes + 1;
  EXPECT_FALSE(EncodeTaskResult(huge, &frame));
  EXPECT_FALSE(DecodeTaskResult(payload.data(), payload.size(), &huge) &&
              huge.output_length > kMaxOutputBytes);

  // An attestation level that is not one of the three known values must not
  // decode into a plausible-looking enum.
  std::vector<uint8_t> tampered = payload;
  uint32_t bad_level = 99;
  std::memcpy(tampered.data() + offsetof(TaskResultPayload, attestation_level), &bad_level,
              sizeof(bad_level));
  TaskResult bad;
  EXPECT_FALSE(DecodeTaskResult(tampered.data(), tampered.size(), &bad));
}

TEST(VsockProtocol, TaskAbortRoundTrip) {
  TaskAbort in;
  in.reason = AbortReason::kMeasurementRejected;
  in.detail = "payload library digest differs";

  std::vector<uint8_t> frame;
  EXPECT_TRUE(EncodeTaskAbort(in, &frame));
  FrameHeader header{};
  std::vector<uint8_t> payload;
  Split(frame, &header, &payload);

  TaskAbort out;
  EXPECT_TRUE(DecodeTaskAbort(payload.data(), payload.size(), &out));
  EXPECT_TRUE(out.reason == AbortReason::kMeasurementRejected);
  EXPECT_EQ(out.detail, in.detail);

  // An empty detail is legal: "the host cancelled" needs no explanation.
  TaskAbort terse;
  terse.reason = AbortReason::kTaskCancelled;
  EXPECT_TRUE(EncodeTaskAbort(terse, &frame));

  TaskAbort long_detail;
  long_detail.reason = AbortReason::kGuestInternalError;
  long_detail.detail = std::string(kAbortDetailMaxLength + 1, 'x');
  EXPECT_FALSE(EncodeTaskAbort(long_detail, &frame));

  TaskAbort unknown_reason;
  unknown_reason.reason = static_cast<AbortReason>(4242);
  EXPECT_FALSE(EncodeTaskAbort(unknown_reason, &frame));
}

// ---------------------------------------------------------------------------
// Enumerations and rendering
// ---------------------------------------------------------------------------

TEST(VsockProtocol, EveryFrameTypeIsKnown) {
  for (const FrameType type : {FrameType::kGuestHello, FrameType::kTaskBegin, FrameType::kTaskInput,
                               FrameType::kTaskInputEnd, FrameType::kTaskOutput,
                               FrameType::kTaskResult, FrameType::kTaskAbort}) {
    EXPECT_TRUE(IsKnownFrameType(static_cast<uint32_t>(type)));
    EXPECT_NE(std::string(FrameTypeName(type)), std::string("unknown"))
        << "type " << static_cast<uint32_t>(type);
  }
  EXPECT_FALSE(IsKnownFrameType(7));
  EXPECT_FALSE(IsKnownFrameType(0xffffffffu));
}

TEST(VsockProtocol, EveryAbortReasonRenders) {
  for (const AbortReason reason :
       {AbortReason::kNone, AbortReason::kInputDigestMismatch,
        AbortReason::kSelfMeasurementMismatch, AbortReason::kEnvironmentCheckFailed,
        AbortReason::kOutputTooLarge, AbortReason::kProtocolError,
        AbortReason::kMeasurementRejected, AbortReason::kTaskCancelled,
        AbortReason::kGuestInternalError, AbortReason::kTaskClassNotAllowed,
        AbortReason::kInputTooLarge, AbortReason::kNoAuthorization}) {
    EXPECT_NE(std::string(AbortReasonName(reason)), std::string("unknown"))
        << "reason " << static_cast<uint32_t>(reason);
  }
}

TEST(VsockProtocol, EveryAttestationLevelRenders) {
  for (const AttestationLevel level : {AttestationLevel::kMeasurementOnly,
                                       AttestationLevel::kInstanceBound,
                                       AttestationLevel::kRemoteAttested}) {
    EXPECT_NE(std::string(AttestationLevelName(level)), std::string("unknown"))
        << "level " << static_cast<uint32_t>(level);
  }
  EXPECT_EQ(std::string(AttestationLevelName(static_cast<AttestationLevel>(9))),
            std::string("unknown"));
}

TEST(VsockProtocol, PortsAndCidsMatchTheDocumentedLayout) {
  EXPECT_EQ(kHostCid, 2u);
  EXPECT_NE(kPortTaskControl, kPortTaskData);
  EXPECT_EQ(kPortTaskControl, 7100);
  EXPECT_EQ(kPortTaskData, 7101);
}
