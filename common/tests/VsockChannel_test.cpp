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

// Tests for common/vsock/VsockChannel.cpp — the framed transport both ends of
// the data plane use.
//
// These run over an AF_UNIX socketpair rather than a real vsock. That is not a
// compromise, it is the point: VsockChannel is deliberately written against
// stream-socket semantics and nothing else, so a socketpair exercises every code
// path it has — partial reads, partial writes, EAGAIN, orderly close, hangup,
// timeouts — without a hypervisor, a device or a guest image. A transport that
// could only be tested against a real pVM would be a transport whose failure
// paths nobody had ever seen run.
//
// The timeouts are generous on purpose. These tests run on shared CI machines,
// and a test that fails under load teaches people to ignore failures.

#include "VsockChannel.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

namespace {

using ::xrom::avf::VsockChannel;
using namespace ::xrom::avf::vsock;  // NOLINT(build/namespaces) — test-local convenience

constexpr auto kTimeout = std::chrono::milliseconds(10000);

struct SocketPair {
  int host_fd = -1;
  int guest_fd = -1;

  SocketPair() {
    int fds[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
      ADD_FAILURE() << "socketpair failed: " << strerror(errno);
      return;
    }
    host_fd = fds[0];
    guest_fd = fds[1];
  }
  ~SocketPair() {
    if (host_fd >= 0) {
      close(host_fd);
    }
    if (guest_fd >= 0) {
      close(guest_fd);
    }
  }
  SocketPair(const SocketPair&) = delete;
  SocketPair& operator=(const SocketPair&) = delete;

  // Writes raw bytes to the "guest" end, bypassing the framing, so that a test
  // can put a corrupt or truncated frame on the wire.
  bool Inject(const void* data, size_t length) {
    const ssize_t written = ::send(guest_fd, data, length, MSG_NOSIGNAL);
    return written == static_cast<ssize_t>(length);
  }
};

// Encodes a complete frame for injection.
std::vector<uint8_t> Frame(FrameType type, const void* payload, size_t length) {
  std::vector<uint8_t> frame;
  EncodeFrame(type, payload, length, &frame);
  return frame;
}

std::vector<uint8_t> Payload(size_t length, uint8_t fill) {
  return std::vector<uint8_t>(length, fill);
}

}  // namespace

// ---------------------------------------------------------------------------
// Happy paths, through the typed API
// ---------------------------------------------------------------------------

TEST(VsockChannel, TaskBeginRoundTrip) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  VsockChannel guest(pair.guest_fd);
  pair.host_fd = pair.guest_fd = -1;  // the channels own them now

  TaskBegin begin;
  begin.task_id = "task-42";
  begin.task_class = 1;
  begin.input_length = 4096;
  begin.authorization_level = 1;
  begin.nonce.fill(0xab);
  begin.input_digest.fill(0xcd);

  std::string error;
  EXPECT_TRUE(host.SendTaskBegin(begin, &error)) << error;
  EXPECT_TRUE(error.empty());

  FrameHeader header{};
  TaskBegin received;
  EXPECT_TRUE(guest.ReceiveTaskBegin(kTimeout, &received, &header, &error)) << error;
  EXPECT_EQ(header.type, static_cast<uint32_t>(FrameType::kTaskBegin));
  EXPECT_EQ(header.payload_length, sizeof(TaskBeginPayload));
  EXPECT_EQ(received.task_id, "task-42");
  EXPECT_EQ(received.task_class, 1u);
  EXPECT_EQ(received.input_length, 4096u);
  EXPECT_EQ(received.authorization_level, 1u);
  EXPECT_TRUE(received.nonce == begin.nonce);
  EXPECT_TRUE(received.input_digest == begin.input_digest);

  EXPECT_EQ(host.frames_sent(), 1u);
  EXPECT_EQ(guest.frames_received(), 1u);
  EXPECT_EQ(guest.bytes_received(), sizeof(TaskBeginPayload));
}

TEST(VsockChannel, TaskResultAndAbortRoundTrip) {
  SocketPair pair;
  VsockChannel guest(pair.host_fd);
  VsockChannel host(pair.guest_fd);
  pair.host_fd = pair.guest_fd = -1;

  TaskResult result;
  result.nonce.fill(0x01);
  result.output_digest.fill(0x02);
  result.instance_binding.fill(0x03);
  result.payload_lib_digest.fill(0x04);
  result.vm_config_digest.fill(0x05);
  result.exit_code = 0;
  result.output_length = 12345;
  result.attestation_level = AttestationLevel::kInstanceBound;

  std::string error;
  EXPECT_TRUE(guest.SendTaskResult(result, &error)) << error;
  FrameHeader header{};
  TaskResult received;
  EXPECT_TRUE(host.ReceiveTaskResult(kTimeout, &received, &header, &error)) << error;
  EXPECT_EQ(received.output_length, 12345u);
  EXPECT_EQ(received.exit_code, 0);
  EXPECT_TRUE(received.attestation_level == AttestationLevel::kInstanceBound);
  EXPECT_TRUE(received.output_digest == result.output_digest);
  EXPECT_TRUE(received.instance_binding == result.instance_binding);
  EXPECT_TRUE(received.nonce == result.nonce);

  EXPECT_TRUE(guest.SendTaskAbort(AbortReason::kMeasurementRejected, "digest differs", &error))
      << error;
  TaskAbort abort;
  EXPECT_TRUE(host.ReceiveTaskAbort(kTimeout, &abort, &error)) << error;
  EXPECT_TRUE(abort.reason == AbortReason::kMeasurementRejected);
  EXPECT_EQ(abort.detail, "digest differs");
}

TEST(VsockChannel, EmptyFrameRoundTrip) {
  SocketPair pair;
  VsockChannel sender(pair.host_fd);
  VsockChannel receiver(pair.guest_fd);
  pair.host_fd = pair.guest_fd = -1;

  std::string error;
  EXPECT_TRUE(sender.SendFrame(FrameType::kTaskInputEnd, nullptr, 0, &error)) << error;
  FrameHeader header{};
  std::vector<uint8_t> payload;
  EXPECT_TRUE(receiver.ReceiveFrame(kTimeout, &header, &payload, &error)) << error;
  EXPECT_EQ(header.type, static_cast<uint32_t>(FrameType::kTaskInputEnd));
  EXPECT_EQ(payload.size(), 0u);
  EXPECT_EQ(receiver.bytes_received(), 0u);
}

// ---------------------------------------------------------------------------
// A frame split across many reads
// ---------------------------------------------------------------------------

TEST(VsockChannel, ReassemblesAFrameTrickledOneByteAtATime) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;

  const std::vector<uint8_t> payload = Payload(5000, 0x42);
  const std::vector<uint8_t> frame = Frame(FrameType::kTaskInput, payload.data(), payload.size());

  // One byte per send, with a delay, so that every read in ReadExact returns less
  // than it asked for. This is the path that a naive implementation gets wrong by
  // assuming recv() fills the buffer.
  std::thread writer([fd = pair.guest_fd, frame]() {
    for (const uint8_t byte : frame) {
      ssize_t written;
      do {
        written = ::send(fd, &byte, 1, MSG_NOSIGNAL);
      } while (written < 0 && errno == EINTR);
      ::usleep(30);
    }
    ::close(fd);
  });
  pair.guest_fd = -1;

  FrameHeader header{};
  std::vector<uint8_t> received;
  std::string error;
  EXPECT_TRUE(host.ReceiveFrame(std::chrono::milliseconds(60000), &header, &received, &error))
      << error;
  EXPECT_TRUE(received == payload);
  writer.join();
}

// ---------------------------------------------------------------------------
// Corruption and truncation
// ---------------------------------------------------------------------------

TEST(VsockChannel, DetectsACorruptedPayloadByte) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;

  const std::vector<uint8_t> payload = Payload(64, 0x11);
  std::vector<uint8_t> frame = Frame(FrameType::kTaskOutput, payload.data(), payload.size());
  frame[kFrameHeaderSize + 10] ^= 0xff;
  EXPECT_TRUE(pair.Inject(frame.data(), frame.size()));
  close(pair.guest_fd);
  pair.guest_fd = -1;

  FrameHeader header{};
  std::vector<uint8_t> received;
  std::string error;
  EXPECT_FALSE(host.ReceiveFrame(kTimeout, &header, &received, &error));
  EXPECT_EQ(error, VsockChannel::kErrorDigestMismatch);
  // A rejected frame must not leave half-decoded bytes behind for a caller to
  // mistake for output.
  EXPECT_TRUE(received.empty());
}

TEST(VsockChannel, RejectsABadMagic) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;

  std::vector<uint8_t> frame = Frame(FrameType::kTaskOutput, "x", 1);
  frame[0] ^= 0xff;
  EXPECT_TRUE(pair.Inject(frame.data(), frame.size()));

  FrameHeader header{};
  std::vector<uint8_t> received;
  std::string error;
  EXPECT_FALSE(host.ReceiveFrame(kTimeout, &header, &received, &error));
  EXPECT_EQ(error.find("frame header rejected"), 0u) << error;
}

TEST(VsockChannel, RejectsATruncatedFrame) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;

  // The header declares 4096 bytes and only 100 arrive before the peer hangs up.
  const std::vector<uint8_t> payload = Payload(4096, 0x77);
  const std::vector<uint8_t> frame = Frame(FrameType::kTaskOutput, payload.data(), payload.size());
  EXPECT_TRUE(pair.Inject(frame.data(), kFrameHeaderSize + 100));
  close(pair.guest_fd);
  pair.guest_fd = -1;

  FrameHeader header{};
  std::vector<uint8_t> received;
  std::string error;
  EXPECT_FALSE(host.ReceiveFrame(kTimeout, &header, &received, &error));
  EXPECT_TRUE(VsockChannel::IsPeerClosed(error)) << error;
}

TEST(VsockChannel, RejectsAPayloadPassedWhereAFrameWasExpected) {
  // SendEncodedFrame validates before writing, so a caller that confuses a
  // payload buffer with an encoded frame gets an error here rather than a digest
  // mismatch on the far side. EncodeTaskBegin and friends return COMPLETE frames
  // while SendFrame takes a payload, which is exactly the confusion this closes.
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;

  const std::vector<uint8_t> not_a_frame = Payload(64, 0x5a);
  std::string error;
  EXPECT_FALSE(host.SendEncodedFrame(not_a_frame, &error));
  EXPECT_NE(error.find("not self-consistent"), std::string::npos) << error;

  // The channel must still be usable, and must not have put a partial frame on
  // the wire: a rejected write that leaked bytes would desynchronise the stream.
  EXPECT_TRUE(host.SendFrame(FrameType::kTaskInput, not_a_frame, &error)) << error;
  EXPECT_EQ(host.frames_sent(), 1u);

  VsockChannel guest(pair.guest_fd);
  pair.guest_fd = -1;
  FrameHeader header{};
  std::vector<uint8_t> received;
  EXPECT_TRUE(guest.ReceiveFrame(kTimeout, &header, &received, &error)) << error;
  EXPECT_TRUE(received == not_a_frame);
}

// ---------------------------------------------------------------------------
// Peer state
// ---------------------------------------------------------------------------

TEST(VsockChannel, ReportsACleanPeerClose) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;
  close(pair.guest_fd);
  pair.guest_fd = -1;

  FrameHeader header{};
  std::vector<uint8_t> payload;
  std::string error;
  EXPECT_FALSE(host.ReceiveFrame(kTimeout, &header, &payload, &error));
  EXPECT_TRUE(VsockChannel::IsPeerClosed(error)) << error;
  EXPECT_FALSE(VsockChannel::IsTimeout(error));
}

TEST(VsockChannel, TimesOutOnASilentPeer) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;

  FrameHeader header{};
  std::vector<uint8_t> payload;
  std::string error;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(host.ReceiveFrame(std::chrono::milliseconds(200), &header, &payload, &error));
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
  EXPECT_TRUE(VsockChannel::IsTimeout(error)) << error;
  // It must actually wait. Returning immediately would look like a timeout to the
  // caller and spin the task loop.
  EXPECT_GE(elapsed, 150);
  EXPECT_LT(elapsed, 5000);
}

TEST(VsockChannel, WaitForReadableAnswersBothWays) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;

  bool readable = true;
  std::string error;
  EXPECT_TRUE(host.WaitForReadable(std::chrono::milliseconds(100), &readable, &error));
  EXPECT_FALSE(readable);

  EXPECT_TRUE(pair.Inject("q", 1));
  EXPECT_TRUE(host.WaitForReadable(kTimeout, &readable, &error)) << error;
  EXPECT_TRUE(readable);

  // A hangup counts as readable, so that the following read reports the close
  // instead of blocking on a descriptor that will never deliver.
  close(pair.guest_fd);
  pair.guest_fd = -1;
  EXPECT_TRUE(host.WaitForReadable(kTimeout, &readable, &error));
  EXPECT_TRUE(readable);
}

// ---------------------------------------------------------------------------
// Denial-of-service ceilings
// ---------------------------------------------------------------------------

TEST(VsockChannel, EnforcesTheReceiveBudget) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;
  host.SetReceiveBudget(1024);

  const std::vector<uint8_t> payload = Payload(2048, 0x33);
  const std::vector<uint8_t> frame = Frame(FrameType::kTaskOutput, payload.data(), payload.size());
  EXPECT_TRUE(pair.Inject(frame.data(), frame.size()));

  FrameHeader header{};
  std::vector<uint8_t> received;
  std::string error;
  EXPECT_FALSE(host.ReceiveFrame(kTimeout, &header, &received, &error));
  EXPECT_EQ(error, VsockChannel::kErrorBudgetExceeded);
  // The bytes were never accumulated, which is the whole point of the budget:
  // the cost of a hostile guest is bounded before the allocation happens.
  EXPECT_EQ(host.bytes_received(), 0u);
  EXPECT_EQ(host.receive_budget_remaining(), 1024u);
}

TEST(VsockChannel, EnforcesTheFrameLimit) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;
  host.SetMaxFrames(2);

  const std::vector<uint8_t> frame = Frame(FrameType::kTaskOutput, "z", 1);
  EXPECT_TRUE(pair.Inject(frame.data(), frame.size()));
  EXPECT_TRUE(pair.Inject(frame.data(), frame.size()));
  EXPECT_TRUE(pair.Inject(frame.data(), frame.size()));

  FrameHeader header{};
  std::vector<uint8_t> received;
  std::string error;
  EXPECT_TRUE(host.ReceiveFrame(kTimeout, &header, &received, &error)) << error;
  EXPECT_TRUE(host.ReceiveFrame(kTimeout, &header, &received, &error)) << error;
  EXPECT_FALSE(host.ReceiveFrame(kTimeout, &header, &received, &error));
  EXPECT_EQ(error, VsockChannel::kErrorFrameLimit);
}

TEST(VsockChannel, AcceptsExactlyTheBudget) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  pair.host_fd = -1;
  host.SetReceiveBudget(64);

  const std::vector<uint8_t> payload = Payload(64, 0x21);
  const std::vector<uint8_t> frame = Frame(FrameType::kTaskOutput, payload.data(), payload.size());
  EXPECT_TRUE(pair.Inject(frame.data(), frame.size()));

  FrameHeader header{};
  std::vector<uint8_t> received;
  std::string error;
  EXPECT_TRUE(host.ReceiveFrame(kTimeout, &header, &received, &error)) << error;
  EXPECT_EQ(host.receive_budget_remaining(), 0u);
}

// ---------------------------------------------------------------------------
// Frame type checking
// ---------------------------------------------------------------------------

TEST(VsockChannel, ReceiveTypedRefusesTheWrongFrameType) {
  SocketPair pair;
  VsockChannel host(pair.host_fd);
  VsockChannel guest(pair.guest_fd);
  pair.host_fd = pair.guest_fd = -1;

  GuestHello hello;
  hello.payload_lib_digest.fill(0x11);
  hello.vm_config_digest.fill(0x22);
  hello.apk_contents_digest.fill(0x33);
  std::string error;
  EXPECT_TRUE(host.SendGuestHello(hello, &error)) << error;

  TaskBegin begin;
  FrameHeader header{};
  EXPECT_FALSE(guest.ReceiveTaskBegin(kTimeout, &begin, &header, &error));
  EXPECT_EQ(error.find(VsockChannel::kErrorUnexpectedFrameType), 0u) << error;
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

TEST(VsockChannel, MoveTransfersOwnershipExactlyOnce) {
  SocketPair pair;
  std::string error;
  {
    VsockChannel first(pair.host_fd);
    pair.host_fd = -1;
    VsockChannel second(std::move(first));
    EXPECT_FALSE(first.IsOpen());
    EXPECT_TRUE(second.IsOpen());
    EXPECT_TRUE(second.SendFrame(FrameType::kTaskInputEnd, nullptr, 0, &error)) << error;
    // |second| closes the descriptor here; |first| must not close it again.
  }

  VsockChannel guest(pair.guest_fd);
  pair.guest_fd = -1;
  FrameHeader header{};
  std::vector<uint8_t> payload;
  EXPECT_TRUE(guest.ReceiveFrame(kTimeout, &header, &payload, &error)) << error;
  EXPECT_EQ(header.type, static_cast<uint32_t>(FrameType::kTaskInputEnd));
}

TEST(VsockChannel, ReleaseFdHandsOwnershipBack) {
  SocketPair pair;
  const int original = pair.host_fd;
  {
    VsockChannel channel(pair.host_fd);
    pair.host_fd = -1;
    EXPECT_EQ(channel.ReleaseFd(), original);
    EXPECT_FALSE(channel.IsOpen());
    EXPECT_EQ(channel.ReleaseFd(), -1);
  }
  // Still open, because ReleaseFd does not close. The test fixture owns it.
  std::string error;
  EXPECT_TRUE(pair.Inject("x", 1));
  pair.host_fd = original;
}

TEST(VsockChannel, RefusesToOperateWhenNotOpen) {
  VsockChannel closed;
  std::string error;
  EXPECT_FALSE(closed.SendFrame(FrameType::kTaskBegin, "x", 1, &error));
  EXPECT_EQ(error, VsockChannel::kErrorNotOpen);

  FrameHeader header{};
  std::vector<uint8_t> payload;
  EXPECT_FALSE(closed.ReceiveFrame(kTimeout, &header, &payload, &error));
  EXPECT_EQ(error, VsockChannel::kErrorNotOpen);

  bool readable = true;
  EXPECT_FALSE(closed.WaitForReadable(kTimeout, &readable, &error));
  EXPECT_EQ(error, VsockChannel::kErrorNotOpen);

  EXPECT_FALSE(closed.AdoptFd(-1));
  EXPECT_FALSE(closed.IsOpen());
}

TEST(VsockChannel, AdoptFdReplacesThePreviousDescriptor) {
  SocketPair pair;
  VsockChannel channel(pair.host_fd);
  pair.host_fd = -1;
  // Adopting a second descriptor must close the first, or the socketpair stays
  // open and the peer never sees the hangup.
  EXPECT_TRUE(channel.AdoptFd(pair.guest_fd));
  pair.guest_fd = -1;
  EXPECT_TRUE(channel.IsOpen());
}
