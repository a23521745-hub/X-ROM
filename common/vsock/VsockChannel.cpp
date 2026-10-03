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

#include "VsockChannel.h"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <utility>

namespace xrom::avf {
namespace {

using ::xrom::avf::vsock::FrameHeader;
using ::xrom::avf::vsock::AbortReason;
using ::xrom::avf::vsock::FrameType;
using ::xrom::avf::vsock::kFrameHeaderSize;

std::string ErrnoString(const char* what) {
  return std::string(what) + ": " + strerror(errno);
}

// poll() takes an int millisecond count. Anything above INT_MAX or below zero is
// clamped rather than wrapped: a wrapped negative timeout means "return
// immediately", which would look like a spurious peer-closed error.
int ToPollTimeout(std::chrono::milliseconds timeout) {
  if (timeout.count() <= 0) {
    return 0;
  }
  if (timeout.count() > std::numeric_limits<int>::max()) {
    return std::numeric_limits<int>::max();
  }
  return static_cast<int>(timeout.count());
}

}  // namespace

VsockChannel::VsockChannel(int fd) { fd_ = fd; }

VsockChannel::~VsockChannel() { Close(); }

VsockChannel::VsockChannel(VsockChannel&& other) noexcept
    : fd_(other.fd_),
      frames_sent_(other.frames_sent_),
      frames_received_(other.frames_received_),
      bytes_received_(other.bytes_received_),
      receive_budget_bytes_(other.receive_budget_bytes_),
      max_frames_(other.max_frames_) {
  other.fd_ = -1;
}

VsockChannel& VsockChannel::operator=(VsockChannel&& other) noexcept {
  if (this != &other) {
    Close();
    fd_ = other.fd_;
    frames_sent_ = other.frames_sent_;
    frames_received_ = other.frames_received_;
    bytes_received_ = other.bytes_received_;
    receive_budget_bytes_ = other.receive_budget_bytes_;
    max_frames_ = other.max_frames_;
    other.fd_ = -1;
  }
  return *this;
}

bool VsockChannel::AdoptFd(int fd) {
  Close();
  if (fd < 0) {
    return false;
  }
  fd_ = fd;
  return true;
}

int VsockChannel::ReleaseFd() {
  const int fd = fd_;
  fd_ = -1;
  return fd;
}

void VsockChannel::Close() {
  if (fd_ >= 0) {
    // shutdown() first so that a peer blocked in write() sees the close instead
    // of discovering it on its next send. A half-open vsock that nobody notices
    // is how a stuck guest turns into a stuck daemon.
    ::shutdown(fd_, SHUT_RDWR);
    ::close(fd_);
    fd_ = -1;
  }
}

uint64_t VsockChannel::receive_budget_remaining() const {
  return bytes_received_ >= receive_budget_bytes_ ? 0 : receive_budget_bytes_ - bytes_received_;
}

bool VsockChannel::Poll(short events, std::chrono::milliseconds timeout, int* revents,
                        std::string* error) {
  if (!IsOpen()) {
    *error = kErrorNotOpen;
    return false;
  }
  struct pollfd pfd {};
  pfd.fd = fd_;
  pfd.events = events;
  pfd.revents = 0;

  for (;;) {
    const int result = ::poll(&pfd, 1, ToPollTimeout(timeout));
    if (result > 0) {
      *revents = pfd.revents;
      return true;
    }
    if (result == 0) {
      *error = kErrorTimedOut;
      return false;
    }
    if (errno == EINTR) {
      // Restarting after a signal is correct here; the caller's timeout is a wall
      // clock budget, and a daemon that receives SIGCHLD from the VM lifecycle
      // must not turn that into a spurious timeout.
      continue;
    }
    *error = ErrnoString("poll failed");
    return false;
  }
}

bool VsockChannel::WriteAll(const uint8_t* data, size_t length, std::string* error) {
  if (!IsOpen()) {
    *error = kErrorNotOpen;
    return false;
  }
  size_t written = 0;
  while (written < length) {
    const ssize_t result = ::send(fd_, data + written, length - written, MSG_NOSIGNAL);
    if (result > 0) {
      written += static_cast<size_t>(result);
      continue;
    }
    if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      int revents = 0;
      // No timeout on the write side: the host is the one holding the data and
      // the task deadline is enforced by IsolationService, not here. Waiting for
      // the buffer to drain is the only way to keep a frame from being split.
      if (!Poll(POLLOUT, std::chrono::milliseconds(-1), &revents, error)) {
        return false;
      }
      if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
        *error = kErrorClosedByPeer;
        return false;
      }
      continue;
    }
    if (result == 0) {
      *error = kErrorPeerClosed;
      return false;
    }
    *error = ErrnoString("send failed");
    return false;
  }
  return true;
}

bool VsockChannel::ReadExact(uint8_t* out, size_t length, std::chrono::milliseconds timeout,
                             std::string* error) {
  if (!IsOpen()) {
    *error = kErrorNotOpen;
    return false;
  }
  if (length == 0) {
    return true;
  }

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  size_t received = 0;
  while (received < length) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    int revents = 0;
    if (!Poll(POLLIN, remaining, &revents, error)) {
      return false;
    }
    if (revents & POLLIN) {
      const ssize_t result = ::recv(fd_, out + received, length - received, 0);
      if (result > 0) {
        received += static_cast<size_t>(result);
        continue;
      }
      if (result == 0) {
        *error = kErrorPeerClosed;
        return false;
      }
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      *error = ErrnoString("recv failed");
      return false;
    }
    if (revents & (POLLERR | POLLNVAL)) {
      *error = kErrorClosedByPeer;
      return false;
    }
    if (revents & POLLHUP) {
      // A hangup with no data pending is a clean close from the guest's side.
      *error = kErrorPeerClosed;
      return false;
    }
    *error = kErrorTimedOut;
    return false;
  }
  return true;
}

bool VsockChannel::WaitForReadable(std::chrono::milliseconds timeout, bool* readable,
                                   std::string* error) {
  if (readable == nullptr) {
    *error = "readable output pointer is null";
    return false;
  }
  *readable = false;
  int revents = 0;
  if (!Poll(POLLIN, timeout, &revents, error)) {
    // A timeout is a legitimate answer to "is anything there yet?", not a fault.
    return IsTimeout(*error);
  }
  if (revents & (POLLERR | POLLNVAL)) {
    *error = kErrorClosedByPeer;
    return false;
  }
  *readable = (revents & (POLLIN | POLLHUP)) != 0;
  return true;
}

bool VsockChannel::SendFrame(FrameType type, const void* payload, size_t payload_length,
                             std::string* error) {
  if (error == nullptr) {
    return false;
  }
  if (!IsOpen()) {
    *error = kErrorNotOpen;
    return false;
  }

  std::vector<uint8_t> frame;
  if (!vsock::EncodeFrame(type, payload, payload_length, &frame)) {
    *error = "the frame could not be encoded (type, length or payload rejected)";
    return false;
  }
  // One write per frame, with no interleaving possible: EncodeFrame has already
  // built the header and payload into a single buffer, so a partially sent frame
  // can only mean a failure, never a stream desynchronisation.
  if (!WriteAll(frame.data(), frame.size(), error)) {
    return false;
  }
  ++frames_sent_;
  return true;
}

bool VsockChannel::SendFrame(FrameType type, const std::vector<uint8_t>& payload,
                             std::string* error) {
  return SendFrame(type, payload.data(), payload.size(), error);
}

bool VsockChannel::SendEncodedFrame(const std::vector<uint8_t>& frame, std::string* error) {
  if (error == nullptr) {
    return false;
  }
  if (!IsOpen()) {
    *error = kErrorNotOpen;
    return false;
  }
  // Validated before it goes on the wire, so a locally corrupted frame is a
  // reported error here rather than a digest mismatch on the far side.
  FrameHeader header{};
  const uint8_t* payload = nullptr;
  size_t payload_size = 0;
  if (!vsock::DecodeFrame(frame.data(), frame.size(), &header, &payload, &payload_size)) {
    *error = "the encoded frame is not self-consistent";
    return false;
  }
  if (!WriteAll(frame.data(), frame.size(), error)) {
    return false;
  }
  ++frames_sent_;
  return true;
}

bool VsockChannel::SendGuestHello(const vsock::GuestHello& hello, std::string* error) {
  std::vector<uint8_t> frame;
  if (!vsock::EncodeGuestHello(hello, &frame)) {
    if (error != nullptr) {
      *error = kErrorDecodeFailed;
    }
    return false;
  }
  return SendEncodedFrame(frame, error);
}

bool VsockChannel::SendTaskBegin(const vsock::TaskBegin& begin, std::string* error) {
  std::vector<uint8_t> frame;
  if (!vsock::EncodeTaskBegin(begin, &frame)) {
    if (error != nullptr) {
      *error = kErrorDecodeFailed;
    }
    return false;
  }
  return SendEncodedFrame(frame, error);
}

bool VsockChannel::SendTaskResult(const vsock::TaskResult& result, std::string* error) {
  std::vector<uint8_t> frame;
  if (!vsock::EncodeTaskResult(result, &frame)) {
    if (error != nullptr) {
      *error = kErrorDecodeFailed;
    }
    return false;
  }
  return SendEncodedFrame(frame, error);
}

bool VsockChannel::SendTaskAbort(AbortReason reason, const std::string& detail,
                                 std::string* error) {
  vsock::TaskAbort abort;
  abort.reason = reason;
  abort.detail = detail;
  std::vector<uint8_t> frame;
  if (!vsock::EncodeTaskAbort(abort, &frame)) {
    if (error != nullptr) {
      *error = kErrorDecodeFailed;
    }
    return false;
  }
  return SendEncodedFrame(frame, error);
}

bool VsockChannel::ReceiveTyped(FrameType expected, std::chrono::milliseconds timeout,
                                FrameHeader* header, std::vector<uint8_t>* payload,
                                std::string* error) {
  if (!ReceiveFrame(timeout, header, payload, error)) {
    return false;
  }
  if (header->type != static_cast<uint32_t>(expected)) {
    *error = std::string(kErrorUnexpectedFrameType) + ": got " +
             (vsock::IsKnownFrameType(header->type)
                  ? vsock::FrameTypeName(static_cast<FrameType>(header->type))
                  : "an unknown type") +
             ", expected " + vsock::FrameTypeName(expected);
    payload->clear();
    return false;
  }
  return true;
}

bool VsockChannel::ReceiveGuestHello(std::chrono::milliseconds timeout, vsock::GuestHello* out,
                                     FrameHeader* header, std::string* error) {
  std::vector<uint8_t> payload;
  if (!ReceiveTyped(FrameType::kGuestHello, timeout, header, &payload, error)) {
    return false;
  }
  if (!vsock::DecodeGuestHello(payload.data(), payload.size(), out)) {
    *error = kErrorDecodeFailed;
    return false;
  }
  return true;
}

bool VsockChannel::ReceiveTaskBegin(std::chrono::milliseconds timeout, vsock::TaskBegin* out,
                                    FrameHeader* header, std::string* error) {
  std::vector<uint8_t> payload;
  if (!ReceiveTyped(FrameType::kTaskBegin, timeout, header, &payload, error)) {
    return false;
  }
  if (!vsock::DecodeTaskBegin(payload.data(), payload.size(), out)) {
    *error = kErrorDecodeFailed;
    return false;
  }
  return true;
}

bool VsockChannel::ReceiveTaskResult(std::chrono::milliseconds timeout, vsock::TaskResult* out,
                                     FrameHeader* header, std::string* error) {
  std::vector<uint8_t> payload;
  if (!ReceiveTyped(FrameType::kTaskResult, timeout, header, &payload, error)) {
    return false;
  }
  if (!vsock::DecodeTaskResult(payload.data(), payload.size(), out)) {
    *error = kErrorDecodeFailed;
    return false;
  }
  return true;
}

bool VsockChannel::ReceiveTaskAbort(std::chrono::milliseconds timeout, vsock::TaskAbort* out,
                                    std::string* error) {
  FrameHeader header{};
  std::vector<uint8_t> payload;
  if (!ReceiveTyped(FrameType::kTaskAbort, timeout, &header, &payload, error)) {
    return false;
  }
  if (!vsock::DecodeTaskAbort(payload.data(), payload.size(), out)) {
    *error = kErrorDecodeFailed;
    return false;
  }
  return true;
}

bool VsockChannel::ReceiveFrame(std::chrono::milliseconds timeout, FrameHeader* header,
                                std::vector<uint8_t>* payload, std::string* error) {
  if (header == nullptr || payload == nullptr || error == nullptr) {
    return false;
  }
  if (!IsOpen()) {
    *error = kErrorNotOpen;
    return false;
  }
  if (frames_received_ >= max_frames_) {
    *error = kErrorFrameLimit;
    return false;
  }

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  const auto remaining = [&deadline]() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
  };

  // The header is a fixed size and read first: it is what tells us how much more
  // to accept, so the allocation for the payload is always bounded by a value we
  // have already validated.
  std::array<uint8_t, kFrameHeaderSize> header_bytes{};
  if (!ReadExact(header_bytes.data(), header_bytes.size(), remaining(), error)) {
    return false;
  }
  if (!vsock::DecodeHeader(header_bytes.data(), header_bytes.size(), header)) {
    *error = "frame header rejected (bad magic, version, type or declared length)";
    return false;
  }

  if (header->payload_length > 0) {
    if (static_cast<uint64_t>(header->payload_length) > receive_budget_remaining()) {
      *error = kErrorBudgetExceeded;
      return false;
    }
    payload->resize(header->payload_length);
    if (!ReadExact(payload->data(), payload->size(), remaining(), error)) {
      payload->clear();
      return false;
    }
  } else {
    payload->clear();
  }

  if (!vsock::VerifyPayloadDigest(*header, payload->data(), payload->size())) {
    *error = kErrorDigestMismatch;
    payload->clear();
    return false;
  }

  ++frames_received_;
  bytes_received_ += payload->size();
  return true;
}

}  // namespace xrom::avf
