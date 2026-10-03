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

#ifndef XROM_AVF_VSOCK_CHANNEL_H_
#define XROM_AVF_VSOCK_CHANNEL_H_

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "VsockProtocol.h"

namespace xrom::avf {

// ---------------------------------------------------------------------------
// A framed, bounded, blocking-with-timeout byte pipe over one connected vsock.
//
// WHY THIS CLASS HAS NO BINDER, NO LIBBASE AND NO LOGGING
// ------------------------------------------------------
// It is the host half of the data plane and its only job is turning a file
// descriptor into whole, digest-verified frames. Everything that decides *which*
// descriptor it gets (IVirtualMachine::connectVsock, SELinux, the VM lifecycle)
// lives outside it. Keeping it dependency-free means the transport itself — the
// part where a bug becomes a memory-safety problem or a hang — is testable on a
// build host over a socketpair, with no device, no APEX and no hypervisor. See
// tests/VsockChannel_test.cpp.
//
// WHY IT IS NOT THE PAYLOAD'S ONLY ROUTE BY CONSTRUCTION, AND WHAT MAKES IT SO
// ---------------------------------------------------------------------------
// Nothing in this file restricts the guest. The vsock-only property is enforced
// in three places that do not depend on the payload cooperating:
//   1. sepolicy/microdroid/xrom_microdroid_hardening.te — neverallow rules on
//      packet_socket, rawip_socket and every netlink family for
//      microdroid_payload. These are classes AVF's network permission never
//      grants, so the rules hold whether or not RELEASE_AVF_ENABLE_NETWORK is on.
//   2. device/x1/microdroid/xvault/assets/vm_config.json — no "network": true,
//      so microdroid gives the payload no net device at all. There is nothing to
//      connect to.
//   3. The Microdroid linker namespace exposes the NDK library set, so the
//      payload has no getaddrinfo, no libssl and no HTTP client to reach for.
// vsock is therefore the only socket family the payload can open, and this class
// plus VsockProtocol.h is the only thing on the other end of it.
// ---------------------------------------------------------------------------

// One connected channel. Move-only: two objects closing the same fd is the sort
// of bug that turns into a use-after-free in the VM lifecycle.
class VsockChannel {
 public:
  VsockChannel() = default;
  explicit VsockChannel(int fd);
  ~VsockChannel();

  VsockChannel(const VsockChannel&) = delete;
  VsockChannel& operator=(const VsockChannel&) = delete;
  VsockChannel(VsockChannel&& other) noexcept;
  VsockChannel& operator=(VsockChannel&& other) noexcept;

  // Takes ownership of an already-connected descriptor. Closes any previous one.
  bool AdoptFd(int fd);

  // Hands ownership back without closing. -1 if the channel was not open.
  int ReleaseFd();

  void Close();
  bool IsOpen() const { return fd_ >= 0; }

  // Writes one complete frame: EncodeFrame computes the payload digest, then the
  // header and payload are written without interruption from any other thread.
  bool SendFrame(vsock::FrameType type, const void* payload, size_t payload_length,
                 std::string* error);
  bool SendFrame(vsock::FrameType type, const std::vector<uint8_t>& payload, std::string* error);

  // Writes an already-encoded frame, header and all.
  bool SendEncodedFrame(const std::vector<uint8_t>& frame, std::string* error);

  // --- typed senders and receivers ---------------------------------------
  //
  // EncodeTaskBegin and friends return a COMPLETE frame, not a payload, and
  // SendFrame takes a payload. Passing one to the other silently nests a frame
  // inside a frame — it round-trips, the digest verifies, and the far end then
  // fails to decode the inner bytes, which reads like a guest bug rather than a
  // host one. These wrappers make that mistake unrepresentable: each one owns
  // both the encode and the write, and each receiver also checks the frame type.
  //
  // Both sides of the channel use this class — the host over
  // IVirtualMachine::connectVsock, the guest over accept(AF_VSOCK) — so the
  // typed helpers are the whole API either end needs.
  bool SendGuestHello(const vsock::GuestHello& hello, std::string* error);
  bool SendTaskBegin(const vsock::TaskBegin& begin, std::string* error);
  bool SendTaskResult(const vsock::TaskResult& result, std::string* error);
  bool SendTaskAbort(vsock::AbortReason reason, const std::string& detail, std::string* error);

  // ReceiveFrame plus a frame-type check.
  bool ReceiveTyped(vsock::FrameType expected, std::chrono::milliseconds timeout,
                    vsock::FrameHeader* header, std::vector<uint8_t>* payload,
                    std::string* error);
  bool ReceiveGuestHello(std::chrono::milliseconds timeout, vsock::GuestHello* out,
                         vsock::FrameHeader* header, std::string* error);
  bool ReceiveTaskBegin(std::chrono::milliseconds timeout, vsock::TaskBegin* out,
                        vsock::FrameHeader* header, std::string* error);
  bool ReceiveTaskResult(std::chrono::milliseconds timeout, vsock::TaskResult* out,
                         vsock::FrameHeader* header, std::string* error);
  bool ReceiveTaskAbort(std::chrono::milliseconds timeout, vsock::TaskAbort* out,
                        std::string* error);

  // Reads exactly one frame: a header, then the payload it declares, then a
  // digest check over the bytes actually received. A frame whose digest does not
  // match is an error, not a dropped frame — a corrupted frame means the channel
  // is not trustworthy and the caller should abort the task.
  //
  // Returns false with error == kErrorPeerClosed when the guest hung up cleanly.
  bool ReceiveFrame(std::chrono::milliseconds timeout, vsock::FrameHeader* header,
                    std::vector<uint8_t>* payload, std::string* error);

  // Blocks until at least one byte is readable, the peer hangs up, or the timeout
  // expires. Used to wait for kGuestHello without committing to a read.
  bool WaitForReadable(std::chrono::milliseconds timeout, bool* readable, std::string* error);

  // --- denial-of-service ceilings ------------------------------------------
  //
  // A compromised or merely buggy guest can send anything. Each of these turns
  // "anything" into "an error at a bounded cost":
  //
  //   receive budget   total payload bytes accepted over the channel's lifetime.
  //                    Input is bounded by TaskBegin, but output frames are the
  //                    guest's to send, so the ceiling here is what stops a guest
  //                    from streaming until the host's memory is gone.
  //   frame ceiling    from VsockProtocol.h; enforced by DecodeHeader.
  //   frame counter    a guest sending millions of tiny frames pays a syscall
  //                    each, but so does the host; the counter makes that a
  //                    bounded exchange rather than an open-ended one.
  void SetReceiveBudget(uint64_t bytes) { receive_budget_bytes_ = bytes; }
  void SetMaxFrames(uint64_t frames) { max_frames_ = frames; }

  uint64_t frames_sent() const { return frames_sent_; }
  uint64_t frames_received() const { return frames_received_; }
  uint64_t bytes_received() const { return bytes_received_; }
  uint64_t receive_budget_remaining() const;

  // Distinguishes "the guest hung up" from "the guest is broken", which decides
  // whether IsolationService reports kVmTerminated or kProtocolError.
  static constexpr char kErrorPeerClosed[] = "peer closed the channel";
  static constexpr char kErrorTimedOut[] = "timed out";
  static constexpr char kErrorNotOpen[] = "channel is not open";
  static constexpr char kErrorBudgetExceeded[] = "receive budget exceeded";
  static constexpr char kErrorFrameLimit[] = "frame limit exceeded";
  static constexpr char kErrorDigestMismatch[] = "frame payload digest mismatch";
  static constexpr char kErrorUnexpectedFrameType[] = "unexpected frame type";
  static constexpr char kErrorDecodeFailed[] = "frame payload could not be decoded";
  static constexpr char kErrorClosedByPeer[] = "channel closed by peer (POLLHUP/POLLERR)";

  static bool IsPeerClosed(const std::string& error) { return error == kErrorPeerClosed; }
  static bool IsTimeout(const std::string& error) { return error == kErrorTimedOut; }

 private:
  bool WriteAll(const uint8_t* data, size_t length, std::string* error);
  bool ReadExact(uint8_t* out, size_t length, std::chrono::milliseconds timeout,
                 std::string* error);
  bool Poll(short events, std::chrono::milliseconds timeout, int* revents, std::string* error);

  int fd_ = -1;
  uint64_t frames_sent_ = 0;
  uint64_t frames_received_ = 0;
  uint64_t bytes_received_ = 0;
  // Default 64 MiB: four times kMaxOutputBytes, so a legitimate task that sends
  // its output in several frames is never truncated by the ceiling.
  uint64_t receive_budget_bytes_ = 64u * 1024 * 1024;
  uint64_t max_frames_ = 4096;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_VSOCK_CHANNEL_H_
