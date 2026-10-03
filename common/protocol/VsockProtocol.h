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

#ifndef XROM_COMMON_PROTOCOL_VSOCK_PROTOCOL_H_
#define XROM_COMMON_PROTOCOL_VSOCK_PROTOCOL_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Sha256.h"

namespace xrom::avf::vsock {

// ---------------------------------------------------------------------------
// Host <-> guest wire protocol for X-ROM isolation tasks.
//
// Shared by the host daemon (services/avf/xrom_avfd) and the guest payload
// (device/x1/microdroid/xvault), which is why it lives in neither of them: a
// protocol that one side owns is a protocol the two sides will drift on.
//
// vsock is the only channel into a protected VM. There is no network, no shared
// filesystem and no binder. Each VM gets a 32-bit CID from
// virtualizationservice; the host reaches it through
// IVirtualMachine::connectVsock(port) and the guest listens with a plain
// AF_VSOCK socket.
//
// THE HANDSHAKE, AND WHY IT IS ORDERED THIS WAY
// ---------------------------------------------
//   guest -> host  kGuestHello   self-measurement of what is actually running
//   host  verifies it against the signed payload manifest, aborts on mismatch
//   host  -> guest kTaskBegin    nonce + expected input digest + task class
//   host  -> guest kTaskInput*   the input bytes
//   host  -> guest kTaskInputEnd
//   guest -> host  kTaskOutput*  the output bytes
//   guest -> host  kTaskResult   nonce echo + output digest + instance binding
//
// The guest measures itself BEFORE the host sends any input. Reversing that
// order would mean handing data to a VM that might not be the VM we pinned, and
// discovering the problem afterwards. Both sides may send kTaskAbort at any
// point.
//
// TRUST DIRECTION
// ---------------
// The host does not trust the guest's *claims*; it requires agreement between two
// independently produced measurements (its own pre-launch digest of the APK, and
// the guest's in-VM digest of the same artifacts). The guest does not trust the
// host either: it re-derives the input digest from the bytes it actually received
// and refuses to run on a mismatch, because a pVM's threat model puts the host
// outside the trusted base.
//
// ROBUSTNESS
// ----------
// Every frame is length-prefixed with a hard ceiling and carries a SHA-256 of its
// payload. A peer that streams unbounded data, sends a truncated frame, or claims
// a length it does not deliver is performing a resource-exhaustion attack, and
// under AVF's threat model the availability of the host is explicitly inside the
// attacker's control. So every decode is bounds-checked and every read is capped.
// ---------------------------------------------------------------------------

// Reserved CIDs from the virtio socket specification.
inline constexpr uint32_t kHostCid = 2;
inline constexpr uint32_t kLocalCid = 1;
inline constexpr uint32_t kAnyCid = 0xFFFFFFFFu;

// X-ROM ports, declared in one place so the two sides cannot drift.
// The guest listens on kPortTaskControl; kPortTaskData is reserved for a future
// bulk channel so that a large transfer cannot stall control messages.
inline constexpr int32_t kPortTaskControl = 7100;
inline constexpr int32_t kPortTaskData = 7101;

// "XROM" in ASCII, little-endian.
inline constexpr uint32_t kFrameMagic = 0x4D4F5258u;
inline constexpr uint32_t kProtocolVersion = 1;

inline constexpr size_t kFrameHeaderSize = 48;
inline constexpr size_t kNonceBytes = 32;

// Hard ceilings. Chosen so a fully populated frame fits comfortably inside the
// memory ceiling IsolationPolicy enforces on the VM.
inline constexpr uint32_t kMaxFramePayloadBytes = 4u * 1024 * 1024;
inline constexpr uint32_t kMaxInputBytes = 16u * 1024 * 1024;
inline constexpr uint32_t kMaxOutputBytes = 16u * 1024 * 1024;
inline constexpr size_t kTaskIdMaxLength = 64;
inline constexpr size_t kAbortDetailMaxLength = 64;

enum class FrameType : uint32_t {
  kGuestHello = 0,   // guest -> host: protocol version + self-measurement
  kTaskBegin = 1,    // host  -> guest: nonce, expected input digest, task class
  kTaskInput = 2,    // host  -> guest: input bytes
  kTaskInputEnd = 3, // host  -> guest: no more input
  kTaskOutput = 4,   // guest -> host: output bytes
  kTaskResult = 5,   // guest -> host: nonce echo, output digest, instance binding
  kTaskAbort = 6,    // either direction: tear down, do not retry
};

// What the result is backed by. Reported to the caller so that a consumer can
// tell "the measurement matched" from "the VM cryptographically attested to it".
// Never inferred: the guest states it and the host downgrades it, never upgrades.
enum class AttestationLevel : uint32_t {
  // Host-pinned digests and the guest's own self-measurement agree. This is what
  // pKVM + pvmfw + the signed manifest give you, and it is always available.
  kMeasurementOnly = 0,
  // Additionally bound to this VM instance through a key derived from
  // AVmPayload_getVmInstanceSecret(), which is not available to the host. The
  // host cannot verify the binding; what it buys is that a result frame is not
  // transferable between VM instances and the payload can detect replay across
  // boots.
  kInstanceBound = 1,
  // Additionally backed by AVmPayload_requestAttestation(): an RKP certificate
  // chain whose leaf carries the challenge and the payload's codeHash, plus an
  // ECDSA P-256 signature over the result made with a key only that pVM holds.
  // This is the level that proves origin to the host. Requires API level 35+,
  // the AVF remote-attestation release flag, RKP provisioning and network access
  // to the provisioning backend.
  kRemoteAttested = 2,
};

enum class AbortReason : uint32_t {
  kNone = 0,
  kInputDigestMismatch = 1,       // guest: the bytes received do not match kTaskBegin
  kSelfMeasurementMismatch = 2,   // guest: its own APK contents are not what it was built as
  kEnvironmentCheckFailed = 3,    // guest: SELinux permissive, running as root, ...
  kOutputTooLarge = 4,            // guest: result exceeds kMaxOutputBytes
  kProtocolError = 5,             // either: bad magic, version, type or length
  kMeasurementRejected = 6,       // host: kGuestHello disagreed with the signed manifest
  kTaskCancelled = 7,             // host: the caller cancelled or the daemon is shutting down
  kGuestInternalError = 8,        // guest: anything else
  kTaskClassNotAllowed = 9,       // guest: kTaskBegin named a class it does not serve
  kInputTooLarge = 10,            // guest: declared input exceeds the compiled ceiling
  kNoAuthorization = 11,          // guest: no kTaskBegin arrived before the timeout
};

// Fixed-size, little-endian, no padding. Both ends are compiled by the same
// build, but the layout is stated explicitly anyway so that a future guest
// written in Rust or Go has something concrete to match.
struct FrameHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t type;
  uint32_t payload_length;
  uint8_t payload_digest[32];
} __attribute__((packed));

struct GuestHelloPayload {
  uint32_t protocol_version;
  uint8_t payload_lib_digest[32];
  uint8_t vm_config_digest[32];
  uint8_t apk_contents_digest[32];
} __attribute__((packed));

struct TaskBeginPayload {
  uint8_t nonce[32];
  uint8_t input_digest[32];
  uint32_t task_class;
  uint32_t input_length;
  uint32_t authorization_level;
  char task_id[64];
} __attribute__((packed));

struct TaskResultPayload {
  uint8_t nonce[32];
  uint8_t output_digest[32];
  uint8_t instance_binding[32];
  uint8_t payload_lib_digest[32];
  uint8_t vm_config_digest[32];
  int32_t exit_code;
  uint32_t output_length;
  uint32_t attestation_level;
  uint32_t flags;
} __attribute__((packed));

struct TaskAbortPayload {
  uint32_t reason;
  char detail[64];
} __attribute__((packed));

static_assert(sizeof(FrameHeader) == 48, "FrameHeader must stay 48 bytes on the wire");
static_assert(sizeof(GuestHelloPayload) == 100, "GuestHelloPayload layout changed");
static_assert(sizeof(TaskBeginPayload) == 140, "TaskBeginPayload layout changed");
static_assert(sizeof(TaskResultPayload) == 176, "TaskResultPayload layout changed");
static_assert(sizeof(TaskAbortPayload) == 68, "TaskAbortPayload layout changed");
static_assert(alignof(FrameHeader) == 1, "FrameHeader must not be padded");

// Friendly forms. The wire structs above are POD for layout control; these are
// what the two sides actually pass around, with std::string instead of fixed
// char buffers and typed digests instead of byte arrays.
struct GuestHello {
  uint32_t protocol_version = kProtocolVersion;
  ::xrom::crypto::Sha256Digest payload_lib_digest{};
  ::xrom::crypto::Sha256Digest vm_config_digest{};
  ::xrom::crypto::Sha256Digest apk_contents_digest{};
};

struct TaskBegin {
  std::array<uint8_t, kNonceBytes> nonce{};
  ::xrom::crypto::Sha256Digest input_digest{};
  uint32_t task_class = 0;
  uint32_t input_length = 0;
  uint32_t authorization_level = 0;
  std::string task_id;
};

struct TaskResult {
  std::array<uint8_t, kNonceBytes> nonce{};
  ::xrom::crypto::Sha256Digest output_digest{};
  ::xrom::crypto::Sha256Digest instance_binding{};
  ::xrom::crypto::Sha256Digest payload_lib_digest{};
  ::xrom::crypto::Sha256Digest vm_config_digest{};
  int32_t exit_code = 0;
  uint32_t output_length = 0;
  AttestationLevel attestation_level = AttestationLevel::kMeasurementOnly;
  uint32_t flags = 0;
};

struct TaskAbort {
  AbortReason reason = AbortReason::kGuestInternalError;
  std::string detail;
};

// ---------------------------------------------------------------------------
// Codec. Every function is total: it returns false on any malformed input
// rather than reading past a buffer, and every encode validates its own output
// length so a bad struct cannot produce a frame the other side would reject.
//
// Plain C++ with no Android dependencies, so the same encode/decode pair is
// exercised by tests on a build host. A protocol whose only test is "it worked
// once against a real VM" is a protocol with an untested failure path.
// ---------------------------------------------------------------------------

bool EncodeHeader(FrameType type, uint32_t payload_length,
                  const ::xrom::crypto::Sha256Digest& payload_digest,
                  std::array<uint8_t, kFrameHeaderSize>* out);

// Validates magic, version, type and length against the ceilings above.
bool DecodeHeader(const uint8_t* data, size_t size, FrameHeader* out);

// Recomputes the payload digest and compares it with the header's. Used after a
// read completes, before the bytes are acted on.
bool VerifyPayloadDigest(const FrameHeader& header, const uint8_t* payload, size_t payload_size);

// Whole-buffer form: validates that |size| bytes contain one complete,
// self-consistent frame — a header whose declared payload actually fits inside
// the buffer, and a payload whose digest matches. Returns pointers into |data|
// instead of copying.
//
// DecodeHeader deliberately does NOT check that the payload fits, because a
// streaming reader parses the header before it knows how much more to read. Using
// DecodeHeader alone on a truncated buffer is the footgun this function closes.
bool DecodeFrame(const uint8_t* data, size_t size, FrameHeader* header,
                 const uint8_t** payload, size_t* payload_size);

bool EncodeFrame(FrameType type, const void* payload, size_t payload_length,
                 std::vector<uint8_t>* out);

bool EncodeGuestHello(const GuestHello& in, std::vector<uint8_t>* out);
bool DecodeGuestHello(const void* payload, size_t size, GuestHello* out);

bool EncodeTaskBegin(const TaskBegin& in, std::vector<uint8_t>* out);
bool DecodeTaskBegin(const void* payload, size_t size, TaskBegin* out);

bool EncodeTaskResult(const TaskResult& in, std::vector<uint8_t>* out);
bool DecodeTaskResult(const void* payload, size_t size, TaskResult* out);

bool EncodeTaskAbort(const TaskAbort& in, std::vector<uint8_t>* out);
bool DecodeTaskAbort(const void* payload, size_t size, TaskAbort* out);

bool IsKnownFrameType(uint32_t raw_type);

// True for every AbortReason this build knows how to interpret. Used by BOTH the
// encoder and the decoder, which is the point: a reason the encoder will send and
// the decoder will reject is a protocol that disagrees with itself, and adding an
// enumerator without updating one of the two is how that happens.
bool IsKnownAbortReason(AbortReason reason);

// The same check for the attestation level a result claims.
bool IsKnownAttestationLevel(AttestationLevel level);
const char* FrameTypeName(FrameType type);
const char* AbortReasonName(AbortReason reason);
const char* AttestationLevelName(AttestationLevel level);

}  // namespace xrom::avf::vsock

#endif  // XROM_COMMON_PROTOCOL_VSOCK_PROTOCOL_H_
