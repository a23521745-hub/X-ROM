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

#include "VsockProtocol.h"

#include <cstring>

namespace xrom::avf::vsock {
namespace {

using ::xrom::crypto::Sha256;
using ::xrom::crypto::Sha256Digest;

// Copies a string into a fixed wire buffer, always NUL-terminating and always
// zero-filling the remainder. Fails rather than truncating: a silently truncated
// task id would let two different tasks share an identifier.
bool ToFixedBuffer(const std::string& in, char* buffer, size_t buffer_size) {
  // One byte of room is reserved for the terminator, so the usable length is
  // buffer_size - 1 even though the field on the wire is buffer_size wide.
  if (in.size() >= buffer_size) {
    return false;
  }
  // An embedded NUL is rejected here rather than silently truncated. FromFixedBuffer
  // reads up to the first NUL and then requires the rest of the buffer to be zero,
  // so a string like "ab\0cd" would decode as "ab" — the two ends would disagree
  // about the value without either reporting an error, and a task id that differs
  // between host and guest is a task whose result cannot be matched to its request.
  if (in.find('\0') != std::string::npos) {
    return false;
  }
  std::memset(buffer, 0, buffer_size);
  std::memcpy(buffer, in.data(), in.size());
  return true;
}

// Reads a fixed wire buffer back into a string. Does not trust NUL termination,
// because the buffer arrived from a peer: it scans at most buffer_size bytes and
// rejects any non-NUL byte appearing after the terminator, which is what a
// tampered or uninitialised frame looks like.
bool FromFixedBuffer(const char* buffer, size_t buffer_size, std::string* out) {
  size_t length = 0;
  while (length < buffer_size && buffer[length] != '\0') {
    ++length;
  }
  for (size_t i = length; i < buffer_size; ++i) {
    if (buffer[i] != '\0') {
      return false;
    }
  }
  out->assign(buffer, length);
  return true;
}

// The wire structs are packed and alignof(1), so memcpy from an unaligned buffer
// is well defined and a reinterpret_cast would not be.
template <typename T>
bool DecodePod(const void* payload, size_t size, T* out) {
  if (payload == nullptr || out == nullptr || size != sizeof(T)) {
    return false;
  }
  std::memcpy(out, payload, sizeof(T));
  return true;
}

}  // namespace

bool IsKnownFrameType(uint32_t raw_type) {
  switch (static_cast<FrameType>(raw_type)) {
    case FrameType::kGuestHello:
    case FrameType::kTaskBegin:
    case FrameType::kTaskInput:
    case FrameType::kTaskInputEnd:
    case FrameType::kTaskOutput:
    case FrameType::kTaskResult:
    case FrameType::kTaskAbort:
      return true;
  }
  return false;
}

bool EncodeHeader(FrameType type, uint32_t payload_length, const Sha256Digest& payload_digest,
                  std::array<uint8_t, kFrameHeaderSize>* out) {
  if (out == nullptr || !IsKnownFrameType(static_cast<uint32_t>(type)) ||
      payload_length > kMaxFramePayloadBytes) {
    return false;
  }
  FrameHeader header;
  header.magic = kFrameMagic;
  header.version = kProtocolVersion;
  header.type = static_cast<uint32_t>(type);
  header.payload_length = payload_length;
  std::memcpy(header.payload_digest, payload_digest.data(), sizeof(header.payload_digest));
  static_assert(sizeof(FrameHeader) == kFrameHeaderSize, "header size must match the buffer");
  std::memcpy(out->data(), &header, kFrameHeaderSize);
  return true;
}

bool DecodeHeader(const uint8_t* data, size_t size, FrameHeader* out) {
  if (data == nullptr || out == nullptr || size < kFrameHeaderSize) {
    return false;
  }
  FrameHeader header;
  std::memcpy(&header, data, sizeof(header));
  if (header.magic != kFrameMagic || header.version != kProtocolVersion ||
      !IsKnownFrameType(header.type) || header.payload_length > kMaxFramePayloadBytes) {
    return false;
  }
  *out = header;
  return true;
}

bool VerifyPayloadDigest(const FrameHeader& header, const uint8_t* payload, size_t payload_size) {
  if (payload_size != header.payload_length) {
    return false;
  }
  if (payload == nullptr && payload_size != 0) {
    return false;
  }
  const Sha256Digest computed = Sha256::Hash(payload, payload_size);
  Sha256Digest claimed{};
  std::memcpy(claimed.data(), header.payload_digest, claimed.size());
  return Sha256::Equal(computed, claimed);
}

bool DecodeFrame(const uint8_t* data, size_t size, FrameHeader* header, const uint8_t** payload,
                 size_t* payload_size) {
  if (data == nullptr || header == nullptr || payload == nullptr || payload_size == nullptr) {
    return false;
  }
  if (!DecodeHeader(data, size, header)) {
    return false;
  }
  const size_t total = kFrameHeaderSize + header->payload_length;
  if (size < total) {
    return false;
  }
  *payload = data + kFrameHeaderSize;
  *payload_size = header->payload_length;
  return VerifyPayloadDigest(*header, *payload, *payload_size);
}

bool EncodeFrame(FrameType type, const void* payload, size_t payload_length,
                 std::vector<uint8_t>* out) {
  if (out == nullptr || payload_length > kMaxFramePayloadBytes) {
    return false;
  }
  if (payload == nullptr && payload_length != 0) {
    return false;
  }
  const Sha256Digest digest = Sha256::Hash(payload, payload_length);
  std::array<uint8_t, kFrameHeaderSize> header_bytes{};
  if (!EncodeHeader(type, static_cast<uint32_t>(payload_length), digest, &header_bytes)) {
    return false;
  }
  out->clear();
  out->reserve(kFrameHeaderSize + payload_length);
  out->insert(out->end(), header_bytes.begin(), header_bytes.end());
  if (payload_length > 0) {
    const uint8_t* bytes = static_cast<const uint8_t*>(payload);
    out->insert(out->end(), bytes, bytes + payload_length);
  }
  return true;
}

bool EncodeGuestHello(const GuestHello& in, std::vector<uint8_t>* out) {
  if (in.protocol_version != kProtocolVersion) {
    return false;
  }
  GuestHelloPayload payload;
  payload.protocol_version = in.protocol_version;
  std::memcpy(payload.payload_lib_digest, in.payload_lib_digest.data(), 32);
  std::memcpy(payload.vm_config_digest, in.vm_config_digest.data(), 32);
  std::memcpy(payload.apk_contents_digest, in.apk_contents_digest.data(), 32);
  return EncodeFrame(FrameType::kGuestHello, &payload, sizeof(payload), out);
}

bool DecodeGuestHello(const void* payload, size_t size, GuestHello* out) {
  GuestHelloPayload wire;
  if (!DecodePod(payload, size, &wire) || wire.protocol_version != kProtocolVersion ||
      out == nullptr) {
    return false;
  }
  out->protocol_version = wire.protocol_version;
  std::memcpy(out->payload_lib_digest.data(), wire.payload_lib_digest, 32);
  std::memcpy(out->vm_config_digest.data(), wire.vm_config_digest, 32);
  std::memcpy(out->apk_contents_digest.data(), wire.apk_contents_digest, 32);
  return true;
}

bool EncodeTaskBegin(const TaskBegin& in, std::vector<uint8_t>* out) {
  // Rejected here as well as in DecodeTaskBegin. An encoder that happily produces
  // a frame its own decoder refuses is how the two ends drift: the host would
  // send it, the guest would drop the connection, and the failure would look like
  // a transport problem rather than a validation one.
  if (in.task_id.empty()) {
    return false;
  }
  TaskBeginPayload payload;
  std::memcpy(payload.nonce, in.nonce.data(), sizeof(payload.nonce));
  std::memcpy(payload.input_digest, in.input_digest.data(), 32);
  payload.task_class = in.task_class;
  payload.input_length = in.input_length;
  payload.authorization_level = in.authorization_level;
  if (in.input_length > kMaxInputBytes) {
    return false;
  }
  if (!ToFixedBuffer(in.task_id, payload.task_id, sizeof(payload.task_id))) {
    return false;
  }
  return EncodeFrame(FrameType::kTaskBegin, &payload, sizeof(payload), out);
}

bool DecodeTaskBegin(const void* payload, size_t size, TaskBegin* out) {
  TaskBeginPayload wire;
  if (!DecodePod(payload, size, &wire) || out == nullptr) {
    return false;
  }
  if (wire.input_length > kMaxInputBytes) {
    return false;
  }
  std::string task_id;
  if (!FromFixedBuffer(wire.task_id, sizeof(wire.task_id), &task_id) || task_id.empty()) {
    return false;
  }
  std::memcpy(out->nonce.data(), wire.nonce, out->nonce.size());
  std::memcpy(out->input_digest.data(), wire.input_digest, 32);
  out->task_class = wire.task_class;
  out->input_length = wire.input_length;
  out->authorization_level = wire.authorization_level;
  out->task_id = std::move(task_id);
  return true;
}

bool EncodeTaskResult(const TaskResult& in, std::vector<uint8_t>* out) {
  TaskResultPayload payload;
  std::memcpy(payload.nonce, in.nonce.data(), sizeof(payload.nonce));
  std::memcpy(payload.output_digest, in.output_digest.data(), 32);
  std::memcpy(payload.instance_binding, in.instance_binding.data(), 32);
  std::memcpy(payload.payload_lib_digest, in.payload_lib_digest.data(), 32);
  std::memcpy(payload.vm_config_digest, in.vm_config_digest.data(), 32);
  payload.exit_code = in.exit_code;
  payload.output_length = in.output_length;
  payload.attestation_level = static_cast<uint32_t>(in.attestation_level);
  payload.flags = in.flags;
  if (in.output_length > kMaxOutputBytes) {
    return false;
  }
  return EncodeFrame(FrameType::kTaskResult, &payload, sizeof(payload), out);
}

bool DecodeTaskResult(const void* payload, size_t size, TaskResult* out) {
  TaskResultPayload wire;
  if (!DecodePod(payload, size, &wire) || out == nullptr) {
    return false;
  }
  if (wire.output_length > kMaxOutputBytes) {
    return false;
  }
  switch (static_cast<AttestationLevel>(wire.attestation_level)) {
    case AttestationLevel::kMeasurementOnly:
    case AttestationLevel::kInstanceBound:
    case AttestationLevel::kRemoteAttested:
      break;
    default:
      return false;
  }
  std::memcpy(out->nonce.data(), wire.nonce, out->nonce.size());
  std::memcpy(out->output_digest.data(), wire.output_digest, 32);
  std::memcpy(out->instance_binding.data(), wire.instance_binding, 32);
  std::memcpy(out->payload_lib_digest.data(), wire.payload_lib_digest, 32);
  std::memcpy(out->vm_config_digest.data(), wire.vm_config_digest, 32);
  out->exit_code = wire.exit_code;
  out->output_length = wire.output_length;
  out->attestation_level = static_cast<AttestationLevel>(wire.attestation_level);
  out->flags = wire.flags;
  return true;
}

bool IsKnownAbortReason(AbortReason reason) {
  switch (reason) {
    case AbortReason::kNone:
    case AbortReason::kInputDigestMismatch:
    case AbortReason::kSelfMeasurementMismatch:
    case AbortReason::kEnvironmentCheckFailed:
    case AbortReason::kOutputTooLarge:
    case AbortReason::kProtocolError:
    case AbortReason::kMeasurementRejected:
    case AbortReason::kTaskCancelled:
    case AbortReason::kGuestInternalError:
    case AbortReason::kTaskClassNotAllowed:
    case AbortReason::kInputTooLarge:
    case AbortReason::kNoAuthorization:
      return true;
    default:
      return false;
  }
}

bool IsKnownAttestationLevel(AttestationLevel level) {
  switch (level) {
    case AttestationLevel::kMeasurementOnly:
    case AttestationLevel::kInstanceBound:
    case AttestationLevel::kRemoteAttested:
      return true;
    default:
      return false;
  }
}

bool EncodeTaskAbort(const TaskAbort& in, std::vector<uint8_t>* out) {
  if (!IsKnownAbortReason(in.reason)) {
    return false;
  }
  TaskAbortPayload payload;
  payload.reason = static_cast<uint32_t>(in.reason);
  if (!ToFixedBuffer(in.detail, payload.detail, sizeof(payload.detail))) {
    return false;
  }
  return EncodeFrame(FrameType::kTaskAbort, &payload, sizeof(payload), out);
}

bool DecodeTaskAbort(const void* payload, size_t size, TaskAbort* out) {
  TaskAbortPayload wire;
  if (!DecodePod(payload, size, &wire) || out == nullptr) {
    return false;
  }
  if (!IsKnownAbortReason(static_cast<AbortReason>(wire.reason))) {
    return false;
  }
  std::string detail;
  if (!FromFixedBuffer(wire.detail, sizeof(wire.detail), &detail)) {
    return false;
  }
  out->reason = static_cast<AbortReason>(wire.reason);
  out->detail = std::move(detail);
  return true;
}

const char* FrameTypeName(FrameType type) {
  switch (type) {
    case FrameType::kGuestHello:
      return "guest_hello";
    case FrameType::kTaskBegin:
      return "task_begin";
    case FrameType::kTaskInput:
      return "task_input";
    case FrameType::kTaskInputEnd:
      return "task_input_end";
    case FrameType::kTaskOutput:
      return "task_output";
    case FrameType::kTaskResult:
      return "task_result";
    case FrameType::kTaskAbort:
      return "task_abort";
  }
  return "unknown";
}

const char* AbortReasonName(AbortReason reason) {
  switch (reason) {
    case AbortReason::kNone:
      return "none";
    case AbortReason::kInputDigestMismatch:
      return "input-digest-mismatch";
    case AbortReason::kSelfMeasurementMismatch:
      return "self-measurement-mismatch";
    case AbortReason::kEnvironmentCheckFailed:
      return "environment-check-failed";
    case AbortReason::kOutputTooLarge:
      return "output-too-large";
    case AbortReason::kProtocolError:
      return "protocol-error";
    case AbortReason::kMeasurementRejected:
      return "measurement-rejected";
    case AbortReason::kTaskCancelled:
      return "task-cancelled";
    case AbortReason::kGuestInternalError:
      return "guest-internal-error";
    case AbortReason::kTaskClassNotAllowed:
      return "task-class-not-allowed";
    case AbortReason::kInputTooLarge:
      return "input-too-large";
    case AbortReason::kNoAuthorization:
      return "no-authorization";
  }
  return "unknown";
}

const char* AttestationLevelName(AttestationLevel level) {
  switch (level) {
    case AttestationLevel::kMeasurementOnly:
      return "measurement_only";
    case AttestationLevel::kInstanceBound:
      return "instance_bound";
    case AttestationLevel::kRemoteAttested:
      return "remote_attested";
  }
  return "unknown";
}

}  // namespace xrom::avf::vsock
