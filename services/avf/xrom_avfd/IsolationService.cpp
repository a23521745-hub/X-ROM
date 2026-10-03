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

#include "IsolationService.h"

#include <fcntl.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/unique_fd.h>
#include <binder/IPCThreadState.h>

#include "VsockProtocol.h"

namespace xrom::avf {
namespace {

using ::android::base::unique_fd;
using ::android::binder::Status;
using ::android::sp;
using ::xrom::avf::vsock::FrameHeader;
using ::xrom::avf::vsock::FrameType;
using ::xrom::crypto::Sha256;
using ::xrom::crypto::Sha256Digest;

constexpr int32_t kWaitPollMs = 500;

// AIDL byte[] is std::vector<uint8_t>; the wire digests are std::array<uint8_t,
// 32>. The conversion is written once because an empty vector and a zero-filled
// vector mean different things to a consumer: empty is "the payload never
// reported one", zeroes would be a digest of nothing.
std::vector<uint8_t> ToAidlBytes(const ::xrom::crypto::Sha256Digest& digest) {
  return std::vector<uint8_t>(digest.begin(), digest.end());
}

// The inverse, for comparing what the guest sent against what the host pinned.
bool DigestEquals(const std::vector<uint8_t>& reported, const ::xrom::crypto::Sha256Digest& pinned) {
  return reported.size() == pinned.size() &&
         std::equal(reported.begin(), reported.end(), pinned.begin());
}

// Both conversions are ASCII-only by construction: task ids are validated
// against [a-z0-9_.-] before they are stored, and anything coming back from a
// caller that is not ASCII is rejected by IsolationPolicy rather than
// transliterated.
std::string Utf16ToUtf8(const std::u16string& in) {
  std::string out;
  out.reserve(in.size());
  for (const char16_t c : in) {
    if (c >= 0x20 && c < 0x7f) {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('?');
    }
  }
  return out;
}

std::u16string Utf8ToUtf16(const std::string& in) {
  return std::u16string(in.begin(), in.end());
}

TaskClass FromAidl(aidl_xrom::TaskClass value) {
  switch (value) {
    case aidl_xrom::TaskClass::STATIC_ANALYSIS:
      return TaskClass::kStaticAnalysis;
    case aidl_xrom::TaskClass::INTEGRITY_CHECK:
      return TaskClass::kIntegrityCheck;
    case aidl_xrom::TaskClass::ATTESTATION:
      return TaskClass::kAttestation;
    case aidl_xrom::TaskClass::CRYPTO_OPERATION:
      return TaskClass::kCryptoOperation;
  }
  // Not a value X-ROM defines. Mapping it to kCryptoOperation means the strictest
  // policy applies, so an unknown class is the most heavily restricted one rather
  // than the least.
  return TaskClass::kCryptoOperation;
}

}  // namespace

IsolationService::IsolationService(AvfController* controller, IsolationPolicy policy,
                                   Tunables tunables)
    : controller_(controller), policy_(std::move(policy)), tunables_(tunables) {}

IsolationService::~IsolationService() { Shutdown(); }

void IsolationService::Start() {
  const int32_t workers = std::max(1, policy_.options().max_concurrent_vms);
  workers_.reserve(workers);
  for (int32_t i = 0; i < workers; ++i) {
    workers_.emplace_back([this] { WorkerMain(); });
  }
  LOG(INFO) << "xrom_avfd: started " << workers << " isolation worker(s)";
}

void IsolationService::Shutdown() {
  if (shutdown_.exchange(true)) {
    return;  // already shutting down
  }
  cv_.notify_all();

  // Drop everything still queued. Workers that are mid-task finish it: RunTask
  // polls for shutdown every kWaitPollMs, so the drain is bounded and no pVM is
  // left running because its owner disappeared.
  {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.clear();
  }
  for (auto& worker : workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  workers_.clear();
  LOG(INFO) << "xrom_avfd: isolation workers stopped";
}

std::string IsolationService::PeerSelinuxDomain(int32_t pid) {
  if (pid <= 0) {
    return "";
  }
  const std::string path = "/proc/" + std::to_string(pid) + "/attr/current";
  std::unique_ptr<FILE, decltype(&fclose)> file(fopen(path.c_str(), "re"), fclose);
  if (file == nullptr) {
    return "";
  }
  char buffer[128] = {};
  if (fgets(buffer, sizeof(buffer), file.get()) == nullptr) {
    return "";
  }
  std::string context(buffer);
  // The kernel terminates the context with a NUL that fgets keeps.
  while (!context.empty() && (context.back() == '\0' || context.back() == '\n')) {
    context.pop_back();
  }
  // Return only the domain, not the full u:r:domain:s0 context.
  const size_t first = context.find(':');
  const size_t second = (first == std::string::npos) ? std::string::npos : context.find(':', first + 1);
  if (first != std::string::npos && second != std::string::npos && second > first + 1) {
    return context.substr(first + 1, second - first - 1);
  }
  return context;
}

Status IsolationService::submitTask(const aidl_xrom::IsolationTaskRequest& request,
                                    const sp<aidl_xrom::IIsolationTaskCallback>& callback,
                                    int64_t* out_sequence) {
  *out_sequence = static_cast<int64_t>(Rejection::kMalformed);
  if (callback == nullptr) {
    LOG(WARNING) << "xrom_avfd: submitTask with a null callback";
    return Status::ok();
  }
  if (shutdown_.load()) {
    *out_sequence = static_cast<int64_t>(Rejection::kDenied);
    return Status::ok();
  }

  const int32_t calling_uid = ::android::IPCThreadState::self()->getCallingUid();
  const int32_t calling_pid = ::android::IPCThreadState::self()->getCallingPid();

  TaskRequest native;
  native.task_id = Utf16ToUtf8(request.taskId);
  native.task_class = FromAidl(request.taskClass);
  native.input_digest = request.inputDigest;
  native.input_path = Utf16ToUtf8(request.inputPath);
  native.requested_memory_mib = request.requestedMemoryMib;
  native.request_debug = request.requestDebug;

  CallerIdentity caller;
  caller.uid = calling_uid;
  caller.pid = calling_pid;
  caller.selinux_domain = PeerSelinuxDomain(calling_pid);
  caller.is_debuggable_build = tunables_.debuggable_build;

  // The reservation and the decision happen under one lock. Checking capacity
  // here and reserving later would let a burst of submissions all pass the check
  // and then all boot, which is exactly the resource-exhaustion path the ceiling
  // exists to close.
  WorkItem item;
  int64_t sequence = 0;
  PolicyDecision decision;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    decision = policy_.Evaluate(caller, native, active_vms_, committed_memory_mib_);
    if (decision.allowed()) {
      const VmSpec preview = policy_.BuildSpec(native);
      sequence = next_sequence_++;
      item.sequence = sequence;
      item.request = native;
      item.caller = caller;
      item.callback = callback;
      item.reserved_memory_mib = preview.limits.memory_mib;

      Record record;
      record.owner_uid = calling_uid;
      record.vm_name = preview.name;
      record.result.taskId = request.taskId;
      record.result.state = aidl_xrom::TaskState::PENDING;
      record.result.exitCode = -1;
      record.result.cid = -1;
      records_[sequence] = record;

      ++active_vms_;
      committed_memory_mib_ += preview.limits.memory_mib;
      queue_.push_back(item);
    }
  }

  if (!decision.allowed()) {
    LOG(WARNING) << "xrom_avfd: refused uid=" << calling_uid
                 << " domain=" << caller.selinux_domain << " :: " << decision.Reason();
    *out_sequence = static_cast<int64_t>(decision.rejection);
    return Status::ok();
  }

  LOG(INFO) << "xrom_avfd: accepted task " << native.task_id << " seq=" << sequence
            << " uid=" << calling_uid << " class=" << TaskClassName(native.task_class);
  cv_.notify_one();
  SetState(item, aidl_xrom::TaskState::PENDING);
  *out_sequence = sequence;
  return Status::ok();
}

Status IsolationService::getResult(int64_t sequence, aidl_xrom::IsolationTaskResult* out_result) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = records_.find(sequence);
  // An unknown sequence and a sequence owned by another uid are indistinguishable
  // from outside: tasks are not enumerable across callers.
  if (it == records_.end() || it->second.owner_uid !=
                                  ::android::IPCThreadState::self()->getCallingUid()) {
    out_result->taskId = u"";
    out_result->state = aidl_xrom::TaskState::DENIED;
    out_result->exitCode = -1;
    out_result->cid = -1;
    out_result->detail = u"no such task for this caller";
    return Status::ok();
  }
  *out_result = it->second.result;
  return Status::ok();
}

Status IsolationService::cancelTask(int64_t sequence) {
  bool notify = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = records_.find(sequence);
    if (it != records_.end() &&
        it->second.owner_uid == ::android::IPCThreadState::self()->getCallingUid()) {
      it->second.cancelled = true;
      notify = true;
    }
  }
  if (notify) {
    cv_.notify_all();  // wakes workers out of their poll interval
    LOG(INFO) << "xrom_avfd: task seq=" << sequence << " cancellation requested";
  }
  return Status::ok();
}

Status IsolationService::isProtectedVmAvailable(bool* out_available) {
  *out_available = controller_->IsProtectedVmAvailable();
  return Status::ok();
}

Status IsolationService::getActiveVmCount(int32_t* out_count) {
  std::lock_guard<std::mutex> lock(mutex_);
  *out_count = active_vms_;
  return Status::ok();
}

void IsolationService::ReleaseSlot(const WorkItem& item) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = records_.find(item.sequence);
  if (it != records_.end()) {
    it->second.running = false;
  }
  if (active_vms_ > 0) {
    --active_vms_;
  }
  committed_memory_mib_ =
      std::max<int64_t>(0, committed_memory_mib_ - item.reserved_memory_mib);
}

bool IsolationService::IsCancelled(int64_t sequence) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = records_.find(sequence);
  return it != records_.end() && it->second.cancelled;
}

void IsolationService::SetState(const WorkItem& item, aidl_xrom::TaskState state) {
  UpdateRecord(item.sequence, [&state](aidl_xrom::IsolationTaskResult* result) {
    result->state = state;
  });
  if (item.callback != nullptr) {
    // oneway: cannot block on the caller.
    item.callback->onStateChanged(Utf8ToUtf16(item.request.task_id), state);
  }
}

void IsolationService::Complete(const WorkItem& item, const aidl_xrom::IsolationTaskResult& result) {
  UpdateRecord(item.sequence, [&result](aidl_xrom::IsolationTaskResult* stored) { *stored = result; });
  if (item.callback != nullptr) {
    item.callback->onCompleted(result);
  }
}

void IsolationService::UpdateRecord(
    int64_t sequence,
    const std::function<void(aidl_xrom::IsolationTaskResult*)>& mutate) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = records_.find(sequence);
  if (it != records_.end()) {
    mutate(&it->second.result);
  }
}

void IsolationService::WorkerMain() {
  while (true) {
    WorkItem item;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait(lock, [this] { return shutdown_.load() || !queue_.empty(); });
      if (shutdown_.load() && queue_.empty()) {
        return;
      }
      if (queue_.empty()) {
        continue;
      }
      item = queue_.front();
      queue_.pop_front();
    }

    bool cancelled = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto it = records_.find(item.sequence);
      if (it != records_.end()) {
        cancelled = it->second.cancelled;
        it->second.running = !cancelled;
      }
    }
    if (cancelled) {
      aidl_xrom::IsolationTaskResult result;
      result.taskId = Utf8ToUtf16(item.request.task_id);
      result.state = aidl_xrom::TaskState::CANCELLED;
      result.exitCode = -1;
      result.cid = -1;
      result.detail = u"cancelled before the VM was created";
      Complete(item, result);
      ReleaseSlot(item);
      continue;
    }

    RunTask(item);
    ReleaseSlot(item);
  }
}

IsolationService::DataPlaneOutcome IsolationService::RunDataExchange(
    const WorkItem& item, const AvfController::VmHandle& handle, const VerifiedPayload& verified,
    std::chrono::steady_clock::time_point deadline) {
  DataPlaneOutcome outcome;
  const auto fail = [&outcome](const std::string& message) -> DataPlaneOutcome& {
    outcome.ok = false;
    outcome.error = message;
    return outcome;
  };

  const auto remaining = [&deadline]() {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    return left.count() > 0 ? left : std::chrono::milliseconds(0);
  };

  std::string error;

  // --- 1. connect ---------------------------------------------------------
  int fd = -1;
  if (!controller_->ConnectVsock(handle, vsock::kPortTaskControl, &fd, &error)) {
    return fail("cannot connect the control vsock: " + error);
  }
  VsockChannel channel(fd);
  // The guest may send up to kMaxOutputBytes of output split over several
  // frames; the ceiling bounds the total, not the frame.
  channel.SetReceiveBudget(vsock::kMaxOutputBytes + (4u * 1024 * 1024));

  // --- 2. the guest identifies itself first -------------------------------
  //
  // This is the ordering the whole design rests on. The guest measures its own
  // code and configuration from inside the VM and reports it before the host has
  // sent anything. Until those digests match the ones pinned in the signed
  // manifest, not one byte of task input leaves the host.
  FrameHeader header{};
  if (!channel.ReceiveGuestHello(std::chrono::milliseconds(tunables_.hello_timeout_ms),
                                 &outcome.hello, &header, &error)) {
    return fail("the payload did not identify itself: " + error);
  }
  outcome.hello_received = true;

  const bool lib_matches = outcome.hello.payload_lib_digest == verified.manifest.payload_lib_sha256;
  const bool config_matches = outcome.hello.vm_config_digest == verified.manifest.vm_config_sha256;
  if (!lib_matches || !config_matches) {
    // Tell the guest why it is being cut off, then cut it off. Best effort: a
    // failed abort must not mask the real reason.
    std::string ignored;
    channel.SendTaskAbort(vsock::AbortReason::kMeasurementRejected,
                          lib_matches ? "vm_config digest" : "payload library digest", &ignored);
    return fail(std::string("the guest's self-measurement does not match the signed manifest: ") +
                (!lib_matches ? "payload library " : "") +
                (!lib_matches ? Sha256::ToHex(outcome.hello.payload_lib_digest) : "") +
                (!config_matches ? " vm_config " : "") +
                (!config_matches ? Sha256::ToHex(outcome.hello.vm_config_digest) : ""));
  }
  LOG(INFO) << "xrom_avfd: task " << item.request.task_id
            << " guest self-measurement matches the signed manifest ("
            << verified.manifest.payload_name << "); apk contents "
            << Sha256::ToHex(outcome.hello.apk_contents_digest).substr(0, 12);

  // --- 3. measure the input, then send it ---------------------------------
  //
  // Two passes over the file on purpose. The digest has to be in kTaskBegin,
  // which goes out before the first byte of input, and holding the whole input in
  // host memory to get that would make the caller's file size a limit on the
  // daemon's memory use.
  Sha256Digest input_digest{};
  int64_t input_length = 0;
  {
    Sha256 hasher;
    std::string path = item.request.input_path;
    unique_fd input_fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (input_fd.get() < 0) {
      return fail("cannot open the task input " + path + ": " + strerror(errno));
    }
    std::vector<uint8_t> buffer(static_cast<size_t>(tunables_.transfer_chunk_bytes));
    for (;;) {
      const ssize_t got = TEMP_FAILURE_RETRY(
          read(input_fd.get(), buffer.data(), buffer.size()));
      if (got < 0) {
        return fail("cannot read the task input: " + strerror(errno));
      }
      if (got == 0) {
        break;
      }
      input_length += got;
      if (input_length > static_cast<int64_t>(vsock::kMaxInputBytes)) {
        return fail("the task input exceeds the " + std::to_string(vsock::kMaxInputBytes) +
                    " byte ceiling");
      }
      hasher.Update(buffer.data(), static_cast<size_t>(got));
    }
    input_digest = hasher.Finalize();
  }

  std::array<uint8_t, vsock::kNonceBytes> nonce{};
  // RAND_bytes rather than /dev/urandom: libcrypto is already linked, it is a
  // CSPRNG whose seeding the platform is responsible for, and it does not need a
  // file descriptor or an SELinux grant.
  if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
    return fail("cannot generate a task nonce");
  }

  vsock::TaskBegin begin;
  begin.nonce = nonce;
  begin.input_digest = input_digest;
  begin.task_class = static_cast<uint32_t>(item.request.task_class);
  begin.input_length = static_cast<uint32_t>(input_length);
  // The level the host will accept, sent before the work starts so that a guest
  // capable of more can produce it and a guest capable of less can say so in
  // kTaskResult instead of being downgraded after the fact.
  begin.authorization_level = static_cast<uint32_t>(outcome.attestation);
  begin.task_id = item.request.task_id;
  if (!channel.SendTaskBegin(begin, &error)) {
    return fail("cannot send kTaskBegin: " + error);
  }

  {
    unique_fd input_fd(TEMP_FAILURE_RETRY(open(item.request.input_path.c_str(),
                                               O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (input_fd.get() < 0) {
      return fail("cannot reopen the task input: " + strerror(errno));
    }
    std::vector<uint8_t> buffer(static_cast<size_t>(tunables_.transfer_chunk_bytes));
    for (;;) {
      const ssize_t got = TEMP_FAILURE_RETRY(read(input_fd.get(), buffer.data(), buffer.size()));
      if (got < 0) {
        return fail("cannot read the task input: " + strerror(errno));
      }
      if (got == 0) {
        break;
      }
      if (!channel.SendFrame(FrameType::kTaskInput, buffer.data(), static_cast<size_t>(got),
                             &error)) {
        return fail("cannot send the task input: " + error);
      }
      if (shutdown_.load() || IsCancelled(item.sequence)) {
        std::string ignored;
        channel.SendTaskAbort(vsock::AbortReason::kTaskCancelled, "cancelled during input",
                              &ignored);
        return fail("cancelled while the input was being sent");
      }
    }
  }
  if (!channel.SendFrame(FrameType::kTaskInputEnd, nullptr, 0, &error)) {
    return fail("cannot send kTaskInputEnd: " + error);
  }
  LOG(INFO) << "xrom_avfd: task " << item.request.task_id << " sent " << input_length
            << " input bytes, digest " << Sha256::ToHex(input_digest).substr(0, 12);

  // --- 4. collect the output ----------------------------------------------
  //
  // The channel has already verified each frame's payload digest, so what is
  // accumulated here is exactly what arrived. What it cannot know is whether the
  // whole output is what the guest intended, which is what kTaskResult's
  // output_digest is for: it is compared against a digest the host recomputes over
  // the bytes it collected.
  Sha256 output_hasher;
  bool done = false;
  vsock::TaskAbort abort;
  while (!done) {
    std::vector<uint8_t> payload;
    if (!channel.ReceiveFrame(remaining(), &header, &payload, &error)) {
      return fail("the output transfer stopped: " + error);
    }
    switch (header.type) {
      case static_cast<uint32_t>(FrameType::kTaskOutput):
        if (outcome.output.size() + payload.size() > vsock::kMaxOutputBytes) {
          std::string ignored;
          channel.SendTaskAbort(vsock::AbortReason::kOutputTooLarge, "output over the ceiling",
                                &ignored);
          return fail("the payload sent more than " + std::to_string(vsock::kMaxOutputBytes) +
                      " bytes of output");
        }
        output_hasher.Update(payload.data(), payload.size());
        outcome.output.insert(outcome.output.end(), payload.begin(), payload.end());
        break;
      case static_cast<uint32_t>(FrameType::kTaskResult):
        if (!vsock::DecodeTaskResult(payload.data(), payload.size(), &outcome.task_result)) {
          return fail("kTaskResult could not be decoded");
        }
        outcome.result_received = true;
        done = true;
        break;
      case static_cast<uint32_t>(FrameType::kTaskAbort):
        if (!vsock::DecodeTaskAbort(payload.data(), payload.size(), &abort)) {
          return fail("kTaskAbort could not be decoded");
        }
        return fail(std::string("the payload aborted: ") +
                    vsock::AbortReasonName(abort.reason) + " (" + abort.detail + ")");
      default:
        return fail("unexpected frame type " + std::to_string(header.type) + " during output");
    }
    if (shutdown_.load() || IsCancelled(item.sequence)) {
      std::string ignored;
      channel.SendTaskAbort(vsock::AbortReason::kTaskCancelled, "cancelled during output",
                            &ignored);
      return fail("cancelled while the output was being received");
    }
  }

  // --- 5. verify the result ------------------------------------------------
  const vsock::TaskResult& reported = outcome.task_result;

  if (reported.nonce != nonce) {
    // A result carrying someone else's nonce is either a replay or a payload that
    // ignored kTaskBegin. Neither may be reported as a success.
    return fail("the result does not echo this task's nonce");
  }
  const Sha256Digest recomputed_output = output_hasher.Finalize();
  if (recomputed_output != reported.output_digest) {
    return fail("the recomputed output digest does not match the one the payload reported");
  }
  if (reported.output_length != outcome.output.size()) {
    return fail("the payload reported " + std::to_string(reported.output_length) +
                " output bytes but sent " + std::to_string(outcome.output.size()));
  }
  if (reported.exit_code != 0) {
    return fail("the payload reported exit code " + std::to_string(reported.exit_code));
  }
  // The measurements are re-sent with the result so that a result cannot be
  // separated from the identity of the payload that produced it. Re-checking them
  // here costs nothing and catches a payload that identified itself honestly and
  // then changed.
  if (reported.payload_lib_digest != verified.manifest.payload_lib_sha256 ||
      reported.vm_config_digest != verified.manifest.vm_config_sha256) {
    return fail("the measurements in the result differ from the ones in kGuestHello");
  }

  // --- 6. clamp the attestation level --------------------------------------
  //
  // The guest states a level; the host asserts only what it corroborated. It can
  // always corroborate MEASUREMENT_ONLY, because it just did. INSTANCE_BOUND
  // additionally requires a non-zero binding — the host cannot recompute it, so
  // the check is that the guest actually produced one. REMOTE_ATTESTED would
  // require a certificate chain the host verified, which the protocol does not
  // carry; see AttestationLevel.aidl for why that is unreachable here.
  outcome.attestation = aidl_xrom::AttestationLevel::MEASUREMENT_ONLY;
  if (reported.attestation_level == vsock::AttestationLevel::kInstanceBound ||
      reported.attestation_level == vsock::AttestationLevel::kRemoteAttested) {
    const bool binding_present =
        std::any_of(reported.instance_binding.begin(), reported.instance_binding.end(),
                    [](uint8_t b) { return b != 0; });
    if (binding_present) {
      outcome.attestation = aidl_xrom::AttestationLevel::INSTANCE_BOUND;
    }
  }
  if (reported.attestation_level == vsock::AttestationLevel::kRemoteAttested) {
    LOG(WARNING) << "xrom_avfd: task " << item.request.task_id
                 << " claimed REMOTE_ATTESTED; the host cannot corroborate it and is reporting "
                 << "INSTANCE_BOUND instead";
  }

  outcome.ok = true;
  LOG(INFO) << "xrom_avfd: task " << item.request.task_id << " verified " << outcome.output.size()
            << " output bytes, digest " << Sha256::ToHex(recomputed_output).substr(0, 12)
            << ", attestation "
            << static_cast<int32_t>(outcome.attestation);
  return outcome;
}

void IsolationService::RunTask(const WorkItem& item) {
  aidl_xrom::IsolationTaskResult result;
  result.taskId = Utf8ToUtf16(item.request.task_id);
  result.state = aidl_xrom::TaskState::FAILED;
  result.exitCode = -1;
  result.cid = -1;

  const auto fail = [&](const std::string& detail) {
    result.state = aidl_xrom::TaskState::FAILED;
    result.detail = Utf8ToUtf16(detail);
    LOG(ERROR) << "xrom_avfd: task " << item.request.task_id << " failed: " << detail;
    Complete(item, result);
  };

  SetState(item, aidl_xrom::TaskState::VM_STARTING);

  const VmSpec spec = policy_.BuildSpec(item.request);
  const std::vector<std::string> problems = spec.Validate(policy_.options().allow_debuggable_vm);
  if (!problems.empty()) {
    std::string joined;
    for (const auto& problem : problems) {
      joined += "[" + problem + "] ";
    }
    fail("generated VM spec failed validation: " + joined);
    return;
  }

  // -----------------------------------------------------------------------
  // Payload trust. This runs before EnsureIdsig, before an instance id is
  // allocated and before the VM exists, so a payload whose manifest does not
  // verify is never offered to AVF at all: it never reaches pvmfw, never gets a
  // CID and never touches /dev/kvm.
  //
  // AVF verifies the payload too — pvmfw checks the APK's fs-verity digest tree
  // and measures it into the VM identity. That answers "was this APK tampered
  // with?". What it cannot answer on a self-built ROM is "did X-ROM choose this
  // APK?", because every payload here is signed with the same platform
  // certificate. The manifest adds a second trust anchor that is not the platform
  // key, and pins the SHA-256 of the exact APK bytes.
  // -----------------------------------------------------------------------
  VerifiedPayload verified;
  std::vector<std::string> verify_errors;
  if (!verifier_.Verify(spec, &verified, &verify_errors)) {
    std::string joined;
    for (const auto& reason : verify_errors) {
      joined += "[" + reason + "] ";
    }
    result.state = aidl_xrom::TaskState::DENIED;
    result.detail = Utf8ToUtf16("payload verification failed: " + joined);
    LOG(ERROR) << "xrom_avfd: refusing to launch " << spec.name << ": " << joined;
    Complete(item, result);
    return;
  }

  // Second gate: the manifest is signed for specific task classes, and this
  // request has to be one of them. A payload cannot be talked into doing work it
  // was not signed for, even by a caller the policy otherwise permits.
  const PolicyDecision trust_decision = policy_.EvaluatePayloadTrust(item.request,
                                                                     verified.manifest);
  if (!trust_decision.allowed()) {
    result.state = aidl_xrom::TaskState::DENIED;
    result.detail = Utf8ToUtf16("payload authorisation: " + trust_decision.Reason());
    LOG(ERROR) << "xrom_avfd: task " << item.request.task_id << " denied: "
               << trust_decision.Reason();
    Complete(item, result);
    return;
  }

  std::string error;
  if (!controller_->EnsureIdsig(spec, &error)) {
    fail("idsig preparation failed: " + error);
    return;
  }

  InstanceId instance_id{};
  if (!controller_->AllocateInstanceId(&instance_id, &error)) {
    fail("instance id allocation failed: " + error);
    return;
  }

  AvfController::VmHandle handle;
  if (!controller_->StartVm(spec, instance_id, policy_.options().allow_debuggable_vm,
                            std::chrono::milliseconds(tunables_.vm_launch_timeout_ms), &handle,
                            &error)) {
    // A task whose class needs a protected VM but whose platform lost pKVM
    // between admission and start is DENIED, not FAILED: nothing went wrong with
    // the work, the precondition disappeared.
    result.state = controller_->IsProtectedVmAvailable() ? aidl_xrom::TaskState::FAILED
                                                         : aidl_xrom::TaskState::DENIED;
    result.detail = Utf8ToUtf16(error);
    LOG(ERROR) << "xrom_avfd: VM start failed for " << spec.ToString() << ": " << error;
    Complete(item, result);
    return;
  }

  result.cid = handle.cid;
  SetState(item, aidl_xrom::TaskState::RUNNING);
  LOG(INFO) << "xrom_avfd: " << spec.name << " is up on cid=" << handle.cid
            << "; control port " << vsock::kPortTaskControl << ", data port "
            << vsock::kPortTaskData;

  const int32_t total_ms = tunables_.task_timeout_ms;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(total_ms);

  // Wait for onPayloadReady rather than onPayloadStarted. The X-Vault payload
  // binds and listens on the control port before it notifies, so readiness means
  // a connectVsock will find a listener. Connecting on "started" instead would
  // race the guest's bind() and fail with an error that looks like a broken VM.
  bool ready = false;
  bool interrupted = false;
  for (int32_t elapsed = 0; elapsed < tunables_.vm_launch_timeout_ms; elapsed += kWaitPollMs) {
    if (handle.observer->WaitForPayloadReady(std::chrono::milliseconds(kWaitPollMs))) {
      ready = true;
      break;
    }
    if (handle.observer->WaitForTerminal(std::chrono::milliseconds(0))) {
      break;  // the VM ended without ever becoming ready
    }
    if (shutdown_.load() || IsCancelled(item.sequence)) {
      interrupted = true;
      break;
    }
  }

  // The data plane, bounded by the same deadline as everything else.
  DataPlaneOutcome exchange;
  if (interrupted) {
    exchange.error = shutdown_.load() ? "daemon shutting down while the VM was starting"
                                      : "cancelled by the caller";
  } else if (!ready) {
    exchange.error = "the payload never reported ready; last phase " +
                     std::string(VmLifecycleObserver::PhaseName(handle.observer->phase()));
  } else {
    exchange = RunDataExchange(item, handle, verified, deadline);
  }

  // Let the VM finish on its own terms so that exitCode and any failure detail
  // come from the guest rather than from being killed. Bounded by the same
  // deadline, and poll-interrupted so a cancellation lands within kWaitPollMs.
  bool terminal = false;
  if (!interrupted) {
    while (std::chrono::steady_clock::now() < deadline) {
      if (handle.observer->WaitForTerminal(std::chrono::milliseconds(kWaitPollMs))) {
        terminal = true;
        break;
      }
      if (shutdown_.load() || IsCancelled(item.sequence)) {
        interrupted = true;
        break;
      }
    }
  }

  // -----------------------------------------------------------------------
  // Turning the two sources of truth into one answer.
  //
  // The data plane and the VM lifecycle can disagree: the exchange can succeed
  // and the VM can then die, or the VM can exit 0 having never sent a result.
  // A result is only SUCCEEDED when BOTH say the task worked, because a verified
  // output from a VM that crashed afterwards may have been produced with state
  // the crash corrupted, and a clean exit with no verified output is just a
  // process that finished.
  // -----------------------------------------------------------------------
  if (interrupted) {
    result.state = shutdown_.load() ? aidl_xrom::TaskState::FAILED
                                    : aidl_xrom::TaskState::CANCELLED;
    result.detail = Utf8ToUtf16(shutdown_.load() ? "daemon shutting down while the task ran"
                                                 : "cancelled by the caller");
  } else if (!exchange.ok) {
    result.state = aidl_xrom::TaskState::FAILED;
    result.detail = Utf8ToUtf16(exchange.error);
  } else if (!terminal) {
    result.state = aidl_xrom::TaskState::FAILED;
    result.detail = Utf8ToUtf16("the output was verified but the VM did not finish within " +
                                std::to_string(total_ms) + "ms; last phase " +
                                VmLifecycleObserver::PhaseName(handle.observer->phase()));
  } else if (handle.observer->failed()) {
    result.state = aidl_xrom::TaskState::FAILED;
    result.detail = Utf8ToUtf16("the payload verified its output and then the VM failed: " +
                                handle.observer->failure_detail());
    result.exitCode = handle.observer->exit_code();
  } else {
    result.state = aidl_xrom::TaskState::SUCCEEDED;
    result.exitCode = exchange.task_result.exit_code;
    result.detail = u"";
  }

  // Provenance. Only filled in when the exchange produced a verified result: an
  // empty outputDigest means "there is no verified output", and filling these
  // with zeroes would make that indistinguishable from an output that hashes to
  // zero.
  result.outputDigest = {};
  result.attestationLevel = exchange.attestation;
  result.outputLength = 0;
  result.payloadLibDigest = {};
  result.vmConfigDigest = {};
  result.apkContentsDigest = {};
  result.instanceBinding = {};
  result.nonce = {};
  result.payloadName = Utf8ToUtf16(verified.manifest.payload_name);
  result.manifestKeyId = Utf8ToUtf16(verified.manifest.key_id);
  result.manifestSecurityVersion = verified.manifest.security_version;

  if (exchange.ok && exchange.result_received) {
    result.outputDigest = ToAidlBytes(exchange.task_result.output_digest);
    result.outputLength = static_cast<int32_t>(exchange.task_result.output_length);
    result.payloadLibDigest = ToAidlBytes(exchange.task_result.payload_lib_digest);
    result.vmConfigDigest = ToAidlBytes(exchange.task_result.vm_config_digest);
    result.apkContentsDigest = ToAidlBytes(exchange.hello.apk_contents_digest);
    result.nonce = std::vector<uint8_t>(exchange.task_result.nonce.begin(),
                                        exchange.task_result.nonce.end());
    if (exchange.attestation == aidl_xrom::AttestationLevel::INSTANCE_BOUND) {
      result.instanceBinding = ToAidlBytes(exchange.task_result.instance_binding);
    }
    // Cross-check the digests the guest sent against the ones the host pinned,
    // independently of the comparison RunDataExchange already made. Cheap, and a
    // second implementation of the same check catching the first is worth more
    // than the two lines it costs.
    if (!DigestEquals(result.payloadLibDigest, verified.manifest.payload_lib_sha256) ||
        !DigestEquals(result.vmConfigDigest, verified.manifest.vm_config_sha256)) {
      result.state = aidl_xrom::TaskState::FAILED;
      result.detail = u"the reported measurements do not match the signed manifest";
      result.outputDigest = {};
    }
  }

  controller_->StopVm(&handle);
  LOG(INFO) << "xrom_avfd: task " << item.request.task_id << " finished, state="
            << static_cast<int32_t>(result.state) << " exit=" << result.exitCode;
  Complete(item, result);
}

}  // namespace xrom::avf
