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

#include "VmLifecycleObserver.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

namespace xrom::avf {
namespace {

std::string Utf16ToUtf8(const std::u16string& in) {
  // AVF error messages are ASCII in practice. Anything above 0x7f is rendered as
  // a code point rather than passed through, so a malformed message cannot be
  // used to smuggle control characters into the audit log.
  std::string out;
  out.reserve(in.size());
  for (const char16_t c : in) {
    if (c >= 0x20 && c < 0x7f) {
      out.push_back(static_cast<char>(c));
    } else {
      out += android::base::StringPrintf("<U+%04X>", static_cast<unsigned int>(c));
    }
  }
  return out;
}

}  // namespace

void VmLifecycleObserver::EnterPhase(Phase phase) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    phase_ = phase;
  }
  cv_.notify_all();
}

::android::binder::Status VmLifecycleObserver::onPayloadStarted(int32_t cid) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    cid_ = cid;
  }
  LOG(INFO) << "xrom_avfd: payload started, cid=" << cid;
  EnterPhase(Phase::kPayloadStarted);
  return ::android::binder::Status::ok();
}

::android::binder::Status VmLifecycleObserver::onPayloadReady(int32_t cid) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    cid_ = cid;
    // Set here rather than in EnterPhase so that the flag and the phase move
    // together under one lock: a waiter that sees kPayloadReady must also see
    // payload_ready_, and the reverse.
    payload_ready_ = true;
  }
  LOG(INFO) << "xrom_avfd: payload ready, cid=" << cid;
  EnterPhase(Phase::kPayloadReady);
  return ::android::binder::Status::ok();
}

::android::binder::Status VmLifecycleObserver::onPayloadFinished(int32_t cid, int32_t exit_code) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    cid_ = cid;
    exit_code_ = exit_code;
  }
  LOG(INFO) << "xrom_avfd: payload finished, cid=" << cid << " exit=" << exit_code;
  EnterPhase(Phase::kPayloadFinished);
  return ::android::binder::Status::ok();
}

::android::binder::Status VmLifecycleObserver::onError(
    int32_t cid, const ::aidl::android::system::virtualizationcommon::ErrorCode& error_code,
    const std::u16string& message) {
  const int32_t code = static_cast<int32_t>(error_code);
  const std::string detail = android::base::StringPrintf(
      "avf error code=%d message=%s", code, Utf16ToUtf8(message).c_str());
  {
    std::lock_guard<std::mutex> lock(mutex_);
    cid_ = cid;
    detail_ = detail;
  }
  LOG(ERROR) << "xrom_avfd: " << detail;
  EnterPhase(Phase::kError);
  return ::android::binder::Status::ok();
}

::android::binder::Status VmLifecycleObserver::onDied(
    int32_t cid, const ::aidl::android::system::virtualizationcommon::DeathReason& reason) {
  const int32_t code = static_cast<int32_t>(reason);
  const std::string death = android::base::StringPrintf("vm died, death reason=%d", code);
  std::string detail;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    cid_ = cid;
    if (detail_.empty()) {
      detail_ = death;
    }
    detail = detail_;
  }
  LOG(ERROR) << "xrom_avfd: cid=" << cid << " " << detail;
  EnterPhase(Phase::kDied);
  return ::android::binder::Status::ok();
}

bool VmLifecycleObserver::WaitForPayloadLaunched(std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(mutex_);
  const bool settled = cv_.wait_for(lock, timeout, [this] {
    return phase_ >= Phase::kPayloadStarted;
  });
  if (!settled) {
    return false;
  }
  // kError and kDied sort above kPayloadStarted, so they must be excluded
  // explicitly rather than by the ordering.
  return phase_ != Phase::kError && phase_ != Phase::kDied;
}

bool VmLifecycleObserver::WaitForPayloadReady(std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(mutex_);
  cv_.wait_for(lock, timeout, [this] {
    return payload_ready_ || phase_ >= Phase::kPayloadFinished;
  });
  return payload_ready_;
}

bool VmLifecycleObserver::payload_ready() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return payload_ready_;
}

bool VmLifecycleObserver::WaitForTerminal(std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(mutex_);
  return cv_.wait_for(lock, timeout, [this] {
    return phase_ == Phase::kPayloadFinished || phase_ == Phase::kError || phase_ == Phase::kDied;
  });
}

VmLifecycleObserver::Phase VmLifecycleObserver::phase() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return phase_;
}

bool VmLifecycleObserver::failed() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (phase_ == Phase::kError || phase_ == Phase::kDied) {
    return true;
  }
  // exit_code_ is only meaningful once the payload has reported; before that it
  // holds the -1 sentinel, which must not read as a failure.
  return phase_ == Phase::kPayloadFinished && exit_code_ != 0;
}

int32_t VmLifecycleObserver::exit_code() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return exit_code_;
}

int32_t VmLifecycleObserver::cid() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return cid_;
}

std::string VmLifecycleObserver::failure_detail() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!detail_.empty()) {
    return detail_;
  }
  if (phase_ == Phase::kPayloadFinished) {
    return android::base::StringPrintf("payload exited with code %d", exit_code_);
  }
  return android::base::StringPrintf("vm stopped in phase %s", PhaseName(phase_));
}

const char* VmLifecycleObserver::PhaseName(Phase phase) {
  switch (phase) {
    case Phase::kCreated:
      return "created";
    case Phase::kPayloadStarted:
      return "payload_started";
    case Phase::kPayloadReady:
      return "payload_ready";
    case Phase::kPayloadFinished:
      return "payload_finished";
    case Phase::kError:
      return "error";
    case Phase::kDied:
      return "died";
  }
  return "unknown";
}

}  // namespace xrom::avf
