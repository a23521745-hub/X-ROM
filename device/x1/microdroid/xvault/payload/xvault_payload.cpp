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

// ---------------------------------------------------------------------------
// X-Vault — the isolated security task that runs INSIDE the Microdroid pVM.
//
// Trust orientation matters here and is the opposite of the host daemon's. On the
// host, everything coming from a caller is untrusted. In here, everything coming
// from the host is untrusted too: the host configured this VM, chose its memory
// and CPU counts, and is now sending bytes down a socket it opened. pKVM
// guarantees the host cannot read this process's memory; it does not guarantee
// the host is honest.
//
// THE ORDER OF OPERATIONS IS THE SECURITY ARGUMENT
// ------------------------------------------------
// 1. Verify the guest environment (SELinux enforcing, not root).
// 2. Measure this binary and its configuration, from inside, without asking the
//    host for anything.
// 3. Bind and listen on the vsock control port.
// 4. Only now call AVmPayload_notifyPayloadReady(). The host treats onPayloadReady
//    as "the guest is ready to be talked to", so notifying before the listener
//    exists would be a race the host cannot detect.
// 5. Send kGuestHello carrying the measurements from step 2, and WAIT. Until the
//    host accepts them, this payload has not been shown a single byte of task
//    input. That is deliberate: input is the thing an attacker would want to
//    divert, so it is never handed to a VM whose identity has not been checked.
// 6. Re-verify the input digest from the kTaskBegin frame against a hash computed
//    incrementally over the bytes actually received. The host's digest and this
//    one are computed independently, from different copies of the data, by code on
//    opposite sides of the hypervisor.
// 7. Do the work, then send kTaskResult with the output digest, the measurements
//    again, the echoed nonce and an instance binding.
//
// WHY THE NONCE AND THE INSTANCE BINDING ARE IN THE RESULT
// --------------------------------------------------------
// The nonce echo proves the result belongs to this request and not to a recorded
// one. The instance binding is a SHA-256 over a secret that only this VM instance
// can obtain (AVmPayload_getVmInstanceSecret) mixed with the nonce and the output
// digest. The host cannot recompute it — that is the point, and it is also the
// limit: see the comment on ComputeInstanceBinding for exactly what that does and
// does not prove.
// ---------------------------------------------------------------------------

#include <dirent.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/vm_sockets.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

#include "Sha256.h"
#include "VsockProtocol.h"
#include "VsockChannel.h"

// Declares AVmPayload_main, the symbol microdroid_launcher resolves in this
// library, plus the guest-side support API. __has_include so that the file also
// compiles in a plain host build (tools/hostcheck and the transport tests) where
// Microdroid's headers are absent.
#if __has_include(<vm_payload.h>)
#include <vm_payload.h>
#define XROM_HAVE_VM_PAYLOAD_API 1
#else
#define XROM_HAVE_VM_PAYLOAD_API 0
#endif

#if __has_include(<log/log.h>)
#include <log/log.h>
#define XROM_LOG(fmt, ...) ALOGI("xvault: " fmt, ##__VA_ARGS__)
#define XROM_LOGE(fmt, ...) ALOGE("xvault: " fmt, ##__VA_ARGS__)
#else
#define XROM_LOG(fmt, ...) fprintf(stderr, "xvault: " fmt "\n", ##__VA_ARGS__)
#define XROM_LOGE(fmt, ...) fprintf(stderr, "xvault: " fmt "\n", ##__VA_ARGS__)
#endif

// microdroid_launcher dlopens this library and calls AVmPayload_main(). The
// declaration lives in Microdroid's vm_payload.h; the macro keeps this file
// compilable when that header is absent.
#if XROM_HAVE_VM_PAYLOAD_API
#define XROM_PAYLOAD_ENTRY extern "C" int AVmPayload_main
#else
extern "C" int AVmPayload_main();
#define XROM_PAYLOAD_ENTRY extern "C" int AVmPayload_main
#endif

namespace {

using ::xrom::avf::VsockChannel;
using ::xrom::avf::vsock::AbortReason;
using ::xrom::avf::vsock::AttestationLevel;
using ::xrom::avf::vsock::FrameHeader;
using ::xrom::avf::vsock::FrameType;
using ::xrom::avf::vsock::GuestHello;
using ::xrom::avf::vsock::TaskBegin;
using ::xrom::avf::vsock::TaskResult;
using ::xrom::crypto::Sha256;
using ::xrom::crypto::Sha256Digest;

// --- timings ---------------------------------------------------------------
//
// A payload that waits forever is a payload that holds a VM allocation, its
// memory and its /dev/kvm slot open forever. Every wait here is bounded, and the
// bound is shorter than the host's task deadline so that the guest reports its own
// failure rather than being killed mid-frame.
constexpr int kAcceptTimeoutMs = 30 * 1000;
constexpr int kHelloAckTimeoutMs = 60 * 1000;
constexpr int kInputFrameTimeoutMs = 60 * 1000;

// Output is sent in chunks no larger than this. 64 KiB keeps a single frame well
// inside the vsock buffer size, so a chunk is never split across a flow-control
// boundary that the host would have to reassemble.
constexpr size_t kOutputChunkBytes = 64 * 1024;

// The classes this payload is built to serve. This list is the guest's own and is
// not taken from the host: a kTaskBegin naming a class outside it is refused even
// though the signed manifest on the host says the same thing, because two
// independent checks that disagree are a signal and one check is a single point of
// failure. ATTESTATION and CRYPTO_OPERATION are deliberately absent — see the
// comment on ComputeInstanceBinding.
constexpr int32_t kServedTaskClasses[] = {0, 1};

// --- the report ------------------------------------------------------------
//
// The task output. Fixed size, all integers, no floating point and no
// self-reference: the host hashes these bytes to get outputDigest, so the report
// must not contain its own digest, and it must be byte-identical for byte-identical
// input on every run. Entropy is scaled to a fixed point to keep that true — a
// double would be reproducible in practice but is not worth the argument.
struct XVaultReport {
  uint32_t report_version;
  uint32_t task_class;
  uint64_t input_length;
  uint8_t input_sha256[32];
  uint64_t distinct_byte_values;
  uint64_t entropy_microbits;  // Shannon entropy in bits per byte, times 1e6
  uint8_t reserved[16];
} __attribute__((packed));

static_assert(sizeof(XVaultReport) == 80, "the host parses XVaultReport by offset");

constexpr uint32_t kReportVersion = 1;

// --- environment checks ----------------------------------------------------

// Reads a small text file. Returns false if it cannot be read, which the caller
// must treat as a failed check rather than as a pass: inside a pVM, "I could not
// verify X" and "X is fine" must never be the same answer.
bool ReadSmallFile(const char* path, std::string* out) {
  FILE* file = fopen(path, "re");
  if (file == nullptr) {
    return false;
  }
  char buffer[512];
  out->clear();
  while (fgets(buffer, sizeof(buffer), file) != nullptr) {
    *out += buffer;
    if (out->size() > 4096) {
      fclose(file);
      return false;
    }
  }
  const bool ok = !out->empty();
  fclose(file);
  return ok;
}

// The guest must be running with SELinux enforcing. Microdroid ships enforcing by
// default and applies its own payload policy (the microdroid_payload attribute),
// so a permissive guest means the image did not come up the way it was measured.
bool CheckSelinuxEnforcing() {
  std::string mode;
  if (!ReadSmallFile("/sys/fs/selinux/enforce", &mode)) {
    XROM_LOGE("cannot read /sys/fs/selinux/enforce");
    return false;
  }
  if (mode[0] != '1') {
    XROM_LOGE("SELinux is not enforcing inside the guest (mode byte 0x%02x)",
              static_cast<unsigned char>(mode[0]));
    return false;
  }
  return true;
}

// The payload must not run as root inside the guest. Root in the guest would let
// a compromised payload rewrite its own policy, and the defense-in-depth that
// AVF's security model claims for pVMs assumes the payload is confined by more
// than the hypervisor.
bool CheckNotRoot() {
  if (geteuid() == 0) {
    XROM_LOGE("running as root inside the guest; refusing");
    return false;
  }
  return true;
}

// --- self-measurement ------------------------------------------------------
//
// Nothing here asks the host for a value. /proc/self/exe is the binary the kernel
// is actually executing, so hashing it measures the code rather than a claim about
// the code; the host pins the same digest in the signed manifest and the two are
// compared before any input is released.

// Records which binary is executing and returns its SHA-256.
bool MeasureSelf(Sha256Digest* out, std::string* path_out) {
  char path[4096];
  const ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
  if (length <= 0) {
    XROM_LOGE("cannot resolve /proc/self/exe: %s", strerror(errno));
    return false;
  }
  path[length] = '\0';
  if (path_out != nullptr) {
    *path_out = path;
  }
  std::string error;
  if (!Sha256::HashFile(path, out, &error)) {
    XROM_LOGE("cannot measure %s: %s", path, error.c_str());
    return false;
  }
  return true;
}

// Where Microdroid unzipped the read-only APK contents. Empty when the support API
// is not present (a host build, or an older tree).
std::string ApkContentsPath() {
#if XROM_HAVE_VM_PAYLOAD_API
  const char* path = AVmPayload_getApkContentsPath();
  if (path != nullptr) {
    return path;
  }
#endif
  return "";
}

// Measures assets/vm_config.json as the guest sees it, i.e. after extraction from
// the verified APK. This is the same file whose digest the host pins in the signed
// manifest, computed here from a different copy at a different time.
bool MeasureVmConfig(const std::string& apk_contents, Sha256Digest* out) {
  if (apk_contents.empty()) {
    XROM_LOGE("AVmPayload_getApkContentsPath() is unavailable; cannot measure vm_config.json");
    return false;
  }
  const std::string path = apk_contents + "/assets/vm_config.json";
  std::string error;
  if (!Sha256::HashFile(path, out, &error)) {
    XROM_LOGE("cannot measure %s: %s", path.c_str(), error.c_str());
    return false;
  }
  return true;
}

// A digest over the whole unzipped APK directory: SHA-256 of, for every regular
// file in sorted order, "<relative path>\0<length>\0<sha256>\0".
//
// What this is for, precisely: the host already pins the SHA-256 of the APK itself,
// so "nothing in the APK changed" is covered on the host side and does not need
// this. What the host cannot see is the extraction. This digest detects a payload
// directory that was modified after microdroid unzipped it, and because it is
// reported in both kGuestHello and kTaskResult it also ties a result to the exact
// directory state that produced it. It is recorded and cross-checked for
// self-consistency; it is not a replacement for the two pinned digests.
bool MeasureApkContents(const std::string& root, Sha256Digest* out) {
  if (root.empty()) {
    return false;
  }
  std::vector<std::string> entries;
  std::vector<std::string> stack{root};
  while (!stack.empty()) {
    const std::string dir = stack.back();
    stack.pop_back();
    DIR* handle = opendir(dir.c_str());
    if (handle == nullptr) {
      XROM_LOGE("cannot open %s while measuring the APK contents: %s", dir.c_str(),
                strerror(errno));
      return false;
    }
    struct dirent* entry = nullptr;
    while ((entry = readdir(handle)) != nullptr) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        continue;
      }
      entries.push_back(dir + "/" + entry->d_name);
    }
    closedir(handle);
  }
  std::sort(entries.begin(), entries.end());

  // One NUL between fields, so that no concatenation of two different listings can
  // produce the same byte sequence. Without a separator, a file named "ab" of
  // length 1 and a file named "a" of length 11 would be ambiguous.
  static constexpr uint8_t kSeparator = 0;

  Sha256 hasher;
  for (const std::string& path : entries) {
    struct stat st {};
    if (lstat(path.c_str(), &st) != 0) {
      XROM_LOGE("cannot stat %s: %s", path.c_str(), strerror(errno));
      return false;
    }
    if (S_ISDIR(st.st_mode)) {
      stack.push_back(path);
      continue;
    }
    if (!S_ISREG(st.st_mode)) {
      // A socket, device or symlink in the extracted contents would mean the
      // directory is not what microdroid produced. Refuse rather than skip:
      // skipping is how a smuggled file becomes invisible.
      XROM_LOGE("%s is not a regular file; the APK contents were modified", path.c_str());
      return false;
    }
    Sha256Digest file_digest{};
    std::string error;
    if (!Sha256::HashFile(path, &file_digest, &error)) {
      XROM_LOGE("cannot measure %s: %s", path.c_str(), error.c_str());
      return false;
    }
    const std::string relative = path.substr(root.size());
    hasher.Update(relative.data(), relative.size());
    hasher.Update(&kSeparator, sizeof(kSeparator));
    const uint64_t length = static_cast<uint64_t>(st.st_size);
    hasher.Update(&length, sizeof(length));
    hasher.Update(&kSeparator, sizeof(kSeparator));
    hasher.Update(file_digest.data(), file_digest.size());
    hasher.Update(&kSeparator, sizeof(kSeparator));
  }
  *out = hasher.Finalize();
  return true;
}

// --- the vsock listener ----------------------------------------------------
//
// The guest is the server: it binds and listens, then notifies readiness, and the
// host connects via IVirtualMachine::connectVsock. Binding first is what makes
// onPayloadReady mean "you can talk to me now".
int ListenOnControlPort(std::string* error) {
  const int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    *error = std::string("socket(AF_VSOCK) failed: ") + strerror(errno);
    return -1;
  }

  struct sockaddr_vm address {};
  address.svm_family = AF_VSOCK;
  address.svm_cid = VMADDR_CID_ANY;
  address.svm_port = static_cast<uint32_t>(::xrom::avf::vsock::kPortTaskControl);

  if (bind(fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) != 0) {
    *error = std::string("bind(AF_VSOCK, port ") +
             std::to_string(::xrom::avf::vsock::kPortTaskControl) + ") failed: " + strerror(errno);
    close(fd);
    return -1;
  }
  if (listen(fd, 1) != 0) {
    *error = std::string("listen failed: ") + strerror(errno);
    close(fd);
    return -1;
  }
  return fd;
}

int AcceptWithTimeout(int listen_fd, int timeout_ms, std::string* error) {
  struct pollfd pfd {};
  pfd.fd = listen_fd;
  pfd.events = POLLIN;
  const int polled = poll(&pfd, 1, timeout_ms);
  if (polled == 0) {
    *error = "no host connection within the accept timeout";
    return -1;
  }
  if (polled < 0) {
    if (errno == EINTR) {
      *error = "interrupted while waiting for the host to connect";
    } else {
      *error = std::string("poll on the listener failed: ") + strerror(errno);
    }
    return -1;
  }

  struct sockaddr_vm peer {};
  socklen_t peer_length = sizeof(peer);
  const int fd = accept4(listen_fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_length,
                         SOCK_CLOEXEC);
  if (fd < 0) {
    *error = std::string("accept failed: ") + strerror(errno);
    return -1;
  }
  // Only the host may connect. CID 2 is the host on every AVF VM; anything else
  // means either a second guest or a routing mistake, and neither is acceptable.
  if (peer.svm_cid != ::xrom::avf::vsock::kHostCid) {
    *error = "a connection arrived from CID " + std::to_string(peer.svm_cid) +
             " instead of the host";
    close(fd);
    return -1;
  }
  return fd;
}

// --- the instance binding --------------------------------------------------
//
// AVmPayload_getVmInstanceSecret derives a secret from a device-specific
// hypervisor value, this payload's code and its non-modifiable configuration. It
// is stable across stop and restart while the VM identity is unchanged, it is not
// available to the host, and it is not available to any other VM.
//
// WHAT THAT BUYS, STATED WITHOUT OVERSELLING IT
// ---------------------------------------------
// Mixing the secret into the result makes a kTaskResult frame non-transferable:
// a recording of one VM's result cannot be replayed as another VM instance's
// answer, and the payload itself can detect a replay across boots. It does NOT let
// the host verify the result, because the host cannot obtain the secret. Proof of
// origin that the host can check comes from one of two places: the measurement
// agreement (kMeasurementOnly — the host pinned the APK digest, the guest measured
// its own code, and the two match), or AVF remote attestation (kRemoteAttested).
// Claiming more than that is the failure mode this comment exists to prevent.
//
// WHY REMOTE ATTESTATION IS NOT REQUESTED HERE
// --------------------------------------------
// AVmPayload_requestAttestation needs the RKP service, which needs network access.
// This payload is hardened to vsock-only egress — no net device in vm_config.json
// and neverallow rules in xrom_microdroid_hardening.te — so a remote attestation
// request cannot complete in the shipped configuration. Reporting
// kRemoteAttested without one would be a lie, so the honest level here is
// kInstanceBound, and the host clamps anything above what it can corroborate.
// See docs/04-vsock-data-plane-and-payload-signing.md.
constexpr char kInstanceBindingIdentifier[] = "xrom.instance_binding.v1";

bool ComputeInstanceBinding(const Sha256Digest& output_digest,
                            const std::array<uint8_t, ::xrom::avf::vsock::kNonceBytes>& nonce,
                            Sha256Digest* out) {
#if XROM_HAVE_VM_PAYLOAD_API
  std::array<uint8_t, 32> secret{};
  AVmPayload_getVmInstanceSecret(kInstanceBindingIdentifier,
                                 sizeof(kInstanceBindingIdentifier) - 1, secret.data(),
                                 secret.size());
  Sha256 hasher;
  hasher.Update(secret.data(), secret.size());
  hasher.Update(nonce.data(), nonce.size());
  hasher.Update(output_digest.data(), output_digest.size());
  *out = hasher.Finalize();
  // The secret is stack memory in a process that is about to exit and that the
  // host cannot read; clearing it is cheap hygiene rather than a mitigation.
  secret.fill(0);
  return true;
#else
  (void)output_digest;
  (void)nonce;
  out->fill(0);
  return false;
#endif
}

// --- the task --------------------------------------------------------------
//
// Deliberately a pure function of the input bytes: same input, same output, every
// time, on any boot. That is what makes outputDigest a meaningful thing to compare
// and what makes a replayed result detectable. A task with hidden state, a clock
// or a random component would produce a digest nobody could check.
void RunTask(int32_t task_class, const std::vector<uint8_t>& input, std::vector<uint8_t>* output) {
  XVaultReport report{};
  report.report_version = kReportVersion;
  report.task_class = static_cast<uint32_t>(task_class);
  report.input_length = input.size();

  const Sha256Digest input_digest = Sha256::Hash(input.data(), input.size());
  std::memcpy(report.input_sha256, input_digest.data(), sizeof(report.input_sha256));

  uint64_t histogram[256] = {0};
  for (const uint8_t byte : input) {
    ++histogram[byte];
  }
  uint64_t distinct = 0;
  // Entropy in millionths of a bit per byte, accumulated in integer arithmetic.
  // log2(p) = log(p)/log(2), and the scaling keeps the result identical for
  // identical input regardless of the libm in the guest image.
  double entropy_bits = 0.0;
  if (!input.empty()) {
    const double total = static_cast<double>(input.size());
    for (const uint64_t count : histogram) {
      if (count == 0) {
        continue;
      }
      ++distinct;
      const double p = static_cast<double>(count) / total;
      entropy_bits -= p * (log(p) / log(2.0));
    }
  }
  report.distinct_byte_values = distinct;
  report.entropy_microbits = static_cast<uint64_t>(entropy_bits * 1000000.0);

  output->assign(reinterpret_cast<const uint8_t*>(&report),
                 reinterpret_cast<const uint8_t*>(&report) + sizeof(report));
}

bool ServesTaskClass(int32_t task_class) {
  for (const int32_t served : kServedTaskClasses) {
    if (served == task_class) {
      return true;
    }
  }
  return false;
}

}  // namespace

XROM_PAYLOAD_ENTRY() {
  XROM_LOG("starting (vm_payload API %s)", XROM_HAVE_VM_PAYLOAD_API ? "present" : "absent");

  // --- 1. guest environment ---------------------------------------------
  if (!CheckSelinuxEnforcing() || !CheckNotRoot()) {
    XROM_LOGE("guest environment checks failed; exiting without listening");
    return 1;
  }

  // --- 2. self-measurement ------------------------------------------------
  Sha256Digest self_digest{};
  std::string self_path;
  if (!MeasureSelf(&self_digest, &self_path)) {
    return 1;
  }
  const std::string apk_contents = ApkContentsPath();
  Sha256Digest config_digest{};
  Sha256Digest contents_digest{};
  if (!MeasureVmConfig(apk_contents, &config_digest)) {
    return 1;
  }
  if (!MeasureApkContents(apk_contents, &contents_digest)) {
    return 1;
  }
  XROM_LOG("measured %s = %s", self_path.c_str(), Sha256::ToHex(self_digest).c_str());
  XROM_LOG("measured vm_config = %s", Sha256::ToHex(config_digest).c_str());
  XROM_LOG("measured apk contents = %s", Sha256::ToHex(contents_digest).c_str());

  // --- 3. listen before announcing readiness -----------------------------
  std::string error;
  const int listen_fd = ListenOnControlPort(&error);
  if (listen_fd < 0) {
    XROM_LOGE("%s", error.c_str());
    return 1;
  }
  XROM_LOG("listening on vsock port %d", ::xrom::avf::vsock::kPortTaskControl);

  // --- 4. now the host may connect ---------------------------------------
#if XROM_HAVE_VM_PAYLOAD_API
  AVmPayload_notifyPayloadReady();
#endif

  // --- 5. accept, then identify ourselves before receiving anything ------
  const int connection_fd = AcceptWithTimeout(listen_fd, kAcceptTimeoutMs, &error);
  close(listen_fd);
  if (connection_fd < 0) {
    XROM_LOGE("%s", error.c_str());
    return 1;
  }

  VsockChannel channel(connection_fd);
  // The guest is the side that produces output, so its budget has to cover a full
  // result; the host's own budget is set independently in VsockChannel.
  channel.SetReceiveBudget(::xrom::avf::vsock::kMaxInputBytes + (4u * 1024 * 1024));

  GuestHello hello;
  hello.protocol_version = ::xrom::avf::vsock::kProtocolVersion;
  hello.payload_lib_digest = self_digest;
  hello.vm_config_digest = config_digest;
  hello.apk_contents_digest = contents_digest;
  if (!channel.SendGuestHello(hello, &error)) {
    XROM_LOGE("cannot send kGuestHello: %s", error.c_str());
    return 1;
  }

  // --- 6. wait to be authorised, and only then accept input ---------------
  //
  // The host compares the digests above against the signed manifest and either
  // sends kTaskBegin or aborts. Sitting in this wait is the payload's contribution
  // to "no input reaches a VM that has not been identified".
  TaskBegin begin;
  FrameHeader header{};
  if (!channel.ReceiveTaskBegin(std::chrono::milliseconds(kHelloAckTimeoutMs), &begin, &header,
                                &error)) {
    XROM_LOGE("no authorised kTaskBegin arrived: %s", error.c_str());
    // Best effort: if the host is still there, tell it why this run produced no
    // result. A failure to send is not a new failure.
    std::string ignored;
    channel.SendTaskAbort(AbortReason::kNoAuthorization, "no kTaskBegin received", &ignored);
    return 1;
  }
  XROM_LOG("task %s class=%u input_length=%u", begin.task_id.c_str(), begin.task_class,
           begin.input_length);

  if (!ServesTaskClass(static_cast<int32_t>(begin.task_class))) {
    XROM_LOGE("task class %u is not one this payload serves; refusing", begin.task_class);
    channel.SendTaskAbort(AbortReason::kTaskClassNotAllowed, "class not served by this payload",
                          &error);
    return 1;
  }

  // The host declares the length up front. Believing it would let a hostile host
  // make this process allocate without bound, so the declared length is checked
  // against the compiled-in ceiling and against how much was actually sent.
  if (begin.input_length > ::xrom::avf::vsock::kMaxInputBytes) {
    XROM_LOGE("declared input_length %u exceeds the %u byte ceiling", begin.input_length,
              ::xrom::avf::vsock::kMaxInputBytes);
    channel.SendTaskAbort(AbortReason::kInputTooLarge, "declared input over the ceiling", &error);
    return 1;
  }

  // --- 7. stream the input in, hashing as it arrives ---------------------
  std::vector<uint8_t> input;
  input.reserve(std::min<uint64_t>(begin.input_length, ::xrom::avf::vsock::kMaxInputBytes));
  Sha256 input_hasher;
  bool input_complete = false;
  while (!input_complete) {
    std::vector<uint8_t> payload;
    if (!channel.ReceiveFrame(std::chrono::milliseconds(kInputFrameTimeoutMs), &header, &payload,
                              &error)) {
      XROM_LOGE("input transfer failed: %s", error.c_str());
      channel.SendTaskAbort(AbortReason::kInputDigestMismatch, "input transfer failed", &error);
      return 1;
    }
    if (header.type == static_cast<uint32_t>(FrameType::kTaskInputEnd)) {
      input_complete = true;
      continue;
    }
    if (header.type != static_cast<uint32_t>(FrameType::kTaskInput)) {
      XROM_LOGE("expected kTaskInput, got frame type %u", header.type);
      channel.SendTaskAbort(AbortReason::kProtocolError, "unexpected frame during input",
                            &error);
      return 1;
    }
    if (input.size() + payload.size() > begin.input_length) {
      XROM_LOGE("the host sent more input than it declared");
      channel.SendTaskAbort(AbortReason::kInputDigestMismatch, "more input than declared", &error);
      return 1;
    }
    input_hasher.Update(payload.data(), payload.size());
    input.insert(input.end(), payload.begin(), payload.end());
  }

  if (input.size() != begin.input_length) {
    XROM_LOGE("received %zu input bytes but the host declared %u", input.size(),
              begin.input_length);
    channel.SendTaskAbort(AbortReason::kInputDigestMismatch, "short input", &error);
    return 1;
  }

  // The re-verification step. begin.input_digest came from the host over the same
  // socket, so agreeing with it proves the transfer was faithful rather than that
  // the host is honest — but a transfer that is not faithful means every later
  // digest is meaningless, so it is checked first and hard.
  const Sha256Digest received_digest = input_hasher.Finalize();
  if (received_digest != begin.input_digest) {
    XROM_LOGE("input digest mismatch: computed %s, host declared %s",
              Sha256::ToHex(received_digest).c_str(), Sha256::ToHex(begin.input_digest).c_str());
    channel.SendTaskAbort(AbortReason::kInputDigestMismatch, "recomputed digest differs", &error);
    return 1;
  }
  XROM_LOG("input digest verified over %zu bytes", input.size());

  // --- 8. do the work ----------------------------------------------------
  std::vector<uint8_t> output;
  RunTask(static_cast<int32_t>(begin.task_class), input, &output);
  const Sha256Digest output_digest = Sha256::Hash(output.data(), output.size());

  // --- 9. stream the result back -----------------------------------------
  for (size_t offset = 0; offset < output.size(); offset += kOutputChunkBytes) {
    const size_t length = std::min(kOutputChunkBytes, output.size() - offset);
    if (!channel.SendFrame(FrameType::kTaskOutput, output.data() + offset, length, &error)) {
      XROM_LOGE("cannot send kTaskOutput: %s", error.c_str());
      return 1;
    }
  }

  TaskResult result;
  result.nonce = begin.nonce;  // echoed, so the host can tie this to its request
  result.output_digest = output_digest;
  result.payload_lib_digest = self_digest;    // re-sent: a result is only
  result.vm_config_digest = config_digest;    // interpretable with its measurements
  result.exit_code = 0;
  result.output_length = static_cast<uint32_t>(output.size());
  result.attestation_level = AttestationLevel::kMeasurementOnly;
  result.flags = 0;
  if (ComputeInstanceBinding(output_digest, begin.nonce, &result.instance_binding)) {
    result.attestation_level = AttestationLevel::kInstanceBound;
  } else {
    result.instance_binding.fill(0);
  }

  if (!channel.SendTaskResult(result, &error)) {
    XROM_LOGE("cannot send kTaskResult: %s", error.c_str());
    return 1;
  }
  XROM_LOG("result sent: %u output bytes, digest %s, attestation %s", result.output_length,
           Sha256::ToHex(output_digest).c_str(),
           ::xrom::avf::vsock::AttestationLevelName(result.attestation_level));

  channel.Close();
  return 0;
}
