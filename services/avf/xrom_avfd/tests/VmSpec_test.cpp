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

#include "VmSpec.h"

#include <gtest/gtest.h>

namespace xrom::avf {
namespace {

VmSpec MakeValidSpec() {
  VmSpec spec;
  spec.name = "xrom_attestation_demo";
  spec.task_class = TaskClass::kAttestation;
  spec.debug_level = DebugLevel::kNone;
  spec.protected_vm = true;
  spec.limits.memory_mib = 256;
  spec.limits.vcpu_count = 1;
  spec.limits.cpu_topology = CpuTopology::kOneCpu;
  spec.limits.instance_image_bytes = 64LL * 1024 * 1024;
  spec.os_name = "microdroid";
  spec.payload_apk_path = kPayloadApkPath;
  spec.payload_idsig_path = "/data/misc/xrom/avf/xrom_attestation_demo.idsig";
  spec.instance_image_path = "/data/misc/xrom/avf/xrom_attestation_demo.instance.img";
  spec.config_path_in_apk = "assets/vm_config.json";
  return spec;
}

bool Mentions(const std::vector<std::string>& problems, const std::string& needle) {
  for (const auto& problem : problems) {
    if (problem.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

TEST(VmSpecTest, ValidSpecIsAccepted) {
  EXPECT_TRUE(MakeValidSpec().Validate(/*allow_debuggable=*/false).empty());
}

TEST(VmSpecTest, NameMustCarryTheXRomPrefix) {
  VmSpec spec = MakeValidSpec();
  spec.name = "attestation_demo";
  EXPECT_TRUE(Mentions(spec.Validate(false), "must start with"));
}

TEST(VmSpecTest, NameRejectsPathMetacharacters) {
  // The VM name becomes a filename component inside virtualizationservice, so a
  // traversal sequence here is a write primitive somewhere else.
  for (const char* name : {"xrom_../../etc/passwd", "xrom_a/b", "xrom_a b", "xrom_a\nb",
                           "XROM_UPPER"}) {
    VmSpec spec = MakeValidSpec();
    spec.name = name;
    EXPECT_FALSE(spec.Validate(false).empty()) << "accepted name: " << name;
  }
}

TEST(VmSpecTest, NameLengthIsBounded) {
  VmSpec spec = MakeValidSpec();
  spec.name = "xrom_" + std::string(kVmNameMaxLength, 'a');
  EXPECT_TRUE(Mentions(spec.Validate(false), "exceeds"));
}

TEST(VmSpecTest, AttestationRefusesAnUnprotectedVm) {
  VmSpec spec = MakeValidSpec();
  spec.protected_vm = false;
  EXPECT_TRUE(Mentions(spec.Validate(false), "requires a protected VM"));
}

TEST(VmSpecTest, StaticAnalysisMayRunUnprotected) {
  // Its input is data the host already has, so the VM is containing the parser
  // rather than hiding the input.
  VmSpec spec = MakeValidSpec();
  spec.task_class = TaskClass::kStaticAnalysis;
  spec.protected_vm = false;
  EXPECT_TRUE(spec.Validate(false).empty());
}

TEST(VmSpecTest, DebuggableVmNeedsPermission) {
  VmSpec spec = MakeValidSpec();
  spec.debug_level = DebugLevel::kFull;
  EXPECT_TRUE(Mentions(spec.Validate(false), "debuggable"));
  EXPECT_TRUE(spec.Validate(/*allow_debuggable=*/true).empty());
}

TEST(VmSpecTest, OsNameIsAnAllowlist) {
  VmSpec spec = MakeValidSpec();
  spec.os_name = "debian";
  EXPECT_TRUE(Mentions(spec.Validate(false), "unsupported os_name"));
}

TEST(VmSpecTest, MemoryAndCpuAreBounded) {
  for (int32_t memory : {0, kMinMemoryMib - 1, kMaxMemoryMib + 1}) {
    VmSpec spec = MakeValidSpec();
    spec.limits.memory_mib = memory;
    EXPECT_TRUE(Mentions(spec.Validate(false), "memory_mib")) << "memory_mib=" << memory;
  }
  for (int32_t vcpus : {0, kMaxVCpus + 1}) {
    VmSpec spec = MakeValidSpec();
    spec.limits.vcpu_count = vcpus;
    EXPECT_TRUE(Mentions(spec.Validate(false), "vcpu_count")) << "vcpu_count=" << vcpus;
  }
}

TEST(VmSpecTest, InstanceImageMustBePageAligned) {
  VmSpec spec = MakeValidSpec();
  spec.limits.instance_image_bytes = 64LL * 1024 * 1024 + 1;
  EXPECT_TRUE(Mentions(spec.Validate(false), "multiple of the 4096"));
}

TEST(VmSpecTest, PayloadMustComeFromTheVerifiedPartition) {
  for (const char* path : {"/data/local/tmp/evil.apk", "/sdcard/XVaultPayload.apk",
                           "/system_ext/app/XVaultPayload/../../x/other.apk",
                           "/system_ext/app/XVaultPayload/payload.txt"}) {
    VmSpec spec = MakeValidSpec();
    spec.payload_apk_path = path;
    EXPECT_TRUE(Mentions(spec.Validate(false), "payload_apk_path")) << "accepted: " << path;
  }
}

TEST(VmSpecTest, MutableStateMustStayInTheDaemonDirectory) {
  VmSpec spec = MakeValidSpec();
  spec.instance_image_path = "/data/local/tmp/instance.img";
  EXPECT_TRUE(Mentions(spec.Validate(false), "instance_image_path"));
}

TEST(VmSpecTest, PayloadConfigMustBeAnEmbeddedAsset) {
  for (const char* path : {"/config.json", "config.json", "assets/../config.json",
                           "assets/vm_config.txt"}) {
    VmSpec spec = MakeValidSpec();
    spec.config_path_in_apk = path;
    EXPECT_TRUE(Mentions(spec.Validate(false), "config_path_in_apk")) << "accepted: " << path;
  }
  VmSpec spec = MakeValidSpec();
  spec.config_path_in_apk = "assets/vm_config.json";
  EXPECT_TRUE(spec.Validate(false).empty());
}

TEST(VmSpecTest, EveryProblemIsReportedNotJustTheFirst) {
  VmSpec spec = MakeValidSpec();
  spec.name = "noprefix";
  spec.limits.memory_mib = 1;
  spec.os_name = "debian";
  const std::vector<std::string> problems = spec.Validate(false);
  EXPECT_GE(problems.size(), 3u) << "policy leaked one rule at a time";
}

TEST(VmSpecTest, ToStringOmitsPaths) {
  const std::string rendered = MakeValidSpec().ToString();
  EXPECT_NE(rendered.find("xrom_attestation_demo"), std::string::npos);
  EXPECT_EQ(rendered.find("/system_ext"), std::string::npos);
  EXPECT_EQ(rendered.find("/data/misc"), std::string::npos);
}

// --- IsPathContained -------------------------------------------------------

TEST(IsPathContainedTest, AcceptsAFileInsideTheRoot) {
  EXPECT_TRUE(IsPathContained("/data/misc/xrom/avf/vm.idsig", {"/data/misc/xrom/avf/"}));
  EXPECT_TRUE(IsPathContained("/data/misc/xrom/avf/a/b/c.img", {"/data/misc/xrom/avf/"}));
}

TEST(IsPathContainedTest, RejectsEverythingElse) {
  const std::vector<std::string> roots{"/data/misc/xrom/avf/"};
  for (const char* path : {
           "",                                        // empty
           "data/misc/xrom/avf/x",                    // relative
           "/data/misc/xrom/avf",                     // the root itself, not a file
           "/data/misc/xrom/avf/",                    // trailing slash only
           "/data/misc/xrom/avf/../avf/x",            // traversal that resolves back in
           "/data/misc/xrom/avf/../../etc/passwd",    // traversal out
           "/data/misc/xrom/avf//x",                  // empty component
           "/data/misc/xrom/avf/a b",                 // space
           "/data/misc/xrom/avf/a\nb",                // control character
           "/data/misc/xrom/avf/x ",                  // trailing space
           "/other/x",                                // different root
       }) {
    EXPECT_FALSE(IsPathContained(path, roots)) << "accepted: '" << path << "'";
  }
}

TEST(IsPathContainedTest, RootsMustBeAbsoluteAndSlashTerminated) {
  // A malformed root must never turn into "allow everything".
  EXPECT_FALSE(IsPathContained("/data/misc/xrom/avf/x", {"data/misc/xrom/avf/"}));
  EXPECT_FALSE(IsPathContained("/data/misc/xrom/avf/x", {"/data/misc/xrom/avf"}));
  EXPECT_FALSE(IsPathContained("/data/misc/xrom/avf/x", {}));
}

TEST(IsPathContainedTest, AllowsALegitimateDoubleDotInAFilename) {
  // Component-wise comparison, not a substring search.
  EXPECT_TRUE(IsPathContained("/data/misc/xrom/avf/payload..v2.idsig", {"/data/misc/xrom/avf/"}));
}

}  // namespace
}  // namespace xrom::avf
