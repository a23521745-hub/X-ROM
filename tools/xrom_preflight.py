#!/usr/bin/env python3
#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
"""Static pre-flight checks for the X-ROM tree.

Run this before spending hours in an AOSP build, and run it in CI on every pull
request. It needs nothing but Python 3.8+:

    python3 tools/xrom_preflight.py                 # check this repository
    python3 tools/xrom_preflight.py --aosp-root $ANDROID_BUILD_TOP   # + AOSP checks

What it looks for is the class of mistake that a build does not catch, because
each half is individually valid:

  * a path in VmSpec.h that does not match the label in file_contexts, so the
    daemon's own validator accepts a file SELinux will then refuse to open
  * a .cpp added to the tree but not to any Android.bp srcs list, so it silently
    never gets compiled
  * a config key DaemonConfig reads that the shipped avf.json does not set, or
    the reverse, so a knob exists that nobody can turn
  * an unknown key in the Microdroid payload config, which fails schema
    validation inside the VM at boot rather than at build time
  * a service name that differs between the AIDL constant, main.cpp and
    service_contexts, so addService succeeds and nothing can find it
  * a SELinux type used in a rule but never declared, or declared but never used

Each check states what it verified and why the invariant matters, because a
failing check that the reader cannot interpret is not much better than no check.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from typing import Iterable

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FAILURES: list[str] = []
WARNINGS: list[str] = []
CHECKS_RUN = 0

SEPOLICY_DIRS = ("sepolicy/system_ext_public", "sepolicy/system_ext_private", "sepolicy/microdroid")

# Keys Microdroid's payload config schema accepts. An unknown top-level key is a
# boot-time failure inside the VM, which is the worst possible place to discover
# a typo.
MICRODROID_CONFIG_KEYS = {
    "os": {"name"},
    "task": {"type", "command"},
    "apexes": None,
    "extra_apks": None,
    "export_tombstones": None,
}

# Keys DaemonConfig::Load() reads out of avf.json.
DAEMON_CONFIG_KEYS = {
    "allow_debuggable_vm",
    "max_concurrent_vms",
    "memory_budget_mib",
    "instance_image_bytes",
    "allowed_uids",
    "vm_launch_timeout_ms",
    "task_timeout_ms",
}

SOURCE_EXTENSIONS = {".cpp", ".h", ".te", ".mk", ".bp", ".rc", ".aidl", ".xml", ".json", ".py", ".sh", ".fragment"}

# JSON has no comment syntax, so a license header cannot be expressed in it.
# vm_config.json in particular is validated against Microdroid's schema, where an
# unknown key is a boot failure. Licensing for these files is covered by the
# repository-level LICENSE and the SPDX headers of the code that reads them.
NO_LICENSE_HEADER_OK = {".json"}


def fail(check: str, message: str) -> None:
    FAILURES.append(f"[{check}] {message}")


def warn(check: str, message: str) -> None:
    WARNINGS.append(f"[{check}] {message}")


def check_started(name: str) -> str:
    global CHECKS_RUN
    CHECKS_RUN += 1
    return name


def rel(path: str) -> str:
    return os.path.relpath(path, REPO_ROOT)


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def walk_sources() -> list[str]:
    out = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", ".hostcheck", "out"}]
        for name in sorted(files):
            if os.path.splitext(name)[1] in SOURCE_EXTENSIONS:
                out.append(os.path.join(root, name))
    return sorted(out)


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------
REQUIRED_FILES = [
    "Android.bp",
    "LICENSE",
    "README.md",
    "device/x1/Android.bp",
    "device/x1/AndroidProducts.mk",
    "device/x1/BoardConfig.mk",
    "device/x1/avf.mk",
    "device/x1/device.mk",
    "device/x1/xrom_x1.mk",
    "device/x1/xrom_board_switches.mk",
    "device/x1/kernel/gki_xrom_pkvm.fragment",
    "device/x1/permissions/xrom_avf_features.xml",
    "device/x1/permissions/xrom_avf_privapp_permissions.xml",
    "device/x1/rootdir/init.xrom.avf.rc",
    "device/x1/vintf/compatibility_matrix.xml",
    "device/x1/vintf/manifest.xml",
    "device/x1/microdroid/xvault/Android.bp",
    "device/x1/microdroid/xvault/AndroidManifest.xml",
    "device/x1/microdroid/xvault/assets/vm_config.json",
    "device/x1/microdroid/xvault/payload/xvault_payload.cpp",
    "common/protocol/Android.bp",
    "common/protocol/VsockProtocol.h",
    "aidl/Android.bp",
    "aidl/android/xrom/isolation/IXIsolationService.aidl",
    "aidl/android/xrom/isolation/IIsolationTaskCallback.aidl",
    "aidl/android/xrom/isolation/IsolationTaskRequest.aidl",
    "aidl/android/xrom/isolation/IsolationTaskResult.aidl",
    "aidl/android/xrom/isolation/TaskClass.aidl",
    "aidl/android/xrom/isolation/TaskState.aidl",
    "sepolicy/system_ext_public/service.te",
    "sepolicy/system_ext_public/xrom_avfd.te",
    "sepolicy/system_ext_private/file.te",
    "sepolicy/system_ext_private/file_contexts",
    "sepolicy/system_ext_private/property.te",
    "sepolicy/system_ext_private/property_contexts",
    "sepolicy/system_ext_private/service_contexts",
    "sepolicy/system_ext_private/xrom_avfd.te",
    "sepolicy/microdroid/xrom_microdroid_hardening.te",
    "services/avf/xrom_avfd/Android.bp",
    "services/avf/xrom_avfd/AvfCompat.h",
    "services/avf/xrom_avfd/AvfController.cpp",
    "services/avf/xrom_avfd/AvfController.h",
    "services/avf/xrom_avfd/DaemonConfig.cpp",
    "services/avf/xrom_avfd/DaemonConfig.h",
    "services/avf/xrom_avfd/IsolationPolicy.cpp",
    "services/avf/xrom_avfd/IsolationPolicy.h",
    "services/avf/xrom_avfd/IsolationService.cpp",
    "services/avf/xrom_avfd/IsolationService.h",
    "services/avf/xrom_avfd/MicrodroidVmBuilder.cpp",
    "services/avf/xrom_avfd/MicrodroidVmBuilder.h",
    "services/avf/xrom_avfd/VmLifecycleObserver.cpp",
    "services/avf/xrom_avfd/VmLifecycleObserver.h",
    "services/avf/xrom_avfd/VmSpec.cpp",
    "services/avf/xrom_avfd/VmSpec.h",
    "services/avf/xrom_avfd/main.cpp",
    "services/avf/xrom_avfd/xrom_avfd_config.json",
    "services/avf/xrom_avfd/tests/Android.bp",
    "services/avf/xrom_avfd/tests/IsolationPolicy_test.cpp",
    "services/avf/xrom_avfd/tests/VmSpec_test.cpp",
    "tools/hostcheck/hostcheck_main.cpp",
    "tools/hostcheck/run_host_tests.sh",
    "tools/xrom_avf_verify.sh",
]


def check_structure() -> None:
    name = check_started("structure")
    for path in REQUIRED_FILES:
        absolute = os.path.join(REPO_ROOT, path)
        if not os.path.isfile(absolute):
            fail(name, f"missing required file: {path}")
        elif os.path.getsize(absolute) == 0:
            fail(name, f"required file is empty: {path}")


def check_license_headers() -> None:
    name = check_started("license")
    for path in walk_sources():
        if os.path.splitext(path)[1] in NO_LICENSE_HEADER_OK:
            continue
        text = read(path)
        head = text[:2000]
        if "SPDX-License-Identifier: Apache-2.0" in head:
            continue
        if "http://www.apache.org/licenses/LICENSE-2.0" in head:
            continue
        fail(name, f"{rel(path)} carries no Apache-2.0 license header")


# ---------------------------------------------------------------------------
# Syntax-level sanity: balanced delimiters and block keywords
# ---------------------------------------------------------------------------
def strip_noise(text: str, line_comment: str, block_comment: bool,
                char_literals: bool = False) -> str:
    """Single-pass removal of comments and string literals.

    A regex per construct is not enough: `"//"` inside a string must not be read
    as a comment, and a quote inside a comment must not start a string. Doing it
    in one left-to-right scan is the only order that gets both right, and getting
    it wrong makes the delimiter balance check report phantom failures on paths
    like /data/misc/xrom/avf//x.

    |char_literals| additionally removes C++ character literals, and is opt-in
    because `'` means something else in the other languages this is used on.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if block_comment and ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
            continue
        if line_comment and text.startswith(line_comment, i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
            continue
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            out.append('""')
            continue
        if char_literals and ch == "'":
            # A C++ character literal. Without this branch, `case '"':` reads as
            # the start of a string literal: the scanner swallows everything up to
            # the next double quote and unbalances the very braces the caller is
            # counting. That is not a hypothetical — it is what the JSON escaper in
            # common/ota/OtaManifest.cpp does, and the balance check reported the
            # file as unbalanced until this branch existed.
            #
            # Opt-in rather than always on, because SELinux policy is m4-flavoured
            # and uses `'` as a closing quote: define(`xrom_avfd_client', ...).
            # Stripping `'...'` there would eat the macro names that
            # check_sepolicy_types looks for.
            if out and out[-1].isdigit() and nxt.isdigit():
                out.append(ch)  # C++14 digit separator: 1'000'000
                i += 1
                continue
            j = i + 1
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            j += 1
            # A real character literal is a handful of characters at most. An
            # unterminated or implausible span means this `'` was not a literal,
            # and failing open — emitting it and moving on — is better than
            # swallowing the rest of the file.
            if 2 <= j - i <= 12:
                out.append("''")
                i = j
                continue
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def check_balanced() -> None:
    name = check_started("balance")
    for path in walk_sources():
        ext = os.path.splitext(path)[1]
        text = read(path)
        if ext in {".bp", ".cpp", ".h", ".aidl"}:
            # Preprocessor lines are dropped before counting: a macro may define
            # an entry point whose brace lives on the expansion line, and the
            # source text is then legitimately unbalanced.
            kept = "\n".join(line for line in text.splitlines()
                             if not line.lstrip().startswith("#"))
            cleaned = strip_noise(kept, "//", True, char_literals=True)
            pairs = {"{": "}", "(": ")", "[": "]"}
            stack: list[str] = []
            for ch in cleaned:
                if ch in pairs:
                    stack.append(pairs[ch])
                elif ch in pairs.values():
                    if not stack or stack.pop() != ch:
                        fail(name, f"{rel(path)}: unbalanced '{ch}'")
                        break
            else:
                if stack:
                    fail(name, f"{rel(path)}: unclosed {stack}")
        elif ext == ".te":
            cleaned = strip_noise(text, "#", False)
            for opener, closer in (("{", "}"), ("(", ")")):
                if cleaned.count(opener) != cleaned.count(closer):
                    fail(name, f"{rel(path)}: {cleaned.count(opener)} '{opener}' vs "
                               f"{cleaned.count(closer)} '{closer}'")
        elif ext == ".mk":
            keywords = re.findall(r"^\s*(ifeq|ifneq|ifdef|ifndef|else|endif)\b", text, re.M)
            depth = 0
            for keyword in keywords:
                if keyword in {"ifeq", "ifneq", "ifdef", "ifndef"}:
                    depth += 1
                elif keyword == "endif":
                    depth -= 1
                    if depth < 0:
                        fail(name, f"{rel(path)}: 'endif' without a matching conditional")
                        break
            if depth != 0:
                fail(name, f"{rel(path)}: {depth} unclosed conditional block(s)")


def check_xml_and_json() -> None:
    name = check_started("xml/json")
    for path in walk_sources():
        ext = os.path.splitext(path)[1]
        try:
            if ext == ".xml":
                ET.parse(path)
            elif ext == ".json":
                with open(path, "r", encoding="utf-8") as handle:
                    json.load(handle)
        except Exception as exc:  # noqa: BLE001 - report any parse failure verbatim
            fail(name, f"{rel(path)} does not parse: {exc}")


# ---------------------------------------------------------------------------
# Microdroid payload config
# ---------------------------------------------------------------------------
def check_microdroid_config() -> None:
    name = check_started("microdroid-config")
    path = os.path.join(REPO_ROOT, "device/x1/microdroid/xvault/assets/vm_config.json")
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        fail(name, f"vm_config.json does not parse: {exc}")
        return

    for key in config:
        if key not in MICRODROID_CONFIG_KEYS:
            fail(name, f"vm_config.json has unknown top-level key '{key}'. Microdroid validates "
                       "this file against config_schema.xsd inside the VM, so an unknown key is a "
                       "boot failure, not a warning. Put commentary in a README instead.")
    for key, allowed in MICRODROID_CONFIG_KEYS.items():
        if allowed is None or key not in config:
            continue
        for subkey in config[key]:
            if subkey not in allowed:
                fail(name, f"vm_config.json '{key}' has unknown key '{subkey}'")

    command = config.get("task", {}).get("command", "")
    if not command.endswith(".so"):
        fail(name, "vm_config.json task.command must name a shared library")
        return
    library_name = command[:-3]
    payload_bp = read(os.path.join(REPO_ROOT, "device/x1/microdroid/xvault/Android.bp"))
    if f'name: "{library_name}"' not in payload_bp:
        fail(name, f"vm_config.json asks microdroid_launcher to run '{command}' but no module "
                   f"named '{library_name}' is defined in the payload Android.bp")
    if 'jni_libs: ["' + library_name + '"]' not in payload_bp:
        fail(name, f"'{library_name}' is not listed in the APK's jni_libs, so it will not be "
                   "inside XVaultPayload.apk and microdroid_launcher will not find it")


# ---------------------------------------------------------------------------
# Daemon configuration
# ---------------------------------------------------------------------------
def check_daemon_config() -> None:
    name = check_started("daemon-config")
    config_path = os.path.join(REPO_ROOT, "services/avf/xrom_avfd/xrom_avfd_config.json")
    source_path = os.path.join(REPO_ROOT, "services/avf/xrom_avfd/DaemonConfig.cpp")
    if not (os.path.isfile(config_path) and os.path.isfile(source_path)):
        return
    with open(config_path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    source = read(source_path)

    shipped = {k for k in config if not k.startswith("_")}
    documented = {k for k in config if k.startswith("_")} | {
        k[1:] for k in config if k.startswith("_")
    }

    for key in shipped - DAEMON_CONFIG_KEYS:
        fail(name, f"avf.json sets '{key}' but DaemonConfig::Load() never reads it; a knob that "
                   "does nothing is worse than no knob")
    for key in DAEMON_CONFIG_KEYS - shipped:
        fail(name, f"DaemonConfig::Load() reads '{key}' but avf.json does not set it, so the "
                   "shipped image silently uses the compiled-in default")
    for key in shipped:
        if f"_{key}" not in documented:
            warn(name, f"avf.json key '{key}' has no '_{key}' explanation")
    # Every key must actually be read through one of the typed readers.
    for key in shipped:
        if f'"{key}"' not in source:
            fail(name, f"'{key}' is not referenced by name in DaemonConfig.cpp")


# ---------------------------------------------------------------------------
# Soong: every source file must be compiled by something
# ---------------------------------------------------------------------------
def collect_bp_srcs(bp_text: str) -> set[str]:
    srcs: set[str] = set()
    for block in re.findall(r"srcs:\s*\[(.*?)\]", bp_text, flags=re.S):
        for entry in re.findall(r'"([^"]+)"', block):
            srcs.add(os.path.basename(entry))
    return srcs


def check_bp_covers_sources() -> None:
    name = check_started("soong-coverage")
    for directory in ("services/avf/xrom_avfd", "device/x1/microdroid/xvault"):
        absolute = os.path.join(REPO_ROOT, directory)
        bp_files = [os.path.join(root, f)
                    for root, _, files in os.walk(absolute) for f in files if f == "Android.bp"]
        if not bp_files:
            fail(name, f"{directory} has no Android.bp")
            continue
        compiled: set[str] = set()
        for bp in bp_files:
            compiled |= collect_bp_srcs(read(bp))
        for root, dirs, files in os.walk(absolute):
            dirs[:] = [d for d in dirs if d != "tests"]
            for entry in sorted(files):
                if not entry.endswith(".cpp"):
                    continue
                if entry not in compiled:
                    fail(name, f"{rel(os.path.join(root, entry))} is not listed in any srcs: "
                               "it will never be compiled")
    # The test sources are covered by tests/Android.bp.
    tests_dir = os.path.join(REPO_ROOT, "services/avf/xrom_avfd/tests")
    if os.path.isdir(tests_dir):
        compiled = collect_bp_srcs(read(os.path.join(tests_dir, "Android.bp")))
        for entry in sorted(os.listdir(tests_dir)):
            if entry.endswith(".cpp") and entry not in compiled:
                fail(name, f"tests/{entry} is not listed in tests/Android.bp srcs")


# ---------------------------------------------------------------------------
# SELinux
# ---------------------------------------------------------------------------
def te_files() -> list[str]:
    out = []
    for directory in SEPOLICY_DIRS:
        absolute = os.path.join(REPO_ROOT, directory)
        if not os.path.isdir(absolute):
            continue
        for entry in sorted(os.listdir(absolute)):
            if entry.endswith(".te"):
                out.append(os.path.join(absolute, entry))
    return out


def check_sepolicy_types() -> None:
    name = check_started("sepolicy-types")
    declared: set[str] = set()
    referenced: set[str] = set()
    for path in te_files():
        text = strip_noise(read(path), "#", False)
        declared |= set(re.findall(r"^\s*(?:type|attribute)\s+(xrom_[a-z0-9_]+)", text, re.M))
        # m4 macros are declarations too: xrom_avfd_client() is defined in the
        # public policy and consumed from the private half.
        declared |= set(re.findall(r"define\(`(xrom_[a-z0-9_]+)'", text))
        referenced |= set(re.findall(r"\bxrom_[a-z0-9_]+\b", text))
    for name_used in sorted(referenced - declared):
        fail(name, f"'{name_used}' is used in a .te rule but never declared with `type` or "
                   "`attribute`; the policy build will fail, or worse, an m4 macro will swallow it")
    for name_declared in sorted(declared - referenced):
        warn(name, f"'{name_declared}' is declared but never referenced by any rule")


def check_sepolicy_contexts() -> None:
    name = check_started("sepolicy-contexts")
    private = os.path.join(REPO_ROOT, "sepolicy/system_ext_private")
    declared = set()
    for path in te_files():
        declared |= set(re.findall(r"^\s*(?:type|attribute)\s+(xrom_[a-z0-9_]+)",
                                   strip_noise(read(path), "#", False), re.M))

    for contexts_file in ("file_contexts", "property_contexts", "service_contexts"):
        path = os.path.join(private, contexts_file)
        if not os.path.isfile(path):
            fail(name, f"missing {contexts_file}")
            continue
        for line in read(path).splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                fail(name, f"{contexts_file}: malformed line '{line}'")
                continue
            context = parts[1]
            match = re.match(r"^u:object_r:([a-z0-9_]+):s0$", context)
            if not match:
                fail(name, f"{contexts_file}: '{context}' is not u:object_r:<type>:s0")
                continue
            if match.group(1).startswith("xrom_") and match.group(1) not in declared:
                fail(name, f"{contexts_file} labels with undeclared type '{match.group(1)}'")

    # Every declared file/data/service/property type should be reachable from a
    # contexts file, otherwise it exists in the policy but nothing is ever
    # labelled with it.
    labelled = set()
    for contexts_file in ("file_contexts", "property_contexts", "service_contexts"):
        path = os.path.join(private, contexts_file)
        if os.path.isfile(path):
            labelled |= set(re.findall(r"u:object_r:([a-z0-9_]+):s0", read(path)))

    # A type declared with the `domain` attribute is a process domain: it is entered
    # through a transition from an exec type, never used as a label in a contexts
    # file. Derived from the policy rather than from a hardcoded list, because a list
    # has to be remembered and updated every time a domain is added, and forgetting it
    # produces a warning that looks like a real problem.
    process_domains = set()
    for path in te_files():
        text = strip_noise(read(path), "#", False)
        for type_name, attrs in re.findall(
                r"^\s*type\s+(xrom_[a-z0-9_]+)\s*,([^;]*);", text, re.M):
            if re.search(r"\bdomain\b", attrs):
                process_domains.add(type_name)

    for type_name in sorted(declared):
        if type_name.endswith("_exec"):
            continue  # an exec type is what a transition matches on, not a label
        if type_name in process_domains:
            continue
        if type_name in {"xrom_avfd", "xrom_isolated_payload"}:
            # Kept for the domains declared outside this tree's .te files.
            continue
        if type_name not in labelled:
            warn(name, f"type '{type_name}' is declared but no contexts file uses it as a label")


def check_sepolicy_least_privilege() -> None:
    """The daemon policy must contain the denials X-ROM's threat model rests on."""
    name = check_started("sepolicy-hardening")
    path = os.path.join(REPO_ROOT, "sepolicy/system_ext_private/xrom_avfd.te")
    if not os.path.isfile(path):
        return
    text = strip_noise(read(path), "#", False)
    required_neverallows = [
        (r"neverallow\s+xrom_avfd\s+kvm_device:chr_file",
         "/dev/kvm must belong to crosvm alone; if the daemon can open it, a bug in the daemon is "
         "a hypervisor-escape primitive"),
        (r"neverallow\s+xrom_avfd\s+self:capability\s*\{[^}]*sys_module",
         "the daemon must not be able to load kernel modules"),
        (r"neverallow\s+xrom_avfd\s+self:vsock_socket\s*\{[^}]*listen",
         "the daemon must not be able to open a listening vsock; that would be a second, "
         "unaudited channel into every VM"),
        (r"neverallow\s+\{\s*domain\s+-xrom_avfd\s+-init\s*\}\s+xrom_avfd_data_file:file",
         "no other domain may open the daemon's per-VM state"),
        (r"neverallow\s+\{[^}]*appdomain[^}]*\}\s+xrom_avf_service:service_manager\s+find",
         "apps must not be able to resolve the isolation service"),
    ]
    for pattern, why in required_neverallows:
        if not re.search(pattern, text, re.S):
            fail(name, f"missing neverallow: {why}")

    if "virtualizationservice_use(xrom_avfd)" not in text:
        fail(name, "the daemon does not use AOSP's virtualizationservice_use() macro; hand-rolled "
                   "AVF policy will not track the Android 15 move to virtualizationmanager")
    # \b matters: "neverallow xrom_avfd kvm_device" contains the substring
    # "allow xrom_avfd kvm_device", and reading a denial as a grant would invert
    # the check.
    for forbidden in (r"\ballow\s+xrom_avfd\s+kvm_device", r"\ballow\s+xrom_avfd\s+self:capability\s+sys_admin"):
        if re.search(forbidden, text):
            fail(name, f"the daemon is granted something it must be denied ({forbidden})")


# ---------------------------------------------------------------------------
# Cross-file agreement
# ---------------------------------------------------------------------------
def vm_spec_constants() -> dict[str, str]:
    text = read(os.path.join(REPO_ROOT, "services/avf/xrom_avfd/VmSpec.h"))
    return dict(re.findall(r'inline constexpr char (k\w+)\[\] = "([^"]*)"', text))


def check_paths_agree() -> None:
    name = check_started("path-agreement")
    constants = vm_spec_constants()
    for required in ("kPayloadApkRoot", "kPayloadApkPath", "kStateRoot", "kInboxRoot",
                     "kConfigPathInApk"):
        if required not in constants:
            fail(name, f"VmSpec.h does not define {required}")
    if not all(k in constants for k in ("kPayloadApkRoot", "kStateRoot", "kInboxRoot")):
        return

    file_contexts = read(os.path.join(REPO_ROOT, "sepolicy/system_ext_private/file_contexts"))
    labelled_paths = re.findall(r"^(/\S+)", file_contexts, re.M)

    def is_labelled(path: str) -> bool:
        """True if some file_contexts pattern covers |path|.

        The patterns in file_contexts are POSIX-ish regular expressions, so they
        are converted to Python ones by unescaping the dots AOSP escapes and
        turning the conventional (/.*)? suffix into a plain wildcard.
        """
        target = path.rstrip("/")
        for pattern in labelled_paths:
            regex = pattern.replace(r"\.", ".")
            regex = regex.replace("(/.*)?", "(/.*)?")
            try:
                if re.match(regex + "$", target) or re.match(regex + "/", target):
                    return True
            except re.error:
                continue
        return False

    # The payload APK must be inside a directory that carries a dedicated label,
    # otherwise it inherits system_file and the daemon's r_file_perms on
    # xrom_vault_payload_file would not apply to it.
    root = constants["kPayloadApkRoot"]
    if not any(root.rstrip("/").replace("/", r"/") in p for p in labelled_paths):
        fail(name, f"file_contexts does not label {root}; the payload APK would fall back to "
                   "system_file and xrom_vault_payload_file rules would not match")
    if not constants["kPayloadApkPath"].startswith(root):
        fail(name, f"kPayloadApkPath {constants['kPayloadApkPath']} is not inside kPayloadApkRoot "
                   f"{root}")

    # init must create the directories the daemon and its callers rely on, with
    # the modes the policy assumes.
    init_rc = read(os.path.join(REPO_ROOT, "device/x1/rootdir/init.xrom.avf.rc"))
    created = dict(re.findall(r"^\s*mkdir\s+(\S+)\s+(\S+)", init_rc, re.M))
    for directory, mode in ((constants["kStateRoot"].rstrip("/"), "0700"),
                            (constants["kInboxRoot"].rstrip("/"), "0770")):
        if directory not in created:
            fail(name, f"init.xrom.avf.rc never creates {directory}")
        elif created[directory] != mode:
            fail(name, f"init.xrom.avf.rc creates {directory} with mode {created[directory]}, "
                       f"expected {mode}")
        if not is_labelled(directory + "/"):
            fail(name, f"{directory} is not covered by any file_contexts entry, so it would be "
                       "labelled with a default type and the daemon's rules would not apply")


def check_service_name_agrees() -> None:
    name = check_started("service-name")
    aidl = read(os.path.join(REPO_ROOT, "aidl/android/xrom/isolation/IXIsolationService.aidl"))
    main = read(os.path.join(REPO_ROOT, "services/avf/xrom_avfd/main.cpp"))
    contexts = read(os.path.join(REPO_ROOT, "sepolicy/system_ext_private/service_contexts"))

    instance = re.search(r'const String INSTANCE = "([^"]+)"', aidl)
    registered = re.search(r'kServiceName\[\] = "([^"]+)"', main)
    labelled = re.findall(r"^(\S+)\s+u:object_r:", contexts, re.M)

    if not (instance and registered):
        fail(name, "could not locate the service name in the AIDL and main.cpp")
        return
    interface, _, inst = registered.group(1).partition("/")
    if inst != instance.group(1):
        fail(name, f"main.cpp registers instance '{inst}' but the AIDL declares INSTANCE = "
                   f"'{instance.group(1)}'")
    if interface != "android.xrom.isolation.IXIsolationService":
        fail(name, f"main.cpp registers interface '{interface}', which does not match the AIDL "
                   "package and interface name")
    if registered.group(1) not in labelled:
        fail(name, f"service_contexts does not label '{registered.group(1)}'; servicemanager will "
                   "refuse addService under an enforcing policy")


def check_board_switch_ordering() -> None:
    """AOSP reads product config before BoardConfig.mk; the switches must be shared.

    This is the invariant that silently breaks AVF: a variable assigned in
    BoardConfig.mk is invisible to device.mk and avf.mk, so avf.mk would inherit
    nothing, set no Soong config and ship an image with no AVF — while the build
    reported success.
    """
    name = check_started("switch-ordering")
    switches = os.path.join(REPO_ROOT, "device/x1/xrom_board_switches.mk")
    board = os.path.join(REPO_ROOT, "device/x1/BoardConfig.mk")
    device = os.path.join(REPO_ROOT, "device/x1/device.mk")
    include_line = "include vendor/xrom/device/x1/xrom_board_switches.mk"

    if not os.path.isfile(switches):
        fail(name, "device/x1/xrom_board_switches.mk is missing")
        return
    for path in (board, device):
        text = read(path)
        if include_line not in text:
            fail(name, f"{rel(path)} does not include xrom_board_switches.mk; the AVF switches "
                       "defined in BoardConfig.mk would be invisible to product configuration")
        for switch in re.findall(r"^(XROM_[A-Z0-9_]+)\s*[?:]?=", read(switches), re.M):
            if re.search(rf"^{re.escape(switch)}\s*:=", text, re.M):
                fail(name, f"{rel(path)} assigns {switch} directly; it must come from "
                           "xrom_board_switches.mk so both halves see the same value")

    text = read(switches)
    for switch in ("XROM_ENABLE_AVF", "XROM_ENABLE_PKVM", "XROM_AVF_SOURCE_ABI",
                   "XROM_TARGET_HAS_PVMFW", "XROM_BOARD_SETS_HYPERVISOR_BOOTCONFIG"):
        if not re.search(rf"^{switch}\s*\?=", text, re.M):
            fail(name, f"{switch} is not defined with ?= in xrom_board_switches.mk, so a board "
                       "or command-line override cannot win")


def check_avf_abi_plumbing() -> None:
    name = check_started("avf-abi")
    board = read(os.path.join(REPO_ROOT, "device/x1/BoardConfig.mk"))
    switches = read(os.path.join(REPO_ROOT, "device/x1/xrom_board_switches.mk"))
    root_bp = read(os.path.join(REPO_ROOT, "Android.bp"))
    daemon_bp = read(os.path.join(REPO_ROOT, "services/avf/xrom_avfd/Android.bp"))
    avf_mk = read(os.path.join(REPO_ROOT, "device/x1/avf.mk"))

    setting = re.search(r"^XROM_AVF_SOURCE_ABI\s*\?=\s*(\S+)", switches, re.M)
    if not setting:
        fail(name, "xrom_board_switches.mk does not set XROM_AVF_SOURCE_ABI")
        return
    value = setting.group(1)

    if f'$(call soong_config_set,xrom,avf_abi,$(XROM_AVF_SOURCE_ABI))' not in avf_mk:
        fail(name, "avf.mk does not forward XROM_AVF_SOURCE_ABI to Soong, so the daemon cannot "
                   "learn which AVF AIDL shape to compile against")
    for candidate in ("ANDROID_13", "ANDROID_14_PLUS"):
        if candidate not in root_bp:
            fail(name, f"vendor/xrom/Android.bp does not handle avf_abi={candidate}")
        expected = "-DXROM_AVF_ABI=13" if candidate == "ANDROID_13" else "-DXROM_AVF_ABI=14"
        if expected not in root_bp:
            fail(name, f"{candidate} does not map to {expected}")
    if value not in root_bp:
        fail(name, f"XROM_AVF_SOURCE_ABI='{value}' is not a value the Soong config handles")
    if "xrom_avfd_abi_defaults" not in daemon_bp:
        fail(name, "xrom_avfd does not inherit xrom_avfd_abi_defaults, so -DXROM_AVF_ABI is never "
                   "passed to the compiler and AvfCompat.h silently falls back to its default")
    if "#if XROM_AVF_ABI" not in read(os.path.join(
            REPO_ROOT, "services/avf/xrom_avfd/MicrodroidVmBuilder.cpp")):
        fail(name, "MicrodroidVmBuilder.cpp has no ABI-conditional code, so the Android 13 and "
                   "Android 14+ AIDL shapes cannot both be supported")

    # The pKVM command line must be a kernel parameter, and the androidboot.*
    # keys must be bootconfig. Getting this the wrong way round produces a
    # kernel that boots without a hypervisor and no error at build time.
    if re.search(r"BOARD_KERNEL_CMDLINE\s*\+=\s*androidboot\.", board):
        fail(name, "androidboot.* must go in BOARD_BOOTCONFIG, not BOARD_KERNEL_CMDLINE; on a "
                   "GKI boot-header-v4 device init reads these from /proc/bootconfig")
    if re.search(r"BOARD_BOOTCONFIG\s*\+=\s*kvm-arm\.mode", board):
        fail(name, "kvm-arm.mode=protected is a kernel parameter and belongs on "
                   "BOARD_KERNEL_CMDLINE, not in bootconfig")
    if "kvm-arm.mode=protected" not in board:
        fail(name, "BoardConfig.mk never puts kvm-arm.mode=protected on the kernel command line; "
                   "CONFIG_KVM alone gives plain KVM, not pKVM")


def check_avf_product_wiring() -> None:
    name = check_started("avf-product")
    avf_mk = read(os.path.join(REPO_ROOT, "device/x1/avf.mk"))
    device_mk = read(os.path.join(REPO_ROOT, "device/x1/device.mk"))

    if "packages/modules/Virtualization/build/apex/product_packages.mk" not in avf_mk or \
       "packages/modules/Virtualization/apex/product_packages.mk" not in avf_mk:
        fail(name, "avf.mk must probe both product_packages.mk locations; AOSP moved the file "
                   "between Android 14 and Android 15")
    if "inherit-product,$(XROM_AVF_PACKAGES_MK)" not in avf_mk:
        fail(name, "avf.mk does not inherit the located AVF product_packages.mk")
    if "$(error" not in avf_mk:
        fail(name, "avf.mk should fail the build when AVF is enabled but the Virtualization "
                   "module is absent, rather than quietly producing an image without AVF")
    if "inherit-product, vendor/xrom/device/x1/avf.mk" not in device_mk:
        fail(name, "device.mk does not include avf.mk")
    for module in ("xrom_avfd", "xrom_isolation-cpp", "XVaultPayload", "xrom_avf_features.xml",
                   "init.xrom.avf.rc"):
        if module not in avf_mk:
            fail(name, f"'{module}' is not in PRODUCT_PACKAGES, so it will not be in the image")

    features = read(os.path.join(REPO_ROOT, "device/x1/permissions/xrom_avf_features.xml"))
    if "android.software.virtualization_framework" not in features:
        fail(name, "the AVF feature is not declared; VirtualMachineManager will be null and the "
                   "AVF VTS will report that the device does not support AVF")


# ---------------------------------------------------------------------------
# Optional: checks that need a real AOSP tree
# ---------------------------------------------------------------------------
def check_against_aosp(aosp_root: str) -> None:
    name = check_started("aosp")
    if not os.path.isdir(aosp_root):
        fail(name, f"--aosp-root {aosp_root} is not a directory")
        return

    virt = os.path.join(aosp_root, "packages/modules/Virtualization")
    if not os.path.isdir(virt):
        fail(name, "packages/modules/Virtualization is absent from this tree; AVF cannot be built")
        return
    located = None
    for candidate in ("build/apex/product_packages.mk", "apex/product_packages.mk"):
        if os.path.isfile(os.path.join(virt, candidate)):
            located = candidate
            break
    if located is None:
        fail(name, "neither product_packages.mk location exists in this Virtualization module")
    else:
        print(f"  aosp: AVF product packages at packages/modules/Virtualization/{located}")

    aidl_dir = None
    for candidate in ("android/virtualizationservice/aidl", "virtualizationservice/aidl"):
        if os.path.isdir(os.path.join(virt, candidate)):
            aidl_dir = os.path.join(virt, candidate)
            break
    if aidl_dir is None:
        fail(name, "could not locate the virtualizationservice AIDL directory")
    else:
        frozen = os.path.join(virt, "aidl_api/android.system.virtualizationservice")
        versions = sorted(d for d in os.listdir(frozen) if d.isdigit()) if os.path.isdir(frozen) else []
        print(f"  aosp: virtualizationservice AIDL at {rel(aidl_dir) if aosp_root == REPO_ROOT else aidl_dir}")
        print(f"  aosp: frozen AIDL versions available: {versions or 'none (ToT only)'}")
        app_config = os.path.join(aidl_dir, "android/system/virtualizationservice",
                                  "VirtualMachineAppConfig.aidl")
        if os.path.isfile(app_config):
            text = read(app_config)
            shape = "Android 14+ (name/instanceId/Payload union)" if "instanceId" in text \
                else "Android 13 (flat parcelable with configPath)"
            print(f"  aosp: VirtualMachineAppConfig shape -> {shape}")
            setting = re.search(r"^XROM_AVF_SOURCE_ABI\s*\?=\s*(\S+)",
                                read(os.path.join(REPO_ROOT, "device/x1/xrom_board_switches.mk")), re.M)
            if setting:
                want_14 = setting.group(1) == "ANDROID_14_PLUS"
                have_14 = "instanceId" in text
                if want_14 != have_14:
                    fail(name, f"XROM_AVF_SOURCE_ABI={setting.group(1)} but this tree's "
                               f"VirtualMachineAppConfig is the {shape}")

    te_macros = os.path.join(aosp_root, "system/sepolicy/public/te_macros")
    if os.path.isfile(te_macros):
        if "virtualizationservice_use" not in read(te_macros):
            fail(name, "system/sepolicy/public/te_macros does not define "
                       "virtualizationservice_use(); X-ROM's daemon policy depends on it")
        else:
            print("  aosp: virtualizationservice_use() macro present")
    else:
        fail(name, "system/sepolicy/public/te_macros not found")

    if not os.path.isdir(os.path.join(aosp_root, "system/sepolicy/microdroid")):
        warn(name, "system/sepolicy/microdroid is absent; the guest-side hardening overlay has "
                   "nowhere to be installed")


# ---------------------------------------------------------------------------
# ===========================================================================
# Session 2: the data plane, payload signing and output verification
# ===========================================================================

# Includes that would make code under common/ unlinkable from a Microdroid
# payload. The guest gets the NDK library set, so anything platform-shaped in a
# shared file is a build break on the device and a silent divergence on the host.
FORBIDDEN_IN_SHARED_CODE = (
    "android-base/",
    "binder/",
    "utils/",
    "log/log.h",
    "json/json.h",
    "openssl/",
    "cutils/",
    "aidl/",
)


def check_shared_code_is_dependency_free() -> None:
    """Everything the guest links must compile against nothing but libc++."""
    name = check_started("shared code is dependency free")
    shared_dirs = ("common/crypto", "common/protocol", "common/vsock")
    for shared in shared_dirs:
        directory = os.path.join(REPO_ROOT, shared)
        if not os.path.isdir(directory):
            fail(name, f"{shared} is missing")
            continue
        for entry in sorted(os.listdir(directory)):
            if not entry.endswith((".h", ".cpp")):
                continue
            text = read(os.path.join(directory, entry))
            for forbidden in FORBIDDEN_IN_SHARED_CODE:
                if f"#include <{forbidden}" in text or f'#include "{forbidden}' in text:
                    fail(name, f"{shared}/{entry} includes <{forbidden}...>, which the "
                               f"Microdroid payload cannot link against")
        bp = read(os.path.join(directory, "Android.bp"))
        # The payload needs an NDK variant of every shared library it links, or
        # Soong refuses the dependency outright.
        if "_ndk" not in bp:
            fail(name, f"{shared}/Android.bp defines no *_ndk module, so the Microdroid "
                       f"payload cannot link this code")
        if "host_supported: true" not in bp:
            fail(name, f"{shared}/Android.bp is not host_supported, so the transport tests "
                       f"cannot run on a build machine")

    # The payload must not reach past the shared layer into the daemon's sources.
    payload = read(os.path.join(REPO_ROOT, "device/x1/microdroid/xvault/payload/xvault_payload.cpp"))
    if '#include "IsolationService.h"' in payload or '#include "PayloadVerifier.h"' in payload:
        fail(name, "the guest payload includes a daemon header; the two sides may only share "
                   "common/")
    bp = read(os.path.join(REPO_ROOT, "device/x1/microdroid/xvault/Android.bp"))
    if "libxrom_vsock_channel_ndk" not in bp:
        fail(name, "the payload module does not link libxrom_vsock_channel_ndk")
    for module in ("libxrom_sha256_ndk", "libxrom_vsock_protocol_ndk"):
        if module not in read(os.path.join(REPO_ROOT, "common/vsock/Android.bp")) + \
                        read(os.path.join(REPO_ROOT, "common/protocol/Android.bp")) + \
                        read(os.path.join(REPO_ROOT, "common/crypto/Android.bp")):
            fail(name, f"{module} is not defined anywhere")


def check_protocol_layout() -> None:
    """The wire contract, and that the two ends enumerate it the same way."""
    name = check_started("protocol wire layout")
    header_path = os.path.join(REPO_ROOT, "common/protocol/VsockProtocol.h")
    if not os.path.isfile(header_path):
        fail(name, "common/protocol/VsockProtocol.h is missing")
        return
    header = read(header_path)
    source = read(os.path.join(REPO_ROOT, "common/protocol/VsockProtocol.cpp"))

    # Every wire struct must have a static_assert on its size. A packed struct
    # whose size changes silently is a protocol that stops working across a build.
    structs = re.findall(r"struct (\w+Payload|FrameHeader) \{", header)
    for struct in structs:
        if f"sizeof({struct}) ==" not in header:
            fail(name, f"struct {struct} has no static_assert on its size")

    # Enumerators and the switch statements that interpret them must agree. A new
    # reason that the decoder rejects is a guest abort the host cannot read.
    for enum_name, known_fn, name_fn in (
        ("AbortReason", "IsKnownAbortReason", "AbortReasonName"),
        ("AttestationLevel", "IsKnownAttestationLevel", "AttestationLevelName"),
    ):
        block = re.search(rf"enum class {enum_name}[^{{]*\{{(.*?)\n\}};", header, re.S)
        if not block:
            fail(name, f"enum class {enum_name} not found in VsockProtocol.h")
            continue
        enumerators = re.findall(r"^\s*(k\w+)\s*=", block.group(1), re.M)
        if not enumerators:
            fail(name, f"no enumerators parsed for {enum_name}")
            continue
        for enumerator in enumerators:
            fn = re.search(rf"bool {known_fn}\([^)]*\) \{{(.*?)\n\}}", source, re.S)
            if fn and f"{enum_name}::{enumerator}" not in fn.group(1):
                fail(name, f"{known_fn}() does not handle {enum_name}::{enumerator}")
            render = re.search(rf"const char\* {name_fn}\([^)]*\) \{{(.*?)\n\}}", source, re.S)
            if render and f"{enum_name}::{enumerator}" not in render.group(1):
                fail(name, f"{name_fn}() does not render {enum_name}::{enumerator}")

    # The frame type list is what DecodeHeader accepts; a type that is enumerated
    # but not accepted cannot be sent at all.
    frame_block = re.search(r"enum class FrameType[^{]*\{(.*?)\n\};", header, re.S)
    if not frame_block:
        fail(name, "enum class FrameType not found in VsockProtocol.h")
        return
    types = re.findall(r"^\s*(k\w+)\s*=\s*\d+,", frame_block.group(1), re.M)
    if len(types) < 7:
        fail(name, f"expected at least 7 frame types, found {len(types)}")
    known = re.search(r"bool IsKnownFrameType\(uint32_t raw_type\) \{(.*?)\n\}", source, re.S)
    if known:
        for frame_type in types:
            if f"FrameType::{frame_type}" not in known.group(1):
                fail(name, f"IsKnownFrameType() does not accept FrameType::{frame_type}")

    # Both ends must agree on the ports and the ceilings; these are the numbers a
    # future guest written in another language has to match.
    for constant in ("kPortTaskControl", "kPortTaskData", "kMaxInputBytes", "kMaxOutputBytes",
                     "kFrameMagic", "kProtocolVersion"):
        if constant not in header:
            fail(name, f"{constant} is not defined in VsockProtocol.h")
    payload = read(os.path.join(REPO_ROOT, "device/x1/microdroid/xvault/payload/xvault_payload.cpp"))
    for constant in ("kPortTaskControl", "kMaxInputBytes", "kProtocolVersion"):
        if constant not in payload:
            fail(name, f"the payload does not use vsock::{constant} from the shared header, so it "
                       f"has its own copy of the constant")


def check_vsock_only_egress() -> None:
    """The payload's only route out of the VM is the control vsock."""
    name = check_started("payload egress is vsock only")
    te_path = os.path.join(REPO_ROOT, "sepolicy/microdroid/xrom_microdroid_hardening.te")
    if not os.path.isfile(te_path):
        fail(name, "sepolicy/microdroid/xrom_microdroid_hardening.te is missing")
        return
    policy = read(te_path)

    # Each family is asserted separately so that dropping one is a visible edit
    # rather than an invisible narrowing of a list.
    for family in ("packet_socket", "rawip_socket", "tcp_socket", "udp_socket", "sctp_socket",
                   "dccp_socket", "socket"):
        if not re.search(rf"neverallow xrom_isolated_payload self:{family} \*;", policy):
            fail(name, f"no neverallow on self:{family} for xrom_isolated_payload")
    for family in ("netlink_route_socket", "netlink_xfrm_socket", "netlink_netfilter_socket"):
        if family not in policy:
            fail(name, f"{family} is not covered by the netlink neverallow block")

    # The positive half: vsock must be granted, or the data plane cannot exist.
    if "allow microdroid_payload self:vsock_socket" not in policy:
        fail(name, "microdroid_payload is not granted vsock_socket; the payload cannot listen")

    # No net device for the payload, which is what makes the neverallow rules a
    # second line of defence rather than the only one.
    config_path = os.path.join(REPO_ROOT, "device/x1/microdroid/xvault/assets/vm_config.json")
    if os.path.isfile(config_path):
        config = json.loads(read(config_path))
        if config.get("network") is True:
            fail(name, "vm_config.json sets \"network\": true, which gives the payload a net "
                       "device and contradicts the vsock-only hardening")
    else:
        fail(name, "assets/vm_config.json is missing")


def check_payload_trust_material() -> None:
    """Trust anchors are well formed, public-only, and installed where the code looks."""
    name = check_started("payload trust material")
    trust_dir = os.path.join(REPO_ROOT, "security/payload_trust")
    anchors_path = os.path.join(trust_dir, "trust_anchors.json")
    if not os.path.isfile(anchors_path):
        fail(name, "security/payload_trust/trust_anchors.json is missing; the daemon would fail "
                   "closed on every task with no way to say why")
        return

    try:
        anchors = json.loads(read(anchors_path))["trust_anchors"]
    except (ValueError, KeyError, TypeError) as exc:
        fail(name, f"trust_anchors.json is not a trust_anchors file: {exc}")
        return
    if not isinstance(anchors, list) or not anchors:
        fail(name, "trust_anchors.json contains no anchors; the daemon fails closed")
        return

    enabled = 0
    for anchor in anchors:
        key_id = anchor.get("key_id")
        if not isinstance(key_id, str) or not key_id or len(key_id) > 64:
            fail(name, "an anchor has an invalid key_id")
            continue
        algorithm = anchor.get("algorithm")
        if algorithm not in ("ED25519", "RSA4096_SHA256"):
            fail(name, f"anchor {key_id} has an unsupported algorithm {algorithm!r}")
            continue
        der = base64.b64decode(anchor.get("public_key_base64", "") or "", validate=False)
        if not der or len(der) > 1024:
            fail(name, f"anchor {key_id} has no usable public_key_base64")
            continue
        if algorithm == "ED25519":
            if not der.startswith(bytes.fromhex("302a300506032b6570032100")) or len(der) != 44:
                fail(name, f"anchor {key_id} declares ED25519 but its DER is {len(der)} bytes and "
                           f"not an Ed25519 SubjectPublicKeyInfo")
        else:
            if bytes.fromhex("06092a864886f70d010101") not in der:
                fail(name, f"anchor {key_id} declares RSA but its DER has no rsaEncryption OID")
        if anchor.get("enabled") is not False:
            enabled += 1
    if enabled == 0:
        fail(name, "every trust anchor is disabled, so no payload can ever be verified")

    # A private key in the tree is a release-blocking leak, checked mechanically
    # rather than by review.
    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "security")):
        dirs[:] = [d for d in dirs if d != ".git"]
        for entry in files:
            path = os.path.join(root, entry)
            if entry.endswith(".pem") and not entry.endswith(".pub.pem"):
                fail(name, f"{rel(path)} looks like a private key committed to the tree")
            if entry.endswith((".pem", ".json", ".sig")):
                text = read(path)
                if "PRIVATE KEY" in text:
                    fail(name, f"{rel(path)} contains private key material")

    # The install location has to be the one the code and the SELinux label name.
    spec = read(os.path.join(REPO_ROOT, "services/avf/xrom_avfd/VmSpec.h"))
    match = re.search(r'kPayloadTrustRoot\[\] = "([^"]+)"', spec)
    if not match:
        fail(name, "VmSpec.h does not define kPayloadTrustRoot")
        return
    trust_root = match.group(1)
    contexts = read(os.path.join(REPO_ROOT, "sepolicy/system_ext_private/file_contexts"))
    escaped = re.escape(trust_root.rstrip("/")).replace("/", "/")
    if not re.search(re.escape(trust_root.rstrip("/")).replace(r"/", r"/") + r"\(/\.\*\)\?",
                     contexts):
        fail(name, f"file_contexts does not label {trust_root}(/.*)?")
    if "xrom_payload_trust_file" not in read(
            os.path.join(REPO_ROOT, "sepolicy/system_ext_private/file.te")):
        fail(name, "the xrom_payload_trust_file type is not declared")
    bp = read(os.path.join(trust_dir, "Android.bp"))
    if 'sub_dir: "xrom/trust"' not in bp:
        fail(name, f"security/payload_trust/Android.bp does not install under xrom/trust, so the "
                   f"files will not land in {trust_root}")
    if "system_ext_specific: true" not in bp:
        fail(name, "the trust material is not installed to system_ext")

    # The signed manifest is a release artifact. Its absence is not a failure of
    # the tree, but it must be visible: without it nothing can run.
    manifest = os.path.join(trust_dir, "manifest/xrom_payload_manifest.json")
    signature = manifest + ".sig"
    if not os.path.isfile(manifest) or not os.path.isfile(signature):
        warn(name, "no signed payload manifest in security/payload_trust/manifest/ — the daemon "
                   "will fail closed on every task until one is generated with "
                   "tools/xrom_sign_payload.py (see security/payload_trust/manifest/README.md)")
    elif not os.path.isfile(signature):
        fail(name, "a manifest is present with no detached signature")


def check_data_plane_wiring() -> None:
    """The host and the guest actually speak the protocol, in the right order."""
    name = check_started("data plane wiring")
    service_path = os.path.join(REPO_ROOT, "services/avf/xrom_avfd/IsolationService.cpp")
    service = read(service_path)

    if "SESSION 1 SCOPE" in service:
        fail(name, "IsolationService.cpp still carries a SESSION 1 SCOPE marker; the data plane "
                   "is not wired")
    if "result.outputDigest = {};" in service and "RunDataExchange" not in service:
        fail(name, "IsolationService.cpp leaves outputDigest empty with no data exchange")

    # The host must verify the payload before it creates a VM, not after.
    verify_at = service.find("verifier_.Verify(")
    start_at = service.find("controller_->StartVm(")
    idsig_at = service.find("controller_->EnsureIdsig(")
    if verify_at < 0:
        fail(name, "IsolationService.cpp never calls PayloadVerifier::Verify")
    else:
        if start_at > 0 and verify_at > start_at:
            fail(name, "the payload is verified after StartVm; a rejected payload must never "
                       "reach the hypervisor")
        if idsig_at > 0 and verify_at > idsig_at:
            fail(name, "the payload is verified after EnsureIdsig; verification must be the "
                       "first thing that happens")

    # The checks that make outputDigest mean something.
    for required, why in (
        ("ReceiveGuestHello", "the host never reads the guest's self-measurement"),
        ("payload_lib_sha256", "the guest's measured library is not compared to the manifest"),
        ("kMeasurementRejected", "a measurement mismatch is not reported to the guest"),
        ("RAND_bytes", "the task nonce is not generated from a CSPRNG"),
        ("reported.nonce != nonce", "the result's nonce is not compared to the one sent"),
        ("output_hasher.Finalize()", "the host does not recompute the output digest"),
        ("EvaluatePayloadTrust", "the task class is not checked against the signed manifest"),
        ("WaitForPayloadReady", "the host connects before the guest is listening"),
    ):
        if required not in service:
            fail(name, f"{why} ({required!r} is absent from IsolationService.cpp)")

    # The guest must listen before it announces readiness, and identify itself
    # before it accepts input.
    payload = read(os.path.join(REPO_ROOT, "device/x1/microdroid/xvault/payload/xvault_payload.cpp"))
    # Only the entry point counts. Each of these names also appears in a helper
    # definition and in the file's header comment, where the order is prose rather
    # than execution.
    entry_at = payload.find("XROM_PAYLOAD_ENTRY() {")
    if entry_at < 0:
        fail(name, "the payload has no AVmPayload_main entry point")
        return
    entry = payload[entry_at:]
    listen_at = entry.find("ListenOnControlPort(")
    notify_at = entry.find("AVmPayload_notifyPayloadReady()")
    accept_at = entry.find("AcceptWithTimeout(")
    hello_at = entry.find("SendGuestHello(")
    begin_at = entry.find("ReceiveTaskBegin(")
    for label, position in (("ListenOnControlPort", listen_at), ("notifyPayloadReady", notify_at),
                            ("AcceptWithTimeout", accept_at), ("SendGuestHello", hello_at),
                            ("ReceiveTaskBegin", begin_at)):
        if position < 0:
            fail(name, f"the payload never calls {label}")
    if min(x for x in (listen_at, notify_at, accept_at, hello_at, begin_at) if x >= 0) >= 0:
        if not listen_at < notify_at < accept_at < hello_at < begin_at:
            fail(name, "the payload's ordering is wrong: it must listen, then notify ready, then "
                       "accept, then send kGuestHello, then wait for kTaskBegin")
    for required, why in (
        ("/proc/self/exe", "the payload does not measure the binary it is actually running"),
        ("AVmPayload_getApkContentsPath", "the payload cannot find vm_config.json to measure"),
        ("AVmPayload_getVmInstanceSecret", "there is no instance binding, so a result frame is "
                                           "transferable between VM instances"),
        ("input_hasher.Finalize()", "the payload does not recompute the input digest"),
        ("kInputDigestMismatch", "an input digest mismatch is not reported to the host"),
        ("kHostCid", "the payload does not check that its peer is the host"),
    ):
        if required not in payload:
            fail(name, f"{why} ({required!r} is absent from xvault_payload.cpp)")

    # The channel both ends use must be the same one.
    controller = read(os.path.join(REPO_ROOT, "services/avf/xrom_avfd/AvfController.cpp"))
    if "connectVsock(" not in controller:
        fail(name, "AvfController never calls IVirtualMachine::connectVsock")


def check_host_tests_are_wired() -> None:
    """Every test file runs under both runners, or it does not run at all."""
    name = check_started("host tests are wired")
    runner_path = os.path.join(REPO_ROOT, "tools/hostcheck/run_host_tests.sh")
    runner = read(runner_path)

    test_dirs = ("common/tests", "services/avf/xrom_avfd/tests")
    for test_dir in test_dirs:
        directory = os.path.join(REPO_ROOT, test_dir)
        if not os.path.isdir(directory):
            fail(name, f"{test_dir} is missing")
            continue
        bp = read(os.path.join(directory, "Android.bp"))
        for entry in sorted(os.listdir(directory)):
            if not entry.endswith("_test.cpp"):
                continue
            if entry not in bp:
                fail(name, f"{test_dir}/{entry} is not listed in its Android.bp, so atest never "
                           f"runs it")
            if f"{test_dir}/{entry}" not in runner:
                fail(name, f"{test_dir}/{entry} is not compiled by tools/hostcheck/"
                           f"run_host_tests.sh, so CI never runs it")

    # Every non-test source the suites need must be on the compile line, or the
    # runner fails with an undefined symbol rather than with a test failure.
    for source in ("common/crypto/Sha256.cpp", "common/protocol/VsockProtocol.cpp",
                   "common/vsock/VsockChannel.cpp", "services/avf/xrom_avfd/VmSpec.cpp",
                   "services/avf/xrom_avfd/IsolationPolicy.cpp",
                   "services/avf/xrom_avfd/PayloadManifest.cpp"):
        if source not in runner:
            fail(name, f"run_host_tests.sh does not compile {source}")

    signing_test = os.path.join(REPO_ROOT, "tools/tests/payload_signing_roundtrip.sh")
    if not os.path.isfile(signing_test):
        fail(name, "tools/tests/payload_signing_roundtrip.sh is missing; the signing format would "
                   "have no end-to-end test")
    elif not os.access(signing_test, os.X_OK):
        warn(name, "tools/tests/payload_signing_roundtrip.sh is not executable")


def check_signing_tools() -> None:
    """The release tools exist, parse and agree with the daemon's expectations."""
    name = check_started("payload signing tools")
    for tool in ("tools/xrom_sign_payload.py", "tools/xrom_verify_manifest.py"):
        path = os.path.join(REPO_ROOT, tool)
        if not os.path.isfile(path):
            fail(name, f"{tool} is missing")
            continue
        try:
            compile(read(path), tool, "exec")
        except SyntaxError as exc:
            fail(name, f"{tool} does not parse: {exc}")
        if not os.access(path, os.X_OK):
            warn(name, f"{tool} is not executable")

    # The ceilings the tools enforce must be the ones the daemon enforces, or a
    # manifest can be signed that the device will refuse.
    verifier = read(os.path.join(REPO_ROOT, "services/avf/xrom_avfd/PayloadVerifier.cpp"))
    verify_tool = read(os.path.join(REPO_ROOT, "tools/xrom_verify_manifest.py"))
    for constant, value in (("kMaxManifestBytes", "64 * 1024"),
                            ("kMaxSignatureBytes", "1024"),
                            ("kMaxPublicKeyDerBytes", "1024")):
        if f"{constant} = {value}" not in verifier:
            fail(name, f"PayloadVerifier.cpp does not define {constant} = {value}")
    for value in ("MAX_MANIFEST_BYTES = 64 * 1024", "MAX_SIGNATURE_BYTES = 1024",
                  "MAX_PUBLIC_KEY_BYTES = 1024"):
        if value not in verify_tool:
            fail(name, f"xrom_verify_manifest.py does not enforce {value}")
    if "MANIFEST_VERSION = 1" not in verify_tool:
        fail(name, "xrom_verify_manifest.py does not pin the manifest version")
    manifest_header = read(os.path.join(REPO_ROOT, "services/avf/xrom_avfd/PayloadManifest.h"))
    if "kManifestVersion = 1" not in manifest_header:
        fail(name, "PayloadManifest.h does not pin kManifestVersion = 1")

    # AIDL and the wire protocol must describe the same three levels.
    aidl = read(os.path.join(REPO_ROOT, "aidl/android/xrom/isolation/AttestationLevel.aidl"))
    protocol = read(os.path.join(REPO_ROOT, "common/protocol/VsockProtocol.h"))
    for aidl_value, wire_value in (("MEASUREMENT_ONLY = 0", "kMeasurementOnly = 0"),
                                   ("INSTANCE_BOUND = 1", "kInstanceBound = 1"),
                                   ("REMOTE_ATTESTED = 2", "kRemoteAttested = 2")):
        if aidl_value not in aidl:
            fail(name, f"AttestationLevel.aidl is missing {aidl_value}")
        if wire_value not in protocol:
            fail(name, f"VsockProtocol.h is missing {wire_value}")


def main() -> int:
    parser = argparse.ArgumentParser(description="X-ROM static pre-flight checks")
    parser.add_argument("--aosp-root", help="path to a full AOSP checkout for cross-tree checks")
    parser.add_argument("--quiet", action="store_true", help="only print failures")
    args = parser.parse_args()

    print("X-ROM pre-flight")
    print(f"  repository: {REPO_ROOT}")

    check_structure()
    check_license_headers()
    check_balanced()
    check_xml_and_json()
    check_microdroid_config()
    check_daemon_config()
    check_bp_covers_sources()
    check_sepolicy_types()
    check_sepolicy_contexts()
    check_sepolicy_least_privilege()
    check_paths_agree()
    check_service_name_agrees()
    check_board_switch_ordering()
    check_avf_abi_plumbing()
    check_avf_product_wiring()
    check_shared_code_is_dependency_free()
    check_protocol_layout()
    check_vsock_only_egress()
    check_payload_trust_material()
    check_data_plane_wiring()
    check_host_tests_are_wired()
    check_signing_tools()
    if args.aosp_root:
        check_against_aosp(os.path.abspath(args.aosp_root))

    for message in WARNINGS:
        print(f"  WARN {message}")
    for message in FAILURES:
        print(f"  FAIL {message}")

    print()
    print(f"{CHECKS_RUN} check groups, {len(FAILURES)} failure(s), {len(WARNINGS)} warning(s)")
    if FAILURES:
        print("PRE-FLIGHT FAILED")
        return 1
    print("PRE-FLIGHT PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
