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

#ifndef XROM_AVF_AVF_COMPAT_H_
#define XROM_AVF_AVF_COMPAT_H_

// ---------------------------------------------------------------------------
// Every AVF AIDL revision difference X-ROM knows about, in one file.
//
// The AVF interface is stable and frozen, but it is frozen *per release*, and
// the source shape moved between Android 13 and Android 14. Nothing in this
// daemon should need to know which one it is building against except through
// the macros below.
// ---------------------------------------------------------------------------

// Injected by Soong from XROM_AVF_SOURCE_ABI in device/x1/BoardConfig.mk via
// the xrom_avf_cc_defaults soong_config_module_type in vendor/xrom/Android.bp.
//   13 -> Android 13 (T)
//   14 -> Android 14 and later (U / V / trunk)
#ifndef XROM_AVF_ABI
#define XROM_AVF_ABI 14
#endif

#if XROM_AVF_ABI != 13 && XROM_AVF_ABI != 14
#error "XROM_AVF_ABI must be 13 or 14. Set XROM_AVF_SOURCE_ABI in BoardConfig.mk."
#endif

// --- Difference 1: IVirtualizationService::createVm() arity ---------------
//
//   Android 13      createVm(config, consoleFd, osLogFd)                 3 args
//   Android 14+     createVm(config, consoleOutFd, consoleInFd, osLogFd) 4 args
//
// X-ROM never writes to the guest console, so the extra argument is always a
// null ParcelFileDescriptor. It is passed explicitly rather than defaulted so
// that a future revision adding a fifth parameter is a compile error here and
// not a silent behaviour change.
//
// --- Difference 2: VirtualMachineAppConfig shape --------------------------
//
//   Android 13      flat parcelable: configPath, debugLevel (NONE/APP_ONLY/
//                   FULL), protectedVm, memoryMib, numCpus, cpuAffinity,
//                   taskProfiles. No VM name, no instance id, no osName.
//   Android 14+     name (utf16), instanceId (byte[64]), osName (utf8), a
//                   nested Payload union carrying configPath, cpuTopology
//                   instead of numCpus, debugLevel (NONE/FULL).
//
// Fields X-ROM deliberately does NOT set on any revision, because setting them
// would either widen the permission requirement or pin us to a revision that
// has them: customConfig (USE_CUSTOM_VIRTUAL_MACHINE and a custom kernel),
// encryptedStorageImage, hugePages, boostUclamp.
//
// --- Difference 3: AIDL C++ union tag spelling ---------------------------
//
// The AIDL backends documentation shows union tags as Foo::intField; current
// aidl generates an enum class, Foo::Tag::kIntField. Both spellings are handled
// by XROM_UNION_TAG below. If your tree generates the enum-class form and the
// build fails on a union tag, add this to services/avf/xrom_avfd/Android.bp:
//
//     cflags: ["-DXROM_AIDL_UNION_TAG_ENUM_CLASS"],
//
// It is a build flag rather than a runtime check because the two forms are not
// interchangeable at compile time, and because guessing wrong must fail the
// build loudly instead of selecting the wrong union member.
#ifdef XROM_AIDL_UNION_TAG_ENUM_CLASS
#define XROM_UNION_TAG(Type, lower_field, UpperField) Type::Tag::k##UpperField
#else
#define XROM_UNION_TAG(Type, lower_field, UpperField) Type::lower_field
#endif

// Servicemanager instance name. Stable AIDL services are registered under
// "<interface>/<instance>", and that full string is what service_contexts
// labels — see sepolicy/system_ext_private/service_contexts.
#define XROM_AVF_SERVICE_INSTANCE \
  "android.system.virtualizationservice.IVirtualizationService/virtualization_service"

#endif  // XROM_AVF_AVF_COMPAT_H_
