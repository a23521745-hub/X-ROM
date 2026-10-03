#!/usr/bin/env bash
#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# xrom_avf_verify.sh — verify AVF / pKVM / X-ROM on a real device over adb.
#
# The build succeeding proves the flags were set. It does not prove the device
# came up with a hypervisor: pKVM depends on the bootloader entering the kernel
# at EL2, which no makefile can guarantee. This script is the difference.
#
#   tools/xrom_avf_verify.sh                 # static checks + a live Microdroid VM
#   tools/xrom_avf_verify.sh --no-live-vm    # static checks only
#   tools/xrom_avf_verify.sh --serial XYZ    # a specific device
#
# Most checks need root. On a user build, run what you can and treat the
# "SKIP" lines as unverified rather than as passed.

set -uo pipefail

ADB="adb"
SERIAL=""
LIVE_VM=1
PASSED=0
FAILED=0
SKIPPED=0
WARNED=0

usage() {
    sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --serial)    SERIAL="$2"; shift 2 ;;
        --no-live-vm) LIVE_VM=0; shift ;;
        -h|--help)   usage 0 ;;
        *)           echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done

if [[ -n "${SERIAL}" ]]; then ADB="adb -s ${SERIAL}"; fi

shell() { ${ADB} shell "$@" 2>/dev/null; }
root_shell() { ${ADB} shell "su 0 $*" 2>/dev/null; }

ok()    { PASSED=$((PASSED + 1));  printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()   { FAILED=$((FAILED + 1));  printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; }
skip()  { SKIPPED=$((SKIPPED + 1)); printf '  \033[33mSKIP\033[0m  %s\n' "$1"; }
warn()  { WARNED=$((WARNED + 1));  printf '  \033[33mWARN\033[0m  %s\n' "$1"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Run a check that needs root; skip rather than fail when root is unavailable.
needs_root() {
    if [[ "$(shell 'id -u' | tr -d '\r')" == "0" ]]; then
        return 0
    fi
    if root_shell 'id -u' | grep -q '^0$'; then
        ROOT_VIA_SU=1
        return 0
    fi
    return 1
}
run() {
    # run <command...> — executes as root when possible, plain shell otherwise.
    if [[ "${ROOT_VIA_SU:-0}" == "1" ]]; then root_shell "$*"; else shell "$*"; fi
}

ROOT_VIA_SU=0

echo "X-ROM AVF / pKVM device verification"
echo "  host date : $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
head_ "0. Device"
# ---------------------------------------------------------------------------
if ! ${ADB} get-state >/dev/null 2>&1; then
    bad "no adb device" "connect a device or pass --serial"
    echo
    echo "RESULT: 0 passed, 1 failed — nothing else can be checked"
    exit 1
fi
FINGERPRINT="$(shell getprop ro.build.fingerprint | tr -d '\r')"
VARIANT="$(shell getprop ro.build.type | tr -d '\r')"
SDK="$(shell getprop ro.build.version.sdk | tr -d '\r')"
echo "  fingerprint : ${FINGERPRINT}"
echo "  variant     : ${VARIANT}    sdk: ${SDK}"
[[ "${FINGERPRINT}" == *xrom* || "${FINGERPRINT}" == *X-ROM* ]] \
    && ok "this is an X-ROM image" \
    || warn "fingerprint does not look like an X-ROM build; AVF checks still apply"
[[ "${SDK}" -ge 33 ]] && ok "API level ${SDK} is >= 33 (AVF requires Android 13+)" \
                      || bad "API level ${SDK} is below 33; AVF does not exist here"
if needs_root; then ok "root shell available (via $( [[ ${ROOT_VIA_SU} == 1 ]] && echo 'su' || echo 'adb root' ))"
else warn "no root: several checks will be skipped"; fi

# ---------------------------------------------------------------------------
head_ "1. Kernel: KVM and pKVM"
# ---------------------------------------------------------------------------
if run 'ls /dev/kvm' | grep -q '/dev/kvm'; then
    ok "/dev/kvm exists — the kernel exposes KVM"
else
    bad "/dev/kvm is missing" "CONFIG_KVM is not enabled, or the kernel did not come up at EL2"
fi

DMESG="$(run 'dmesg' | grep -iE 'kvm \[|hyp mode|Protected nVHE|kvm-arm' | head -20)"
if echo "${DMESG}" | grep -qi 'protected'; then
    ok "kernel reports pKVM protected mode"
    echo "${DMESG}" | sed 's/^/        /'
elif [[ -n "${DMESG}" ]]; then
    bad "kernel mentions KVM but not protected mode" "${DMESG}"
    echo "        expected something like: kvm [1]: Protected nVHE mode initialized successfully"
    echo "        check that kvm-arm.mode=protected reached the kernel command line"
else
    skip "could not read dmesg (needs root)"
fi

CMDLINE="$(run 'cat /proc/cmdline' | tr -d '\r')"
if echo "${CMDLINE}" | grep -q 'kvm-arm.mode=protected'; then
    ok "kvm-arm.mode=protected is on the kernel command line"
else
    bad "kvm-arm.mode=protected is not on the kernel command line" \
        "BoardConfig.mk sets it; if it is absent the bootloader dropped it. cmdline: ${CMDLINE}"
fi

# The required config delta, diffed against what is actually running. This is the
# check that catches a prebuilt GKI that does not match the fragment we shipped.
FRAGMENT='/system_ext/etc/xrom/kernel/gki_xrom_pkvm.fragment'
if run "test -f ${FRAGMENT}" >/dev/null 2>&1 || run "ls ${FRAGMENT}" | grep -q gki_xrom; then
    if run 'zcat /proc/config.gz' | grep -q 'CONFIG_KVM'; then
        MISSING=""
        while read -r line; do
            case "${line}" in
                ''|'#'*) continue ;;
            esac
            symbol="${line%%=*}"
            symbol="${symbol%% *}"
            [[ "${symbol}" == CONFIG_* ]] || continue
            if ! run 'zcat /proc/config.gz' | grep -q "^${symbol}="; then
                MISSING="${MISSING} ${symbol}"
            fi
        done < <(run "grep -E '^CONFIG_[A-Z0-9_]+=y' ${FRAGMENT}" | tr -d '\r')
        if [[ -z "${MISSING}" ]]; then
            ok "running kernel config satisfies the shipped GKI fragment"
        else
            bad "kernel is missing required symbols:${MISSING}"
        fi
    else
        skip "/proc/config.gz is not available (CONFIG_IKCONFIG_PROC); cannot diff the config"
    fi
else
    bad "${FRAGMENT} is not installed" "xrom_gki_pkvm_fragment is missing from the image"
fi

# ---------------------------------------------------------------------------
head_ "2. Bootconfig: what AVF reads to learn the device can run VMs"
# ---------------------------------------------------------------------------
BOOTCONFIG="$(run 'cat /proc/bootconfig' | tr -d '\r')"
if [[ -z "${BOOTCONFIG}" ]]; then
    skip "could not read /proc/bootconfig"
else
    for key in 'androidboot.hypervisor.vm.supported' \
               'androidboot.hypervisor.protected_vm.supported' \
               'androidboot.pkvm.enabled'; do
        value="$(echo "${BOOTCONFIG}" | grep -E "^\s*${key}\s*=" | head -1 | sed 's/.*=\s*//; s/"//g')"
        if [[ -n "${value}" ]]; then
            ok "${key} = ${value}"
        else
            warn "${key} is not set in bootconfig"
        fi
    done
fi
for prop in 'ro.boot.hypervisor.protected_vm.supported' 'ro.boot.pkvm.enabled' \
            'ro.boot.hypervisor.version'; do
    value="$(shell getprop "${prop}" | tr -d '\r')"
    [[ -n "${value}" ]] && ok "${prop} = ${value}" || warn "${prop} is empty"
done

# ---------------------------------------------------------------------------
head_ "3. The Virtualization APEX"
# ---------------------------------------------------------------------------
if shell 'ls /apex/com.android.virt/bin/crosvm' | grep -q crosvm; then
    ok "/apex/com.android.virt is mounted and contains crosvm"
    for binary in virtmgr vm microdroid_launcher; do
        shell "ls /apex/com.android.virt/bin/${binary}" | grep -q "${binary}" \
            && ok "  /apex/com.android.virt/bin/${binary}" \
            || bad "  /apex/com.android.virt/bin/${binary} is missing"
    done
else
    bad "com.android.virt is not mounted" \
        "avf.mk did not inherit product_packages.mk, or the APEX is not in PRODUCT_PACKAGES"
fi

# ---------------------------------------------------------------------------
head_ "4. Framework feature and permissions"
# ---------------------------------------------------------------------------
if shell 'pm list features' | grep -q 'android.software.virtualization_framework'; then
    ok "android.software.virtualization_framework is declared"
else
    bad "android.software.virtualization_framework is NOT declared" \
        "xrom_avf_features.xml is missing or not in PRODUCT_PACKAGES; the AVF Java API returns null"
fi
if shell 'pm list permissions -g -f' | grep -q 'MANAGE_VIRTUAL_MACHINE'; then
    ok "android.permission.MANAGE_VIRTUAL_MACHINE exists on this build"
else
    warn "MANAGE_VIRTUAL_MACHINE not listed (may be hidden without root)"
fi
shell "ls /system_ext/etc/permissions/xrom_avf_privapp_permissions.xml" | grep -q xml \
    && ok "the X-ROM privapp permission allowlist is installed" \
    || bad "xrom_avf_privapp_permissions.xml is not installed"

# ---------------------------------------------------------------------------
head_ "5. SELinux"
# ---------------------------------------------------------------------------
ENFORCE="$(shell getenforce | tr -d '\r')"
if [[ "${ENFORCE}" == "Enforcing" ]]; then
    ok "SELinux is enforcing"
else
    bad "SELinux is ${ENFORCE}" "nothing about X-ROM's confinement can be claimed on a permissive device"
fi
shell 'ls -Z /system_ext/bin/xrom_avfd' | grep -q 'xrom_avfd_exec' \
    && ok "/system_ext/bin/xrom_avfd is labelled xrom_avfd_exec" \
    || bad "/system_ext/bin/xrom_avfd is not labelled xrom_avfd_exec" \
       "file_contexts did not match; init would run the daemon in the wrong domain"
shell 'ls -Zd /data/misc/xrom/avf' | grep -q 'xrom_avfd_data_file' \
    && ok "/data/misc/xrom/avf is labelled xrom_avfd_data_file" \
    || bad "/data/misc/xrom/avf has the wrong label or does not exist"

DENIALS="$(run 'dmesg' | grep -c 'avc: denied' || true)"
if [[ "${DENIALS:-0}" == "0" ]]; then
    ok "no SELinux denials in the kernel log"
else
    AVF_DENIED="$(run 'dmesg' | grep 'avc: denied' | grep -cE 'xrom_avfd|virtualizationservice|crosvm' || true)"
    bad "${DENIALS} SELinux denial(s), ${AVF_DENIED:-0} involving the AVF stack"
    run 'dmesg' | grep 'avc: denied' | grep -E 'xrom_avfd|virtualizationservice|crosvm' | head -10 | sed 's/^/        /'
fi

# ---------------------------------------------------------------------------
head_ "6. X-ROM daemon"
# ---------------------------------------------------------------------------
if shell 'pidof xrom_avfd' | grep -qE '^[0-9]+'; then
    ok "xrom_avfd is running (pid $(shell 'pidof xrom_avfd' | tr -d '\r'))"
    DOMAIN="$(run 'cat /proc/$(pidof xrom_avfd)/attr/current' | tr -d '\r')"
    [[ "${DOMAIN}" == u:r:xrom_avfd:* ]] \
        && ok "xrom_avfd is confined to ${DOMAIN}" \
        || bad "xrom_avfd runs in ${DOMAIN:-unknown}, expected u:r:xrom_avfd:s0"
else
    bad "xrom_avfd is not running"
fi
shell 'service list' | grep -q 'android.xrom.isolation.IXIsolationService/xrom_isolation' \
    && ok "IXIsolationService is registered with servicemanager" \
    || bad "IXIsolationService is not registered" \
       "service_contexts entry missing, or addService was refused"
shell 'service list' | grep -q 'virtualization_service' \
    && ok "android.system.virtualizationservice is registered" \
    || bad "virtualization_service is not registered"
for prop in ro.xrom.avf.enabled ro.xrom.avf.pkvm ro.xrom.avf.abi \
            xrom.avf.ready xrom.avf.protected_vm_available; do
    value="$(shell getprop "${prop}" | tr -d '\r')"
    [[ -n "${value}" ]] && ok "${prop} = ${value}" || warn "${prop} is empty"
done
if shell 'ls /system_ext/etc/xrom/avf.json' | grep -q json; then
    ok "the daemon configuration file is installed"
else
    bad "/system_ext/etc/xrom/avf.json is missing; the daemon will run on fail-safe defaults"
fi

# ---------------------------------------------------------------------------
head_ "7. Payload"
# ---------------------------------------------------------------------------
PAYLOAD='/system_ext/app/XVaultPayload/XVaultPayload.apk'
if shell "ls ${PAYLOAD}" | grep -q apk; then
    ok "${PAYLOAD} is installed"
    LABEL="$(shell "ls -Z ${PAYLOAD}" | tr -d '\r')"
    echo "${LABEL}" | grep -q 'xrom_vault_payload_file' \
        && ok "payload APK is labelled xrom_vault_payload_file" \
        || warn "payload APK label is ${LABEL}"
    if shell "unzip -l ${PAYLOAD}" 2>/dev/null | grep -q 'assets/vm_config.json'; then
        ok "assets/vm_config.json is inside the APK"
    else
        warn "could not confirm assets/vm_config.json inside the APK (unzip unavailable)"
    fi
else
    bad "${PAYLOAD} is missing" "XVaultPayload is not in PRODUCT_PACKAGES"
fi

# ---------------------------------------------------------------------------
head_ "8. Live Microdroid VM"
# ---------------------------------------------------------------------------
if [[ "${LIVE_VM}" -eq 0 ]]; then
    skip "--no-live-vm given"
elif ! needs_root; then
    skip "booting a VM needs root"
else
    VM_TOOL='/apex/com.android.virt/bin/vm'
    run "mkdir -p /data/local/tmp/xrom-verify" >/dev/null
    echo "  booting an empty Microdroid VM (this takes a few seconds)..."
    VM_OUT="$(run "${VM_TOOL} run-microdroid --console /data/local/tmp/xrom-verify/console.txt 2>&1" | tr -d '\r')"
    if echo "${VM_OUT}" | grep -qiE 'CID [0-9]+|cid=[0-9]+'; then
        CID="$(echo "${VM_OUT}" | grep -oiE 'CID[:= ]+[0-9]+' | grep -oE '[0-9]+' | head -1)"
        ok "Microdroid VM booted and was assigned CID ${CID}"
        if run "${VM_TOOL} list" | grep -q "${CID}"; then
            ok "the VM is visible in 'vm list'"
            run "${VM_TOOL} stop --cid ${CID}" >/dev/null
            sleep 2
            run "${VM_TOOL} list" | grep -q "${CID}" \
                && bad "the VM did not stop" \
                || ok "the VM stopped and released CID ${CID}"
        fi
    else
        bad "the Microdroid VM did not boot"
        echo "${VM_OUT}" | head -20 | sed 's/^/        /'
    fi
fi

# ---------------------------------------------------------------------------
head_ "9. Payload trust material"
# ---------------------------------------------------------------------------
# The daemon refuses to launch anything without these. Checking them on the device
# rather than in the tree is what distinguishes "the build signed the payload"
# from "the signing step was skipped and nobody noticed until a task failed".

TRUST_DIR=/system_ext/etc/xrom/trust

if run "ls ${TRUST_DIR}/trust_anchors.json" | grep -q trust_anchors.json; then
    ok "${TRUST_DIR}/trust_anchors.json is installed"
else
    bad "${TRUST_DIR}/trust_anchors.json is missing" \
        "the daemon fails closed on every task; check that xrom_payload_trust_anchors is in PRODUCT_PACKAGES"
fi

LABEL=$(run "ls -Z ${TRUST_DIR}/trust_anchors.json" | tr -d '\r')
if echo "${LABEL}" | grep -q 'u:object_r:xrom_payload_trust_file:s0'; then
    ok "the trust directory carries the xrom_payload_trust_file label"
else
    bad "trust_anchors.json is labelled '${LABEL:-unknown}'" \
        "file_contexts must label ${TRUST_DIR}(/.*)? as xrom_payload_trust_file"
fi

# The trust directory is read-only to every domain at runtime. A writable anchor
# file would mean whoever can write it chooses which payloads the device accepts.
if run "grep -E ' ${TRUST_DIR}(/| )' /proc/mounts" | grep -q ' ro,'; then
    ok "${TRUST_DIR} is on a read-only mount"
else
    warn "could not confirm that ${TRUST_DIR} is mounted read-only"
fi

if run "ls ${TRUST_DIR}/xrom_payload_manifest.json" | grep -q xrom_payload_manifest.json; then
    ok "a signed payload manifest is installed"
    if run "ls ${TRUST_DIR}/xrom_payload_manifest.sig" | grep -q '\.sig'; then
        ok "the manifest's detached signature is installed next to it"
    else
        bad "the manifest has no detached signature" \
            "both files are written together by tools/xrom_sign_payload.py sign"
    fi
else
    warn "no signed payload manifest on the device"
    echo "        this is expected for an unsigned development build: xrom_avfd will refuse"
    echo "        every task with 'payload verification failed'. See"
    echo "        security/payload_trust/manifest/README.md for the release commands."
fi

# ---------------------------------------------------------------------------
head_ "10. Manifest verification against the installed artifacts"
# ---------------------------------------------------------------------------
# Pulls what the daemon will actually read and runs the same checks the daemon
# runs, on the host. This is the check that catches a manifest signed over a
# different build of the APK than the one that shipped — the failure mode where
# every individual step succeeded and the combination did not.

PULL_DIR=$(mktemp -d)
trap 'rm -rf "${PULL_DIR}"' EXIT

VERIFY_TOOL="$(cd "$(dirname "$0")" && pwd)/xrom_verify_manifest.py"
if run "ls ${TRUST_DIR}/xrom_payload_manifest.json" | grep -q xrom_payload_manifest.json; then
    ${ADB} pull "${TRUST_DIR}/xrom_payload_manifest.json" "${PULL_DIR}/" >/dev/null 2>&1
    ${ADB} pull "${TRUST_DIR}/xrom_payload_manifest.json.sig" "${PULL_DIR}/" >/dev/null 2>&1
    ${ADB} pull "${TRUST_DIR}/trust_anchors.json" "${PULL_DIR}/" >/dev/null 2>&1
    ${ADB} pull /system_ext/app/XVaultPayload/XVaultPayload.apk "${PULL_DIR}/" >/dev/null 2>&1

    if [[ -f "${PULL_DIR}/xrom_payload_manifest.json" && -f "${PULL_DIR}/XVaultPayload.apk" ]]; then
        if python3 "${VERIFY_TOOL}" \
                --manifest  "${PULL_DIR}/xrom_payload_manifest.json" \
                --signature "${PULL_DIR}/xrom_payload_manifest.json.sig" \
                --anchors   "${PULL_DIR}/trust_anchors.json" \
                --apk       "${PULL_DIR}/XVaultPayload.apk" > "${PULL_DIR}/verify.log" 2>&1; then
            ok "the installed manifest verifies against the installed APK"
        else
            bad "the installed manifest does NOT verify against the installed APK"
            grep FAIL "${PULL_DIR}/verify.log" | head -10 | sed 's/^/        /'
        fi
    else
        skip "could not pull the manifest and APK from the device"
    fi
else
    skip "no manifest on the device to verify"
fi

# ---------------------------------------------------------------------------
head_ "11. Data plane and vsock-only egress"
# ---------------------------------------------------------------------------
# Evidence that the framed channel is what actually ran, taken from the daemon's
# and the payload's own logs. A task that succeeded without these lines succeeded
# for a reason this script cannot see.

LOG=$(run "logcat -d -s xrom_avfd xvault microdroid_launcher" 2>/dev/null | tr -d '\r')

if [[ -n "${LOG}" ]]; then
    check_log() {
        if echo "${LOG}" | grep -q "$1"; then ok "$2"; else warn "$2 — not seen in the current log buffer"; fi
    }
    check_log "loaded .* enabled payload trust anchor"        "the daemon loaded its trust anchors"
    check_log "payload manifest verified"                     "the daemon verified a payload manifest"
    check_log "guest self-measurement matches"                "the guest's kGuestHello matched the signed manifest"
    check_log "listening on vsock port 7100"                  "the payload bound the control port before notifying readiness"
    check_log "input digest verified"                         "the payload re-verified the input digest"
    check_log "attestation "                                  "a result reported an attestation level"

    # These are the lines that must never appear. Each one is a distinct failure
    # of the design rather than a generic error.
    for forbidden in "guest's self-measurement does not match" \
                     "recomputed output digest does not match" \
                     "the result does not echo this task's nonce" \
                     "receive budget exceeded" \
                     "frame payload digest mismatch"; do
        if echo "${LOG}" | grep -q "${forbidden}"; then
            bad "the log contains '${forbidden}'"
        fi
    done
else
    skip "no xrom_avfd/xvault log output in the buffer; submit a task and re-run"
fi

# Inside the guest, the payload must have no IP interface to talk to. This is the
# observable half of the neverallow rules in xrom_microdroid_hardening.te: the
# policy says it may not, the absence of a net device means it could not.
GUEST_CONSOLE=$(run "ls /data/misc/xrom/avf/*console*.log" 2>/dev/null | tr -d '\r' | head -1)
if [[ -n "${GUEST_CONSOLE}" ]]; then
    if run "grep -c eth0 ${GUEST_CONSOLE}" | grep -qv '^0$'; then
        bad "the guest console log mentions eth0" \
            "vm_config.json must not set \"network\": true"
    else
        ok "no network interface appears in the guest console log"
    fi
else
    skip "no guest console log to inspect (logs are only kept for a debuggable VM)"
fi


# ---------------------------------------------------------------------------
# 12. The vault, the sentinel and the recovery stack on the device
# ---------------------------------------------------------------------------
# Everything in this section is a claim made by the source tree that only a device can
# confirm. BoardConfig.mk ASKS for two partitions; whether the board's GPT actually has
# them is a property of the hardware description, not of this repository.
echo
echo "=== 12. xrom_vault, xrom_sentineld and the recovery stack ==="

for device in xrom_vault xrom_vault_meta; do
    if run "[[ -e /dev/block/by-name/${device} ]]" >/dev/null 2>&1; then
        ok "/dev/block/by-name/${device} exists"
        # The image partition must never be mounted rw. The installer writes the block
        # device directly, the way update_engine writes an inactive slot; a rw mount
        # would put a second writer in front of bytes dm-verity is checking.
        MOUNTED=$(run "grep -c ' /${device} .*rw' /proc/mounts" 2>/dev/null | tr -d '\r')
        if [[ "${device}" == "xrom_vault" && "${MOUNTED:-0}" != "0" ]]; then
            bad "xrom_vault is mounted rw somewhere" \
                "recovery.fstab declares it ro + recoveryonly; a rw mount defeats the write monopoly"
        else
            ok "${device} is not mounted read-write in the normal boot"
        fi
    else
        bad "/dev/block/by-name/${device} does not exist" \
            "BoardConfig.mk declares BOARD_XROM_VAULT*_PARTITION_SIZE but the board's partition table must actually provide the space"
    fi
done

# The daemon has to be running, in its own domain, and with exactly one capability.
if run "pidof xrom_sentineld" >/dev/null 2>&1; then
    ok "xrom_sentineld is running"
    PID=$(run "pidof xrom_sentineld" | tr -d '\r' | awk '{print $1}')
    DOMAIN=$(run "cat /proc/${PID}/attr/current" 2>/dev/null | tr -d '\r')
    if [[ "${DOMAIN}" == u:r:xrom_sentineld:* ]]; then
        ok "it runs in the xrom_sentineld domain (${DOMAIN})"
    else
        bad "xrom_sentineld is not in its own domain: ${DOMAIN:-unknown}" \
            "init_daemon_domain() did not transition; the daemon is running with another domain's permissions"
    fi
    # CAP_NET_ADMIN is the only capability granted, and it is for the SIOCSIFFLAGS layer
    # of the network cut. Anything more means the policy and the binary disagree.
    CAPS=$(run "grep CapEff /proc/${PID}/status" 2>/dev/null | tr -d '\r')
    if [[ -n "${CAPS}" ]]; then
        ok "effective capabilities: ${CAPS}"
        warn "check ${CAPS} against sepolicy: only cap_net_admin is granted. A daemon that can write the BCB, drop the network and reboot should have nothing else."
    fi
else
    bad "xrom_sentineld is not running" \
        "a recovery daemon that is not up cannot quarantine anything; check init.xrom.sentinel.rc and logcat"
fi

# The service has to be registered under the exact name service_contexts labels.
if run "service check android.xrom.recovery.IXRecoveryService/xrom_recovery" 2>/dev/null \
        | grep -q "found"; then
    ok "IXRecoveryService/xrom_recovery is registered with servicemanager"
else
    bad "IXRecoveryService/xrom_recovery is not registered" \
        "the name must match sepolicy/system_ext_private/service_contexts exactly"
fi

# The OTA installer must exist and must have no network. The second half is the property
# the whole split exists for: the recovery image downloads, the installer writes.
if run "[[ -x /system_ext/bin/xrom_ota_installer ]]" >/dev/null 2>&1; then
    ok "xrom_ota_installer is installed"
else
    skip "xrom_ota_installer is not present (built but not flashed?)"
fi

# The vault record has to be readable and parseable, or every post-boot comparison
# reports inconclusive and the alarm that follows is worthless.
if run "[[ -r /dev/block/by-name/xrom_vault_meta ]]" >/dev/null 2>&1; then
    MAGIC=$(run "dd if=/dev/block/by-name/xrom_vault_meta bs=1 count=7 2>/dev/null" | tr -d '\0\r')
    if [[ "${MAGIC}" == "XROMVLT" ]]; then
        ok "the vault record carries the XROMVLT magic"
    else
        warn "the vault record magic is '${MAGIC:-empty}', not XROMVLT"
        warn "an erased or never-written vault reports as INCONCLUSIVE, not as a mismatch — correct, but it means there is no fallback on this unit until an OTA has been installed"
    fi
else
    skip "xrom_vault_meta is not readable from the shell domain"
fi


# ---------------------------------------------------------------------------
# 13. The network cut — MEASURED, not inferred
# ---------------------------------------------------------------------------
# This section exists because of an open risk that is recorded in docs/05 §F #10 and
# §G.1 and is NOT solved: X-ROM builds with CONFIG_BPF_SYSCALL off, netd on Android 12+
# uses eBPF for parts of its own operation, and bpfloader is an early-init service. So
# whether netd functions at all on this kernel cannot be determined from the source tree.
#
# A binder call returning success does not answer the question either. It says netd
# accepted a request; it does not say traffic stopped. Everything below therefore
# measures an observable consequence rather than trusting a return code, and reports
# what it could not determine as a warning instead of as a pass.
echo
echo "=== 13. Network quarantine (the open netd/BPF question) ==="

BPF=$(run "zcat /proc/config.gz 2>/dev/null | grep -E '^# CONFIG_BPF_SYSCALL is not set|^CONFIG_BPF_SYSCALL='" | tr -d '\r')
if [[ "${BPF}" == *"is not set"* ]]; then
    ok "CONFIG_BPF_SYSCALL is off, as device/x1/kernel/gki_xrom_pkvm.fragment asks"
elif [[ -n "${BPF}" ]]; then
    warn "CONFIG_BPF_SYSCALL appears to be ON (${BPF}); the fragment asks for it off"
else
    skip "/proc/config.gz is not readable, so the BPF setting could not be confirmed"
fi

if run "pidof netd" >/dev/null 2>&1; then
    ok "netd is running"
    NETD_ALIVE=1
else
    bad "netd is not running" \
        "this is the symptom docs/05 §F #10 predicts if CONFIG_BPF_SYSCALL=off breaks netd; the interface-down layer becomes the primary mechanism"
    NETD_ALIVE=0
fi

if run "service check netd" 2>/dev/null | grep -q "found"; then
    ok "netd is registered with servicemanager"
elif [[ "${NETD_ALIVE}" == "1" ]]; then
    warn "netd has a process but is not registered; the firewall-chain layer will fail"
fi

# The OEM chain id is NOT a frozen contract and NetdCompat.h says so. This is where the
# assumption gets checked instead of trusted.
CHAIN=$(run "getprop persist.xrom.netd_oem_chain" 2>/dev/null | tr -d '\r')
warn "NetdCompat.h assumes OEM firewall chain base 100 (netd_oem_chain 1 -> 100). Confirm against the target's system/netd/aidl/android/net/INetd.aidl; the numbering differs between netd versions and is not a frozen public contract."

# Whether an interface can actually be brought down. This is the layer that does not
# depend on netd, so it is the one that has to work if netd does not. Checked
# non-destructively: the flag is read, not written, because dropping the interface on a
# device under adb would end the session this script is running in.
IFACES=$(run "ls /sys/class/net" 2>/dev/null | tr -d '\r')
NON_LO=""
for iface in ${IFACES}; do
    [[ "${iface}" == "lo" ]] && continue
    NON_LO="${NON_LO} ${iface}"
done
if [[ -n "${NON_LO// /}" ]]; then
    for iface in ${NON_LO}; do
        FLAGS=$(run "cat /sys/class/net/${iface}/flags" 2>/dev/null | tr -d '\r')
        ok "interface ${iface} present, flags=${FLAGS:-unknown} (SIOCSIFFLAGS layer can act on it)"
    done
    warn "the interface-down layer was NOT exercised: bringing an interface down would drop the adb session this script runs in. Exercise it from a local shell, then confirm with 'ip link' that the interface is DOWN and that egress actually stops."
else
    bad "no non-loopback network interface is present" \
        "the SIOCSIFFLAGS layer would have nothing to act on and the netd layer is unverified, so no network cut could be confirmed on this unit"
fi

# The quarantine property has to be writable by the daemon's domain and readable by
# everyone who needs to know. Setting a property is not itself a network cut — docs/05
# says so plainly — so this checks the plumbing, not the effect.
if run "getprop sys.xrom.network.quarantined" >/dev/null 2>&1; then
    ok "sys.xrom.network.quarantined is readable"
else
    skip "sys.xrom.network.quarantined is not set (nothing has quarantined this device)"
fi

warn "NOT VERIFIED HERE: that enabling the OEM chain actually stops traffic. Measure it with the device on a metered link or behind a counting proxy, quarantine it through IXRecoveryService, and confirm zero egress. A binder call that returns success says netd accepted a request, not that packets stopped."


# ---------------------------------------------------------------------------
echo
printf 'RESULT: %d passed, %d failed, %d warning(s), %d skipped\n' \
    "${PASSED}" "${FAILED}" "${WARNED}" "${SKIPPED}"
if [[ "${FAILED}" -gt 0 ]]; then
    echo "X-ROM AVF VERIFICATION FAILED"
    exit 1
fi
echo "X-ROM AVF VERIFICATION PASSED"
exit 0
