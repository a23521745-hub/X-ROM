# X-ROM kernel configuration

`gki_xrom_pkvm.fragment` is the GKI config delta X-ROM requires. It is **not** a
standalone `.config`. There are two supported ways to make it real, and which
one applies depends on whether you build the kernel from source.

## Path A — build the ACK kernel from source (recommended)

The fragment is merged over `gki_defconfig` by the Soong `kernel_build` in the
Android Common Kernel tree:

```
kernel_build {
    name: "kernel_aarch64",
    defconfig: "gki_defconfig",
    defconfig_fragments: [
        {
            name: "xrom_pkvm_hardening",
            srcs: ["vendor/xrom/device/x1/kernel/gki_xrom_pkvm.fragment"],
        },
    ],
    // ... existing properties unchanged ...
}
```

The `defconfig_fragments` property name and struct shape have moved between ACK
branches. Confirm against your own `common/Android.bp` before editing — the
mechanism is stable, the spelling is not.

GKI imposes a KMI symbol list, so a fragment may only *enable* features; it may
not change the layout of exported structures. Everything in
`gki_xrom_pkvm.fragment` is within that constraint.

## Path B — prebuilt GKI

If you ship Google's prebuilt GKI you cannot change its config, so the fragment
becomes a **verification contract** instead of an input. Two things enforce it:

1. `prebuilt_etc { name: "xrom_gki_pkvm_fragment" }` installs it to
   `/system_ext/etc/xrom/kernel/gki_xrom_pkvm.fragment`.
2. `tools/xrom_avf_verify.sh` pulls `/proc/config.gz` off the device and diffs
   it against that fragment. Any missing symbol fails the check.

In practice Google's GKI already ships `CONFIG_KVM=y` and every
`[gki-default]` symbol above, so Path B passes today. The value of the check is
that it keeps passing: a future GKI that drops, say, `CONFIG_ARM64_MTE` turns
into a red CI job rather than a silently weaker X-ROM.

## pKVM is not a Kconfig option

This trips people up. `CONFIG_KVM=y` gives you KVM. What turns KVM into pKVM is
booting the host kernel at EL2 with:

```
kvm-arm.mode=protected
```

which `BoardConfig.mk` puts on `BOARD_KERNEL_CMDLINE`. The bootloader must hand
control to the kernel at EL2; if it drops to EL1 first, `kvm-arm.mode=protected`
is ignored and the kernel logs that it is running without a hypervisor. Verify
with:

```
adb shell dmesg | grep -i 'kvm \['
# pKVM:  kvm [1]: Protected nVHE mode initialized successfully
# no pKVM: kvm [1]: KVM: hyp mode initialization failed  /  CPU: all CPU(s) started at EL1
```

## Guest side (Microdroid)

The Microdroid guest kernel is built by `packages/modules/Virtualization`, not
by this tree. It needs `CONFIG_ARM_PKVM_GUEST=y` so it can issue the share /
unshare hypercalls that let the guest expose selected IPA ranges back to the
host VMM. Do not set that symbol on the host — see section 1 of the fragment.
