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
package android.xrom.isolation;

/**
 * How strongly an IsolationTaskResult is backed by evidence that it came from the
 * payload that was verified before launch.
 *
 * This enum exists because "the VM produced this" is not one property but three
 * different ones with very different strengths, and a caller deciding whether to
 * trust an outputDigest needs to know which one it got. The values mirror
 * vsock::AttestationLevel in common/protocol/VsockProtocol.h.
 *
 * The daemon may DOWNGRADE the level the guest reported — when the guest claims
 * more than the host can corroborate, the host reports what it could check. It
 * never upgrades.
 *
 * WHAT IS DELIBERATELY NOT CLAIMED
 * --------------------------------
 * Neither MEASUREMENT_ONLY nor INSTANCE_BOUND is a cryptographic proof of origin
 * that the host can verify. Both are statements the host can check for
 * self-consistency against material it already pinned; only REMOTE_ATTESTED
 * carries a signature the host can verify with a key it did not give the guest.
 * REMOTE_ATTESTED is unreachable in X-ROM's shipped configuration, because AVF
 * remote attestation needs RKP, and RKP needs network access, and X-ROM's
 * Microdroid payloads are hardened to vsock-only egress. Reporting a level the
 * device cannot reach would be worse than not having the enum at all, so the
 * honest ceiling here is INSTANCE_BOUND. See
 * docs/04-vsock-data-plane-and-payload-signing.md.
 */
@Backing(type="int")
enum AttestationLevel {
    /**
     * The host pinned the SHA-256 of the payload APK and library in a signed
     * manifest, and the guest independently measured the same artifacts from
     * inside the VM and reported matching digests in kGuestHello and again in
     * kTaskResult.
     *
     * This is what pKVM plus pvmfw plus the X-ROM manifest give you, and it is
     * always available. What it rules out is a substituted payload: the bytes the
     * guest is executing are the bytes X-ROM signed. What it does not rule out is
     * a dishonest host, which is why the digests are re-sent with the result.
     */
    MEASUREMENT_ONLY = 0,

    /**
     * Additionally bound to this VM instance. The result carries a SHA-256 over a
     * secret from AVmPayload_getVmInstanceSecret(), mixed with the request nonce
     * and the output digest. That secret is derived from a device-specific
     * hypervisor value, the payload's code and its non-modifiable configuration;
     * it is stable across stop and restart while the VM identity is unchanged and
     * it is not available to the host or to any other VM.
     *
     * What this buys is that a recorded kTaskResult cannot be replayed as the
     * answer to a different request or presented as coming from a different VM
     * instance, and that the payload itself can detect a replay across boots.
     * The host cannot recompute the binding, so this is not host-verifiable proof.
     */
    INSTANCE_BOUND = 1,

    /**
     * Additionally backed by AVF remote attestation: an RKP certificate chain
     * whose leaf carries the challenge and the payload's codeHash, plus an ECDSA
     * P-256 signature made with a key only that pVM holds. This is the only level
     * at which the host can verify origin with public-key cryptography.
     *
     * Requires API level 35 or later, the AVF remote attestation release flag, RKP
     * provisioning, and network access from the payload — which the vsock-only
     * hardening in sepolicy/microdroid/xrom_microdroid_hardening.te forbids. The
     * daemon never reports this level unless every part of that chain actually
     * verified, and in the shipped configuration it therefore never reports it.
     */
    REMOTE_ATTESTED = 2,
}
