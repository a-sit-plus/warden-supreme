# Android Attestation Deep Dive

This page explains **how trust is established from boot through app installation** and how that state is **proven** to a
back-end service via Android hardware attestation. It expands on certificate chains, the `KeyDescription` schema,
verification steps, and **edge cases**, and it ties these to the Android Verified Boot (AVB) chain and APK signing.

[In contrast to iOS](ios.md#setup), Android requires no special setup procedure, and an app can use attestation


<figure>
    <img src="../../assets/images/android.png" alt="High-level structure of an Android key attestation result">
    <figcaption>Figure&nbsp;1: High-level structure of an Android key attestation result</figcaption>
</figure>

!!! tip
    Keep Figure&nbsp;1 at your ready while digging through this page, as it will be referenced throughout!


## How platform trust is established during boot


1. **Boot ROM** (immutable in SoC) verifies the **first-stage bootloader** using SoC fuses / OEM root.
2. Bootloader verifies **`vbmeta`** and the **partition chain** via **AVB**. `vbmeta` contains the **public key** (or
   hash thereof) authorizing images and **rollback indexes**.
3. If verification passes and the **bootloader is locked**, boot proceeds with **`verifiedBootState = VERIFIED`**;
   otherwise `SELF_SIGNED`, `UNVERIFIED`, or `FAILED` states are signaled.
4. **dm-verity** ensures runtime integrity of verified partitions (system/vendor/product).
5. **Rollback protection**: bootloader maintains **rollback index slots** in tamper-resistant storage; images signed
   with **older rollback index** are rejected. Not all devices advertise this.

### What the attestation proves about the boot

The **`RootOfTrust`** structure in the attestation extension contains:

- `verifiedBootKey`: hash of the **AVB root** public key that authorized the boot images.
- `deviceLocked`: boolean derived from bootloader lock state.
- `verifiedBootState`: one of `VERIFIED`, `SELF_SIGNED`, `UNVERIFIED`, `FAILED`.
- Patch claims: `osVersion`, `osPatchLevel`, and (on newer devices) `bootPatchLevel`/`vendorPatchLevel`.

**Policy implication:** Your server can require `deviceLocked=true`, `verifiedBootState=VERIFIED`, and minimum patch
levels; optionally pin the **expected `verifiedBootKey`** (accept OEM keys only, or accept **your** enterprise/sovereign
AVB key(s) if you operate a trusted ROM program).


## How trust is established for the app at install time

- **Signature Scheme v2/v3/v4** embeds signatures over the app contents at the APK level (post-Android 7).
- The platform verifies the **signing certificate(s)** when installing/updating an app.

### What the attestation proves about the app

The **`AttestedApplicationId`** section contains:
- `package_infos`
    - `package_name` identifying your application
    - `version` indicating the version of the application
- `signature_digests`: values (SHA-256 digests of the signing certificate(s)) pulled
  from the Package Manager at attestation time.

**Policy implication:** Your server must check against the package name and **signer digest(s)** of your **release**
build(s). If you use key rotation, store and accept **all legitimate digests**. Re-attest while enforcing application versions to enforce updates.

## How attestation is produced (on-device) and verified (server-side)

### On-device production

1. App requests a **new key** from **KeyMint/StrongBox** with required properties (algorithm, size, purposes, user-auth
   requirements).
2. App calls **attestKey** with a **fresh server-provided challenge**.
3. KeyMint produces a **certificate chain** for the key:
    - **Leaf certificate** embeds the **attestation extension** (`KeyDescription`) with `RootOfTrust`,
      `AttestedApplication`, and **AuthorizationLists**.
    - Intermediates up to a **Google Attestation Root** (for hardware attestation on certified devices).
4. App sends **{certChain, challenge, metadata}** to your backend.

### Server-side verification pipeline (normative checklist)

1. **Chain validation**: X.509 path build and verify (signatures, BasicConstraints, EKU if present, issuer/subject continuity).
2. **Time validity**: validate NotBefore / NotAfter on intermediates; tolerate known **leaf-time quirks** only if you apply strict freshness windows (see §6).
3. **Attestation root**: anchor in Google’s published **attestation-root set** (keep updated).
4. **Extension parse**: parse **`KeyDescription`** with a standards-compliant ASN.1/DER library; **respect DER sorting for SET OF**.
5. **Challenge**: exact match to your **one-time** challenge; reject reuse or replay.
6. **Root-of-trust**: require `verifiedBootState = VERIFIED`, `deviceLocked = true`; optionally **pin `verifiedBootKey`** and enforce minimum `osPatchLevel` / `vendorPatchLevel` / `bootPatchLevel`.
7. **App binding**: require `packageName` and **signer digest(s)** to match your allow-list; optionally pin **`versionCode`** via an app-side claim bound to the challenge.
8. **Key properties**: check `securityLevel` in `hardwareEnforced` is **TrustedEnvironment** or **StrongBox**; verify **`userAuth`** parameters (auth-per-use / timeouts) meet your policy.
9. **Revocation**: check against **revoked attestation keys** (Google feeds) and your own deny-lists; fail closed in high-assurance contexts.
10. **Decision & logging**: produce an auditable decision with specific reasons (e.g., “boot not verified”, “signer mismatch”, “patch too old”).


## User authentication & key lifecycle in attestation

- **User presence / authorization**: If `userAuth` is required, KeyMint enforces biometric/PIN **at key use**. The
  authorization policy (per-use, validity window) appears in the AuthorizationLists and is **remotely checkable**.
- **Invalidation triggers** (enforced by Android, no server telemetry needed):
    - Disable/reset of secure **lock screen** → auth-bound keys invalidated.
    - **Biometric enrollment** changes (if so configured) → invalidate.
    - **Bootloader unlock** or verified-boot failure → keys wiped/unusable; subsequent attestations show
      `deviceLocked=false` or degraded `verifiedBootState`.
    - **Factory reset** → keys deleted.
- **Best practice**: bind critical operations (e.g., credential issuance, high-value transactions) to **auth-required
  keys** whose attestation you already validated.


## Certificate chains & trust anchors

- Expect a chain terminating in a **Google Hardware Attestation Root** for hardware-backed attestation.
- Always validate **full chain**: signatures, validity, path length, EKU (if present).
- Reject **software/hybrid** attestation unless explicitly allowed for test scenarios; keep a separate trust store for
  emulators.
- Keep the **attestation root set** and **revocation lists** up to date on your server; retrieve and cache periodically.

## Verification pitfalls to avoid

- **Ignoring the challenge**: always bind to a fresh, single-use nonce and reject replays.
- **Trusting package name alone**: you must match **signing certificate digest(s)**.
- **Accepting SELF_SIGNED states**: only acceptable for tightly scoped test channels.
- **Relying solely on patch level**: combine with verified boot, device lock, and (optionally) pinned `verifiedBootKey`.
- **Parsing ASN.1 with ad-hoc code**: use a proper DER parser to handle `SET OF` ordering and nested structures.

## References & libraries

- [Developer guide (Key Attestation)](https://developer.android.com/privacy-and-security/security-key-attestation)
- [AOSP schema & extension documentation](https://source.android.com/docs/security/features/keystore/attestation#schema)
- [Libraries (legacy)](https://github.com/google/android-key-attestation)
- [Libraries (current)](https://github.com/android/keyattestation)
- Warden Supreme (this project)
