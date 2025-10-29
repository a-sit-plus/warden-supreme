# Technical — iOS App Attest Deep Dive

This page explains **how trust is established for an iOS app instance** using **App Attest**, from key creation in the
Secure Enclave to attestation and ongoing assertions, and how a service verifies those artifacts. It links to
Apple’s canonical sequence diagrams and focuses on **how App Attest works**, not on client library configuration.


## Setup
Apple requires developers to perform some up-front tasks and configure the build setup to App Attest.
In particular, the following requirements must be met:

* Active Apple Developer Program membership
* iOS device (not Simulator) as target, running iOS 14+
* Xcode 15+ recommended

### Step 1: Prepare your App ID and Signing

* Ensure your app’s Bundle ID is registered in your Apple Developer account.
* Build and run on a physical device using a valid signing certificate and provisioning profile.

### Step 2: Add Required Capabilities in Xcode

* Open your project > target > Signing & Capabilities.
* Add Associated Domains (recommended):
    * If you’ll bind to your domain, add webcredentials:your.domain (and/or applinks:your.domain for related flows).
* App Attest entitlement:
    * When you call DCAppAttestService, Xcode adds com.apple.developer.devicecheck.appattest-environment automatically.
    * Environment is development for debug/TestFlight/sandbox and production for App Store. Your server must verify this.

Once everything is set up, App Attest can be used in your app.

## End-to-end flow (high level)

Apple platforms support _attestation_ and _assertion_, aimed at different use cases.
Attestation is the initial step to establish a device's and an app's integrity, while assertion can be used to
(re-)assert integrity prior to executing critical actions.

1. **Attestation**
    - App calls `generateKey()` to create a **Secure Enclave** key for App Attest.
    - App obtains a **one-time server challenge** and then calls `attestKey(keyId, clientDataHash)`.
    - Apple returns an **attestation object** proving that the key belongs to a legitimate instance of your app, and a *
      *certificate chain** rooted in **Apple’s App Attest CA**.
    - App sends `{attestationObject, keyId, challenge}` to your backend.

2. **Ongoing use (Assertion)**
    - For each privileged request, your server issues a fresh **challenge**.
    - App calls `generateAssertion(keyId, clientDataHash)` to get an **assertion**:
      `{authenticatorData, signature, keyId, (counter)}`.
    - Server verifies the assertion using the **stored public key** (from registration) and ensures the **counter
      increases**, proving continuity.

From a high-level point of view, both flows involve the same entities, as shown in Figure&nbsp;1.

<figure>
<picture>
    <!-- Dark-mode asset -->
    <source
        media="(prefers-color-scheme: dark)"
        srcset="https://docs-assets.developer.apple.com/published/4af6b5e0a27bb7176fa92a73104de5e3/establishing_your_app_s_integrity-1~dark%402x.png" />

    <!-- Light-mode asset -->
    <source
        media="(prefers-color-scheme: light)"
        srcset="https://docs-assets.developer.apple.com/published/2b7a2d8c173ccb7e4e7f4c52f5a21925/establishing_your_app_s_integrity-1%402x.png" />

    <!-- Fallback (srcset for browsers that don’t support `prefers-color-scheme`) -->
    <img
        src="https://docs-assets.developer.apple.com/published/2b7a2d8c173ccb7e4e7f4c52f5a21925/establishing_your_app_s_integrity-1%402x.png"
        alt="Apple App Attest Flows"
        style="width:100%;height:auto;" />

</picture>

<figcaption>Figure&nbsp;1: Apple App Attest Flows</figcaption>
</figure>

Signum Supreme, relies on attestation, but also generates a separate public/private key pair inside the Secure Enclave,
and feeds the public key's hash into `clientDataHash`, to bind the public key to the attestation.
Since Apple platforms do not allow for attesting keys (the hardware-backed keys used for attestation cannot be used), this
way of binding a usable key to an attestation is used to emulate key attestation (see [Emulating Key Attestation](#emulating-key-attestation)).

Signum Supreme does not natively support assertion (for reasons explained [below](#assertion-wrap-up)) and relies on attestation, and emulating key attestation to replicate
Android's behaviour for a consistend UX across both platforms.

## Attestation Validation

### Parse & verify the certificate chain

- Extract `attStmt.x5c` and build a chain to Apple’s **App Attest intermediate** and **root**; verify signatures, Basic
  Constraints, key usages, and time validity.
- Pin trust to **Apple’s App Attest roots**; do **not** rely on a general-purpose system trust store.

### Recompute and verify the nonce

Apple defines the **nonce** as the SHA‑256 hash of `authenticatorData || SHA256(challengeBytes)` (concatenation of raw
bytes). it is calculated as follows:

1. Compute `clientDataHash = SHA256(challengeBytes)` using exactly the challenge your server issued.
2. Concatenate `authenticatorData || clientDataHash`, then compute `nonce = SHA256(...)`.
3. Compare `nonce` to the value in the **leaf attestation certificate extension** as specified by Apple’s guide.

### Validate `authenticatorData` semantics

!!! note inline end "Limitations"
    Unlike Android, iOS does not allow binding arbitrary app keys to system-enforced user authentication with configurable timeouts, nor can such user-auth requirements be attested for those keys.

Within `authenticatorData`, validate at least:

- **RP ID hash**: Must equal `SHA‑256( TeamID + "." + BundleID )`. Reject if mismatched.
- **Flags**: Ensure expected bits are set (user present/verified semantics are Apple-defined for App Attest; you
  primarily rely on counter and RP ID hash).
- **Sign count / counter**: On **attestation**, Apple requires **counter = 0**.
- **AAGUID / environment**: Confirms **Production** vs **Sandbox**; reject environment mismatches.

## Emulating Key Attestation

App Attest natively attests **the app instance** (App ID) and the Apple‑managed key. To emulate **key attestation** for
**your** application key material:

1. Your client builds `clientDataBytes` that includes your **public key bytes** (to be used for subsequent
   protocol steps) and the **server challenge**.
2. Compute `clientDataHash = SHA256(clientDataBytes)` and pass it into **`attestKey`** / **`generateAssertion`**.
3. On the server, after validating the Apple artifacts, extract and validate the **public key bytes** embedded in your
   client‑data.
4. This binds Apple’s attestation to your application key, yielding **verifiable linkage** similar to Android key
   attestation.

Signum Supreme provides emulated key attestation out of the box, automating this whole process, and
streamlining back-end checks by relying on Vincent Haupert's excellent [DeviceCheck / AppAttest library](https://github.com/veehaitch/devicecheck-appattest).
Hence, no custom logic is required on clients and on the back-end.

## Assertion Details and Usage Model

As touched, Apple platofrms allow _asserting_ an app's and device's state after an initial attestation has been performed
and recorded. This section subsumes the intended usage modle as postulated by Apple.

### Assertion Contents
An assertion from `generateAssertion(keyId, clientDataHash)` yields:
- `authenticatorData`: Includes the RP ID hash and a monotonically increasing sign counter.
- `signature`: Over `authenticatorData || clientDataHash` using the registered App Attest key. Hence, the key used for the original attestation must be recorded.
- `keyId`: Identifies the App Attest key pair on device.

The server verifies the signature with the stored public key (from the attestation/registration step) and validates that
the RP ID hash matches the expected `SHA256(TeamID + "." + BundleID)`.

### The Sign Counter
An assertion contains a counter value.
- The counter starts at `0` at attestation time.
- Each successful `generateAssertion` should increase it by at least `+1`.
- The server needs to persist the highest seen counter per `keyId`. On each request:
    - Reject if the new counter `<=` last seen (replay or rollback).
    - Accept if strictly higher, then update stored value.
- Counter continuity provides tamper-resistance (e.g., against state rollback from device backups).

### Periodic Re-Attestation via Assertions

!!! warning inline end "Complyxity Ahead!"
    Performing re-attestation through attestation requires tracking device states over the whole lifetime of the service
    used by the app.

- Apple intended assertions to guard privileged actions with a fresh, server-bound challenge.
- You can treat recurring assertions as “lightweight re-attestation”:
    - Issue a challenge at session start, high-risk operations, or on a cadence (e.g., hourly).
    - Require a valid assertion and counter increment to proceed.
    - This confirms the same App Attest key is active, on the same app instance, and not rolled back.

### Apple’s Intended Usage of App Attest
!!! warning inline end
    Even "lightweight re-attestation" requires devices to interact with Apple services, alowing for user tracking

- Protect critical sections and privileged API calls with per-request challenges and assertions.
- Use full attestation (registration) once per app instance, then rely on assertions to maintain trust over time.
- Assertions are expected to be online: the device contacts Apple during assertion generation, so budget for this latency in UX and retries.

### Assertion Wrap-Up

Using assertions as “re-attestation” has two notable downsides:
- Backend state management burden
    - You must persist per-device key state (keyId, highest seen counter, environment), enforce strict counter monotonicity,
      handle resets/rollbacks (e.g., device restores), and design recovery paths (counter desync, key rotation, multi-device users). 
      This adds storage, concurrency control, migration, and incident-handling complexity.
      Risk-based policies (cadence, per-action challenges) further increase statefulness and operational overhead.

- Privacy and tracking concerns
    - Assertions require contacting Apple services. This creates additional metadata exposure to Apple (time, frequency,
      success/failure of assertions) and can enable cross-session correlation via stable keyIds if you don’t carefully
      scope/rotate them. On your side, the very act of frequent assertions encourages building long-lived device-level
      identifiers and histories, which can increase linkability of user behavior. Minimizing assertion cadence, scoping
      identifiers, and separating environments reduces—but does not eliminate—these privacy risks.

For these reasons, Warden Supreme does not natively support it, but rather relies on attestation with emulated key attestation
to mimic the simple, but powerful model Android uses. In the end, re-attestation using fresh attestations rather than asserting
a state before a critical section is much more decoupled from specific user actions.

## Operational guidance

- **Online dependency**: App Attest requires a **live connection to Apple** for attestation and assertions. Implement
  retries/queuing and clear UX.
  See: https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service
- **Rate limiting**: Avoid unnecessary re‑attestation; cache successful registrations and only assert per privileged
  request or session cadence that suits your risk posture.
- **Stage separation**: Keep **Sandbox** and **Production** completely separate — App ID, keys, and trust anchors don’t
  mix across stages.
- **Privacy**: Apple observes attestation/assertion events.

## Verification pitfalls to avoid

These mostly apply when rolling your own, since Signum Supreme takes care of most of these. Still, for the sake of
completeness, this section lists general common pitfalls.

- **Wrong nonce computation**: Use `nonce = SHA256( authenticatorData || SHA256(challengeBytes) )`. Do not swap order or
  hash the whole CBOR.
- **Ignoring environment**: Production vs Sandbox must match your deployment stage.
- **Trusting system roots**: Pin to **Apple’s App Attest** roots; don’t accept arbitrary Apple CAs.
- **Skipping counter checks**: The **monotonic counter** is your continuity signal; enforce strictly increasing values.
- **Leaking key material**: Never transmit or store private keys. Persist only the **public key** and minimal metadata.
- **Time Drift**: Out-of-sync clocks between clients and server can cause the PKIX validation part to fail.

## References & useful libraries

- [Apple — DeviceCheck (App Attest landing)](https://developer.apple.com/documentation/devicecheck)
- [Apple — Validating apps that connect to your server (with diagrams)](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [Apple — Attestation Object Validation Guide (validation details)](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
- [Apple — Establishing your app’s integrity (client-side)](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
- [Server validation library (Kotlin)](https://github.com/veehaitch/devicecheck-appattest)

