# Using _Warden makoto_ / _Warden roboto_<br>without Integrated Clients

!!! tip inline end
    Both [WARDEN](https://github.com/a-sit-plus/warden) and [WARDEN-roboto](https://github.com/a-sit-plus/warden-roboto)
    live on as modules inside Warden Supreme. These projects are now integrated into Warden Supreme and continue to be
    maintained and published to Maven Central. See [Project Structure](structure.md).

While Warden Supreme aims to make remote attestation across Android and iOS as smooth and consistent as possible via
Kotlin Multiplatform, it is clear that not every iOS app will be written in Kotlin, and not every Android application
will want to pull in Signum as dependency.

In addition, legacy deployments that cannot yet transition to the new integrated Warden Supreme attestation flows are
still and will remain operational. Until a migration is possible (see [migration notes](migration.md)), this page serves
as documentation for _Warden makoto_ (previously WARDEN) and _Warden roboto_ (previously WARDEN‑roboto).


## When to use _makoto_ vs. _roboto_

| <img alt="Warden roboto" src="../../assets/images/roboto.png" width="249" style="height:auto;"> | <picture><source media="(prefers-color-scheme: dark)" srcset="../../assets/images/makoto-w.png"><source media="(prefers-color-scheme: light)" srcset="../../assets/images/makoto-b.png"><img alt="Warden makoto" src="../../assets/images/makoto-w.png" width="232" height="36" style="height:auto;"></picture> |
|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Android-only server-side key and app attestation library.                                       | Unified server-side Android and iOS attestation library.                                                                                                                                                                                                                                                        |
| Maven coordinates: `at.asitplus.warden:roboto`                                                  | Maven coordinates: `at.asitplus.warden:makoto`                                                                                                                                                                                                                                                                  |

- Choose Warden makoto if you need both Android and iOS support or want a single, streamlined back-end interface.
- Choose Warden roboto if you truly only need Android and want minimal dependencies.

In both cases, refer Warden Supreme's [Back-End Configuration](supreme.md#back-end-configuration) guide, as it lists and explains
configuration properties for iOS and Android. This page focuses on behavior, inputs/outputs, and expected client responsibilities.


!!! warning "Additional Setup Required"
    Be sure to follow the [setup procedure for iOS](../technical/ios.md#setup) to enable App Attest. Otherwise, App Attest
    is unavailable and will fail hard.

## Architecture and Flow Overview

Without integrated clients, your mobile apps must manually:

- Obtain a fresh server challenge.
- Create or select a key on-device.
- Produce an attestation proof bound to the server challenge.
- Send the proof (and any auxiliary data) to your verifier endpoint.
- On iOS, emulate key attestation yourself.

Your server must:

!!! tip inline end
    Treat attestation like authentication: server owns challenge issuance and freshness; clients only echo and bind it into
    their proofs.

- Issue unpredictable challenges with a strict freshness window.
- Manually wire endpoints to parse client data and call Warden makoto/roboto to
    - Validate attestation certificate paths and trust anchors.
    - Enforce policy (security level, boot state, patch level, app identity).
    - Bind the app’s public key to your account/session, if applicable.


## Common Data Model (Wire Format Responsibilities)

When not using the integrated clients, you define the wire format.
Hence, you need to come op with a format that conveys at least the following recommended properties:

- Challenge: Base64URL-encoded bytes issued by the server.
- Platform: iOS / Android; either implicitly using legacy WARDEN endpoints (intentionally not documented here. See [legacy API docs](https://a-sit-plus.github.io/warden/warden/at.asitplus.attestation/-warden/index.html#-1296395129%2FFunctions%2F-2065255732).)
- Key material:
    - Android: attestation certificate chain (leaf → intermediates), plus the attested key’s public key if not derivable
      from the leaf.
    - iOS:
        - App Attest attestation object (CBOR, with x5c in attStmt) on registration
        - key attestation emulation needs to follow the Supreme attestation format, or the legacy attestation format
          as described in the original [WARDEN example usage](https://github.com/a-sit-plus/warden#example-usage).
- Binding:
    - If you emulate unified binding (recommended), define a mechanism and format to convey an equivalent to Warden Supreme's binding certificate.

## Warden makoto<br>(Unified Android + iOS Attestation)

Warden makoto is the modernized variant of legacy WARDEN, sharing the same API:

- Android key attestation verification with policy enforcement.
- iOS App Attest verification, including unified key-binding semantics (challenge + public key in clientDataHash),
  assertions with counters, AAGUID enforcement, and trust anchor validation.

!!! tip Platform Specifics
    Like legacy WARDEN, Warden makoto also exposes OS-specific endpoints for more fine-grained app attestation on iOS,
    and a more low-level API for Android targets. Refer to the respective platform-sepcific APIs, both of which are exposed by the
    [`Warden`](../dokka/makoto/at.asitplus.attestation/-warden/index.html):
    
    * [iOS](../dokka/makoto/at.asitplus.attestation/-warden/ios.html)
    * [Android](../dokka/makoto/at.asitplus.attestation/-warden/android.html)


Recommended endpoints:
- GET `/attestation/challenge`
    - Issue per-request challenges with short TTL.
- POST `/attestation/register`
    - Android: submit X.509 attestation chain with Android KeyDescription challenge binding.
    - iOS: submit App Attest attestation object with clientDataHash binding.
- POST `/attestation/assert` (if iOS assertion is required)
    - iOS only: submit assertion bound to a fresh challenge; enforce monotonic counters and receipt if used.

General tips/requirements apply:
- Require challenge freshness and correct nonce/challenge echo in the platform-specific mechanism.
- Replay: Reject reused challenges; on iOS, also enforce increasing counters per key.
- Stage alignment: Configure sandbox vs. production AAGUID correctly on iOS.
- Cache receipts/tokens server-side to reduce iOS attestation churn.
- Time drift: compensate in validator; never let client clock override server policy.


## Warden roboto<br>(Android-only Attestation)

Warden roboto encapsulates the Android verification logic from the legacy WARDEN-roboto project.

Supported attestation types:

- StrongBox: preferred when available; highest protection.
- TrustedEnvironment (TEE): widely available; enforced verified boot.
- Software/Nougat-hybrid: acceptable only for testing or very narrow cases; avoid for production OS/app attestation.

Client duties (Android):

!!! warning inline end
    If you want to support hardware attestation and Nougat/hybrid attestation, you must wire this yourself!

- Request a server challenge.
- Generate or select an Android Keystore key with attestation parameters such that the server challenge is properly embedded
- Return the attestation certificate chain and any auxiliary metadata.

## References
- Background and platform deep dives: see Technical sections
  for [Android](../technical/android.md), [iOS](../technical/ios.md), and [Quirks](../technical/quirks.md).
- End-to-end integration: see the [Integration Guide](supreme.md).
- Configuration (authoritative): see [supreme.md#back-end_configuration](supreme.md#back-end-configuration).