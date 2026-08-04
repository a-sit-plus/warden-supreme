# Using _Warden makoto_ / _Warden roboto_<br>Without Integrated Clients

!!! danger "Warden Supreme 0.9.99: Changed Defaults"
    
    * Android leaf cert validity is ignored by default because Warden Supreme uses random cryptographic nonces.
        * The `ingoreLeafValidity()` (yes, with typo!) function of the `AndroidAttestationConfiguration.Builder` is now a deprecated NOOP to be removed.
        * The `enforceLeafValidity()` (without typo!) function was introduced.
    * Android `attestationStatementValiditySeconds` defaults to `null` because Warden Supreme uses random cryptographic nonces.
    * Attestation verification time offset now defaults to five minutes to account for clock drift.
    * iOS attestation validity is increased by those five minutes.
    
    **Ignoring these changes from legacy deployments can result in a security failure if you do not ensure freshness by feeding random cryptographic nonces into attestation statement creation and properly checking them.**

!!! tip inline end
    Both [WARDEN](https://github.com/a-sit-plus/warden) and [WARDEN-roboto](https://github.com/a-sit-plus/warden-roboto)
    live on as modules inside Warden Supreme. These projects are now integrated into Warden Supreme and continue to be
    maintained and published to Maven Central. See [Project Structure](structure.md) and [Migration](migration.md).

The integrated client provides one Kotlin Multiplatform attestation flow for Android and iOS. Applications written in
another language, and Android applications that do not want to depend on Signum, can use the server-side modules
directly.

If you are evaluating whether to use Warden Supreme at all for a single platform, see
[Why Warden Supreme?](../why-supreme.md).

This page also documents _Warden makoto_ (previously WARDEN) and _Warden roboto_ (previously WARDEN-roboto) for legacy
deployments that have not yet adopted the integrated flow. See the [migration notes](migration.md) when moving between
the APIs.

!!! tip "Hybrid Integration"
    It is possible to use Warden Supreme's verifier with custom clients by adhering to the [same flows](supreme.md#high-level-attestation-flow) and [data model](datamodel.md).

## When to Use _makoto_ vs. _roboto_

| <img alt="Warden roboto" src="../../assets/images/roboto.png" width="249" style="height:auto;"> | <picture><img alt="Warden makoto" src="../../assets/images/makoto-w.png" width="232" height="36" style="height:auto;"></picture> |
|-------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| Android-only server-side key and app attestation library.                                       | Unified server-side Android and iOS attestation library.                                                                         |
| Maven coordinates: `at.asitplus.warden:roboto`                                                  | Maven coordinates: `at.asitplus.warden:makoto`                                                                                   |

- Choose Warden makoto if you need both Android and iOS support or want a single back-end interface.
- Choose Warden roboto if you truly only need Android and want minimal dependencies.

In both cases, refer to Warden Supreme's [back-end configuration](supreme.md#warden-supreme-step-by-step-guide) guide, as it lists and explains
configuration properties for iOS and Android. This page focuses on behaviour, inputs/outputs, and expected client responsibilities.


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

Without the integrated clients, the application owns the wire format. It should carry at least the following properties:

- Challenge: Base64URL-encoded bytes issued by the server.
- Platform: iOS / Android; either implicitly using legacy WARDEN endpoints (intentionally not documented here). See [legacy API docs](https://a-sit-plus.github.io/warden/warden/at.asitplus.attestation/-warden/index.html#-1296395129%2FFunctions%2F-2065255732).
- Key material:
    - Android: attestation certificate chain (leaf → intermediates), plus the attested key’s public key if not derivable
      from the leaf.
    - iOS:
        - App Attest attestation object (CBOR, with `x5c` in `attStmt`) on registration
        - Key attestation emulation needs to follow the Supreme attestation format, or the legacy attestation format
          as described in the original [WARDEN example usage](https://github.com/a-sit-plus/warden#example-usage).
- Binding:
    - If you emulate unified binding (recommended), define a mechanism and format to convey an equivalent to Warden Supreme's binding certificate.

## Warden makoto<br>(Unified Android + iOS Attestation)

Warden makoto is the modernised variant of legacy WARDEN, sharing the same API:

- Android key attestation verification with policy enforcement.
- iOS App Attest verification, including unified key-binding semantics (challenge + public key in clientDataHash),
  assertions with counters, AAGUID enforcement, and trust anchor validation.

!!! tip "Platform Specifics"
    Like legacy WARDEN, Warden makoto also exposes OS-specific endpoints for more fine-grained app attestation on iOS,
    and a more low-level API for Android targets. Refer to the respective platform-specific APIs, both of which are exposed by
    [`Makoto`](../dokka/makoto/at.asitplus.attestation/-makoto/index.html):
    
    * [iOS](../dokka/makoto/at.asitplus.attestation/-makoto/ios.html)
    * [Android](../dokka/makoto/at.asitplus.attestation/-makoto/android.html)


Recommended endpoints:

- GET `/attestation/challenge`
    - Issue per-request challenges with short TTL.
- POST `/attestation/register`
    - Android: submit X.509 attestation chain with Android KeyDescription challenge binding.
    - iOS: submit App Attest attestation object with clientDataHash binding.
- POST `/attestation/assert` (if iOS assertion is required)
    - iOS only: submit assertion bound to a fresh challenge; enforce monotonic counters and receipt if used.

### iOS Assertion Flow with Stored `ValidatedAttestation`

If you run a custom iOS client flow (no integrated Supreme client), the recommended server-side sequence is:

1. `POST /attestation/register`:
    - Verify App Attest once via `Makoto.ios.verifyAppAttestation(attestationObject, challenge)`.
    - Persist the returned `ValidatedAttestation` (`AttestationResult.IOS.Verified.attestation`) together with your
      key/user binding and current counter state.
2. `POST /attestation/assert`:
    - Load the previously stored `ValidatedAttestation`.
    - Verify a fresh assertion against a fresh challenge via `Makoto.ios.verifyAssertion(...)`.
    - On success, update your stored counter state.

`verifyAssertion(...)` does **not** re-verify attestation freshness. Challenge freshness and replay protection remain
your responsibility.
Counter semantics are based on the value **before** creating the assertion:
- `validCounters.first`: strict lower bound (`counterBefore > first`)
- `validCounters.last`: inclusive upper bound (`counterBefore <= last`)

!!! example "Reference implementation (JSON + ASN.1/DER persistence and assertion validation)"
    ```kotlin
    --8<-- "Readme-Raw-ios-assertion.kt:35:60"
    ```

    1. Registers the incoming App Attest payload and verifies it against the registration challenge.
    2. Narrows the result to `AttestationResult.IOS.Verified` to access the returned `ValidatedAttestation`.  
       You want proper error handling in your actual production code!
    3. Serializes `ValidatedAttestation` to JSON using `ValidatedAttestationSerializer` for persistence.
    4. Verifies a fresh assertion using the deserialized, previously recorded attestation.
    5. Counter bounds are checked against the value **before** creating the assertion.  
       This example asserts a single valid counter value.
    6. Shows the canonical ASN.1/DER persistence alternative via `canonicalize().encodeToDer()`.

General tips and requirements:

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

!!! tip "Pinned custom Android boot keys"
    When integrating `Warden roboto` directly, `verifiedBootKeys` is the knob for Android boot policy. The default
    `[OEM]` accepts vendor-managed `VERIFIED` boot. Add hex digests to also allow known-good `SELF_SIGNED` keys, or
    omit `OEM` to accept only those custom keys. Keep `allowBootloaderUnlock = false` when doing this, otherwise
    bootloader-lock, verified boot state, and verified boot key checks are skipped entirely. GrapheneOS is a good
    real-world example because it publishes its
    [verified boot key hashes](https://grapheneos.org/install/web#verified-boot-key-hash).

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
