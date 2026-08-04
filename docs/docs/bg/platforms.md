# Platform Specifics

Android and iOS expose different attestation models. This page introduces the evidence each platform provides and the
consequences for verification and policy.

## Android (Key & App/ID Attestation)

!!! tip inline end
    For a formal treatment of Android’s security model, see the [**Android Platform Security Model** paper by Mayrhofer et al.]({{ links.android_platform_security_model_paper }}). It explains **Verified Boot**, **TEE/StrongBox**, and the OS trust chain your policies rely on.

An Android attestation statement is an X.509 certificate chain. The leaf certificate contains:

- the public part of the newly generated key
- information about the OS state
- the application that initiated key creation
- whether user authentication is required (fingerprint/password) to use the key
- various other information about the device and OS state (e.g., bootloader lock state, verified boot state)

!!! note "Privacy Note"
    Verification happens entirely on your back-end; devices do not contact Google per attestation.
    Your back-end validates the certificate chain to Google’s Hardware Attestation Root and evaluates attestation fields. You must periodically fetch Google’s revocation information on the server.
    See [Background → Privacy](./privacy.md) for detailed data flows and trade-offs.

### Device Certification Terminology

Android “certification” is overloaded terminology. Throughout these docs, **GMS-certified** refers to Android devices
that **launched** with a Google licence to ship **Google Mobile Services (GMS)**, including Google Play services and the
Play Store, and passed Google's compatibility and certification process for this device build.

Devices that did **not** launch as GMS-certified generally cannot produce an attestation certificate chain that validates against Google’s attestation trust anchors. Examples commonly include:

- Many **Huawei** devices due to an embargo (and other vendor/device lines that ship without GMS)
- **Amazon Fire OS** devices
- Many **China-market variants** of otherwise global Android devices (shipping without Google Play services)

**Installing or sideloading the Play Store / Google Play services later typically does _not_ “add certification”** and does not make such devices validate against the Google root of trust.
In controlled ecosystems, a custom trust policy may still treat such devices as trusted (for example by using custom trust anchors), but that is a different trust model than “Google-rooted Android hardware attestation”.

You will also see these terms used (inconsistently) across vendor docs and community write-ups:

- **GMS-licensed**, **GMS-certified** — OEM/partner wording for “licensed to ship Google Mobile Services (GMS)”.
- **Google Play certified** — Common shorthand for devices certified to ship with Google Play.
- **Play Protect certified** — User-facing wording for “Google Play certified” (often exposed via the Play Store app).
- **Google-certified**, **Android-certified**, **OEM-certified** — Informal/ambiguous shorthands; in practice they often mean “GMS-certified”, but sometimes they merely mean “ships Android” or “ships OEM firmware”.
- **CTS-passed**, **CDD-compliant**, **Android compatible**, **GTS/VTS passed** — Compatibility and test-suite terms; often prerequisites for certification, but not reliable synonyms for a GMS license.
- **AOSP-only**, **non-GMS**, “without Google Play services” — Devices without a GMS license (no Play Store / Play services); many such devices cannot produce a Google-rooted hardware attestation chain.
- Chain of trust: **Leaf (app key)** → **Device‑embedded attestation key** → **Manufacturer/Google intermediates** → **Google Hardware Attestation Root**. Verify against **Google trust anchors**. (see [Android Key Attestation]({{ links.android_key_attestation }})).
- Attestation extension (*KeyDescription*): OS version & patch level, verified boot state, deviceLocked, bootloaderUnlocked, app package/signature digest, key purpose/alg, userAuth authorisations, rollbackResistant, security level (TEE vs StrongBox). (see [AOSP schema]({{ links.android_key_id_attestation }})).
- **Auth & Presence**: Require biometric/PIN per use by setting authorisations when generating the key; verification confirms the requirement. (see [Android Keystore]({{ links.android_keystore_overview }})).
- **Key invalidation events**: Changing device auth (adding/removing fingerprints or PIN reset) can **invalidate keys requiring user auth**; **bootloader unlock** or verified‑boot failures invalidate trust; **factory reset** deletes keys. (see [Android Keystore]({{ links.android_keystore_overview }})).

This terminology is **not** the same as Google’s verdict service APIs. Do not confuse “GMS-certified” with **Google Play Integrity** (see [Google Play Integrity](./privacy.md#google-play-integrity-google-hosted-verdict-service)).

!!! warning inline end
    **Never** use a custom trust anchor or Google's software root of trust in production! Doing so renders all attestation checks moot.

Attestation can also be used in pure test setups, including automated tests, by either:

- overriding the trust anchor with a custom one used only for testing and issuing test certificates with custom-made attestation information
- setting one of Google's software root trust anchors and using an Android emulator, since emulators are capable of producing attestation statements structurally and semantically identical to real devices

!!! info
    Enrolling new fingerprints (or, in general, changing user authentication), factory-resetting a device, uninstalling an app, unlocking, or relocking a device's bootloader will invalidate keys, requiring the creation of fresh keys and attesting them all over again.

## iOS (App Attest, Emulating Key Attestation)
!!! tip inline end
    Apple devices require an active internet connection and need to be able to reach an Apple service during attestation. This service is subject to rate limiting!

Apple devices ship with a dedicated secure element, so iOS does not expose separate software and hardware attestation
levels. App Attest consequently has one validation path. An Apple-operated service evaluates the device, OS, and
application state with support from the Secure Enclave. Its heuristics are proprietary, which matters for privacy and
governance. The back-end does not contact Apple during verification: Apple has just issued the attestation, and no
revocation check is available.

The hardware-bound App Attest key is unavailable for general-purpose cryptographic operations. iOS provides no native
attestation for arbitrary keys, but Warden Supreme emulates it by creating a fresh key pair in the Secure Enclave and
including its public key in the data sent to Apple. A valid attestation bound in this manner establishes that the key was
created inside the Secure Enclave when the statement also establishes:

- an untampered device
- an authentic OS
- an unmodified app published by the app's legitimate developer

!!! warning inline end
    Since iOS only supports hardware attestation, it is impossible to use attestation on a simulator. Trying to do so will cause exceptions or even app hangs or crashes. The same is true for biometric auth.

Warden Supreme implements this complete binding procedure.

Automated simulator tests therefore require a test-only trust anchor and a manually generated attestation statement.
Warden Supreme does not generate these statements. Apple hardware is sufficiently homogeneous that testing with one
real device is usually representative of the supported fleet.

!!! info
    Neither enrolling new fingerprints (or, in general, changing user authentication), factory-resetting a device, nor uninstalling an app will invalidate keys on iOS. Hence, app developers must take measures to explicitly delete keys and check for remnants of old
    keys during an app's first start.
