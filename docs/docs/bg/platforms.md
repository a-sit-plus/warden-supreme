# Platform Specifics

iOS and Android tackle remote attestation differently. This page provides a high-level overview of each platform’s concepts and how they differ.

## Android (Key & App/ID Attestation)

!!! tip inline end
    For a formal treatment of Android’s security model, see the [**Android Platform Security Model** paper by Mayrhofer et al.]({{ links.android_platform_security_model_paper }}). It explains **Verified Boot**, **TEE/StrongBox**, and the OS trust chain your policies rely on.

An Android attestation statement is an X.509 certificate chain. The leaf certificate contains:
- the public part of the newly generated key
- information about the OS state
- the application that initiated key creation
- whether user authentication is required (fingerprint/password) to use the key
- various other information about the device and OS state (e.g., bootloader lock state, verified boot state)

Privacy note: Verification happens entirely on your back-end; devices do not contact Google per attestation.
Your back-end validates the certificate chain to Google’s Hardware Attestation Root and evaluates attestation fields. You must periodically fetch Google’s revocation information on the server.
See [Background → Privacy](./privacy.md) for detailed data flows and trade-offs.

!!! warning inline end
    **Never** use a custom trust anchor or Google's software root of trust in production! Doing so renders all attestation checks moot.

Attestation can also be used in pure test setups, including automated tests, by either:
- overriding the trust anchor with a custom one used only for testing and issuing test certificates with custom-made attestation information
- setting one of Google's software root trust anchors and using an Android emulator, since emulators are capable of producing attestation statements structurally and semantically identical to real devices

!!! info
    Enrolling new fingerprints (or, in general, changing user authentication), factory-resetting a device, uninstalling an app, unlocking, or relocking a device's bootloader will invalidate keys, requiring the creation of fresh keys and attesting them all over again.


- Chain of trust: **Leaf (app key)** → **Device‑embedded attestation key** → **Manufacturer/Google intermediates** → **Google Hardware Attestation Root**. Verify against **Google trust anchors**. (see [Android Key Attestation]({{ links.android_key_attestation }})).
- Attestation extension (*KeyDescription*): OS version & patch level, verified boot state, deviceLocked, bootloaderUnlocked, app package/signature digest, key purpose/alg, userAuth authorisations, rollbackResistant, security level (TEE vs StrongBox). (see [AOSP schema]({{ links.android_key_id_attestation }})).
- **Auth & Presence**: Require biometric/PIN per use by setting authorisations when generating the key; verification confirms the requirement. (see [Android Keystore]({{ links.android_keystore_overview }})).
- **Key invalidation events**: Changing device auth (adding/removing fingerprints or PIN reset) can **invalidate keys requiring user auth**; **bootloader unlock** or verified‑boot failures invalidate trust; **factory reset** deletes keys. (see [Android Keystore]({{ links.android_keystore_overview }})).

## iOS (App Attest, Emulating Key Attestation)
!!! tip inline end
    Apple devices require an active internet connection and need to be able to reach an Apple service during attestation. This service is subject to rate limiting!

Apple devices all ship with a dedicated secure element. As a result, iOS does not have different attestation “levels” like Android (software vs. hardware attestation).
Hence, there is only a single validation path for App Attest statements.  
The actual device, OS, and software-integrity checks are performed by an Apple‑operated service. The device communicates with Apple infrastructure, and a proprietary service evaluates device state (with the help of the Secure Enclave) using undocumented heuristics.
This matters in data protection and privacy discussions.
On the back-end, no contact with Apple services is required because no revocation checks are possible and the attestation is freshly provided by Apple.

Moreover, the hardware-bound key used to create an attestation statement cannot be used by the app for general-purpose cryptographic operations outside App Attest assertions.
There is no native key attestation on iOS, but it can be emulated by creating a fresh key pair inside the Secure Enclave and feeding its public key into the data sent to Apple for attestation.
If a valid attestation statement is received that is bound to the key in this manner, the key can also be trusted to be created inside the Secure Enclave if the attestation statement indicates:

- an untampered device
- an authentic OS
- an unmodified app published by the app's legitimate developer

Warden Supreme supports this procedure out of the box.

!!! warning inline end
    Since iOS only supports hardware attestation, it is impossible to use attestation on a simulator. Trying to do so will cause exceptions or even app hangs or crashes. The same is true for biometric auth.

Without attestation support in device simulators, automated testing becomes a bit more involved. The only way to support automated tests is to override the default Apple trust anchor with a custom one that is only valid for testing.
The lack of simulator support also means that an attestation statement needs to be created manually. Warden Supreme currently does not support this out of the box, as Apple devices are very homogeneous. As a result, testing with one real device is usually representative of all Apple devices.

!!! info
    Neither enrolling new fingerprints (or, in general, changing user authentication), factory-resetting a device, nor uninstalling an app will invalidate keys on iOS. Hence, app developers must take measures to explicitly delete keys and check for remnants of old
    keys during an app's first start.
