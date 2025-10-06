# Platform Specifics

iOS and Android tackle remote attestation differently. This page provides a high-level overview of the general concepts each platform uses and how they differ.

## Android (Key & App/ID Attestation)

!!! tip inline end
    For a formal treatment of Android’s security model, see the **Android Platform Security Model** paper by Mayrhofer et al. [(PDF)](https://arxiv.org/abs/1904.05572). It explains **Verified Boot**, **TEE/StrongBox**, and the OS trust chain your policies rely on.

An Android attestation statement is an X.509 certificate chain. The leaf certificate contains
* the public part of the newly generated key
* information about the OS state
* the application that issued key creation
* whether user authentication is required (fingerprint / password) to use the key
* various other information about the device and OS state (e.g., bootloader lock state, verified boot state)

Privacy note: Verification happens entirely on your backend; devices do not contact Google per attestation. Your backend validates the certificate chain to Google’s Hardware Attestation Root and evaluates attestation fields. You must periodically fetch Google’s revocation information on the server. See [Background → Privacy](./privacy.md) for detailed data flows and trade-offs.

!!! warning inline end
    **Never** use a custom trust anchor or Google's software root of trust in production! Doing so renders all attestation checks moot.

Attestation can also be used in pure test-setups including automated tests, by either
* overriding the trust anchor with a custom one used only for testing and issuing test certificates with custom-made attestation information
* setting one of Google's software root trust anchors and using an Android emulator, since emulators are capable of producing attestation statements structurally and semantically identical to real devices.

!!! info
    Enrolling new fingerprints (or in general) changing user authentication, factory-resetting a device, uninstalling an app, unlocking, or relocking a device's bootloader will invalidate keys, requiring the creation of fresh keys and attesting them all over again.


- Chain of trust: **Leaf (app key)** → **Device‑embedded attestation key** → **Manufacturer/Google intermediates** → **Google Hardware Attestation Root**. Verify against **Google trust anchors**. (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)).
- Attestation extension (*KeyDescription*): OS version & patch level, verified boot state, deviceLocked, bootloaderUnlocked, app package/signature digest, key purpose/alg, userAuth authorizations, rollbackResistant, security level (TEE vs StrongBox). (see [AOSP schema](https://source.android.com/docs/security/features/keystore/attestation#schema)).
- **Auth & Presence**: Require biometric/PIN per use by setting authorizations when generating the key; verification confirms the requirement. (see [Android Keystore](https://developer.android.com/privacy-and-security/keystore)).
- **Key invalidation events**: Changing device auth (adding/removing fingerprints or PIN reset) can **invalidate keys requiring user auth**; **bootloader unlock** or verified‑boot failures invalidate trust; **factory reset** deletes keys. (see [Android Keystore](https://developer.android.com/privacy-and-security/keystore)).

## iOS (App Attest, Emulating Key Attestation)
!!! tip inline end
    Apple devices require an active internet connection and need to be able to reach an Apple service during attestation. This service is subject to rate limiting!

Apple devices all ship with a dedicated secure element. Hence, there are no different levels of attestation like on Android, which supports software and hardware attestation.
Hence, there is only a single code path to validate an attestation statement received from iOS.  
The actual device, OS, and software integrity checks are performed by a service operated by Apple. Hence, the device communicates with Apple infrastructure, and a proprietary Apple service analyses the device's
state with the help of the Secure Enclave on the device and determines whether the device (and its OS) is trustworthy using undocumented heuristics.
This fact needs to be observed in data protection and privacy discussions!
On the backend, however, no contact with Apple services is required, since no revocation checks are possible, as the attestation itself is freshly provided by Apple.

Moreover, the hardware-bound key used to create an attestation statement cannot be used by the app for any cryptographic operations.
Hence, there is no key attestation on iOS, but it can be emulated by creating a fresh keypair inside the Secure Enclave and feeding its public part into the data sent to Apple for attestation.
If a valid attestation statement is revived that is bound to the key in this matter, the key can also be trusted to be created inside the Secure Enclave if the attestation statement indicates

* an untampered device
* authentic OS
* an unmodified app published by the app's legitimate developer

Signum Supreme supports this procedure out of the box.

!!! warning inline end
    Since iOS only supports hardware attestation, it is impossible to use attestation on a simulator. Trying to do so will cause exceptions to be thrown or even cause app hangs or crashes! The same is true for biometric auth.

Without attestation support in device simulators, automated testing becomes a bit more involved. The only way to support automated tests, is to override the default Apple trust anchor with a custom one, only valid for testing.
The lack of simulator support also means that an attestation statement needs to be created manually. Warden Supreme currently does not support this out of the box, as Apple devices are very homogeneous. Thus, testing with one real device
is usually representative for all Apple devices.

!!! info
    Neither enrolling new fingerprints (or in general) changing user authentication, factory-resetting a device, or uninstalling an app will invalidate keys. Hence, app developers must take measures to explicitly delete keys and check for remnants of old
    keys during an app's first start.
