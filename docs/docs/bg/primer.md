# What Remote Attestation Is (and Isn’t)

Remote attestation lets a server verify the app, device, and system state behind a cryptographic proof. It complements
ordinary client authentication: knowing which account signed a request does not establish which application produced
it or whether the device was in an acceptable state. The client creates a key in secure hardware and obtains a
verifiable statement about this key and the relevant device and application state. The server validates this statement
against trusted roots and its own policy.

**What It Establishes**:

- **Client integrity** beyond TLS and user authentication: the service can establish which app and device produced a
  proof.
- **Hardware-backed key storage**: a client can prove that sensitive cryptographic material was created in protected
  hardware and cannot be exported.
- **Enforceable access policy**, such as admitting only unmodified devices with sufficiently recent security updates.
- **Privacy on Android**: Android key attestation is generated locally. The server still needs current revocation
  information from Google, but fetches it independently of individual attestations. This neither identifies users nor
  tells Google which clients, applications, or services the server is attesting.
  (see [Android Key Attestation]({{ links.android_key_attestation }})).<br>
  On iOS, the device must contact Apple’s App Attest service whenever it creates an attestation statement.
- **Defined limits**: Attestation does not identify a person, stop an authenticated user from abusing an account,
  prevent credential theft outside the app, or detect unknown vulnerabilities. It authenticates an app-and-device
  instance and its reported state.

!!! warning inline end "Performance Impact"
    * **iOS** requires live communication with Apple’s App Attest servers each time an attestation is generated. If network
      conditions are poor, this round-trip can add noticeable latency.
    * **Android** produces the attestation statement entirely offline; only your back-end needs to fetch Google’s public
      revocation list asynchronously. Therefore, attestation adds virtually **no runtime performance impact** for the user.

**Platform Differences** (High Level):

- **Android** provides **Key Attestation** for a key and device state, plus **App/ID attestation** fields in the
  attestation extension (see [Android Key & ID Attestation]({{ links.android_key_id_attestation }})).
- **iOS** provides **App Attest**, which attests an app instance and device integrity through Apple's servers. It does
  not directly attest arbitrary cryptographic keys used by an app. **Key attestation can be emulated** by binding a
  hardware-backed public key into the Apple‑signed `clientDataHash`
  attestation field (see [Apple App Attest]({{ links.ios_devicecheck }})).  
  Warden Supreme natively supports this as described
  [here]({{ links.signum_attestation_docs }}).

## High-Level Attestation Flow

1. **Initial Trust Establishment (Initial Attestation)**  
   When an app first establishes trust, it performs an attestation ceremony with your back-end:
    * The client generates a key inside secure hardware.
    * The platform signs an **attestation statement** that binds this key to reliable device- & app-state data.
    * Your back-end validates the statement against trusted roots and records the resulting device-key identity.

2. **Normal Operation**  
   After trust is established, the app uses the attested hardware-backed key for authenticated API calls, for example
   by signing requests or establishing mTLS. No additional attestation is required until the service decides to renew
   its assessment.

3. **Re-attestation (Periodic or Risk-Based)**  
   The server can request a new attestation on a schedule, after an OS update, or in response to increased risk:
    * The client repeats the attestation ceremony, incurring the same overhead as the initial attestation.
    * The server verifies that the device/app state is still compliant with policy and updates its trust record.


## Concepts and Terms Used Often

!!! tip
    Refer to the [full glossary](../glossary.md) for additional terms.

- **Verified Boot** — Android’s secure boot chain that verifies each boot stage and enforces **locked bootloader**
  policies. An attestation statement exposes the `verifiedBootState`.  
  Apple devices behave similarly, but imply a verified boot process through the mere presence of an Apple-signed
  attestation statement.
- **TEE (Trusted Execution Environment)** — Hardware‑isolated environment **inside the CPU/SoC** (e.g., ARM TrustZone)
  securely storing unextractable keys and performing cryptographic operations (see [Extraction Prevention]({{ links.android_keystore_extraction_prevention }})).
- **StrongBox** — (Android only) A separate secure element with dedicated CPU/RAM, providing stronger physical attack
  resistance than a TEE. Very few devices are manufactured with it (see [StrongBox]({{ links.android_keystore_strongbox_keymint }})).
- **Secure Enclave** — Apple’s secure coprocessor (a secure element, like StrongBox) providing hardware key isolation,
  implementation of cryptographic procedures and counters inside dedicated hardware (see [Secure Enclave]({{ links.ios_secure_enclave }})).
- **Key Attestation (Android)** — X.509 cert chain with an Android‑specific ASN.1 extension (*KeyDescription*) that
  encodes device/app state (OS version, patch level, verified boot, app package/signing digest, etc.). (see [Android Key Attestation]({{ links.android_key_attestation }})
  and [AOSP schema]({{ links.android_key_id_attestation }})).
- **App Attest (iOS)** — Apple‑operated attestation where `DCAppAttestService` creates a Secure Enclave key and Apple
  signs an **attestation object**; your server validates Apple’s chain and the **nonce** binding to your challenge.
  (see [DeviceCheck / App Attest]({{ links.ios_devicecheck }})).
- **Trust Anchor** — A root certificate your server trusts to validate an attestation chain. For Android, use Google’s
  attestation roots; for iOS, Apple’s App Attest root. (see [Android Key Attestation]({{ links.android_key_attestation }})
  and [Apple Attestation Validation Guide]({{ links.ios_attestation_validation }})).
- **User-Authentication-Bound Keys** — Android keys can require user presence (biometrics/PIN) per‑use; Warden can
  enforce or read these authorisations. (see [Android Keystore]({{ links.android_keystore_overview }})).
- **Remote Provisioning** — Newer Androids provision attestation/identities over the air; offline devices can **exhaust
  key pools** until connectivity returns. Plan for this in testing. (see conceptual notes
  in [AOSP Key & ID Attestation]({{ links.android_key_id_attestation }})).
- **App vs. Key Attestation (iOS)** — iOS does **app** attestation. **Key‑attestation emulation** is possible by
  embedding the public key bytes into the Apple‑signed attestation format (using our unified format). (see [Signum Supreme]({{ links.signum_supreme }})).
