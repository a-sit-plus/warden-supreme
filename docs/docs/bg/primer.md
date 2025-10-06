# What Remote Attestation Is (and Isn’t)

Remote attestation lets your server verify **what** generated a cryptographic proof on a device (e.g., an app running on
a verified OS on a genuine device) — not just **who** is at the other end. In practice, the client creates a key in
secure hardware and obtains a **verifiable statement** about the key and the device/app state. Your server validates
that statement against **trusted roots** and **policy**.

**Key Outcomes**:

- **Stronger client trust** than “just TLS + user auth” — you know *which* app and device you’re talking to.
- **Guarantees on hardware-backed key storage**: When done right, clients can prove to a service that sensitive
  cryptographic material is securely stored in hardware, such that it cannot be extracted.
- **Lower fraud risk** and **tight policy enforcement** (e.g., “only unmodified devices with the latest security updates
  applied may access resource _X_”).
- **Privacy aspects**: On Android, verification uses Google roots but **doesn’t require the device to talk to Google
  during attestation**; only *your* server sees the data. While your backend must check Google’s revocation list, this
  doesn't expose any data traceable to users to third-party services or Google's infrastructure.
  (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)).<br>
  On iOS, the story is a bit different, and, sadly, client devices will need to contact Apple servers to create an
  attestation statement.
- **Limits**: Attestation **can’t** stop a legitimate user from later abusing an account; it **won’t** prevent
  credential theft outside the app; and it **doesn’t** identify a person — it authenticates an **app+device instance**,
  and it **cannot** detect zero-day exploits.

!!! warning inline end "Performance Impact"
    * **iOS** requires live communication with Apple’s App Attest servers each time an attestation is generated. If network
    conditions are poor, this round-trip can add noticeable latency.  
    * **Android** produces the attestation statement entirely offline; only your backend needs to fetch Google’s public
    revocation list asynchronously. Therefore, attestation adds virtually **no runtime performance impact** for the user.

**Platform Differences** (high level):

- **Android**: provides **Key Attestation** (attests a key and device state) and **App/ID attestation** fields in the
  attestation extension (
  see [Android Key & ID Attestation](https://source.android.com/docs/security/features/keystore/attestation)).
- **iOS**: provides **App Attest** (attests an app instance and device integrity via Apple's servers). It’s conceptually
  **app attestation**, providing no out-of-the-box guarantees about any cryptographic material used by an app.
  **Key attestation can be emulated** by binding a hardware-backed public key into the Apple‑signed `clientData`
  attestation field (see [Apple App Attest](https://developer.apple.com/documentation/devicecheck)).  
  Warden Supreme natively supports this as described
  [here](https://a-sit-plus.github.io/signum/supreme/#attestation).

## High-Level Attestation Flow

1. **Initial Trust Establishment (Initial Attestation)**  
   The very first time an app starts, it performs an attestation ceremony with your backend:
    * The client generates a key inside secure hardware.
    * The platform signs an **attestation statement** that binds this key to reliable device- & app-state data.
    * Your backend validates the statement against trusted roots and stores the resulting device-key identity as
      “trusted”.

2. **Normal Operation**
After trust is established, the app uses the previously attested hardware-backed key for day-to-day authenticated API
calls (e.g., by signing requests or establishing mTLS). No further attestation is needed during this period, so
performance is on par with ordinary cryptographic operations.

3. **Re-attestation (Periodic or Risk-Based)**  
On a schedule, after an OS update, or when risk signals rise, the server can ask the client to
re-attest:
    * The client restarts the attestation ceremony. This incurs the same overhead as the initial attestation.
    * The server verifies that the device/app state is still compliant with policy and updates its trust record.


## Concepts & Terms used Often

!!! tip
    Refer to the [full glossary](../glossary.md) for a more comprehensive list of relevant terms.

- **Verified Boot** — Android’s secure boot chain that verifies each boot stage and enforces **locked bootloader**
  policies. An attestation statement exposes the `verifiedBootState`.  
  Apple devices behave similartly, but imply a verified boot process through the mere presence of an Apple-signed
  attestation statement.
- **TEE (Trusted Execution Environment)** — Hardware‑isolated environment **inside the CPU/SoC** (e.g., ARM TrustZone)
  securely storing unextractable keys and performing cryptographic operations (see [Extraction prevention](https://developer.android.com/privacy-and-security/keystore#ExtractionPrevention)).
- **StrongBox** — (Android only) A separate secure element with dedicated CPU/RAM, providing stronger physical attack
  resistance than a TEE. Only few devices are manufactured with it (see [StrongBox](https://developer.android.com/privacy-and-security/keystore#StrongBoxKeyMint)).
- **Secure Enclave** - Apple’s secure coprocessor (a secure element, like StrongBox) providing hardware key isolation,
  implementation of cryptographic procedures and counters inside dedicated hardware (see [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)).
- **Key Attestation (Android)** — X.509 cert chain with an Android‑specific ASN.1 extension (*KeyDescription*) that
  encodes device/app state (OS version, patch level, verified boot, app package/signing digest, etc.). (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
  and [AOSP schema](https://source.android.com/docs/security/features/keystore/attestation#schema)).
- **App Attest (iOS)** — Apple‑operated attestation where `DCAppAttestService` creates a Secure‑Enclave key and Apple
  signs an **attestation object**; your server validates Apple’s chain and the **nonce** binding to your challenge.
  (see [DeviceCheck / App Attest](https://developer.apple.com/documentation/devicecheck)).
- **Trust Anchor** — A root certificate your server trusts to validate an attestation chain. For Android, use Google’s
  attestation roots; for iOS, Apple’s App Attest root. (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
  and [Apple Attestation Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)).
- **User Authentication bound Keys** — Android keys can require user presence (biometrics/PIN) per‑use; Warden can
  enforce or read these authorizations. (see [Android Keystore](https://developer.android.com/privacy-and-security/keystore)).
- **Remote provisioning** — Newer Androids provision attestation/identities over the air; offline devices can **exhaust
  key pools** until connectivity returns. Plan for this in testing. (see conceptual notes
  in [AOSP Key & ID Attestation](https://source.android.com/docs/security/features/keystore/attestation)).
- **App vs. Key Attestation (iOS)** — iOS does **app** attestation. **Key‑attestation emulation** is possible by
  embedding the public key bytes into the Apple‑signed attestation format (using our unified format). (see [Signum Supreme](https://a-sit-plus.github.io/signum/supreme/)).

