# Glossary

This glossary centralizes terms used across the documentation. Each entry is concise and self‑contained; where useful, links to authoritative sources are included.

## Core Concepts
- **TEE (Trusted Execution Environment)** — Hardware‑isolated environment inside the CPU/SoC (e.g., ARM TrustZone) that securely stores unextractable keys and performs cryptographic operations (see [Extraction Prevention](https://developer.android.com/privacy-and-security/keystore#ExtractionPrevention)).
- **StrongBox** — Android‑only secure element with dedicated CPU/RAM that provides stronger physical attack resistance than a TEE. Only a subset of devices ship with it (see [StrongBox](https://developer.android.com/privacy-and-security/keystore#StrongBoxKeyMint)).
- **Secure Enclave** — Apple’s secure coprocessor (a secure element, like StrongBox) providing hardware key isolation, cryptographic procedures, and counters inside dedicated hardware (see [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)).
- **Attestation** — A cryptographically signed statement about a key and its execution environment (device/app state).
    - **Key Attestation** — A statement about the key (e.g., stored in secure hardware; non‑extractable).
    - **App Attestation** — A statement about the app (e.g., unmodified app, signed by the developer, running on an unmodified OS).
- **Challenge / Nonce** — A server‑generated, unpredictable byte string used exactly once to guarantee freshness and prevent replay. Android embeds it in the attestation extension; iOS mixes it into the attestation nonce via `clientDataHash` (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)).
- **Binding** — Cryptographically tying data (e.g., public key bytes + challenge) into an attested statement so the verifier can trust their association.

## Identities and Fields
- **App Identity (Android)** — Package name plus signing certificate digest(s); appears in the attestation extension (see [AOSP Key & ID Attestation](https://source.android.com/docs/security/features/keystore/attestation#attested-application-id)).
- **App ID (iOS)** — Concatenation of Team ID and Bundle ID, hashed into the authenticator data; identifies the app instance (see [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)).
- **Team ID (Apple)** — 10‑character identifier of the Apple Developer team; part of iOS App ID checks.
- **Bundle ID (Apple)** — Reverse‑DNS identifier (e.g., `com.example.app`). Appears (hashed) in App Attest authenticator data.
- **AAGUID (Apple App Attest)** — Identifies the attestation authenticator (production vs. sandbox/development) and must match the configured environment (see [Validating Apps That Connect to Your Server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)).

## Cryptographic Material and Encoding
- **X.509 Certificate Chain** — Sequence of certificates from leaf (key’s cert) → intermediate(s) → root (trust anchor). Android attestation uses an X.509 leaf carrying an attestation extension (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)).
- **Leaf / Intermediate / Root** — The key’s certificate is the leaf; intermediates link to a root certificate that the verifier trusts.
- **Trust Anchor** — Known‑good root certificate or public key the verifier explicitly trusts (e.g., Google’s Hardware Attestation Root, Apple’s App Attest Root) (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)).
- **ASN.1 / DER** — Encoding rules used in X.509 and Android’s attestation extension.
- **CBOR / COSE** — Encoding formats used by WebAuthn‑like structures and relevant to Apple’s App Attest internals ([CBOR](https://datatracker.ietf.org/doc/html/rfc7049), [COSE](https://datatracker.ietf.org/doc/html/rfc8152)).

## Android Specifics
- **Key Attestation (Android)** — X.509 chain with an Android‑specific ASN.1 extension (KeyDescription) encoding device/app state (OS version, patch level, verified boot, app package/signing digest, etc.) (see [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [AOSP schema](https://source.android.com/docs/security/features/keystore/attestation#schema)).
- **KeyDescription (Attestation Extension)** — Android’s ASN.1 structure embedded in the leaf certificate containing RootOfTrust, authorization lists, challenge, app identity, OS version, patch level, and more (see [AOSP schema](https://source.android.com/docs/security/features/keystore/attestation#schema)).
- **RootOfTrust** — Sub‑structure exposing verified boot state, device lock, and related boot verification data (see [AOSP schema](https://source.android.com/docs/security/features/keystore/attestation#schema)).
- **Verified Boot** — Android’s secure boot chain enforcing locked bootloader policies. The attestation exposes `verifiedBootState`.  
  Apple devices behave similarly, but verified boot is implied by the presence of an Apple‑signed attestation.
- **Bootloader Lock** — Whether the device bootloader is locked. Unlocked states typically invalidate trust.
- **Device Lock** — Whether the user lock screen is active at boot; part of RootOfTrust semantics.
- **Security Level** — Encoded in Android attestation:
    - `TrustedEnvironment` — Indicates TEE hardware isolation (e.g., TrustZone); common on Android 8.0+ devices.
    - `StrongBox` — Indicates a dedicated StrongBox HSM; highest protection; supported on fewer devices.
    - `Software` — No hardware root of trust; unsuitable for production. Useful for automated tests.
- **Rollback Resistance** — Hardware‑enforced guarantee preventing recovery of deleted keys after OS/firmware downgrade; indicated via `rollbackResistant`. Few devices set this flag even if supported (see [Rollback Resistance](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)).
- **Remote Key Provisioning (RKP)** — Cloud‑backed provisioning of attestation/identity keys on newer Android devices (officially supported on devices launched with Android 12, mandated with Android 13, revised with Android 14). Offline devices may exhaust provisioned pools and temporarily fail to attest (see [Remote Key Provisioning](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning)).
- **Nougat / Hybrid Attestation** — Legacy, partially software‑based path for some devices upgraded from Android 7.0; acceptable for key attestation, not for app/OS attestation.
- **Software Attestation** — No hardware root of trust; suitable for tests only.
- **ID Attestation** — Optional attestation of device identifiers; limited availability and low practical relevance.

## iOS Specifics
- **App Attest** — Apple service attesting an app instance using a Secure Enclave key, an Apple‑signed attestation, and follow‑up assertions with counters (see [DeviceCheck / App Attest](https://developer.apple.com/documentation/devicecheck)).
- **Attestation (Object)** — Structure returned by App Attest containing `authenticatorData`, `attStmt` (with `x5c`), and related metadata (see [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)).
- **Assertion** — A fresh, per‑request proof produced after successful attestation, proving continuity via a monotonic counter and binding a new challenge (see [Validating Apps That Connect to Your Server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)).
- **Secure Enclave** — Apple’s secure coprocessor providing hardware key isolation and counters.
- **Client Data / `clientDataHash`** — Client‑side JSON (or structured) data hashed and mixed into the attestation nonce (e.g., challenge + public key). Introduced in Signum Supreme’s unified format to emulate key attestation. Fully supported by Warden Supreme (see [Signum Supreme](https://a-sit-plus.github.io/signum/supreme/)).
- **Receipt (App Attest)** — Apple‑provided token attesting server‑validated registration; can be stored for later checks.
- **Counter (App Attest)** — Monotonic value in assertions to prevent replay.
- **Production vs. Sandbox** — Distinct environments identified by AAGUID; configuration must match (see [Preparing to Use App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)).

## Policy, Validation & Ops
- **Trust Policy** - Your server-side rules: required **security level**, **patch level**, **OS version**, **boot state**, etc.
- **Patch Level / OS Version** - Values attested by Android for minimum update enforcement. Beware OEM **misencoding** issues on some releases. (see [AOSP Key & ID Attestation](https://source.android.com/docs/security/features/keystore/attestation)). iOS unofficially supports these properties to be attested, but it is neither documented nor officially supported.
- **Revocation** - Mechanisms to invalidate compromised issuer/leaf certs; for Android attestation, check Google-published revocations on the server.
    - Android uses a custom mechanism (see [Android Developer Documentation](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status))
    - iOS does not have any revocation information associated with the certificate chain used for attestation.
- **Replay Protection** - Enforced by challenge/nonce binding and (on iOS) increasing counters.
- **Freshness Window** - Time window during which an attestation/statement is considered valid (e.g., 300s).
- **Time Drift** - Difference between client and backend clocks. May cause temporal validation error to trip attestation checks. Needs to be compensated for.
- **Rate Limiting (iOS)** - Apple may throttle excessive attestation/assertion use; cache receipts and avoid per-launch attestation. (see [Preparing to use App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service))

## Warden and Ecosystem
- **Warden Supreme** — Unified server‑side verifier for Android and iOS attestations, with unified format support for iOS key binding (this project).
- **Warden roboto** — Android‑focused attestation verification utilities used by Warden; previously a dedicated project, now integrated.
- **Warden makoto** — Server‑side mobile client attestation; previously a dedicated project, now integrated.
- **[Signum](https://a-sit-plus.github.io/signum/)** — Kotlin Multiplatform crypto/PKI toolkit. Its Supreme KMP crypto provider implements unified attestation flows in Warden Supreme.
- **[`google/android-key-attestation`](https://github.com/google/android-key-attestation)** — Google’s original parser and low‑level Android attestation check library; deprecated but still used inside Warden roboto due to limitations of the newer parser.
- **[`android/keyattestation`](https://github.com/android/keyattestation)** — Google’s newer attestation parser and PKIX cert path validator; Warden roboto uses the cert path validator but not the parser due to inherent limitations.