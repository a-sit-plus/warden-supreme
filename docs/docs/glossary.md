# Glossary

This glossary defines the terminology used throughout the documentation and links to primary sources where useful.

## Core Concepts
- **TEE (Trusted Execution Environment)** — Hardware‑isolated environment inside the CPU/SoC (e.g., ARM TrustZone) that securely stores unextractable keys and performs cryptographic operations (see [Extraction Prevention]({{ links.android_keystore_extraction_prevention }})).
- **StrongBox** — Android‑only secure element with dedicated CPU/RAM that provides stronger physical attack resistance than a TEE. Only a subset of devices ship with it (see [StrongBox]({{ links.android_keystore_strongbox_keymint }})).
- **Secure Enclave** — Apple’s secure coprocessor (a secure element, like StrongBox) providing hardware key isolation, cryptographic procedures, and counters inside dedicated hardware (see [Secure Enclave]({{ links.ios_secure_enclave }})).
- **HSM (Hardware Security Module)** — Dedicated hardware for key storage and cryptographic operations; on Android, StrongBox is the closest on-device analogue.
- **Attestation** — A cryptographically signed statement about a key and its execution environment (device/app state).
    - **Key Attestation** — A statement about the key (e.g., stored in secure hardware; non‑extractable).
    - **App Attestation** — A statement about the app (e.g., unmodified app, signed by the developer, running on an unmodified OS).
- **Attestation Statement** — The platform-generated attestation payload (Android: X.509 chain with KeyDescription; iOS: App Attest payload).
- **Attestation Object (iOS)** — Apple’s App Attest CBOR structure (`authenticatorData`, `attStmt`, `x5c`) returned by `attestKey`.
- **Attestation Proof** — The authenticated transport sent to the server: either a signed CSR or a hash-bound unsigned TBS CSR carrying the attestation statement payload.
- **Proof of Possession** — Evidence that the client can use the private key corresponding to a public key. Warden Supreme
  obtains this from the CSR signature in `DataAuthentication.Signature` mode. Hash mode deliberately omits it.
- **Data Authentication** — In Warden Supreme, the challenge-selected mechanism binding TBS CSR contents to the ceremony: a CSR signature,
  or a digest incorporated into the platform attestation nonce.
- **Challenge / Nonce** — A server‑generated, unpredictable byte string used exactly once to guarantee freshness and prevent replay. Android embeds it in the attestation extension; iOS mixes it into the attestation nonce via `clientDataHash` (see [Android Key Attestation]({{ links.android_key_attestation }}), [Attestation Object Validation Guide]({{ links.ios_attestation_validation }})).
- **Binding** — Cryptographically tying data (e.g., public key bytes + challenge) into an attested statement so the verifier can trust their association.

## Identities and Fields
- **App Identity (Android)** — Package name plus signing certificate digest(s); appears in the attestation extension (see [AOSP Key & ID Attestation]({{ links.android_key_id_attestation }})).
- **App ID (iOS)** — Concatenation of Team ID and Bundle ID, hashed into the authenticator data; identifies the app instance (see [Attestation Object Validation Guide]({{ links.ios_attestation_validation }})).
- **Team ID (Apple)** — 10‑character identifier of the Apple Developer team; part of iOS App ID checks.
- **Bundle ID (Apple)** — Reverse‑DNS identifier (e.g., `com.example.app`). Appears (hashed) in App Attest authenticator data.
- **AAGUID (Apple App Attest)** — Identifies the attestation authenticator (production vs. sandbox/development) and must match the configured environment (see [Validating Apps That Connect to Your Server]({{ links.ios_validating_apps }})).

## Cryptographic Material and Encoding
- **X.509 Certificate Chain** — Sequence of certificates from leaf (key’s cert) → intermediate(s) → root (trust anchor). Android attestation uses an X.509 leaf carrying an attestation extension (see [Android Key Attestation]({{ links.android_key_attestation }})).
- **Leaf / Intermediate / Root** — The key’s certificate is the leaf; intermediates link to a root certificate that the verifier trusts.
- **Trust Anchor** — Known‑good root certificate or public key the verifier explicitly trusts (e.g., Google’s Hardware Attestation Root, Apple’s App Attest Root) (see [Android Key Attestation]({{ links.android_key_attestation }}), [Attestation Object Validation Guide]({{ links.ios_attestation_validation }})).
- **PKCS#10 / CSR (Certificate Signing Request)** — A signed request containing a CertificationRequestInfo (TBS CSR), a
  signature algorithm, and a signature. Warden Supreme signature mode sends the complete CSR; hash mode sends only the
  unsigned TBS CSR.
- **TBS CSR / CertificationRequestInfo** — The part of a PKCS#10 request containing version, subject, public key, and
  attributes (including requested extensions). It is signed in signature mode and hash-bound in hash mode.
- **AttestationHashInput** — Canonical DER projection of a TBS CSR excluding its public key and single attestation-proof
  attribute. Its digest becomes the platform attestation nonce in hash mode.
- **Attested Client Attribute** — A typed value supplied by verified application code and bound into the TBS CSR. It is
  software-attested rather than independently asserted by the device hardware or OS.
- **OID (Object Identifier)** — Hierarchical identifier used in X.509 and CSR attributes/extensions; used to identify custom attestation payloads and optional device-name attributes.
- **PKI / PKIX** — Public Key Infrastructure and its X.509 profile; governs certificate path validation, constraints, and revocation semantics.
- **ASN.1 / DER** — Encoding rules used in X.509 and Android’s attestation extension.
- **CBOR / COSE** — Encoding formats used by WebAuthn‑like structures and relevant to Apple’s App Attest internals ([CBOR]({{ links.rfc_7049_cbor }}), [COSE]({{ links.rfc_8152_cose }})).

## Android Specifics
- **Key Attestation (Android)** — X.509 chain with an Android‑specific ASN.1 extension (KeyDescription) encoding device/app state (OS version, patch level, verified boot, app package/signing digest, etc.) (see [Android Key Attestation]({{ links.android_key_attestation }}), [AOSP schema]({{ links.android_key_id_attestation }})).
- **KeyDescription (Attestation Extension)** — Android’s ASN.1 structure embedded in the leaf certificate containing RootOfTrust, authorisation lists, challenge, app identity, OS version, patch level, and more (see [AOSP schema]({{ links.android_key_id_attestation }})).
- **RootOfTrust** — Sub‑structure exposing verified boot state, device lock, and related boot verification data (see [AOSP schema]({{ links.android_key_id_attestation }})).
- **AVB (Android Verified Boot)** — Boot-time verification scheme using `vbmeta` and rollback indexes; its results are attested via RootOfTrust and patch-level fields.
- **Verified Boot** — Android’s secure boot chain enforcing locked bootloader policies. The attestation exposes `verifiedBootState`.  
  Apple devices behave similarly, but verified boot is implied by the presence of an Apple‑signed attestation.
- **Bootloader Lock** — Whether the device bootloader is locked. Unlocked states typically invalidate trust.
- **Device Lock** — Whether the user lock screen is active at boot; part of RootOfTrust semantics.
- **KeyMint** — Modern Android keystore subsystem for key generation and attestation (successor to Keymaster); its capabilities and versions influence attestation features.
- **Keymaster** — Legacy Android keystore HAL name for key generation and attestation; older devices still expose it.
- **Security Level** — Encoded in Android attestation:
    - `TrustedEnvironment` — Indicates TEE hardware isolation (e.g., TrustZone); common on Android 8.0+ devices.
    - `StrongBox` — Indicates a dedicated StrongBox HSM; highest protection; supported on fewer devices.
    - `Software` — No hardware root of trust; unsuitable for production. Useful for automated tests.
- **Rollback Resistance** — Hardware‑enforced guarantee preventing recovery of deleted keys after OS/firmware downgrade; indicated via `rollbackResistant`. Few devices set this flag even if supported (see [Rollback Resistance]({{ links.android_implementer_ref_rollback_resistance }})).
- **Remote Key Provisioning (RKP)** — Cloud‑backed provisioning of attestation/identity keys on newer Android devices (officially supported on devices launched with Android 12, mandated with Android 13, revised with Android 14). Offline devices may exhaust provisioned pools and temporarily fail to attest (see [Remote Key Provisioning]({{ links.android_rkp_docs }})).
- **Nougat / Hybrid Attestation** — Legacy, partially software‑based path for some devices upgraded from Android 7.0; acceptable for key attestation, not for app/OS attestation.
- **Software Attestation** — No hardware root of trust; suitable for tests only.
- **ID Attestation** — Optional attestation of device identifiers; limited availability and low practical relevance.

## iOS Specifics
- **App Attest** — Apple service attesting an app instance using a Secure Enclave key, an Apple‑signed attestation, and follow‑up assertions with counters (see [DeviceCheck / App Attest]({{ links.ios_devicecheck }})).
- **Attestation Object (App Attest)** — Structure returned by App Attest containing `authenticatorData`, `attStmt` (with `x5c`), and related metadata (see [Attestation Object Validation Guide]({{ links.ios_attestation_validation }})).
- **Assertion** — A fresh, per‑request proof produced after successful attestation, proving continuity via a monotonic counter and binding a new challenge (see [Validating Apps That Connect to Your Server]({{ links.ios_validating_apps }})).
- **Client Data / `clientDataHash`** — Client‑defined input mixed into the App Attest nonce. In practice this is typically `SHA-256` over app‑defined bytes (often JSON) that include the server challenge and any binding context. Warden Supreme’s unified format uses this to emulate key attestation semantics on iOS (see [Signum Supreme]({{ links.signum_supreme }})).
- **Receipt (App Attest)** — Apple‑provided token attesting server‑validated registration; can be stored for later checks.
- **Counter (App Attest)** — Monotonic value in assertions to prevent replay.
- **Production vs. Sandbox** — Distinct environments identified by AAGUID; configuration must match (see [Preparing to Use App Attest]({{ links.ios_preparing_app_attest }})).

## Policy, Validation & Ops
- **Trust Policy** — Server‑side rules: required security level, patch level, OS version, boot state, etc.
- **Patch Level / OS Version** — Values attested by Android for minimum update enforcement. Beware OEM misencoding issues on some releases (see [AOSP Key & ID Attestation]({{ links.android_key_id_attestation }})).
- **Revocation** — Mechanisms to invalidate compromised issuer/leaf certs; for Android attestation, check Google‑published revocations on the server.
    - Android uses a custom mechanism (see [Android Key Attestation]({{ links.android_key_attestation }})).
    - iOS does not provide revocation information for the attestation certificate chain.
- **Replay Protection** — Enforced by challenge/nonce binding and (on iOS) increasing counters.
- **Freshness Window** — Time window during which an attestation/statement is considered valid (e.g., 300 seconds).
- **Time Drift** — Difference between client and server clocks. Can cause time‑based verification failures and needs to be compensated for.
- **Rate Limiting (iOS)** — Apple may throttle excessive attestation/assertion use; cache receipts and avoid per‑launch attestation (see [Preparing to Use App Attest]({{ links.ios_preparing_app_attest }})).

## Warden and Ecosystem
- **Warden Supreme** — Unified server‑side verifier for Android and iOS attestations, with unified format support for iOS key binding (this project).
- **Warden roboto** — Android‑focused attestation verification utilities used by Warden; previously a dedicated project, now integrated.
- **Warden makoto** — Server‑side Android+iOS attestation library; previously a dedicated project, now integrated.
- **[Signum]({{ links.signum_home }})** — Kotlin Multiplatform crypto/PKI toolkit. Its Supreme KMP crypto provider implements unified attestation flows in Warden Supreme.
- **[`google/android-key-attestation`]({{ links.github_google_android_key_attestation }})** — Google’s original parser and low‑level Android attestation check library; deprecated but still used inside Warden roboto due to limitations of the newer parser.
- **[`android/keyattestation`]({{ links.github_android_keyattestation }})** — Google’s newer attestation parser and PKIX cert path validator; Warden roboto uses the cert path validator but not the parser due to inherent limitations.
