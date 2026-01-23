# Data Model and Wire Format

Warden Supreme standardises how attestation challenges, proofs, and outcomes are represented across platforms, based on
[Signum's multiplatform attestation data model](https://a-sit-plus.github.io/signum/dokka/indispensable/at.asitplus.signum.indispensable/-attestation/index.html).
The chosen data model achieves the following:

- Uniform parsing/validation for Android and iOS.
- Comprehensible transport of challenges and proofs.
- Explicit, auditable responses for success/failure.

!!! tip inline end "JSON Schemas"
    * [AttestationChallenge](../schemas/AttestationChallenge.json)
    * [Attestation](../schemas/Attestation.json)
    * [AttestationResponse](../schemas/AttestationResponse.json)


Warden Supreme does not specify an encoding for its wire format. However, JSON has become the de facto standard for many
HTTP-based APIs. We therefore provide **experimental**, auto-generated schemas for Warden Supreme's data types.
These can be helpful for integrating third-party clients.  
Please note that these schemas really are experimental as of now.

## Core Artefacts

### Challenge (Server → Client)
The challenge binds a future attestation proof to a fresh, server-originating value and tells the client where and how
to respond.

**Fields**
- `issuedAt`: when the challenge was issued.
- `validity`: how long the challenge is valid.
- `timeZone`: optional server time zone (informational).
- `nonce`: server-chosen nonce (≤128 bytes).
- `attestationEndpoint`: where the client submits the attestation proof.
- `proofOID`: CSR attribute identifier used to carry the attestation statement payload.
- `genericDeviceNameOID`: whether to include a generic make/model (not user-assignable name) in the CSR.
- `version`: data format version.
- `keyConstraints`: desired key parameters and protection policy for the client.

### Proof Transport (Client → Server)
The platform-specific attestation payload (Android Key/ID Attestation, iOS App Attest) is embedded into a PKCS#10
Certificate Signing Request (CSR) attribute identified by the provided `proofOID`. It is represented as a JSON-encoded UTF-8
string inside the extension.

The CSR subject encodes the challenge nonce in a `serialNumber` RDN. This yields a single, signed container that carries
both the device/app attestation and linkage to the server’s challenge. In this documentation, "attestation statement"
means the platform payload, "attestation proof" means the transport container (CSR), and "attestation object" refers
specifically to iOS App Attest.

### Server Response (Server → Client)
The response is an either type:

#### Success
`Success` contains a single property: a `certificateChain` (X.509). This enables immediate consumption by arbitrary applications
(mTLS, signed requests), regardless of platform specifics.

- The leaf is a binding certificate issued for the attested key by the back-end.
- The root is intended to be the root CA for the binding PKI configured at the back-end. However, the semantics can be adapted as desired.

#### Failure
`Failure` is a typed error with an optional explanation. These categories are the **client-facing** semantics; low-level
attestation exceptions are mapped into one of these four buckets (see [Error Handling](errorhandling.md) for the full mapping).

- `TRUST`: trust or policy violations, such as:
    - Untrusted or mismatched root/intermediate (e.g., wrong environment or CA).
    - App identity mismatch (Team ID / Bundle ID, package signature digest, etc.).
    - Device state non-compliance (e.g., verified boot state, patch level, production vs. sandbox).
- `TIME`: timing and validity issues, such as:
    - Challenge expired or not yet valid.
    - Excessive clock skew between client and server.
    - Certificate or attestation statement outside its validity window.
- `CONTENT`: malformed, missing, or semantically invalid input, such as:
    - CSR missing the expected attribute (`proofOID`) or an unparsable payload.
    - Nonce binding absent, incorrect, or not issued by the server.
    - Attestation statement fails policy checks (package name, signer digest, boot state, rollback resistance, OS/app version, security level).
    - Platform configuration mismatch (e.g., statement received for a non-configured platform).
    - Structurally invalid or nonsensical attestation statement content.
- `INTERNAL`: server-side processing failures, such as:
    - Deserialisation or I/O errors during verification.
    - Transient infrastructure issues.
    - Unexpected exceptions not attributable to client input.

## How Verification Ties Together
The server extracts the challenge nonce from the CSR subject and the attestation statement from the CSR attribute
identified by `proofOID`, then validates:

- **Challenge binding**: the nonce must match the exact server-issued nonce and it must not be expired.
- **Platform trust and policy**: certificate chain, environment (prod/sandbox), app identity, device state, counters/continuity
  (see [iOS deep dive](../technical/ios.md)), boot/patch state (see [Android deep dive](../technical/android.md)).
- **Time**: issuance time and validity windows for replay protection. See also [Clock Drifts and Temporal Validity](../technical/quirks.md#clock-drifts-and-temporal-validity).
