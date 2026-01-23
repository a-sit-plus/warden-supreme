# Data Model and Wire Format

Warden Supreme standardises how attestation challenges, proofs, and outcomes are represented across platforms, based
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

- Challenge (Server → Client)
    - Contents:
        - `issuedAt`
        - `validity` indicating how long the challenge is valid
        - optional `timeZone`
        - a server-chosen `nonce` (≤128 bytes)
        - the `attestationEndpoint` to submit the attestation proof to
        - `proofOID` that identifies the CSR attribute to hold the attestation statement inside the CSR produced by the client
          serving as attestation proof.
        - `includeGenericDeviceName` to indicate whether the make and model of the client device (not the user-assignable name) should be included in the CSR
        - `version` to indicate the data format version
        - `keyConstraints` to tell the client which kind of key to create and attest.
    - Purpose: binds the proof to a fresh, server-originating value; communicates where and how to submit the
      attestation.

- Proof Transport (Client → Server)
    - The platform-specific attestation statement (Android Key/ID Attestation, iOS App Attest) is embedded into a
      PKCS#10 Certification Request (CSR) attribute identified by the provided `proofOID`.  
      It is represented as a JSON-encoded UTF-8 string inside the extension
    - The CSR subject encodes the challenge nonce in a serialNumber RDN.
    - This yields a single, signed container that carries both the device/app attestation and linkage to the server’s
      challenge.

- Server Response (Server → Client)  
This is a simple either class, branching as follows:
    - **Success** contains a single property: a `certificateChain` (X.509). This enables immediate consumption by arbitrary applications (mTLS, signed requests), regardless of platform specifics.
        - The leaf is a binding certificate issued for the attested key by the back-end.
        - The root is intended to be the root CA for the binding PKI configured at the back-end. However, the semantics can be adapted as desired.
    - **Failure** is a typed error with an optional explanation. Categories:
        - `TRUST`: trust or policy violations, such as:
            - Untrusted or mismatched root/intermediate (e.g., wrong environment or CA).
            - App identity mismatch (Team ID / Bundle ID, package signature digest, etc.).
            - Device state non-compliance (e.g., verified boot state, patch level, production vs. sandbox).
        - `TIME`: timing and validity issues, such as:
            - Challenge expired, not yet valid, or excessive clock skew between client and server.
            - Certificate/statement outside its validity window.
        - `CONTENT`: malformed or missing attestation proof content, such as:
            - CSR missing the expected attribute (proofOID) or unparsable payload.
            - Nonce binding absent or incorrect; unexpected or invalid structure in the attestation statement.
        - `INTERNAL`: server-side processing failures, such as:
            - Deserialisation or I/O errors during verification.
            - Transient infrastructure issues or unexpected exceptions not attributable to client input.

## Validation Linkage
The server extracts the challenge nonce from the CSR subject and the attestation statement from the CSR attribute
identified by proofOID, then validates:

- Challenge binding: the nonce must match the exact server-issued nonce and it must not be expired.
- Platform trust & policy: certificate chain, environment (prod/sandbox), app identity, device state,
  counters/continuity (see iOS notes below), boot/patch state (Android).
- Time: issuance time and validity windows for replay protection.
