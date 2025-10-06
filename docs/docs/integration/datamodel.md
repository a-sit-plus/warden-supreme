# Data Model and Wire Format

Warden Supreme standardizes how attestation challenges, proofs, and outcomes are represented across platforms, based
[Signum's multiplatform attestation data model](https://a-sit-plus.github.io/signum/dokka/indispensable/at.asitplus.signum.indispensable/-attestation/index.html).
The chose data model achieves the following:

- Uniform parsing/validation for Android and iOS.
- Comprehensible transport of challenges and proofs.
- Explicit, auditable responses for success/failure.

## Core Artifacts

- Challenge (Server → Client)
    - Contents:
        - `issuedAt`
        - optional `validity` indicating how long the challenge is valid
        - optional `timeZone`
        - a server-chosen `nonce` (≤128 bytes)
        - the `attestationEndpoint` to submit the attestation proof to
        - `proofOID` that identifies the CSR attribute to hold the attestation statement inside the CSR prodiced by the client
          serving as attestation proof.
    - Purpose: binds the proof to a fresh, server-originating value; communicates where and how to submit the
      attestation.

- Proof Transport (Client → Server)
    - The platform-specific attestation statement (Android Key/ID Attestation, iOS App Attest) is embedded into a
      PKCS#10 Certification Request (CSR) attribute identified by the provided `proofOID`.
    - The CSR subject encodes the challenge nonce in a serialNumber RDN.
    - This yields a single, signed container that carries both the device/app attestation and linkage to the server’s
      challenge.

- Server Response (Server → Client)  
This is a simple either-class, branching as follows:
    - **Success** contains a single property: a `certificateChain` (X.509). This enables immediate consumption by the arbitrary applications (mTLS, signed requests), regardless of platform specifics.
        - The leaf is a binding certificate issued for the attested key by the backend.
        - The root is the root CA configured at the backend.
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
            - Deserialization or I/O errors during verification.
            - Transient infrastructure issues or unexpected exceptions not attributable to client input.

## Validation Linkage
The server extracts the challenge nonce from the CSR subject and the attestation statement from the CSR attribute
identified by proofOID, then validates:

- Challenge binding: the attestation’s nonce/clientDataHash must incorporate the exact server-issued nonce.
- Platform trust & policy: certificate chain, environment (prod/sandbox), app identity, device state,
  counters/continuity (see iOS notes below), boot/patch state (Android), and key usage constraints.
- Time: issuance time and validity windows to mitigate clock drift and replay.

## Semantics across Platforms

- Android: supports offline attestation/assertion semantics with negligible runtime impact once keys are provisioned.
- iOS: does not natively expose Android-style offline assertions. Warden Supreme replicates uniform assertion-like
  semantics on iOS by leveraging App Attest artifacts plus a server-issued challenge to mirror Android behavior.
  On iOS these proofs require contacting Apple services, which can
  introduce latency.

## Rationale

- Single canonical container: a CSR provides a signed envelope with well-understood parsing and signature semantics.
- Cross-platform uniformity: Android’s native flows and iOS’s replicated assertion semantics slot into the same
  transport and verification pipeline.
- Explicit outcomes: typed responses allow clients to differentiate retryable time issues from policy/trust failures.

## Operational Implications

- Statefulness: backends persist per-app-instance identity (key IDs/public keys), but forego complex tracking mechanisms
  like those proposed by Apple's App Attest.
- Privacy Controls: This strategy inimizes stored identifiers and prevents concrete user tracking.