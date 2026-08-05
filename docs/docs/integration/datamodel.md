# Data Model and Wire Format

Warden Supreme standardises how attestation challenges, proofs, and outcomes are represented across platforms, based on
[Signum's multiplatform attestation data model](https://a-sit-plus.github.io/signum/dokka/indispensable/at.asitplus.signum.indispensable/-attestation/index.html).
The data model gives you:

- One parsing and validation path for both Android and iOS.
- A single transport for challenges and proofs.
- Explicit, auditable success/failure responses.

!!! tip inline end "JSON Schemas"
    * [AttestationChallenge](../schemas/AttestationChallenge.json)
    * [Attestation](../schemas/Attestation.json)
    * [AttestationResponse](../schemas/AttestationResponse.json)


Warden Supreme does not enforce a specific encoding for its wire format. However, JSON has become the de facto standard for HTTP-based
APIs, so we provide ready-to-use JSON representation and **experimental**, auto-generated schemas for Warden Supreme's data types. They are meant to help you
wire up third-party clients. Treat them as experimental for now, as the integrated clients will interopertate seamlessly with Warden Supreme's back-end verifier out of the box.

## Core Artefacts

### Challenge (Server → Client)
The challenge binds a future attestation proof to a fresh, server-originating value and tells the client where and how
to respond.

**Fields:**

- `issuedAt`: when the challenge was issued.
- `validity`: how long the challenge is valid.
- `timeZone`: optional server time zone (informational).
- `nonce`: server-chosen nonce (≤128 bytes). This is sensitive replay-protection material. Treat it as a short-lived bearer value: do not log it, do not expose it across sessions or callers, and serve challenges only over protected transport.
- `attestationEndpoint`: where the client submits the attestation proof.
- `proofOID`: TBS CSR attribute identifier used to carry the attestation statement payload.
- `genericDeviceNameOID`: whether to include a generic make/model (not user-assignable name) in the TBS CSR.
- `version`: data format version.
- `keyConstraints`: desired key parameters and protection policy for the client.
- `dataAuth`: required proof authentication: signed PKCS#10 (`Signature`, the default) or hash-bound unsigned TBS CSR
  (`hash` plus a digest algorithm).
- `toBeAttestedAttributes`: optional OID plus an ordered list of named, typed client-provided values. Each value can be
  required or optional.
- `additionalPayload`: optional, service-defined key/value payload to piggyback along with the challenge (see below).
- `transientData`: optional runtime-only attachment; not serialized and not part of the wire format.

#### `additionalPayload`
Some deployments carry extra server-side policy context with the challenge: a session id, tenant id, UI flow hints, or
other metadata available again after the challenge is matched. This is not a client-attested value. Use
`toBeAttestedAttributes` when the client must supply a value that is cryptographically bound to the ceremony.

`additionalPayload` is a nested map structure:
- Keys are `String`.
- Values are constrained to primitives (`Boolean`, `String`, numeric types, `Char`), nested maps, or `null`.

Some serialisation formats omit default scalar values on the wire (e.g. they encode `0` as "field absent"). To avoid
such ambiguity, each value is encoded internally as a small "typed envelope" that always carries a non-default
discriminator. The payload therefore survives JSON, CBOR, and Protobuf-style encodings even when they apply
default-elision optimisations.

#### `transientData`
`transientData` exists for server-side convenience (e.g., attaching a database ID or request context to a challenge instance).
It is annotated as transient, excluded from equality/hashing, and therefore never appears on the wire or in generated schemas.
You may set it when constructing an `AttestationChallenge` on the server, to keep runtime-only state associated with the challenge.

### Proof Transport (Client → Server)
The platform-specific attestation payload (Android Key/ID Attestation, iOS App Attest) is embedded into a PKCS#10
CertificationRequestInfo (TBS CSR) attribute identified by `proofOID`, as a JSON-encoded UTF-8 string. The TBS CSR subject
encodes the original server nonce in a `serialNumber` RDN. Extensions, the optional generic device name, and requested
client-provided attributes are carried by the same TBS CSR.

`AttestationProof` makes the two possible transports explicit:

- `Signed` carries a complete PKCS#10 CSR. The client signs the TBS CSR with the attested key, authenticating every field
  and proving possession of the private key.
- `Hashed` carries an unsigned TBS CSR. Before generating the attested key, the client DER-encodes an
  `AttestationHashInput`: the future TBS CSR version, subject, extensions, and attributes, excluding only the not-yet-known
  public key and attestation-proof attribute. It hashes that structure and uses the digest as the platform attestation
  nonce. The verifier reconstructs and hashes the same structure and independently checks that the TBS CSR public key is
  the attested key. This authenticates the included data but deliberately provides no proof of possession.

The raw HTTP body is DER in both cases. `AttestationProof.decodeFromDer` distinguishes a complete CSR from a TBS CSR
by their different ASN.1 structures; it does not need the challenge or a caller-supplied hash algorithm. The verifier then
loads the matching challenge, obtains the expected authentication mode and digest algorithm from it, and rejects a
signed/unsigned shape mismatch.

In this documentation, "attestation statement" means the platform payload, "attestation proof" means either authenticated
transport, and "attestation object" refers specifically to iOS App Attest.

#### Requested attested attributes

`toBeAttestedAttributes` defines one dedicated CSR attribute OID and an ordered schema. Each value is encoded at its list
position using `PrimitiveType`; optional missing values are represented as ASN.1 `NULL`. The client callback receives the
schema and must return exactly one value per entry. Required values cannot be `null`.

These values originate in application code and are therefore "software-attested": they are trustworthy only to the extent
that the verified app and the selected authentication mode are trusted. They are bound by the CSR signature in signature
mode and by `AttestationHashInput` in hash mode.

### Server Response (Server → Client)
The response is an `either` type:

#### Success
`Success` contains a single property: a `certificateChain` (X.509). Any application can consume it directly (mTLS, signed
requests), regardless of platform specifics.

- The leaf is a binding certificate issued for the attested key by the back-end.
- The root is intended to be the root CA for the binding PKI configured at the back-end. However, the semantics can be adapted as desired.

#### Failure
`Failure` is a typed error with an optional explanation. These categories are the **client-facing** semantics; low-level
attestation exceptions are mapped into one of these four buckets (see [Error Handling](errorhandling.md) for the full mapping).

- `TRUST`: trust or policy violations, such as:
    - Untrusted or mismatched root/intermediate (e.g., wrong environment or CA).
    - App identity mismatch (Team ID / Bundle ID, package signature digest, etc.).
    - Device state non-compliance (e.g., verified boot state, patch level, production vs. sandbox).
    - The public key claimed by the CSR does not match the key proven by the attestation statement.
    - The submitted transport does not provide the authentication mode required by the challenge.
- `TIME`: timing and validity issues, such as:
    - Challenge expired or not yet valid.
    - Excessive clock skew between client and server.
    - Certificate or attestation statement outside its validity window.
- `CONTENT`: malformed, missing, or semantically invalid input, such as:
    - CSR missing the expected attribute (`proofOID`) or an unparsable payload.
    - Duplicate attribute or extension OIDs, malformed extension requests, or non-canonical DER attribute order.
    - Missing, malformed, unexpected, or type-invalid requested attributes.
    - Nonce binding absent, incorrect, or not issued by the server.
    - Attestation statement fails policy checks (package name, signer digest, boot state, rollback resistance, OS/app version, security level).
    - Platform configuration mismatch (e.g., statement received for a non-configured platform).
    - Structurally invalid or nonsensical attestation statement content.
- `INTERNAL`: server-side processing failures, such as:
    - Deserialisation or I/O errors during verification.
    - Transient infrastructure issues.
    - Unexpected exceptions not attributable to client input.

## How Verification Ties Together
The server extracts the original challenge nonce from the TBS CSR subject and the attestation statement from the attribute
identified by `proofOID`, then validates:

- **Challenge binding**: the nonce must identify the exact server-issued, unexpired challenge.
- **Authentication mode**: signed and hashed transports are not interchangeable.
- **Data binding**: verify the CSR signature and proof of possession in signature mode, or recompute the canonical hash
  input in hash mode.
- **Key binding**: the TBS CSR public key must equal the key proven by platform attestation in both modes.
- **Requested attributes**: the dedicated attribute must match the challenge's ordered types and required/optional rules.
- **Platform trust and policy**: certificate chain, environment (prod/sandbox), app identity, device state, counters/continuity
  (see [iOS deep dive](../technical/ios.md)), boot/patch state (see [Android deep dive](../technical/android.md)).
- **Time**: issuance time and validity windows for replay protection. See also [Clock Drifts and Temporal Validity](../technical/quirks.md#clock-drifts-and-temporal-validity).
