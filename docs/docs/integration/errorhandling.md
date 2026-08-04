# Error Handling

!!! tip inline end "Project Structure"
    See [project structure details](structure.md) for info on components, their names, functionality, and interdependencies.

Attestation has many expected failure modes. Makoto, the unified server-side Android and iOS verifier at the core of
Warden Supreme, groups them into semantic categories that can be handled consistently across platforms.

In the integrated flow, malformed proofs and invalid challenges may be rejected before Makoto receives the platform
attestation statement.

Back-end integrators should understand where failures occur even when using the integrated verifier and client. This is
necessary to define opaque client-facing error codes and diagnose failures observed in the field.

This page first describes server-side errors and then maps them to the categories communicated to clients.

## Server-Side (Low-Level Errors)
The low-level hierarchy covers failures from platform verification. Pre-attestation errors cover checks performed by the
Supreme verifier before Makoto receives the platform evidence.

### Attestation Error Hierarchy

Makoto uses exceptions because navigable stack traces are valuable during diagnosis. All attestation failures derive
from the sealed `AttestationException` class, whose subclasses provide the semantic categories.

Every such exception features:

- **a `platform` property** indicating whether an iOS or Android attestation failed to verify
- **a nullable `message`** providing human-readable debugging context rather than an end-user message
- **a `cause`** carrying the underlying platform-specific exception


On a high level, three different categories of attestation errors exist across iOS 
and Android:

1. Certificate errors
    * Trust
    * Time
2. Configuration errors
    * May be thrown during initialisation. Example reasons include:
        * No apps were configured
        * Negative validity duration was specified
        * Neither iOS nor Android attestation was setup
        * Illegal team identifier for iOS attestation
    * Thrown when an attestation statement is received for a platform that is not configured
      (i.e. only iOS attestation is configured, but an Android attestation statement is received or vice versa).
3. Invalid attestation statement contents
   * Most of the time containing platform specifics
   * Also thrown for nonsensical/invalid inputs

The snippet below shows the attestation exceptions that may be thrown. Its annotations explain each case.
Note that the `onAttestationError` callback is side-effect-free except that it allows for returning a (nullable) string
to customise the error message/error code conveyed to the client.

```kotlin
--8<-- "Readme-Backend-errorhandling.kt:15:60"
```

1. Refer to [Debugging](debugging.md)
2. Certificate is not yet valid or expired. Clock drift is the main source for this error.
3. An untrusted root certificate was encountered. E.g., an Android Emulator was used in production.
4. Thrown when an attestation statement is received for a platform that is not configured.
5. The client OS is too old (with respect to the configured minimum OS version)
6. The attestation statement creation timestamp (not the certificate validity!) is too far in the past or absent.  
   Warden Supreme's defaults account for ordinary clock drift.
7. The challenge encoded into the attestation statement payload does not match the expected challenge.
8. The app's package name does not match the expected package name.  
   I.e., an unauthorised app is trying to attest to the back-end.
9. The app was signed with an unknown key.  
   Could be an indicator for a repackaging attack.
10. The client app is too old (i.e., minimum version constraint not fulfilled).
11. Rollback resistance was enforced, but the client device is not rollback-resistant.
12. In theory, this will happen when the attestation or keymaster security level does not match the expected level
    (e.g. hardware attestation is enforced, but an emulator is trying to attest). In practice, however, this will never
    occur because hardware and software attestation use different trust anchors.
    Hence, an `AttestationException.Certificate.Trust` is thrown before this check can even be triggered.
13. A client's bootloader lock state or verified boot state is unlocked/unverified, even though the attestation policy
    expects a locked bootloader and a factory image.
14. This usually indicates a structural error in the attestation statement and therefore requires manual debugging to make sense of.
15. Minimum iOS version/build number not satisfied.
16. The attestation statement creation timestamp (not the certificate validity!) is too far in the past. This is usually due to a clock drift between client and server.  
    The Supreme Verifier prevents the client from even attempting to send an attestation, as clock drift detection is implemented as client-side functionality.
17. The challenge encoded into the attestation statement payload does not match the expected challenge.
18. The team ID and/or bundle identifier and/or stage (sandbox vs. production) of the client app do not match.
19. The signature counter encoded into the assertion is too high. See [iOS technical deep dive](../technical/ios.md).
20. This usually indicates a structural error in the attestation statement and therefore requires manual debugging to make sense of.
21. This is usually triggered by structurally invalid input, such as an empty proof or CSR or misencoded certificates,
    and requires manual debugging. It has not occurred in production with a legitimate client app.

!!! tip inline end "Debugging"
    Refer to [Debugging](debugging.md) for detailed information and guidance on debugging.

All platform-specific exceptions are contained in the `AttestationException.Content` hierarchy. Applications rarely
need this detail when reacting to an error, but it is essential for diagnosis.
In particular, the call in line&nbsp;4 will produce a log entry with a self-contained, replayable attestation call for
offline analysis.

### Pre-Attestation Errors
When using fully integrated attestation, preprocessing steps are automatically performed to extract, check, and invalidate
the received challenge, parse the signed CSR or unsigned TBS CSR, extract the attestation statement, validate the selected
authentication mode and canonical CSR structure, match the attested public key, and decode requested attributes.
Arbitrary input can fail any of these steps. The following snippet shows how to handle pre-attestation errors.
Note that the `onPreAttestationError` callback is side-effect-free except that it allows for returning a (nullable) string
to customise the error message/error code conveyed to the client.

```kotlin
--8<-- "Readme-Backend-preerrorhandling.kt:16:38"
```

1. The attestation statement could not be extracted from the received transport. New code receives
   `AugmentedAttestationStatementExtraction`, which contains `AttestationProof`; the CSR-only class is retained for
   the deprecated verifier overload.
2. The nonce/challenge could not be extracted from the received TBS CSR.
3. Challenge verification or an operational pre-attestation step failed.
4. `ClientDataValidation` exposes a precise `reason`, the received transport, the validated challenge, and the underlying
   throwable. Reasons cover authentication-mode mismatch, duplicate attribute/extension OIDs, malformed extension
   requests, non-canonical attribute order, hash binding, public-key mismatch, and requested-attribute extraction/matching.

The callback's non-null return value becomes the client-facing explanation. Exceptions thrown by this observation callback
are ignored and the verifier uses its safe fallback explanation.


## Client-Side (Generic, High-Level Error Categories)
Using fully integrated attestation only ever returns either an `AttestationResponse.Success`
or an `AttestationResponse.Failure`. The latter indicates one of four error reasons:

1. `TRUST` encompassing untrusted roots, revoked certificates, invalid certificate chains, invalid CSR signatures, a
   public key that does not match the attested key, or a transport that does not provide the authentication mode required
   by the challenge
2. `TIME` encompassing temporal validity errors with respect to certificates and attestation statements 
3. `CONTENT` encompassing cases where the attestation statement fails to parse or verify against policy, and invalid proof
   transport content such as ambiguous/malformed CSR attributes or missing/invalid requested attributes
4. `INTERNAL` encompassing errors on a more fundamental level, such as a structurally valid CSR, but using unsupported signature algorithms, for example,
   or outright implementation issues in Warden Supreme.

At no point are exceptions related to attestations transmitted to the client.
Instead, a nullable `explanation` string property is present, which can be used to convey context and/or error codes and
all server-side exceptions are automatically mapped to one of those four error types based on their semantics.

<!--TODO Snippet that maps to error codes as an example-->
