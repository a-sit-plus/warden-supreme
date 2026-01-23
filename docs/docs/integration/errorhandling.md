# Error Handling

!!! tip inline end "Project Structure"
    See [project structure details](structure.md) for info on components, their names, functionality, and inter-dependencies.

Attestation can fail for a variety of (expected) reasons.
Makoto (the unified server-side Android and iOS attestation library at the core of Warden Supreme) buckets errors
across iOS and Android attestation checks into semantic categories to streamline handling.

When opting for fully integrated attestation flows (Supreme Verifier and Supreme Client), attestation statements received
from clients may not even come this far and might be rejected before being fed into Makoto for verification.

An in-depth understanding of all nitty-gritty details on this matter (i.e., when, how, and why attestation may fail) is important
for anyone integrating attestation checks on the back-end.
This is true **even when using the fully integrated Supreme verifier and client** solution, 
because it makes sense to define and communicate (opaque) error codes and convey them to the client to debug issues in
the field.

This page first discusses all the details related to every possible attestation error that can happen on the back-end.
Afterwards (i.e. when all context is established), errors communicated to the client are discussed. 

## Server-Side (Low-Level errors)
This section first discusses the low-level attestation error hierarchy.
Details on pre-attestation checks performed by the Supreme attestation verifier before Makoto is tasked with the actual attestation
verification are laid out afterwards.

### Attestation Error Hierarchy

Proper Exceptions, not domain-specific result classes are used because exceptions come with a killer feature for debugging:
stack traces that can be navigated.
However, the root of all attestation errors is a sealed `AttestationException` class, whose subclasses correspond to the aforementioned
semantic bucketing.

Every such exception features:

* **a `platform` property** indicating whether an iOS or Android attestation failed to verify
* **a nullable `message`** providing human-readable context aimed at a smooth debugging experience (not at the end-user)
* **a `cause`** carrying the underlying platform-specific exception


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

The snippet below shows all possible attestation exceptions that might be thrown.
For details, just click on the annotations inside the code below.
Note that the `onAttestationError` callback is side-effect-free except that it allows for returning a (nullable) string
to customise the error message /error code conveyed to the client.

```kotlin
--8<-- "Readme-Backend-errorhandling.kt:15:60"
```

1. Refer to [Debugging](debugging.md)
2. Certificate is not yet valid or expired. Clock drift is the main source for this error.
3. An untrusted root certificate was encountered. E.g., an Android Emulator was used in production.
4. Thrown when an attestation statement is received for a platform that is not configured.
5. The client OS is too old (wrt. to the configured minimum OS version)
6. The attestation statement creation timestamp (not the certificate validity!) is too far in the past or absent.  
   Note that Warden Supreme's sane defaults prevent this from happening.
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
15. Minimum iOS version / build number not satisfied.
16. The attestation statement creation timestamp (not the certificate validity!) is too far in the past. This is usually due to a clock drift between client and server.  
    The Supreme Verifier prevents the client from even attempting to send an attestation, as clock drift detection is implemented as client-side functionality.
17. The challenge encoded into the attestation statement payload does not match the expected challenge.
18. The team ID and/or bundle identifier and/or stage (sandbox vs. production) of the client app do not match.
19. The signature counter encoded into the assertion is too high. See [iOS technical deep dive](../technical/ios.md).
20. This usually indicates a structural error in the attestation statement and therefore requires manual debugging to make sense of.
21. This is usually triggered by structurally invalid input (empty attestation proof/CSR, misencoded certificates, …) and is also a hot take for a manual session debugging.  
    Experience shows, however, that this never happens in production when a legit client app is used.

!!! tip inline end "Debugging"
    Refer to [Debugging](debugging.md) for detailed information and guidance on debugging.

As can be seen, all platform-specific exceptions are contained in the `AttestationException.Content` hierarchy.
Most of the time, however, you do not need this level of detail to react to attestation errors, but it is extremely helpful for debugging.
In particular, the call in Line&nbsp;4 will produce a log entry with a self-contained, replayable attestation call for
offline analysis.

### Pre-Attestation Errors
When using fully integrated attestation, preprocessing steps are automatically performed to extract, check, and invalidate
the received challenge, parse the received CSR, extract the attestation proof (CSR), and so forth.
Naturally, this does not always work as arbitrary data can be sent to the verifier, which means pre-attestation
errors can occur.  
The following snippet shows how to react to such errors.
Note that the `onPreAttestationError` callback is side-effect-free except that it allows for returning a (nullable) string
to customise the error message / error code conveyed to the client.

```kotlin
--8<-- "Readme-Backend-preerrorhandling.kt:15:40"
```

1. Refer to [Debugging](debugging.md)
2. Certificate is not yet valid or expired. Clock drift is the main source for this error.
3. An untrusted root certificate was encountered. E.g., an Android Emulator was used in production.
4. Thrown when an attestation statement is received for a platform that is not configured.


## Client Side (Generic, High-Level Error Categories)
Using fully integrated attestation only ever returns either an `AttestationResponse.Success`
or an `AttestationResponse.Error`. The latter of which indicates one of four error reasons:

1. `TRUST` encompassing untrusted roots, revoked certificates, or invalid certificate chains
2. `TIME` encompassing temporal validity errors wrt. certificates and attestation statements 
3. `CONTENT` encompassing all cases where the attestation statement itself failed to parse or verify against the policy
   (i.e. Android devices having an unlocked bootloader, even though the policy mandates a locked bootloader and a factory image)
4. `INTERNAL` encompassing errors on a more fundamental level, such as a structurally valid CSR, but using unsupported signature algorithms, for example,
   or outright implementation issues in Warden Supreme.

At no point are exceptions related to attestations transmitted to the client.
Instead, a nullable `explanation` string property is present, which can be used to convey context and/or error codes and
all server-side exceptions are automatically mapped to one of those four error types based on their semantics.

<!--TODO Snippet that maps to error codes as an example-->
