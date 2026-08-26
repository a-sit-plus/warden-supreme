# Debugging, Recording,<br>and Replaying Attestation Checks

Attestation failures often depend on the exact certificate chain, configuration, and revocation state present during
verification. Warden Supreme can capture these inputs and replay the failed check offline.

For an interactive look at real-world Android attestation data before building an integration, use the
[Attestation Collector](../collector.md). It displays the parsed statement and verification result.

The workflow is the same whether you use Warden Supreme's integrated flow or the raw _makoto_ or _roboto_ attestation
checkers (see [Usage without Integrated Clients](raw.md)):

1. When verification fails, capture a debug statement containing the exact proof, configuration, verification time, and
   revocation-list snapshot used for the check.
2. Call `serializeCompact()` on that statement and persist the resulting single-line string. This is the portable replay
   artifact to copy from the deployed service to a development machine.
3. Deserialize the compact string and call `replay()` locally. The original check can then be stepped through in a debugger
   without access to the device or the original deployment.
4. Use `serialize()` only when you want a human-readable JSON representation for inspection.

Enrich the surrounding log entry with device make/model, OS, and patch levels so OEM-specific quirks can be correlated over
time.

!!! warning "Privacy Risks and Risk of Chasing Phantoms"
    Three restrictions apply when recording or sharing debug statements.
    
    * Attestation information is personally identifying data if the contained public key is associated with a person.
    * If you publicly paste a debug statement, it will contain your whole configuration, and it will leak information about your service, apps,
      and the environment of your backend that performs the attestation checks.
    * For actual debugging, only ever share debug statements in `serializeCompact()` format, not the human-readable `serialize()` output.
        * The `serializeCompact()` format uses a self-describing, forward-compatible multibase encoding.
        * This encoding is transport-safe. It survives Microsoft Outlook's sometimes creative way of "improving" message formatting,
          as well as "helpful" IDEs and editors being extra-smart when pasting.
        * We once lost a full day of debugging to encoding errors in transit. This is exactly why `serializeCompact()` is the way to record
          and share debug statements for analysis, while `serialize()` is for a human-readable representation.

## Collecting Debug Info

Regardless of whether you are using Warden Supreme's integrated attestation flow, or raw makoto/roboto,
all flows produce a debug statement with the same `serialize()`, `serializeCompact()`, and `replay()` lifecycle. Only
the point at which the statement is collected and its concrete type differ:

| Verification flow | How debug info is obtained                                 | Debug statement type               |
|-------------------|------------------------------------------------------------|------------------------------------|
| Warden Supreme    | Supplied automatically to `onAttestationError`             | `WardenDebugAttestationStatement`  |
| Raw _makoto_      | Call `collectDebugInfo(...)` after the failed verification | `WardenDebugAttestationStatement`  |
| Raw _roboto_      | Call `collectDebugInfo(...)` after the failed verification | `AndroidDebugAttestationStatement` |

In Warden Supreme's integrated flow, the attestation error is the receiver of the `onAttestationError` lambda and the ready-made
debug statement is its argument. Persist the compact replay artefact directly in that callback:

```kotlin
onAttestationError = { debugInfo ->
    logger.error(debugInfo.serializeCompact())
    null
}
```

With raw _makoto_ or _roboto_, call the matching `collectDebugInfo(...)` overload using the same proof and challenge that were
passed to verification, then persist `debugInfo.serializeCompact()`. Collect it after the failed verification so the statement
can include the revocation-list snapshot used by that check.

The resulting compact string is the boundary between production and offline debugging: store or transfer it as one unchanged
line. Do not copy the pretty-printed `serialize()` output for replay.

## Debugging Integrated Attestation
Warden Supreme already contains code to load compact `WardenDebugAttestationStatement`s and `replay()` them. The replay utility
expects a file containing one `serializeCompact()` result per line.
Run the replay utility in an IDE to step through the attestation workflow and inspect the stack trace behind a failure:

* Import this project into IntelliJ IDEA
* Add a breakpoint [here (line 19)](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt#L19)
* Run it in debug mode

Pass the debug-statement file as the single argument described in
[Diag.kt](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt).

The equivalent direct API flow is:

```kotlin
val statement = WardenDebugAttestationStatement.deserializeCompact(recordedLine)
println(statement.serialize()) // optional human-readable JSON
val replayedResult = statement.replay()
```

For a raw _roboto_ recording, use `AndroidDebugAttestationStatement.deserializeCompact(recordedLine)` instead; the remaining
workflow is identical.

## Debugging Raw Android Attestations

!!! tip inline end "Stand-Alone Attestation Parser"
    To use `androidAttestation`&shy;`Extension` on all platforms (e.g., to implement client-side checks on Android),
    include `:supreme-common` in your project, and you are ready to go!

A similar utility for printing the contents of an Android attestation statement lives in [/utils/roboto-diag](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/roboto-diag).
It pretty-prints the leaf certificate's Android attestation extension and expects either:

* `-f path/to/leaf/certificate.pem`
* a base64-encoded certificate as the sole argument

It will then pretty-print the attestation extension's contents.

There is also a nullable `androidAttestationExtension` extension property on the Java `X509Certificate`
and on Signum's `X509Certificate` class (and certificate chains). It exposes `prettyPrint()`, so you can peek into Android attestation extensions at any time.
It even parses malformed values and prints their DER-encoded hex representation.
The parser and renderer remain experimental, but they have been tested against thousands of attestation proofs captured
from real devices. This corpus includes malformed values that Google's old and current parsers reject. Warden's parser
retains these values and renders their DER representation where necessary, making it considerably more useful for
investigating certificates encountered in production.

!!! example "Example of a Pretty-Printed Attestation Record from an Emulator"
    ```properties
    AttestationKeyDescription(
      attestationVersion = 3
      attestationSecurityLevel = TRUSTED_ENVIRONMENT
      keyMintVersion = 41
      keyMintSecurityLevel = TRUSTED_ENVIRONMENT
      attestationChallenge = b5a4a68423c5d2f610328b3dcc8b408d352afc78fb7eb0d4803bd9ef581654eb
      uniqueId = 
      softwareEnforced =
        AuthorizationList(
          purpose = null
          algorithm = null
          keySize = null
          blockMode = null
          digest = null
          padding = null
          callerNonce = false
          minMacLength = null
          ecCurve = null
          rsaPublicExponent = null
          mgfDigest = null
          rollbackResistance = false
          earlyBootOnly = false
          activeDateTime = null
          originationExpireDateTime = null
          usageExpireDateTime = null
          usageCountLimit = null
          userSecureId = null
          noAuthRequired = false
          userAuthType = null
          authTimeout = null
          allowWhileOnBody = false
          trustedUserPresenceRequired = false
          trustedConfirmationRequired = false
          unlockedDeviceRequired = false
          allApplications = false
          creationDateTime = CreationDateTime(intValue=1752703332000, timestamp=2025-07-16T22:02:12Z)
          origin = null
          rollbackResistant = null
          rootOfTrust = null
          osVersion = null
          osPatchLevel = null
          attestationApplicationId = 
            AttestationApplicationId(
              packageInfos = [
                AttestationPackageInfo(packageName='at.asitplus.atttest', version=1)
              ]
              signatureDigests = [
                34b9762c4d6c90d48431940c57bde7314258b26420efe16ac7f7274f0d330ad5
              ]
            )
          attestationIdBrand = null
          attestationIdDevice = null
          attestationIdProduct = null
          attestationIdSerial = null
          attestationIdImei = null
          attestationIdMeid = null
          attestationIdManufacturer = null
          attestationIdModel = null
          vendorPatchLevel = null
          bootPatchLevel = null
          deviceUniqueAttestation = false
          attestationIdSecondImei = null
          moduleHash = null
        )
      hardwareEnforced =
        AuthorizationList(
          purpose = [
            - SIGN
            - VERIFY
          ]
          algorithm = EC
          keySize = KeySize(intValue=256)
          blockMode = null
          digest = [
            - SHA_2_256
          ]
          padding = null
          callerNonce = false
          minMacLength = null
          ecCurve = P_256
          rsaPublicExponent = null
          mgfDigest = null
          rollbackResistance = false
          earlyBootOnly = false
          activeDateTime = null
          originationExpireDateTime = null
          usageExpireDateTime = null
          usageCountLimit = null
          userSecureId = null
          noAuthRequired = false
          userAuthType = UserAuth(authTypes=[FINGERPRINT], intValue=2)
          authTimeout = null
          allowWhileOnBody = false
          trustedUserPresenceRequired = false
          trustedConfirmationRequired = false
          unlockedDeviceRequired = false
          allApplications = false
          creationDateTime = null
          origin = GENERATED
          rollbackResistant = null
          rootOfTrust = 
            RootOfTrust(
              verifiedBootKeyDigest=c2224571c9cd5c89200a7311b1e37aa9cf751e2e19753e8d3702bca00be1d42c
              deviceLocked=true
              verifiedBootState=Verified
              verifiedBootHash=d415abd0e620d3e8a942a62920195ad893ff0515ab8236931a156bc1f49de444
            )
          osVersion = OsVersion(major=13, minor=0, sub=0, intValue=130000)
          osPatchLevel = OsPatchLevel(year=2025, month=MAY, intValue=202505)
          attestationApplicationId = null
          attestationIdBrand = null
          attestationIdDevice = null
          attestationIdProduct = null
          attestationIdSerial = null
          attestationIdImei = null
          attestationIdMeid = null
          attestationIdManufacturer = null
          attestationIdModel = null
          vendorPatchLevel = PatchLevel(year=2025, month=MAY, day=1, intValue=20250501)
          bootPatchLevel = PatchLevel(year=2025, month=MAY, day=1, intValue=20250501)
          deviceUniqueAttestation = false
          attestationIdSecondImei = null
          moduleHash = null
        )
    )
    ```
