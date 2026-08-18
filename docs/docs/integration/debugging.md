# Debugging, Recording,<br>and Replaying Attestation Checks

Attestation failures often depend on the exact certificate chain, configuration, and revocation state present during
verification. Warden Supreme can capture these inputs and replay the failed check offline.

For an interactive look at real-world Android attestation data before building an integration, use the
[Attestation Collector](../collector.md). It displays the parsed statement and verification result produced under the
default policy.

The approach is the same whether you use Warden Supreme's integrated attestation flow or the raw _makoto_ or _roboto_
attestation checkers (see [Usage without Integrated Clients](raw.md)):
- Use Warden Supreme’s `collectDebugInfo(...)` on attestation errors to capture inputs, parsed fields, decisions, and failure reasons.
- Persist the debug info object via `serialize()` / `serializeCompact()` to logs.
- Enrich logs with device make/model, OS and patch levels, so OEM‑specific quirks can be correlated over time.
- Replay collected debug statements offline to analyse attestation failures by invoking `replay()` on a collected debug statement
  (see [Debugging Integrated Attestation](#debugging-integrated-attestation)).

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
Warden Supreme's integrated flow already offers a hook to collect debug statements:
Whenever the actual attestation check fails (i.e., whenever `onAttestationError()` is called), a ready-made `WardenDebugAttestationStatement` is created and passed to this function.
The callback provides two pieces of diagnostic information:

1. The attestation error (as the receiver of this lambda)
2. The debug statement, which can be exported for offline analysis

Warden _roboto_ and _makoto_ offer a `collectDebugInfo()` function to the same effect, creating a serializable debug statement.
The difference is that you call it manually, and the right place and time to call it depends on how _roboto_ or _makoto_ are integrated.
_makoto_ produces a `WardenDebugAttestationStatement` directly, while _roboto_'s `collectDebugInfo()` returns an `AndroidDebugAttestationStatement`.
Both expose the same replay function and carry everything needed to replay the attestation check offline.

## Debugging Integrated Attestation
Warden Supreme already contains code to load `WardenDebugAttestationStatement`s and `replay()` them.
Run the replay utility in an IDE to step through the attestation workflow and inspect the stack trace behind a failure:

* Import this project into IntelliJ IDEA
* Add a breakpoint [here (line 19)](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt#L19)
* Run it in debug mode

Pass the debug-statement file as the single argument described in
[Diag.kt](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt).

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
