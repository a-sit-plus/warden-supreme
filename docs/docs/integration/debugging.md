# Debugging, Recording,<br>and Replaying Attestation Checks
Whenever the actual attestation check fails (i.e., whenever `onAttestationError()` is called), a ready-made `WardenDebugAttestationStatement` is created and passed to this function.
Hence, two pieces of information are available to aid debugging:

1. The attestation error (as the receiver of this lambda)
2. The debug statement, which can be exported for offline analysis

## Debugging Integrated Attestation

The `WardenDebugAttestationStatement` can be serialised to JSON by invoking `.serialize()` (or `serializeCompact()`) on it.
It can later be deserialised by calling `deserialize()` (or `deserializeCompact()`) on its companion.
By finally calling `replay()` on such a deserialised debug info object, the whole attestation verification process is replayed.

Attaching a debugger allows for step-by-step debugging of any attestation errors encountered.
For the most straightforward debugging experience:

* Import this project into IntelliJ IDEA
* Add a breakpoint [here (line 19)](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt#L19)
* Run it in debug mode

Just be sure to add a single argument pointing to a file as described in [Diag.kt](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt)!

## Debugging Raw Android Attestations
A similar utility exists for printing the contents of an Android attestation statement, located in [/utils/roboto-diag](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/roboto-diag).
More specifically, it pretty-prints the contents of the leaf certificate's Android attestation extension and expects either:

* `-f path/to/leaf/certificate.pem`
* a base64-encoded certificate as the sole argument

It will then pretty-print the attestation extension's contents.

!!! tip inline end "Stand-Alone Attestation Parser"
    To use `androidAttestationExtension` on all platforms (e.g., to implement client-side checks on Android),
    include `at.asitplus.warden:supreme-common` in your project, and you are ready to go!

As an added bonus, there is a nullable `androidAttestationExtension` extension property on the Java `X509Certificate`
and on Signum's `X509Certificate` class, which exposes the `prettyPrint()` function so you can peek into Android attestation extensions at any time.
It will even parse malformed values and print those malformed values' DER-encoded hex representation.
The underlying parser and the renderer are still experimental, so your mileage may vary.
Nonetheless, it is still a huge improvement over relying solely on `ParsedAttestationRecord` for debugging.

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
