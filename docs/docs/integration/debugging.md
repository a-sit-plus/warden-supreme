# Debugging, Recording,<br>and Replaying Attestation Checks
Whenever the actual attestation check fails (i.e., whenever `onAttestationError()` is called), a ready-made `WardenDebugAttestationStatement` is created and passed to this function.
Hence, two pieces of information are available to aid debugging:

1. the attestation error (as the receiver of this lambda)
2. the debug statement, which can be exported for off-site analyses

## Debugging Integrated Attestation

The `WardenDebugAttestationStatement` can be serialized to JSON by invoking `.serialize()` (or `serializeCompact()`) on it.
It can later be deserialized by calling `deserialize()` (or `deserializeCompact()`) on its companion.
By finally calling `replaySmart()` on such a deserialized debug info object, the whole attestation verification process is replayed.

Attaching a debugger allows for step-by-step debugging of any attestation errors encountered.
For the most straightforward debugging experience:

* import this project into IDEA
* add a breakpoint [here in line 19](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt#L19)
* and run it in debug mode.

Just be sure to add a single argument pointing to a file as described in [Diag.kt](https://github.com/a-sit-plus/warden-supreme/tree/mainutils/makoto-diag/src/main/kotlin/Diag.kt)!

## Debugging Raw Android Attestations
A similar utility exists for printing the contents of an Android attestation statement, located in [/utils/roboto-diag](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/roboto-diag).
More specifically, it pretty-prints the contents of the leaf certificate's Android attestation extension and expects either:

* `-f path/to/leaf/certificate.pem`
* a base64-encoded certificate as the sole argument

It will then pretty-print the attestation extension's contents.  
As an added bonus, there is a nullable `androidAttestationExtension` extension property on the class
`at.asitplus.signum.indispensable.pki.X509Certificate`, and `java.security.cert.X509Certificate`
which exposes the `prettyPrint()` function so you can peek into Android attestation extensions at any time.
It will even parse malformed values and print you those malformed values' DER-encoded hex representation.
The underlying parser and the renderer are still experimental, so your mileage may vary, but it is still a huge improvement
over relying solely on `ParsedAttestationRecord` for debugging.

!!! example "Example of a Pretty-Printed Attestation Record from an Emulator"
    ```properties
    AttestationKeyDescription(
      attestationVersion = 4
      attestationSecurityLevel = SOFTWARE
      keyMintVersion = 41
      keyMintSecurityLevel = SOFTWARE
      attestationChallenge = 751188b89844f23d2dea561b55fbac804d7b096bc65976299d3c5cc74059f3b1
      uniqueId = 
      softwareEnforced =
        AuthorizationList(
          purpose = [
            - SIGN
            - VERIFY
          ]
          algorithm = RSA
          keySize = KeySize(intValue=4096)
          digest = [
            - SHA1
            - SHA_2_256
          ]
          padding = null
          ecCurve = null
          rsaPublicExponent = RsaPublicExponent(65537)
          mgfDigest = null
          rollbackResistance = false
          earlyBootOnly = false
          activeDateTime = null
          originationExpireDateTime = null
          usageExpireDateTime = null
          usageCountLimit = null
          noAuthRequired = true
          userAuthType = null
          authTimeout = null
          allowWhileOnBody = false
          trustedUserPresenceRequired = false
          trustedConfirmationRequired = false
          unlockedDeviceRequired = false
          allApplications = false
          creationDateTime = CreationDateTime(intValue=1694020749000, timestamp=2023-09-06T17:19:09Z)
          origin = GENERATED
          rollbackResistant = null
          rootOfTrust = 
            RootOfTrust(
              verifiedBootKeyDigest=0000000000000000000000000000000000000000000000000000000000000000
              deviceLocked=false
              verifiedBootState=Unverified
              verifiedBootHash=0000000000000000000000000000000000000000000000000000000000000000
            )
          osVersion = OsVersion(major=11, minor=0, sub=0, intValue=110000)
          osPatchLevel = OsPatchLevel(year=2020, month=NOVEMBER, intValue=202011)
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
          purpose = null
          algorithm = null
          keySize = null
          digest = null
          padding = null
          ecCurve = null
          rsaPublicExponent = null
          mgfDigest = null
          rollbackResistance = false
          earlyBootOnly = false
          activeDateTime = null
          originationExpireDateTime = null
          usageExpireDateTime = null
          usageCountLimit = null
          noAuthRequired = false
          userAuthType = null
          authTimeout = null
          allowWhileOnBody = false
          trustedUserPresenceRequired = false
          trustedConfirmationRequired = false
          unlockedDeviceRequired = false
          allApplications = false
          creationDateTime = null
          origin = null
          rollbackResistant = null
          rootOfTrust = null
          osVersion = null
          osPatchLevel = null
          attestationApplicationId = null
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
    )
    ```