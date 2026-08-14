package examples.examples

import at.asitplus.attestation.APPLE_DEFAULT_TRUSTED_ROOTS
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.IosAttestationConfiguration.OsVersions
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes


val myCustomRoots = APPLE_DEFAULT_TRUSTED_ROOTS


// --8<-- [start:makoto-config]
val makoto = Makoto(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
        applications = listOf(
         /*(1)!*/AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation_client",
                signerFingerprints = setOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
            ),
         /*(2)!*/AndroidAttestationConfiguration.AppData(
             /*(3)!*/packageName = "at.asitplus.attestation_client-hardened",
                signerFingerprints = setOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
                appVersion = 2,
             /*(4)!*/androidVersionOverride = 160000,
                patchLevelOverride = PatchLevel(year = 2025, month = 9,
                 /*(5)!*/maxFuturePatchLevelMonths = 2
                ),
             /*(6)!*/requireRemoteKeyProvisioningOverride = true,
             /*(7)!*/trustedRootOverrides = setOf(GOOGLE_RKP_EC_ROOT),
             /*(8)!*/requireStrongBoxOverride = true,
             /*(9)!*/customProperties = mapOf("an app flag" to "is present"),
            )
        ),
     /*(10)!*/androidVersion = 130000, patchLevel = PatchLevel(2023, 12), requireStrongBox = false,
        allowBootloaderUnlock = false, //DEFAULT
     /*(11)!*/verifiedBootKeys = linkedSetOf(
            VerifiedBootKey.OEM,
            VerifiedBootKey.Digest(
                "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff".parseHex()
            )
        ),
     /*(12)!*/requireRollbackResistance = false, //DEFAULT
     /*(13)!*/ignoreLeafValidity = false, // defaults to true
        hardwareTrustedRoots = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS, //DEFAULT
        softwareTrustedRoots = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12, //DEFAULT
        verificationSecondsOffset = 0, //DEFAULT
     /*(14)!*/disableHardwareAttestation = false,
        enableSoftwareAttestation = false, //DEFAULT
     /*(15)!*/attestationStatementValiditySeconds = null, // DEFAULT; no validity time checks!
     /*(16)!*/revocation = listOf(
            AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("https://192.168.178.74:8000")
        ),
        requireRemoteKeyProvisioning = false, //DEFAULT
     /*(17)!*/enforceFactoryProvisionedChainValidity = true, //DEFAULT
     /*(18)!*/customProperties = mapOf("an Android flag" to "is present") //DEFAULT
    ),

    iosAttestationConfiguration = IosAttestationConfiguration(
        applications = listOf(
         /*(19)!*/IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
             /*(20)!*/iosVersionOverride = OsVersions("16.0", "20A10"),
             /*(21)!*/sandbox = true, //defaults to false
             /*(22)!*/trustedRootOverrides = myCustomRoots,
             /*(23)!*/ customProperties = mapOf("and iOS flag" to "is present"),
            )
        ),
                /* Same as 17.0 ↘↘ */
     /*(24)!*/iosVersion = OsVersions("17", "21A36"), //defaults to null (= no version check)
     /*(25)!*/attestationStatementValiditySeconds = 600, //DEFAULT
     /*(26)!*/trustedRoots = APPLE_DEFAULT_TRUSTED_ROOTS, //DEFAULT
     /*(27)!*/customProperties = mapOf("a global iOS flag" to "is present"), //DEFAULT
    ),
    clock = Clock.System, //DEFAULT
 /*(28)!*/verificationTimeOffset = 5.minutes, //OPTIONAL, defaults shown
)
// --8<-- [end:makoto-config]
