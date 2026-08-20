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
     /*(1)!*/applications = listOf(
            AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation_client",
                signerFingerprints = setOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
            ),
         /*(2)!*/AndroidAttestationConfiguration.AppData(
             /*(3)!*/packageName = "at.asitplus.attestation_client-hardened",
                signerFingerprints = setOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
             /*(4)!*/appVersion = 2,
             /*(5)!*/androidVersionOverride = 160000,
                patchLevelOverride = PatchLevel(year = 2025, month = 9,
                 /*(6)!*/maxFuturePatchLevelMonths = 2
                ),
             /*(7)!*/requireRemoteKeyProvisioningOverride = true,
             /*(8)!*/trustedRootOverrides = setOf(GOOGLE_RKP_EC_ROOT),
             /*(9)!*/requireStrongBoxOverride = true,
             /*(10)!*/customProperties = mapOf("an app flag" to "is present"),
            )
        ),
     /*(11)!*/androidVersion = 130000, patchLevel = PatchLevel(2023, 12),
        requireStrongBox = false,
        allowBootloaderUnlock = false, //DEFAULT
     /*(12)!*/verifiedBootKeys = linkedSetOf(
            VerifiedBootKey.OEM,
            VerifiedBootKey.Digest(
                "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff".parseHex()
            )
        ),
     /*(13)!*/requireRollbackResistance = false, //DEFAULT
     /*(14)!*/ignoreLeafValidity = false, // defaults to true
     /*(15)!*/hardwareTrustedRoots = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS, //DEFAULT
        softwareTrustedRoots = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12, //DEFAULT
        verificationSecondsOffset = 0, //DEFAULT; Android-only clock-drift adjustment in seconds
        disableHardwareAttestation = false,
        enableSoftwareAttestation = false, //DEFAULT
     /*(16)!*/attestationStatementValiditySeconds = null, // DEFAULT; no validity time checks!
     /*(17)!*/revocation = listOf(
            AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("https://192.168.178.74:8000")
        ),
        requireRemoteKeyProvisioning = false, //DEFAULT
     /*(18)!*/enforceFactoryProvisionedChainValidity = true, //DEFAULT
     /*(19)!*/customProperties = mapOf("an Android flag" to "is present") //DEFAULT
    ),

    iosAttestationConfiguration = IosAttestationConfiguration(
     /*(20)!*/applications = listOf(
            IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
             /*(21)!*/iosVersionOverride = OsVersions("16.0", "20A10"),
             /*(22)!*/sandbox = true, //defaults to false
             /*(23)!*/trustedRootOverrides = myCustomRoots,
             /*(24)!*/ customProperties = mapOf("and iOS flag" to "is present"),
            )
        ),
                /* Same as 17.0 ↘↘ */
     /*(25)!*/iosVersion = OsVersions("17", "21A36"), //defaults to null (= no version check)
     /*(26)!*/attestationStatementValiditySeconds = 600, //DEFAULT
     /*(27)!*/trustedRoots = APPLE_DEFAULT_TRUSTED_ROOTS, //DEFAULT
     /*(28)!*/customProperties = mapOf("a global iOS flag" to "is present"), //DEFAULT
    ),
    clock = Clock.System, //DEFAULT
 /*(29)!*/verificationTimeOffset = 5.minutes, //OPTIONAL, defaults shown
)
// --8<-- [end:makoto-config]

// --8<-- [start:read-custom-properties]
val androidFlag = makoto.androidAttestationConfiguration
    ?.customProperties?.get("an Android flag")
val androidAppFlag = makoto.androidAttestationConfiguration
    ?.applications
    ?.firstOrNull { it.packageName == "at.asitplus.attestation_client-hardened" }
    ?.customProperties?.get("an app flag")

val iosFlag = makoto.iosAttestationConfiguration
    ?.customProperties?.get("a global iOS flag")
val iosAppFlag = makoto.iosAttestationConfiguration
    ?.applications
    ?.firstOrNull { it.bundleIdentifier == "at.asitplus.attestation-client" }
    ?.customProperties?.get("and iOS flag")
// --8<-- [end:read-custom-properties]
