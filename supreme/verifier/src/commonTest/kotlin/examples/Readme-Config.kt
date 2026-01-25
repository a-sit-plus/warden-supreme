package examples

import at.asitplus.attestation.APPLE_DEFAULT_TRUSTED_ROOTS
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.IosAttestationConfiguration.OsVersions
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes


val myCustomRoots = APPLE_DEFAULT_TRUSTED_ROOTS


val makoto = Makoto(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
        applications = listOf(
         /*(1)!*/AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation_client",
                signerFingerprints = listOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
            ),
         /*(2)!*/AndroidAttestationConfiguration.AppData(
             /*(3)!*/packageName = "at.asitplus.attestation_client-hardened",
                signerFingerprints = listOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
                appVersion = 2,
             /*(4)!*/androidVersionOverride = 160000,
                patchLevelOverride = PatchLevel(year = 2025, month = 9,
                 /*(5)!*/maxFuturePatchLevelMonths = 2
                ),
             /*(6)!*/requireRemoteKeyProvisioningOverride = true,
             /*(7)!*/trustedRootOverrides = setOf(GOOGLE_RKP_EC_ROOT),
             /*(8)!*/requireStrongBoxOverride = true,
            )
        ),
     /*(9)!*/androidVersion = 130000, patchLevel = PatchLevel(2023, 12), requireStrongBox = false,
        allowBootloaderUnlock = false, //DEFAULT
     /*(10)!*/requireRollbackResistance = false, //DEFAULT
     /*(11)!*/ignoreLeafValidity = false, // defaults to true
        hardwareTrustedRoots = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS, //DEFAULT
        softwareTrustedRoots = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12, //DEFAULT
        verificationSecondsOffset = 0, //DEFAULT
     /*(12)!*/disableHardwareAttestation = false,
        enableSoftwareAttestation = false, //DEFAULT
     /*(13)!*/attestationStatementValiditySeconds = null, // DEFAULT; no validity time checks!
     /*(14)!*/revocation = listOf(
            AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("https://192.168.178.74:8000")
        ),
        requireRemoteKeyProvisioning = false //DEFAULT

    ),
    iosAttestationConfiguration = IosAttestationConfiguration(
        applications = listOf(
         /*(15)!*/IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
             /*(16)!*/iosVersionOverride = OsVersions("16.0", "20A10"),
             /*(17)!*/sandbox = true, //defaults to false
             /*(18)!*/trustedRootOverrides = myCustomRoots
            )
        ),
                /* Same as 17.0 ↘↘ */
     /*(19)!*/iosVersion = OsVersions("17", "21A36"), //defaults to null (= no version check)
     /*(20)!*/attestationStatementValiditySeconds = 600, //DEFAULT
     /*(21)!*/trustedRoots = APPLE_DEFAULT_TRUSTED_ROOTS //DEFAULT
    ),
    clock = Clock.System, //DEFAULT
 /*(22)!*/verificationTimeOffset = 5.minutes, //OPTIONAL, defaults shown
)