package examples

import at.asitplus.attestation.APPLE_DEFAULT_TRUSTED_ROOTS
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.IosAttestationConfiguration.OsVersions
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.*
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

val customTestRoots = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS
val myCustomRoots = APPLE_DEFAULT_TRUSTED_ROOTS


val makoto = Makoto(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
        applications = listOf(
         /*(1)!*/AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation_client",
                signerDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray()),
            ),
         /*(2)!*/AndroidAttestationConfiguration.AppData(
             /*(3)!*/packageName = "at.asitplus.attestation_client-hardened",
                signerDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray()),
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
     /*(10)!*/requireRollbackResistance = false,
     /*(11)!*/ignoreLeafValidity = false,
        hardwareTrustedRoots = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS,   //DEFAULT
        softwareTrustedRoots = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A11, //DEFAULT
        verificationSecondsOffset = 0, //DEFAULT
     /*(12)!*/disableHardwareAttestation = false,
        enableSoftwareAttestation = false, //DEFAULTS
     /*(13)!*/enableNougatAttestation = false,
     /*(14)!*/attestationStatementValiditySeconds = null,
     /*(15)!*/httpProxy = null,
        requireRemoteKeyProvisioning = false

    ),
    iosAttestationConfiguration = IosAttestationConfiguration(
        applications = listOf(
         /*(16)!*/IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
                iosVersionOverride = OsVersions("16.0", "20A10"),
             /*(17)!*/sandbox = true,
             /*(18)!*/trustedRootOverrides = myCustomRoots
            )
        ),
     /*(19)!*/iosVersion = OsVersions("17", "21A36"),
     /*(20)!*/attestationStatementValiditySeconds = 600, //Apple's requirement + verificationTimeOffset
     /*(21)!*/trustedRoots = APPLE_DEFAULT_TRUSTED_ROOTS
    ),
    clock = Clock.System, //DEFAULT
 /*(22)!*/verificationTimeOffset = 5.minutes, //OPTIONAL, defaults shown
)