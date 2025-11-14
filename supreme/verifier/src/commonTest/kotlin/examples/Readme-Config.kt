package examples

import at.asitplus.attestation.APPLE_DEFAULT_TRUSTED_ROOTS
import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.IosAttestationConfiguration.OsVersions
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS
import at.asitplus.attestation.android.GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A11
import at.asitplus.attestation.android.PatchLevel
import kotlin.time.Duration
import kotlin.time.Instant


val myCustomRoot = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS.first()
val myCustomRoots = APPLE_DEFAULT_TRUSTED_ROOTS


//make sure to start at line 20!
val warden = Makoto(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
        applications = listOf(   // REQUIRED: add applications to be attested
         /*(1)*/   AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation_client",
                signerDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray()),
                appVersion = 5
            ),
            AndroidAttestationConfiguration.AppData(
                packageName ="at.asitplus.attestation_client-tiramisu",
                signerDigests =listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray()),
                appVersion = 2,
                androidVersionOverride = 130000,
                patchLevelOverride = PatchLevel(
                    2023,
                    6,
                    maxFuturePatchLevelMonths = 2
                ), // also override patch level and
                requireRemoteKeyProvisioningOverride = true,
                /*(2)!*/trustedRootOverrides = setOf(myCustomRoot)

                /* packageName =
                signatureDigests = l
                appVersion = 2, // with a different versioning scheme
                androidVersionOverride = 130000, // so we need to override this
                patchLevelOverride = PatchLevel(
                    2023,
                    6,
                    maxFuturePatchLevelMonths = 2
                ), // also override patch level and
                // consider patch levels from 2 months in the future
                // as valid
                // maxFuturePatchLevelMonths defaults to 1
                // null means any future patch level is OK


                requireRemoteProvisioningOverride = true,
                requireRemoteKeyProvisioningOverride = false, // require a remotely-provisioned attestation

                /*(1)!*/trustedRootOverrides = setOf(myCustomRoot),  // require a custom root as the trust anchor*/
                // for the attestation certificate chain
            )
        ),
        androidVersion = 110000,                  // OPTIONAL, null by default
        patchLevel = PatchLevel(2022, 12),        // OPTIONAL, null by default; maxFuturePatchLevelMonths defaults to 1
        requireStrongBox = false,                 // OPTIONAL, defaults to false
        allowBootloaderUnlock = false,            // OPTIONAL, defaults to false
        requireRollbackResistance = false,        // OPTIONAL, defaults to false
        ignoreLeafValidity = false,               // OPTIONAL, defaults to false
        /*(2)!*/hardwareTrustedRoots = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS,   // OPTIONAL, defaults shown here
        /*(3)!*/softwareTrustedRoots = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A11, // OPTIONAL, defaults shown here
        verificationSecondsOffset = -300,         // OPTIONAL, defaults to 0
        disableHardwareAttestation = false,       // OPTIONAL, defaults to false; set true to disable HW attestation
        enableNougatAttestation = false,          // OPTIONAL, defaults to false; set true to enable hybrid attestation
        enableSoftwareAttestation = false,        // OPTIONAL, defaults to false; set true to enable SW attestation
        attestationStatementValiditySeconds = 300,// OPTIONAL, defaults to 300s
        httpProxy = null,                         //OPTIONAL HTTP proxy url, such as http://proxy.domain:12345, defaults to null for no proxy
        requireRemoteKeyProvisioning = false      //OPTIONAL, whether to require a remotely provisioned attestation certificate

    ),
    iosAttestationConfiguration = IosAttestationConfiguration(
        applications = listOf(
            IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
                iosVersionOverride = OsVersions("16.0", "20A10"),     // OPTIONAL, null by default
                sandbox = false,                 // OPTIONAL, defaults to false
                /*(4)!*/trustedRootOverrides = myCustomRoots //require a custom trusted root
            )
        ),
        iosVersion = OsVersions("17", "21A36"),                                             // OPTIONAL, null by default
        attestationStatementValiditySeconds = 300,                   // OPTIONAL, defaults to 300s
        /*(5)!*/trustedRoots = APPLE_DEFAULT_TRUSTED_ROOTS                       // OPTIONAL, defaults shown here
    ),
    clock = FixedTimeClock(Instant.parse("2023-04-13T00:00:00Z")),   // OPTIONAL, system clock by default
    verificationTimeOffset = Duration.ZERO,                          // OPTIONAL, defaults to zero
)