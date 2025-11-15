package docs.config.minimal

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.supreme.AttestationVerifier
import kotlin.time.Duration.Companion.minutes


val makoto = Makoto(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
     /*(1)!*/AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.attestation_client",
            signerDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray())
        )
    ),
    iosAttestationConfiguration = IosAttestationConfiguration(
     /*(2)!*/IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.attestation-client",
        )
    ),
 /*(3)!*/verificationTimeOffset = 1.minutes //OPTIONAL, defaults to zero
)