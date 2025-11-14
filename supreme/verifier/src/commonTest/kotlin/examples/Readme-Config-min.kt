package docs.config.minimal

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration


val makoto = Makoto(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
        /*(1)!*/AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.attestation_client",
            signerDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray())
        )
    ),
    /*(2)!*/iosAttestationConfiguration = IosAttestationConfiguration(
        IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.attestation-client",
        )
    )
)