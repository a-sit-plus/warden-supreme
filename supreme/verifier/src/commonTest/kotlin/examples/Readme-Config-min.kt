package docs.config.minimal

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Warden
import at.asitplus.attestation.android.AndroidAttestationConfiguration


val warden = Warden(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
        applications = listOf(   // REQUIRED: add applications to be attested
           /*(1)!*/AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation_client",
                signatureDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray())
            )
        ),
       /*(2)!*/ignoreLeafValidity = true
    ),
   /*(3)!*/iosAttestationConfiguration = IosAttestationConfiguration(
        applications = listOf(
            IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
            )
        )
    )
)