package examples.docs.config.minimal

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.parseHex

val makoto = Makoto(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
     /*(1)!*/AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.attestation_client",
            signerFingerprints = listOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex())
        )
    ),
    iosAttestationConfiguration = IosAttestationConfiguration(
     /*(2)!*/IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.attestation-client",
        )
    )
)