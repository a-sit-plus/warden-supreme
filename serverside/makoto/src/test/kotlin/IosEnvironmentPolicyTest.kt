package at.asitplus.attestation

import at.asitplus.attestation.IosAttestationConfiguration.AppData
import at.asitplus.attestation.IosAttestationConfiguration.OsVersions
import at.asitplus.attestation.data.AttestationData
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val iosEnvironmentPolicyABTest by matrixSuite {
    data(
        "environment policies",
        listOf(
            IosEnvironmentPolicyCase(
                fixture = ios16,
                attestedIosVersion = "16.2.0",

                //Minimum is version is 14, but the provided fixture (captured from a real iPhone) is 16.
                // Since this is sanbdox=true, and the iOS16 fixture is production, it must not match this app
                sandboxApp = AppData(
                    "9CYHJNG644", "at.asitplus.attestation-client", sandbox = true,
                    iosVersionOverride = OsVersions("14.0", "18A373")
                ),
                // the only matching production app requires ios version 99, so zhe captured ios 16 will not fulfill
                // the version requirement, but will match this app in other regards. Hence -> version mismatch error expected
                productionApp = AppData(
                    "9CYHJNG644", "at.asitplus.attestation-client", sandbox = false,
                    iosVersionOverride = OsVersions("99.0", "999ZZ0")
                )
            )
        ),
        nameFn = { _, case ->
            "production ${case.productionApp.teamIdentifier}.${case.productionApp.bundleIdentifier} " +
                "iOS ${case.attestedIosVersion} rejects ${case.productionApp.iosVersionOverride} " +
                "(sandbox permits ${case.sandboxApp.iosVersionOverride})"
        }
    ) test { case ->
        val makoto = Makoto(
            iosAttestationConfiguration = IosAttestationConfiguration(
                applications = listOf(case.sandboxApp, case.productionApp)
            ),
            clock = FixedTimeClock(case.fixture.verificationDate)
        )

        makoto.ios.verifyAppAttestation(case.fixture.attestationProof.first(), case.fixture.challenge)
            .shouldBeInstanceOf<AttestationResult.Error>()
            .cause.platformSpecificCause
            .shouldBeInstanceOf<IosAttestationException>()
            .reason shouldBe IosAttestationException.Reason.OS_VERSION
    }
}

private data class IosEnvironmentPolicyCase(
    val fixture: AttestationData,
    val attestedIosVersion: String,
    val sandboxApp: AppData,
    val productionApp: AppData,
)
