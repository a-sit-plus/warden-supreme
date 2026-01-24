import at.asitplus.attestation.APPLE_DEFAULT_TRUSTED_ROOTS
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.IosAttestationConfiguration.OsVersions
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.seconds

val ConfigurationBuilderTest by testSuite {

    "iOS AppData builder preserves trusted roots" {
        val roots = APPLE_DEFAULT_TRUSTED_ROOTS
        val app = IosAttestationConfiguration.AppData.Builder("TEAMID1234", "com.example.app")
            .trustedRootOverrides(roots)
            .build()

        app.trustedRootOverrides shouldBe roots
    }

    "iOS AppData builder sets sandbox and version override" {
        val version = OsVersions("17.4", "21E219")
        val app = IosAttestationConfiguration.AppData.Builder("TEAMID1234", "com.example.app")
            .sandbox(true)
            .iosVersionOverride(version)
            .build()

        app.sandbox shouldBe true
        app.iosVersionOverride shouldBe version
    }

    "Makoto validity duration picks min and max" {
        val androidApp = AndroidAttestationConfiguration.AppData(
            packageName = "com.example",
            signerFingerprints = listOf(ByteArray(32) { 1 })
        )
        val androidConfig = AndroidAttestationConfiguration(
            applications = listOf(androidApp),
            attestationStatementValiditySeconds = 60
        )
        val iosApp = IosAttestationConfiguration.AppData(
            teamIdentifier = "TEAMID1234",
            bundleIdentifier = "com.example.ios"
        )
        val iosConfig = IosAttestationConfiguration(
            applications = listOf(iosApp),
            attestationStatementValiditySeconds = 120
        )

        val makoto = Makoto(androidConfig, iosConfig)
        makoto.shortestValidityDuration shouldBe 60.seconds
        makoto.longestValidityDuration shouldBe 120.seconds
    }
}
