package at.asitplus.attestation.supreme

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import java.time.Instant

private val iosConfiguration = IosAttestationConfiguration(
    IosAttestationConfiguration.AppData(
        teamIdentifier = "9CYHJNG644",
        bundleIdentifier = "at.asitplus.attestation-client",
    ),
)

val SupremeConfigurationSerializationTest by matrixSuite {
    data(
        "clock implementations",
        listOf(
            "system" to SupremeConfiguration.Clock.System,
            "fixed" to SupremeConfiguration.Clock.Fixed(Instant.parse("2025-01-10T12:34:56.789Z")),
        ),
        nameFn = { _, (name) -> name },
    ) test { (_, clock) ->
        val configuration = SupremeConfiguration(
            ios = iosConfiguration,
            clock = clock,
        )

        SupremeConfiguration.fromJsonString(configuration.toJsonString()) shouldBe configuration
        SupremeConfiguration.fromYamlString(configuration.toYamlString()) shouldBe configuration
    }
}
