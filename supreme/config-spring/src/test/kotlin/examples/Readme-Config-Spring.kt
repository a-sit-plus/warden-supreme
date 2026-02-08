package examples.docs

import at.asitplus.attestation.fromSpringEnvironment
import at.asitplus.attestation.supreme.SupremeConfiguration
import org.springframework.core.env.MapPropertySource
import org.springframework.core.env.StandardEnvironment

@Suppress("UNUSED")
private fun readmeSpringConfigExample() {
    val environment = StandardEnvironment().apply {
        propertySources.addFirst(
            MapPropertySource(
                "example",
                mapOf(
                    "supreme.android.applications[0].packageName" to "com.example.app",
                    "supreme.android.applications[0].signerFingerprints[0]" to "ABCD1234"
                )
            )
        )
    }

    val config: SupremeConfiguration = SupremeConfiguration.fromSpringEnvironment(environment, "supreme")
    config.android
}
