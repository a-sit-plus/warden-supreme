import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import com.github.curiousoddman.rgxgen.nodes.Repeat.minimum
import de.infix.testBalloon.framework.core.TestCompartment
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import java.io.File
import java.io.FileReader
import java.io.FileWriter

val ConfigurationExampleGenerator by testSuite(compartment = { TestCompartment.Sequential }) {


    val pathname = "../../docs/docs/examples".also { File(it).mkdirs() }

    val androidAttestationConfiguration = AndroidAttestationConfiguration(
        /*(1)!*/
        AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.attestation_client",
            signerFingerprints = listOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex())
        ),
        revocation = listOf(
            AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("https://localhost:2345"),
            AndroidRevocationList.FileLoader.Configuration("./localrevocation.json")
        ), // Defaults to null
    )
    val iosAttestationConfiguration = IosAttestationConfiguration(
        /*(2)!*/IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.attestation-client",
        )
    )

    withData(
        "android" to androidAttestationConfiguration, "ios" to iosAttestationConfiguration
    ) - { (name, config) ->
        "Writing $name" {
            withClue("JSON") {
                FileWriter("$pathname/$name.json").use { writer ->
                    writer.write(config.toJsonString())
                }
            }
            withClue("YAML") {
                FileWriter("$pathname/$name.yaml").use { writer ->
                    writer.write(config.toYamlString())
                }
            }
        }

        "Reading $name" - {
            "JSON" {
                FileReader("$pathname/$name.json").use { reader ->
                    val loaded = when (name) {
                        "android" -> AndroidAttestationConfiguration.fromJsonString(reader.readText())
                        "ios" -> IosAttestationConfiguration.fromJsonString(reader.readText())
                        else -> throw RuntimeException("Unknown config type: $name")
                    }
                    loaded shouldBe config
                }
            }
            "YAML" {
                FileReader("$pathname/$name.yaml").use { reader ->
                    val loaded = when (name) {
                        "android" -> AndroidAttestationConfiguration.fromYamlString(reader.readText())
                        "ios" -> IosAttestationConfiguration.fromYamlString(reader.readText())
                        else -> throw RuntimeException("Unknown config type: $name")
                    }
                    loaded shouldBe config
                }
            }
        }
    }

    "Manual YAML" {
        val minimum = """
            applications: 
              - packageName: at.asitplus.attestation_client
                signerFingerprints: 
                  - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
            revocation: 
              - type: google
                value: 
                  fallbackRevocationListValiditySeconds: 60
                  proxyConfig: 
                    type: HTTP
                    url: 'https://localhost:2345'
              - type: file
                value: 
                  path: './localrevocation.json'
                  fallbackRevocationListValiditySeconds: 0
                  fallbackToFileSystemInfo: true
            """.trimIndent()

        AndroidAttestationConfiguration.fromYamlString(minimum) shouldBe androidAttestationConfiguration
    }

    val config = SupremeConfiguration(androidAttestationConfiguration, iosAttestationConfiguration)

    "Writing Supreme" {
        withClue("JSON") {
            FileWriter("$pathname/supreme.json").use { writer ->
                writer.write(config.toJsonString())
            }
        }
        withClue("YAML") {
            FileWriter("$pathname/supreme.yaml").use { writer ->
                writer.write(config.toYamlString())
            }
        }
    }

    "Reading Supreme" - {
        "JSON" {
            FileReader("$pathname/supreme.json").use { reader ->
                val loaded = SupremeConfiguration.fromJsonString(reader.readText())
                loaded shouldBe config
            }
        }
        "YAML" {
            FileReader("$pathname/supreme.yaml").use { reader ->
                val loaded = SupremeConfiguration.fromYamlString(reader.readText())
                loaded shouldBe config
            }
        }
    }

}