package examples.docs

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.hopliteDecoder
import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.DataAuthentication
import at.asitplus.attestation.supreme.PrimitiveType
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addFileSource
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.io.File
import java.io.FileReader
import java.io.FileWriter

@OptIn(ExperimentalHoplite::class)
val ConfigurationExampleGenerator by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {

    fun readResource(path: String): String =
        requireNotNull(object {}.javaClass.classLoader.getResourceAsStream(path)) {
            "Missing test resource: $path"
        }.bufferedReader().use { it.readText() }

    val pathname = "../../docs/docs/examples".also { File(it).mkdirs() }

    val androidAttestationConfiguration = AndroidAttestationConfiguration(
        /*(1)!*/
        AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.attestation_client",
            signerFingerprints = setOf("4a c9 ad ee 7a a0 c5 56 02 ac e2 28 bc ac e1 1b 41 2c c8 b4 aa 8c 08 96 41 8e dd 94 d7 5e 0e e6".parseHex())
        ),
        verifiedBootKeys = linkedSetOf(
            VerifiedBootKey.OEM,
            VerifiedBootKey.Digest(
                "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff".parseHex()
            )
        ),
        revocation = listOf(
            AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("https://localhost:2345"),
            AndroidRevocationList.FileLoader.Configuration("./localrevocation.json")
        ), // Defaults to null
        enforceFactoryProvisionedChainValidity = true
    )
    val iosAttestationConfiguration = IosAttestationConfiguration(
        /*(2)!*/IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.attestation-client",
        )
    )

    data(
        "configs",
        listOf(
        "android" to androidAttestationConfiguration,
        "ios" to iosAttestationConfiguration
        ),
        nameFn = { _, value -> value.first },
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
            "JSON (Hoplite)" {
                val loader = ConfigLoaderBuilder.default()
                    .withExplicitSealedTypes()
                    .addFileSource(File("$pathname/$name.json"))
                    .addDecoder(
                        when (name) {
                            "android" -> AndroidAttestationConfiguration.hopliteDecoder()
                            "ios" -> IosAttestationConfiguration.hopliteDecoder()
                            else -> throw RuntimeException("Unknown config type: $name")
                        }
                    )
                    .build()

                val loaded = when (name) {
                    "android" -> loader.loadConfigOrThrow<AndroidAttestationConfiguration>()
                    "ios" -> loader.loadConfigOrThrow<IosAttestationConfiguration>()
                    else -> throw RuntimeException("Unknown config type: $name")
                }
                loaded shouldBe config
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
            "YAML (legacy)" {
                val legacyYaml = readResource("examples/legacy/$name.yaml")
                val loaded = when (name) {
                    "android" -> AndroidAttestationConfiguration.fromYamlString(legacyYaml)
                    "ios" -> IosAttestationConfiguration.fromYamlString(legacyYaml)
                    else -> throw RuntimeException("Unknown config type: $name")
                }
                loaded shouldBe config
            }
            "YAML (Hoplite)" {
                val loader = ConfigLoaderBuilder.default()
                    .withExplicitSealedTypes()
                    .addFileSource(File("$pathname/$name.yaml"))
                    .addDecoder(
                        when (name) {
                            "android" -> AndroidAttestationConfiguration.hopliteDecoder()
                            "ios" -> IosAttestationConfiguration.hopliteDecoder()
                            else -> throw RuntimeException("Unknown config type: $name")
                        }
                    )
                    .build()

                val loaded = when (name) {
                    "android" -> loader.loadConfigOrThrow<AndroidAttestationConfiguration>()
                    "ios" -> loader.loadConfigOrThrow<IosAttestationConfiguration>()
                    else -> throw RuntimeException("Unknown config type: $name")
                }
                loaded shouldBe config
            }
        }
    }

    "Manual YAML" - {

            val minimum = """
            applications: 
              - packageName: at.asitplus.attestation_client
                signerFingerprints: 
                  - 4a c9 ad ee 7a a0 c5 56 02 ac e2 28 bc ac e1 1b 41 2c c8 b4 aa 8c 08 96 41 8e dd 94 d7 5e 0e e6
            verifiedBootKeys:
              - OEM
              - '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
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
        "Minimal" {
            AndroidAttestationConfiguration.fromYamlString(minimum) shouldBe androidAttestationConfiguration
        }

        "With custom properties" {
            val withProp = "$minimum\ncustomProperties:\n  key: 'value'\n  key2: 'value2'"
            val parsedWithProp= AndroidAttestationConfiguration.fromYamlString(withProp)
            parsedWithProp shouldBe androidAttestationConfiguration.copy(customProperties = mapOf("key" to "value", "key2" to "value2"))
            parsedWithProp shouldNotBe androidAttestationConfiguration
            parsedWithProp.hashCode() shouldNotBe androidAttestationConfiguration.hashCode()
            parsedWithProp.toString() shouldNotBe androidAttestationConfiguration.toString()
            parsedWithProp.customProperties["key"] shouldBe "value"
            parsedWithProp.customProperties["key2"] shouldBe "value2"
        }
    }

    val config = SupremeConfiguration(
        androidAttestationConfiguration,
        iosAttestationConfiguration,
        dataAuth = DataAuthentication.Hash(Digest.SHA256),
        attestableAttributes = AttestationChallenge.AttestableAttributes(
            oid = ObjectIdentifier("2.25.304198582559398858370235454530489176240"),
            attributes = listOf(
                AttestationChallenge.ToBeAttestedAttribute("accountId", PrimitiveType.STRING),
                AttestationChallenge.ToBeAttestedAttribute("riskScore", PrimitiveType.INT, required = false),
            ),
        ),
    )

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
        "JSON (Hoplite)" {
            val loader = ConfigLoaderBuilder.default()
                .withExplicitSealedTypes()
                .addFileSource(File("$pathname/supreme.json"))
                .addDecoder(SupremeConfiguration.hopliteDecoder())
                .build()
            val loaded = loader.loadConfigOrThrow<SupremeConfiguration>()
            loaded shouldBe config
        }
        "YAML" {
            FileReader("$pathname/supreme.yaml").use { reader ->
                val loaded = SupremeConfiguration.fromYamlString(reader.readText())
                loaded shouldBe config
            }
        }
        "YAML (legacy)" {
            val legacyYaml = readResource("examples/legacy/supreme.yaml")
            val loaded = SupremeConfiguration.fromYamlString(legacyYaml)
            loaded shouldBe SupremeConfiguration(androidAttestationConfiguration, iosAttestationConfiguration)
        }
        "YAML (Hoplite)" {
            val loader = ConfigLoaderBuilder.default()
                .withExplicitSealedTypes()
                .addFileSource(File("$pathname/supreme.yaml"))
                .addDecoder(SupremeConfiguration.hopliteDecoder())
                .build()
            val loaded = loader.loadConfigOrThrow<SupremeConfiguration>()
            loaded shouldBe config
        }
    }

}
