package examples.docs

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.*
import at.asitplus.attestation.fromSpringEnvironment
import at.asitplus.attestation.fromSpringMap
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toKmpCertificate
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.WebApplicationType
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.builder.SpringApplicationBuilder
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.env.YamlPropertySourceLoader
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.env.MapPropertySource
import org.springframework.core.io.FileSystemResource
import java.io.FileReader
import java.nio.file.Files

@SpringBootApplication
private open class ConfigSpringExampleApp


@EnableConfigurationProperties(value = [AttestationProperties::class])
@Configuration
private open class TestConfig {
    @Autowired
    lateinit var configurationProperties: AttestationProperties

}

@ConfigurationProperties("attestation")
private
// --8<-- [start:springboot-config]
data class AttestationProperties(
    private val android: Map<String, Any?>? = null,
    private val ios: Map<String, Any?>? = null
) {
    val androidConfig = android?.let { AndroidAttestationConfiguration.fromSpringMap(it) }
    val iosConfig = ios?.let { IosAttestationConfiguration.fromSpringMap(it) }
}

// --8<-- [end:springboot-config]

val SpringBootConfigLoadingTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    "Load example configs from YAML" - {
        val examples = listOf(
            "../../docs/docs/examples/android.yaml" to { env: ConfigurableEnvironment ->
                AndroidAttestationConfiguration.fromSpringEnvironment(env, "")
            },
            "../../docs/docs/examples/ios.yaml" to { env: ConfigurableEnvironment ->
                IosAttestationConfiguration.fromSpringEnvironment(env, "")
            },
            "../../docs/docs/examples/supreme.yaml" to { env: ConfigurableEnvironment ->
                SupremeConfiguration.fromSpringEnvironment(env, "")
            }
        )

        data("examples", examples, nameFn = { _, value -> value.first }) test { (path, loadConfig) ->
            val context = runWithYaml(path)
            val cfg = loadConfig(context.environment)
            cfg.toYamlString() shouldBe FileReader(path).use { it.readText() }
            context.close()
        }
    }

    "Spring Boot applies active profile overrides on nested supreme config" {
        withTempConfigDir(
            "application.yaml" to """
                # --8<-- [start:springboot-config-yaml]
                attestation:
                  android:
                    applications:
                      - packageName: at.asitplus.base.android
                        signerFingerprints:
                          - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
                    verificationSecondsOffset: 30
                  ios:
                    applications:
                      - teamIdentifier: 9CYHJNG644
                        bundleIdentifier: at.asitplus.base.ios
                    iosVersion:
                      semVer: 17.4.1
                      buildNumber: "21E236"
                  clock: system
                  genericDeviceNameOID: 1.2.3.4
                # --8<-- [end:springboot-config-yaml]  
            """.trimIndent(),
            "application-prod.yaml" to """
                attestation:
                  android:
                    requireStrongBox: true
                  genericDeviceNameOID: 1.2.3.999
            """.trimIndent(),
        ) { configDir ->
            runWithConfigDirectory(configDir.toString(), profiles = listOf("prod")).use { context ->
                // --8<-- [start:springboot-env]
                val cfg = SupremeConfiguration.fromSpringEnvironment(context.environment, "attestation")
                // --8<-- [end:springboot-env]

                val testConfig = context.getBean(TestConfig::class.java)
                val props = context.getBean(AttestationProperties::class.java)

                props.iosConfig shouldBe cfg.ios
                props.androidConfig shouldBe cfg.android
                testConfig.configurationProperties.iosConfig shouldBe cfg.ios
                testConfig.configurationProperties.androidConfig shouldBe cfg.android
                cfg.android!!.applications.single().packageName shouldBe "at.asitplus.base.android"
                cfg.android!!.verificationSecondsOffset shouldBe 30
                cfg.android!!.requireStrongBox shouldBe true
                cfg.ios!!.applications.single().bundleIdentifier shouldBe "at.asitplus.base.ios"
                cfg.genericDeviceNameOID.toString() shouldBe "1.2.3.999"


            }
        }
    }

    "Spring Boot higher-precedence properties override config files without breaking loader structure" {
        withTempConfigDir(
            "application.yaml" to """
                attestation:
                  android:
                    applications:
                      - packageName: at.asitplus.base.android
                        signerFingerprints:
                          - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
                    verificationSecondsOffset: 30
                    requireRemoteKeyProvisioning: false
            """.trimIndent(),
        ) { configDir ->
            runWithConfigDirectory(
                configDir = configDir.toString(),
                overrideProperties = mapOf(
                    "attestation.android.verificationSecondsOffset" to 123,
                    "attestation.android.requireRemoteKeyProvisioning" to true,
                )
            ).use { context ->
                val cfg =
                    AndroidAttestationConfiguration.fromSpringEnvironment(context.environment, "attestation.android")

                cfg.applications.single().packageName shouldBe "at.asitplus.base.android"
                cfg.verificationSecondsOffset shouldBe 123
                cfg.requireRemoteKeyProvisioning shouldBe true
            }
        }
    }

    "Spring Boot YAML needs quoted iOS build numbers when they look like scientific notation" {
        withTempConfigDir(
            "application.yaml" to """
                attestation:
                  applications:
                    - teamIdentifier: 9CYHJNG644
                      bundleIdentifier: at.asitplus.invalid-ios
                  iosVersion:
                    semVer: 17.4.1
                    buildNumber: 21E236
            """.trimIndent(),
        ) { configDir ->
            runWithConfigDirectory(configDir.toString()).use { context ->
                kotlin.runCatching {
                    IosAttestationConfiguration.fromSpringEnvironment(context.environment, "attestation")
                }.exceptionOrNull()!!.message!!.contains("buildNumber") shouldBe true
            }
        }
    }

    "Spring Boot supports deep nesting and multiple coexisting prefixes for android ios and supreme" {
        withTempConfigDir(
            "application.yaml" to """
                security:
                  attestation:
                    android:
                      applications:
                        - packageName: at.asitplus.android.nested
                          signerFingerprints:
                            - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
                    ios:
                      applications:
                        - teamIdentifier: 9CYHJNG644
                          bundleIdentifier: at.asitplus.ios.nested
                    supreme:
                      android:
                        applications:
                          - packageName: at.asitplus.supreme.android
                            signerFingerprints:
                              - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
                      ios:
                        applications:
                          - teamIdentifier: 9CYHJNG644
                            bundleIdentifier: at.asitplus.supreme.ios
                      clock: system
            """.trimIndent(),
        ) { configDir ->
            runWithConfigDirectory(configDir.toString()).use { context ->
                val android = AndroidAttestationConfiguration.fromSpringEnvironment(
                    context.environment,
                    "security.attestation.android"
                )
                val ios = IosAttestationConfiguration.fromSpringEnvironment(
                    context.environment,
                    "security.attestation.ios"
                )
                val supreme = SupremeConfiguration.fromSpringEnvironment(
                    context.environment,
                    "security.attestation.supreme"
                )

                android.applications.single().packageName shouldBe "at.asitplus.android.nested"
                ios.applications.single().bundleIdentifier shouldBe "at.asitplus.ios.nested"
                supreme.android!!.applications.single().packageName shouldBe "at.asitplus.supreme.android"
                supreme.ios!!.applications.single().bundleIdentifier shouldBe "at.asitplus.supreme.ios"
            }
        }
    }

    "Spring Boot composes supreme config from imported config files" {
        withTempConfigDir(
            "application.yaml" to """
                attestation:
                  clock: system
            """.trimIndent(),
            "android.yaml" to """
                attestation:
                  android:
                    applications:
                      - packageName: at.asitplus.imported.android
                        signerFingerprints:
                          - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
                    verificationSecondsOffset: 15
            """.trimIndent(),
            "ios.yaml" to """
                attestation:
                  ios:
                    applications:
                      - teamIdentifier: 9CYHJNG644
                        bundleIdentifier: at.asitplus.imported.ios
                    iosVersion:
                      semVer: 17.4.1
                      buildNumber: "21E236"
            """.trimIndent(),
        ) { configDir ->
            runWithConfigDirectory(
                configDir = configDir.toString(),
                properties = mapOf(
                    "spring.config.import" to listOf(
                        "optional:file:${configDir.resolve("android.yaml")}",
                        "optional:file:${configDir.resolve("ios.yaml")}"
                    ).joinToString(",")
                )
            ).use { context ->
                val cfg = SupremeConfiguration.fromSpringEnvironment(context.environment, "attestation")

                cfg.android!!.applications.single().packageName shouldBe "at.asitplus.imported.android"
                cfg.android!!.verificationSecondsOffset shouldBe 15
                cfg.ios!!.applications.single().bundleIdentifier shouldBe "at.asitplus.imported.ios"
                cfg.ios!!.iosVersion shouldBe IosAttestationConfiguration.OsVersions("17.4.1", "21E236")
                cfg.clock shouldBe SupremeConfiguration.Clock.System
            }
        }
    }

    "Spring Boot loads multiline pem trust anchors and revocation config from yaml" {
        val hardwareAnchor = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS.first()
        val softwareAnchor = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.first()

        withTempConfigDir(
            "application.yaml" to """
                attestation:
                  android:
                    applications:
                      - packageName: at.asitplus.multiline.spring
                        signerFingerprints:
                          - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
                    hardwareTrustedRoots:
                      - |-
${trustedRootPem(hardwareAnchor).prependIndent("                          ")}
                    softwareTrustedRoots:
                      - |-
${trustedRootPem(softwareAnchor).prependIndent("                          ")}
                    revocation:
                      - type: mem
                        list:
                          entries:
                            deadbeef:
                              status: REVOKED
                              reason: SOFTWARE_FLAW
                            cafebabe:
                              status: SUSPENDED
                              expires: 2026-03-31
                              comment: still suspended
                          expires: 2026-04-01T00:00:00Z
                      - type: file
                        path: ./localrevocation.json
                        fallbackRevocationListValiditySeconds: 123
                        fallbackToFileSystemInfo: false
            """.trimIndent(),
        ) { configDir ->
            runWithConfigDirectory(configDir.toString()).use { context ->
                val cfg = AndroidAttestationConfiguration.fromSpringEnvironment(
                    context.environment,
                    "attestation.android"
                )

                cfg.hardwareTrustedRoots shouldBe setOf(hardwareAnchor)
                cfg.softwareTrustedRoots shouldBe setOf(softwareAnchor)
                cfg.revocation[0] shouldBe AndroidRevocationList.InMemoryLoader.Configuration(
                    AndroidRevocationList(
                        entries = mapOf(
                            "deadbeef" to AndroidRevocationList.Entry(
                                status = AndroidRevocationList.RevocationStatus.REVOKED,
                                reason = AndroidRevocationList.RevocationReason.SOFTWARE_FLAW
                            ),
                            "cafebabe" to AndroidRevocationList.Entry(
                                status = AndroidRevocationList.RevocationStatus.SUSPENDED,
                                expires = kotlin.time.Instant.parse("2026-03-31T00:00:00Z"),
                                comment = "still suspended"
                            )
                        ),
                        expires = kotlin.time.Instant.parse("2026-04-01T00:00:00Z")
                    )
                )
                cfg.revocation[1] shouldBe AndroidRevocationList.FileLoader.Configuration(
                    path = "./localrevocation.json",
                    fallbackRevocationListValiditySeconds = 123,
                    fallbackToFileSystemInfo = false
                )
            }
        }
    }
}

private fun runWithYaml(path: String): ConfigurableApplicationContext {
    val loader = YamlPropertySourceLoader()
    val initializer = ApplicationContextInitializer<ConfigurableApplicationContext> { ctx ->
        val resource = FileSystemResource(path)
        val propertySource = loader.load(path, resource).single()
        ctx.environment.propertySources.addFirst(propertySource)
    }

    return SpringApplicationBuilder(ConfigSpringExampleApp::class.java)
        .web(WebApplicationType.NONE)
        .initializers(initializer)
        .run()
}

private fun runWithConfigDirectory(
    configDir: String,
    profiles: List<String> = emptyList(),
    properties: Map<String, Any?> = emptyMap(),
    overrideProperties: Map<String, Any?> = emptyMap(),
): ConfigurableApplicationContext {
    val mergedProperties = linkedMapOf<String, Any>(
        "spring.config.location" to "optional:file:${configDir.trimEnd('/')}/",
        "spring.main.banner-mode" to "off",
    )
    if (profiles.isNotEmpty()) {
        mergedProperties["spring.profiles.active"] = profiles.joinToString(",")
    }
    properties.forEach { (key, value) ->
        if (value != null) mergedProperties[key] = value
    }

    val builder = SpringApplicationBuilder(ConfigSpringExampleApp::class.java)
        .web(WebApplicationType.NONE)
        .properties(mergedProperties)
        .initializers(
            ApplicationContextInitializer<ConfigurableApplicationContext> { ctx ->
                val overrides = linkedMapOf<String, Any>()
                overrideProperties.forEach { (key, value) ->
                    if (value != null) overrides[key] = value
                }
                if (overrides.isNotEmpty()) {
                    ctx.environment.propertySources.addFirst(MapPropertySource("test-overrides", overrides))
                }
            }
        )

    return builder.run()
}

private fun withTempConfigDir(
    vararg files: Pair<String, String>,
    block: (java.nio.file.Path) -> Unit,
) {
    val dir = Files.createTempDirectory("spring-config-test-")
    try {
        files.forEach { (name, contents) ->
            dir.resolve(name).toFile().writeText(contents)
        }
        block(dir)
    } finally {
        dir.toFile().deleteRecursively()
    }
}

private fun trustedRootPem(root: TrustedRoot): String = when (root) {
    is TrustedRoot.Certificate -> root.certificate.toKmpCertificate().getOrThrow().encodeToPEM().getOrThrow()
    is TrustedRoot.PublicKey -> root.publicKey.toCryptoPublicKey().getOrThrow().encodeToPEM().getOrThrow()
}
