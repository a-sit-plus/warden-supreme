package at.asitplus.attestation.springtest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

/**
 * Every *file-based* way Spring Boot can supply configuration, each one loaded through
 * `:config-spring` and cross-checked between the `@ConfigurationProperties` and the `Environment`
 * wiring style. The YAML is verbatim so the tests double as documentation.
 */
class ConfigFileLoadingTest {

    @Test
    fun `external yaml via spring config location`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.external.yaml
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                """.trimIndent()
            )
        ) { ctx ->
            ctx.assertAndroidPackage("at.asitplus.external.yaml")
        }
    }

    @Test
    fun `external properties file via spring config location`() {
        runApp(
            files = mapOf(
                "application.properties" to """
                    attestation.android.applications[0].packageName=at.asitplus.external.properties
                    attestation.android.applications[0].signerFingerprints[0]=${Fixtures.SIGNER_FINGERPRINT}
                """.trimIndent()
            )
        ) { ctx ->
            ctx.assertAndroidPackage("at.asitplus.external.properties")
        }
    }

    @Test
    fun `profile specific file overrides the base file`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.base
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        verificationSecondsOffset: 10
                """.trimIndent(),
                "application-prod.yaml" to """
                    attestation:
                      android:
                        verificationSecondsOffset: 42
                        requireStrongBox: true
                """.trimIndent(),
            ),
            profiles = listOf("prod"),
        ) { ctx ->
            val android = ctx.attestationProperties().androidConfig.orFail("android configuration")
            assertEquals("at.asitplus.base", android.applications.single().packageName)
            assertEquals(42, android.verificationSecondsOffset)
            assertTrue(android.requireStrongBox)
            assertEquals(android, ctx.environmentLoader().android())
        }
    }

    @Test
    fun `multi document yaml activates documents per profile`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.multidoc
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        verificationSecondsOffset: 1
                    ---
                    spring:
                      config:
                        activate:
                          on-profile: strict
                    attestation:
                      android:
                        verificationSecondsOffset: 99
                        requireRollbackResistance: true
                """.trimIndent()
            ),
            profiles = listOf("strict"),
        ) { ctx ->
            val android = ctx.attestationProperties().androidConfig.orFail("android configuration")
            assertEquals("at.asitplus.multidoc", android.applications.single().packageName)
            assertEquals(99, android.verificationSecondsOffset)
            assertTrue(android.requireRollbackResistance)
        }
    }

    @Test
    fun `documents not matching the active profile stay inactive`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.multidoc
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        verificationSecondsOffset: 1
                    ---
                    spring:
                      config:
                        activate:
                          on-profile: strict
                    attestation:
                      android:
                        verificationSecondsOffset: 99
                """.trimIndent()
            )
        ) { ctx ->
            assertEquals(
                1,
                ctx.attestationProperties().androidConfig.orFail("android configuration").verificationSecondsOffset
            )
        }
    }

    @Test
    fun `spring config import composes the configuration from several files`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      supreme:
                        clock: system
                """.trimIndent(),
                "android.yaml" to """
                    attestation:
                      supreme:
                        android:
                          applications:
                            - packageName: at.asitplus.imported.android
                              signerFingerprints:
                                - ${Fixtures.SIGNER_FINGERPRINT}
                          verificationSecondsOffset: 15
                """.trimIndent(),
                "ios.yaml" to """
                    attestation:
                      supreme:
                        ios:
                          applications:
                            - teamIdentifier: ${Fixtures.TEAM_IDENTIFIER}
                              bundleIdentifier: at.asitplus.imported.ios
                          iosVersion:
                            semVer: 17.4.1
                            buildNumber: "21E236"
                """.trimIndent(),
            ),
            configDirCustomizer = { dir ->
                mapOf(
                    "spring.config.import" to listOf(
                        "optional:file:${dir.resolve("android.yaml")}",
                        "optional:file:${dir.resolve("ios.yaml")}",
                    ).joinToString(",")
                )
            },
        ) { ctx ->
            val supreme = ctx.attestationProperties().supremeConfig.orFail("supreme configuration")
            val android = supreme.android.orFail("android configuration")
            val ios = supreme.ios.orFail("iOS configuration")
            assertEquals("at.asitplus.imported.android", android.applications.single().packageName)
            assertEquals(15, android.verificationSecondsOffset)
            assertEquals("at.asitplus.imported.ios", ios.applications.single().bundleIdentifier)
            assertEquals(supreme, ctx.environmentLoader().supreme())
        }
    }

    @Test
    fun `several prefixes coexist in one file`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.flat.android
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                      ios:
                        applications:
                          - teamIdentifier: ${Fixtures.TEAM_IDENTIFIER}
                            bundleIdentifier: at.asitplus.flat.ios
                      supreme:
                        clock: system
                        android:
                          applications:
                            - packageName: at.asitplus.nested.android
                              signerFingerprints:
                                - ${Fixtures.SIGNER_FINGERPRINT}
                        ios:
                          applications:
                            - teamIdentifier: ${Fixtures.TEAM_IDENTIFIER}
                              bundleIdentifier: at.asitplus.nested.ios
                """.trimIndent()
            )
        ) { ctx ->
            val properties = ctx.attestationProperties()
            val loader = ctx.environmentLoader()
            val supreme = properties.supremeConfig.orFail("supreme configuration")

            assertEquals(
                "at.asitplus.flat.android",
                properties.androidConfig.orFail("android configuration").applications.single().packageName
            )
            assertEquals(
                "at.asitplus.flat.ios",
                properties.iosConfig.orFail("iOS configuration").applications.single().bundleIdentifier
            )
            assertEquals(
                "at.asitplus.nested.android",
                supreme.android.orFail("android configuration").applications.single().packageName
            )
            assertEquals(
                "at.asitplus.nested.ios",
                supreme.ios.orFail("iOS configuration").applications.single().bundleIdentifier
            )

            assertEquals(properties.androidConfig, loader.android())
            assertEquals(properties.iosConfig, loader.ios())
            assertEquals(properties.supremeConfig, loader.supreme())
        }
    }

    @Test
    fun `a deeply nested prefix binds just as well`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    security:
                      platform:
                        attestation:
                          android:
                            applications:
                              - packageName: at.asitplus.deeply.nested
                                signerFingerprints:
                                  - ${Fixtures.SIGNER_FINGERPRINT}
                """.trimIndent()
            )
        ) { ctx ->
            val android = ctx.environmentLoader().android("security.platform.attestation.android")
            assertEquals("at.asitplus.deeply.nested", android.applications.single().packageName)
        }
    }
}

/**
 * Configuration files loaded from the classpath, base file plus profile-specific sibling.
 *
 * The fixtures are deliberately *not* called `application.yaml`: this module's example round-trip
 * tests build contexts without overriding `spring.config.location`, so a default-named classpath
 * file would leak into their assertions. `spring.config.name` exercises the very same mechanism.
 */
@SpringBootTest(properties = ["spring.config.name=warden-springtest"])
@ActiveProfiles("classpath-android")
class ClasspathConfigFileTest {

    @Autowired
    private lateinit var properties: AttestationProperties

    @Autowired
    private lateinit var loader: WardenEnvironmentLoader

    @Test
    fun `classpath application yaml and profile sibling are both applied`() {
        val android = properties.androidConfig.orFail("android configuration")
        // from src/test/resources/warden-springtest.yaml
        assertEquals("at.asitplus.classpath", android.applications.single().packageName)
        // from src/test/resources/warden-springtest-classpath-android.yaml
        assertEquals(77, android.verificationSecondsOffset)
        assertEquals(android, loader.android())
    }
}
