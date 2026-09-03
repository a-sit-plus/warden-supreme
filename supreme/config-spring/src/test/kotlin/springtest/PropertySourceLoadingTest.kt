package at.asitplus.attestation.springtest

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.TestPropertySource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue

/**
 * Every way of getting configuration into the `Environment` *without* a configuration file:
 * command-line arguments, JVM system properties, OS environment variables, `@TestPropertySource`,
 * `@DynamicPropertySource` and `ApplicationContextRunner`.
 */
class PropertySourceLoadingTest {

    @Test
    fun `command line arguments`() {
        runApp(
            commandLineArgs = listOf(
                "--attestation.android.applications[0].packageName=at.asitplus.cli",
                "--attestation.android.applications[0].signerFingerprints[0]=${Fixtures.SIGNER_FINGERPRINT}",
                "--attestation.android.verificationSecondsOffset=7",
            )
        ) { ctx ->
            ctx.assertAndroidPackage("at.asitplus.cli")
            assertEquals(7, ctx.attestationProperties().androidConfig!!.verificationSecondsOffset)
        }
    }

    @Test
    fun `jvm system properties`() {
        val properties = Fixtures.androidProperties("attestation.android", "at.asitplus.sysprops")
        withSystemProperties(*properties.map { (k, v) -> k to v.toString() }.toTypedArray()) {
            runApp { ctx -> ctx.assertAndroidPackage("at.asitplus.sysprops") }
        }
    }

    @Test
    fun `os environment variables in relaxed upper snake case`() {
        runApp(
            systemEnvironment = Fixtures.androidEnvironmentVariables("ATTESTATION_ANDROID", "at.asitplus.env") +
                mapOf("ATTESTATION_ANDROID_REQUIRESTRONGBOX" to "true")
        ) { ctx ->
            ctx.assertAndroidPackage("at.asitplus.env")
            assertTrue(ctx.attestationProperties().androidConfig!!.requireStrongBox)
        }
    }

    @Test
    fun `application context runner with property values`() {
        ApplicationContextRunner()
            .withUserConfiguration(WardenConfigTestConfiguration::class.java)
            .withPropertyValues(
                *Fixtures.androidProperties("attestation.android", "at.asitplus.contextrunner")
                    .map { (k, v) -> "$k=$v" }
                    .toTypedArray()
            )
            .run { context ->
                val android = context.getBean(AttestationProperties::class.java).androidConfig.orFail("android configuration")
                assertEquals("at.asitplus.contextrunner", android.applications.single().packageName)
                assertEquals(android, context.getBean(WardenEnvironmentLoader::class.java).android())
            }
    }

    @Test
    fun `application context runner reports the binding failure for invalid configuration`() {
        ApplicationContextRunner()
            .withUserConfiguration(WardenConfigTestConfiguration::class.java)
            .withPropertyValues("attestation.android.applications[0].packageName=at.asitplus.incomplete")
            .run { context ->
                val messages = context.startupFailure.orFail("startup failure").messageChain()
                assertTrue("signerFingerprints" in messages, "unexpected diagnostics: $messages")
            }
    }
}

/** Inline properties declared on the test class itself. */
@SpringBootTest
@TestPropertySource(
    properties = [
        "attestation.android.applications[0].packageName=at.asitplus.testpropertysource",
        "attestation.android.applications[0].signerFingerprints[0]=NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
        "attestation.ios.applications[0].teamIdentifier=9CYHJNG644",
        "attestation.ios.applications[0].bundleIdentifier=at.asitplus.testpropertysource.ios",
    ]
)
class TestPropertySourceLoadingTest {

    @Autowired
    private lateinit var properties: AttestationProperties

    @Autowired
    private lateinit var loader: WardenEnvironmentLoader

    @Test
    fun `inline test properties bind through both styles`() {
        assertEquals(
            "at.asitplus.testpropertysource",
            properties.androidConfig.orFail("android configuration").applications.single().packageName
        )
        assertEquals(
            "at.asitplus.testpropertysource.ios",
            properties.iosConfig.orFail("iOS configuration").applications.single().bundleIdentifier
        )
        assertEquals(properties.androidConfig, loader.android())
        assertEquals(properties.iosConfig, loader.ios())
    }
}

/** Properties computed at test time, as used for containers and random ports. */
@SpringBootTest
class DynamicPropertySourceLoadingTest {

    companion object {
        private const val PACKAGE_NAME = "at.asitplus.dynamic"

        @JvmStatic
        @DynamicPropertySource
        fun attestationProperties(registry: DynamicPropertyRegistry) {
            Fixtures.androidProperties("attestation.android", PACKAGE_NAME)
                .forEach { (key, value) -> registry.add(key) { value } }
        }
    }

    @Autowired
    private lateinit var properties: AttestationProperties

    @Test
    fun `dynamically registered properties bind`() {
        assertEquals(PACKAGE_NAME, properties.androidConfig.orFail("android configuration").applications.single().packageName)
    }
}
