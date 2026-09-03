package at.asitplus.attestation.springtest

import org.springframework.boot.WebApplicationType
import org.springframework.boot.builder.SpringApplicationBuilder
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.core.env.MapPropertySource
import org.springframework.core.env.SystemEnvironmentPropertySource
import java.nio.file.Files
import java.nio.file.Path

/**
 * Canonical minimal snippets, so every test starts from configuration that is known to load and
 * only varies the *way* Spring Boot is fed.
 */
object Fixtures {
    const val SIGNER_FINGERPRINT = "NLl2LE1skNSEMZQMV73nMUJYsmQg7A"
    const val TEAM_IDENTIFIER = "9CYHJNG644"

    /** Flat properties for the same Android configuration, as a property source would carry them. */
    fun androidProperties(prefix: String, packageName: String) = mapOf<String, Any>(
        "$prefix.applications[0].packageName" to packageName,
        "$prefix.applications[0].signerFingerprints[0]" to SIGNER_FINGERPRINT,
    )

    /** Relaxed, environment-variable style spelling of the same Android configuration. */
    fun androidEnvironmentVariables(prefix: String, packageName: String) = mapOf<String, Any>(
        "${prefix}_APPLICATIONS_0_PACKAGENAME" to packageName,
        "${prefix}_APPLICATIONS_0_SIGNERFINGERPRINTS_0" to SIGNER_FINGERPRINT,
    )
}

/**
 * Runs the real application against a throw-away external configuration directory, exactly the way
 * `spring.config.location` is used in production deployments.
 *
 * @param files file name to contents, written into the temporary config directory
 * @param profiles active profiles
 * @param properties default properties (lowest precedence of the ones set here)
 * @param commandLineArgs raw `--key=value` arguments
 * @param systemEnvironment entries injected as a `systemEnvironment` property source, i.e. the
 * relaxed `UPPER_SNAKE_CASE` binding container deployments rely on
 * @param highestPrecedenceProperties entries added in front of *all* other property sources
 */
fun runApp(
    files: Map<String, String> = emptyMap(),
    profiles: List<String> = emptyList(),
    properties: Map<String, Any> = emptyMap(),
    commandLineArgs: List<String> = emptyList(),
    systemEnvironment: Map<String, Any> = emptyMap(),
    highestPrecedenceProperties: Map<String, Any> = emptyMap(),
    configDirCustomizer: (Path) -> Map<String, Any> = { emptyMap() },
    block: (ConfigurableApplicationContext) -> Unit,
) {
    val configDir = Files.createTempDirectory("warden-spring-config-")
    try {
        files.forEach { (name, contents) -> configDir.resolve(name).toFile().writeText(contents) }

        val defaults = linkedMapOf<String, Any>(
            "spring.config.location" to "optional:file:$configDir/",
            "spring.main.banner-mode" to "off",
        )
        if (profiles.isNotEmpty()) defaults["spring.profiles.active"] = profiles.joinToString(",")
        defaults += configDirCustomizer(configDir)
        defaults += properties

        SpringApplicationBuilder(WardenConfigTestApplication::class.java)
            .web(WebApplicationType.NONE)
            .properties(defaults)
            .initializers({ ctx: ConfigurableApplicationContext ->
                if (systemEnvironment.isNotEmpty()) {
                    ctx.environment.propertySources.addFirst(
                        SystemEnvironmentPropertySource("systemEnvironment", systemEnvironment)
                    )
                }
                if (highestPrecedenceProperties.isNotEmpty()) {
                    ctx.environment.propertySources.addFirst(
                        MapPropertySource("test-highest-precedence", highestPrecedenceProperties)
                    )
                }
            })
            .run(*commandLineArgs.toTypedArray())
            .use(block)
    } finally {
        configDir.toFile().deleteRecursively()
    }
}

/**
 * Same as [runApp], but expects context start-up to fail, and returns the root cause chain as a
 * single string so tests can assert on the diagnostics a misconfigured application actually sees.
 */
fun startupFailureOf(
    files: Map<String, String> = emptyMap(),
    properties: Map<String, Any> = emptyMap(),
): String {
    val failure = runCatching { runApp(files = files, properties = properties) {} }.exceptionOrNull()
        ?: error("expected application start-up to fail, but it succeeded")
    return generateSequence(failure) { it.cause }.mapNotNull { it.message }.joinToString(" | ")
}

/** Runs [block] with the given JVM system properties set, restoring the previous state afterwards. */
fun withSystemProperties(vararg entries: Pair<String, String>, block: () -> Unit) {
    val previous = entries.associate { (key, _) -> key to System.getProperty(key) }
    try {
        entries.forEach { (key, value) -> System.setProperty(key, value) }
        block()
    } finally {
        previous.forEach { (key, value) -> if (value == null) System.clearProperty(key) else System.setProperty(key, value) }
    }
}

fun ConfigurableApplicationContext.attestationProperties(): AttestationProperties =
    getBean(AttestationProperties::class.java)

fun ConfigurableApplicationContext.environmentLoader(): WardenEnvironmentLoader =
    getBean(WardenEnvironmentLoader::class.java)

/**
 * Asserts the expected Android package name and that both wiring styles produce the exact same
 * configuration object — the whole point of this module.
 */
fun ConfigurableApplicationContext.assertAndroidPackage(packageName: String) {
    val fromProperties = attestationProperties().androidConfig
        ?: error("no android configuration bound via @ConfigurationProperties")
    val fromEnvironment = environmentLoader().android()
    check(fromProperties.applications.single().packageName == packageName) {
        "expected package $packageName, got ${fromProperties.applications.single().packageName}"
    }
    check(fromProperties == fromEnvironment) {
        "@ConfigurationProperties and Environment binding disagree:\n$fromProperties\n$fromEnvironment"
    }
}

/** Kotlin-friendly non-null assertion: fails the test, and smart-casts for the caller. */
fun <T : Any> T?.orFail(what: String): T = this ?: error("expected $what to be present, but it was null")

/** Flattens a throwable chain into one string, for asserting on start-up diagnostics. */
fun Throwable.messageChain(): String =
    generateSequence(this) { it.cause }.mapNotNull { it.message }.joinToString(" | ")
