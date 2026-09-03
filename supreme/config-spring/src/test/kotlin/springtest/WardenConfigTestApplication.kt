package at.asitplus.attestation.springtest

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.fromSpringEnvironment
import at.asitplus.attestation.fromSpringMap
import at.asitplus.attestation.supreme.SupremeConfiguration
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment

/**
 * A plain Spring Boot application consuming Warden Supreme's canonical Spring configuration loading
 * (`:config-spring`).
 *
 * It deliberately offers both supported wiring styles side by side, so the tests in this module can
 * assert that the two agree and that both survive everything Spring Boot can put into an
 * [Environment]: YAML and `.properties` files, profiles, `spring.config.import`,
 * `spring.config.location`, environment variables, JVM system properties, command line arguments,
 * relaxed property names, placeholders and higher-precedence property sources.
 *
 *  * [AttestationProperties] &mdash; the `@ConfigurationProperties` map binding documented for
 *    library consumers, converted via [fromSpringMap]. Conversion happens while the context
 *    refreshes, so broken configuration fails application start-up just like in production.
 *  * [WardenEnvironmentLoader] &mdash; direct prefix binding via [fromSpringEnvironment], loaded on
 *    demand so tests can observe loader exceptions directly.
 */
@SpringBootApplication
open class WardenConfigTestApplication

fun main(args: Array<String>) {
    runApplication<WardenConfigTestApplication>(*args)
}

/**
 * The `@ConfigurationProperties` style documented for library consumers: Spring binds the raw
 * subtree into a [Map], Warden converts it.
 */
@ConfigurationProperties("attestation")
data class AttestationProperties(
    private val supreme: Map<String, Any?>? = null,
    private val android: Map<String, Any?>? = null,
    private val ios: Map<String, Any?>? = null,
) {
    /** The raw, Spring-bound subtrees, so tests can inspect what the binder actually produced. */
    val rawSupreme: Map<String, Any?>? get() = supreme
    val rawAndroid: Map<String, Any?>? get() = android
    val rawIos: Map<String, Any?>? get() = ios

    val supremeConfig: SupremeConfiguration? = supreme?.let { SupremeConfiguration.fromSpringMap(it) }
    val androidConfig: AndroidAttestationConfiguration? =
        android?.let { AndroidAttestationConfiguration.fromSpringMap(it) }
    val iosConfig: IosAttestationConfiguration? = ios?.let { IosAttestationConfiguration.fromSpringMap(it) }
}

/** Loads configurations straight off the [Environment], i.e. without any intermediate binding type. */
class WardenEnvironmentLoader(val environment: Environment) {
    fun supreme(prefix: String = "attestation.supreme"): SupremeConfiguration =
        SupremeConfiguration.fromSpringEnvironment(environment, prefix)

    fun android(prefix: String = "attestation.android"): AndroidAttestationConfiguration =
        AndroidAttestationConfiguration.fromSpringEnvironment(environment, prefix)

    fun ios(prefix: String = "attestation.ios"): IosAttestationConfiguration =
        IosAttestationConfiguration.fromSpringEnvironment(environment, prefix)
}

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AttestationProperties::class)
open class WardenConfigTestConfiguration {
    @Bean
    open fun wardenEnvironmentLoader(environment: Environment) = WardenEnvironmentLoader(environment)
}
