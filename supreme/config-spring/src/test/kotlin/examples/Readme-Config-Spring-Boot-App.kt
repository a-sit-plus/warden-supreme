package examples.docs

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.fromSpringEnvironment
import at.asitplus.attestation.supreme.SupremeConfiguration
import org.junit.jupiter.api.Test
import org.springframework.boot.WebApplicationType
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.builder.SpringApplicationBuilder
import org.springframework.boot.env.YamlPropertySourceLoader
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.io.FileSystemResource

@SpringBootApplication
private open class ConfigSpringExampleApp

class SpringBootConfigLoadingTest {
    @Test
    fun loadExampleConfigsFromYaml() {
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

        examples.forEach { (path, loadConfig) ->
            val context = runWithYaml(path)
            loadConfig(context.environment)
            context.close()
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
