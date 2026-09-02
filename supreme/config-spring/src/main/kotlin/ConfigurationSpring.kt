@file:kotlin.jvm.JvmName("ConfigurationSpring")

package at.asitplus.attestation

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.serializer
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.core.env.Environment
import kotlin.reflect.KClass

/**
 * Binds a Spring Environment prefix into a nested map structure.
 */
fun Environment.toAttestationConfigMap(prefix: String): Map<String, Any?> =
    Binder.get(this)
        .bind(prefix, Bindable.mapOf(String::class.java, Any::class.java))
        .orElse(null)
        ?: throw IllegalArgumentException("No configuration properties found under prefix '$prefix'")

/**
 * Converts a Spring-bound config map into a JsonObject for AttestationConfiguration loading.
 */
fun Map<String, *>.toAttestationJsonObject(): JsonObject =
    mapToJsonElement(this).jsonObject

/**
 * Loads an [AttestationConfiguration] from a Spring Environment using the given prefix.
 */
inline fun <reified A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromSpringEnvironment(
    environment: Environment,
    prefix: String
): A = fromSpringEnvironment(environment, prefix, A::class)

/**
 * Loads an [AttestationConfiguration] from a Spring Environment using the given prefix.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromSpringEnvironment(
    environment: Environment,
    prefix: String,
    kClass: KClass<A>
): A = fromSpringMap(environment.toAttestationConfigMap(prefix), kClass)

/**
 * Loads an [AttestationConfiguration] from a Spring Environment using the given prefix.
 * This version is available for Java callers.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromSpringEnvironment(
    environment: Environment,
    prefix: String,
    clazz: Class<A>
): A = fromSpringEnvironment(environment, prefix, clazz.kotlin)

/**
 * Loads an [AttestationConfiguration] from a Spring-bound config map.
 */
inline fun <reified A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromSpringMap(
    configMap: Map<String, *>
): A = fromSpringMap(configMap, A::class)

/**
 * Loads an [AttestationConfiguration] from a Spring-bound config map.
 */
@OptIn(InternalSerializationApi::class)
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromSpringMap(
    configMap: Map<String, *>,
    kClass: KClass<A>
): A = fromJsonObject(configMap.toAttestationJsonObject().withRelaxedPropertyNames(kClass.serializer()))

/**
 * Loads an [AttestationConfiguration] from a Spring-bound config map.
 * This version is available for Java callers.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromSpringMap(
    configMap: Map<String, *>,
    clazz: Class<A>
): A = fromSpringMap(configMap, clazz.kotlin)


private fun mapToJsonElement(value: Any?): JsonElement = when (value) {
    null -> JsonNull
    is JsonElement -> value
    is Map<*, *> -> mapToJsonElement(value)
    is Iterable<*> -> buildJsonArray {
        value.forEach { add(mapToJsonElement(it)) }
    }
    is Array<*> -> buildJsonArray {
        value.forEach { add(mapToJsonElement(it)) }
    }
    is Boolean -> JsonPrimitive(value)
    is Number -> JsonPrimitive(value)
    is String -> if (value.isBlank()) JsonNull else JsonPrimitive(value)
    is Enum<*> -> JsonPrimitive(value.name)
    else -> JsonPrimitive(value.toString())
}

private fun mapToJsonElement(value: Map<*, *>): JsonElement {
    val indexed = value.keys.mapNotNull { key ->
        (key as? String)?.toIntOrNull()?.let { key to it }
    }
    if (indexed.size == value.size) {
        val indices = indexed.map { it.second }.sorted()
        if (indices.firstOrNull() == 0 && indices.lastOrNull() == indices.size - 1) {
            val entries = indexed.associate { it.second to it.first }
            return buildJsonArray {
                indices.forEach { idx ->
                    add(mapToJsonElement(value[entries[idx]]))
                }
            }
        }
    }
    return buildJsonObject {
        value.forEach { (key, entry) ->
            require(key is String) { "Only string keys are supported when converting config maps to JSON" }
            // Spring represents an empty YAML sequence as null, a blank string, or a list containing a null item when
            // binding it to Map<String, Any>.
            // `revocation: []` must therefore remain distinguishable from an omitted property, which retains defaults.
            put(
                key,
                if (key == "revocation" && entry.isSpringEmptyYamlSequence()) buildJsonArray {}
                else mapToJsonElement(entry)
            )
        }
    }
}

private fun Any?.isSpringEmptyYamlSequence(): Boolean = when (this) {
    null -> true
    is String -> isBlank()
    is Iterable<*> -> all { it == null || it is String && it.isBlank() }
    is Array<*> -> all { it == null || it is String && it.isBlank() }
    else -> false
}
