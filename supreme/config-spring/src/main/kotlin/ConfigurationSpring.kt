package at.asitplus.attestation

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.serializer
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.core.env.Environment

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
): A = fromSpringMap(environment.toAttestationConfigMap(prefix))

/**
 * Loads an [AttestationConfiguration] from a Spring-bound config map.
 */
inline fun <reified A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromSpringMap(
    configMap: Map<String, *>
): A = fromJsonObject(configMap.toAttestationJsonObject().withRelaxedPropertyNames(serializer<A>()))

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
            put(key, mapToJsonElement(entry))
        }
    }
}
