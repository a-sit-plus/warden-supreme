package at.asitplus.attestation

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.PolymorphicSerializer
import net.mamoe.yamlkt.YamlElement
import net.mamoe.yamlkt.YamlList
import net.mamoe.yamlkt.YamlLiteral
import net.mamoe.yamlkt.YamlMap
import net.mamoe.yamlkt.YamlNull
import net.mamoe.yamlkt.toYamlElement
import kotlin.reflect.KClass

/**
 * Polymorphic serializer that flattens `type`/`value` wrappers for yamlkt only.
 * For all other formats, it delegates to the default polymorphic serializer unchanged.
 */
open class YamlFlatteningPolymorphicSerializer<T : Any>(
    private val base: KClass<T>
) : KSerializer<T> {

    private val polymorphicSerializer = PolymorphicSerializer(base)

    override val descriptor: SerialDescriptor = polymorphicSerializer.descriptor

    override fun serialize(encoder: Encoder, value: T) {
        if (isYamlEncoder(encoder)) {
            val json = jsonFor(encoder.serializersModule)
            val element = json.encodeToJsonElement(polymorphicSerializer, value)
            val flattened = flattenTypeValue(element)
            val yamlElement = jsonElementToYamlElement(flattened)
            encoder.encodeSerializableValue(YamlElement.serializer(), yamlElement)
            return
        }
        encoder.encodeSerializableValue(polymorphicSerializer, value)
    }

    override fun deserialize(decoder: Decoder): T {
        if (isYamlDecoder(decoder)) {
            val json = jsonFor(decoder.serializersModule)
            val yamlElement = decoder.decodeSerializableValue(YamlElement.serializer())
            val element = yamlElementToJsonElement(yamlElement)
            val flattened = flattenTypeValue(element)
            return json.decodeFromJsonElement(polymorphicSerializer, flattened)
        }
        return decoder.decodeSerializableValue(polymorphicSerializer)
    }
}

private fun isYamlEncoder(encoder: Encoder): Boolean =
    encoder::class.qualifiedName?.startsWith("net.mamoe.yamlkt") == true

private fun isYamlDecoder(decoder: Decoder): Boolean =
    decoder::class.qualifiedName?.startsWith("net.mamoe.yamlkt") == true

private fun jsonFor(serializersModule: SerializersModule) = Json {
    this.serializersModule = serializersModule
    classDiscriminator = "type"
    encodeDefaults = true
    ignoreUnknownKeys = true
    explicitNulls = false
}

private fun flattenTypeValue(element: JsonElement): JsonElement = when (element) {
    is JsonObject -> {
        val type = element["type"]
        val value = element["value"]
        if (type is JsonPrimitive && value is JsonObject) {
            buildJsonObject {
                put("type", type)
                value.entries.forEach { (k, v) -> put(k, flattenTypeValue(v)) }
                element.entries
                    .filter { it.key != "type" && it.key != "value" }
                    .forEach { (k, v) -> put(k, flattenTypeValue(v)) }
            }
        } else {
            buildJsonObject {
                element.entries.forEach { (k, v) -> put(k, flattenTypeValue(v)) }
            }
        }
    }
    else -> when (element) {
        is JsonArray -> buildJsonArray {
            element.jsonArray.forEach { add(flattenTypeValue(it)) }
        }
        else -> element
    }
}

private fun jsonElementToYamlElement(element: JsonElement): YamlElement =
    jsonElementToPlain(element).toYamlElement()

private fun jsonElementToPlain(element: JsonElement): Any? = when (element) {
    is JsonObject -> element.entries.associate { (k, v) -> k to jsonElementToPlain(v) }
    is JsonArray -> element.jsonArray.map { jsonElementToPlain(it) }
    is JsonPrimitive -> when {
        element.isString -> element.content
        element.booleanOrNull != null -> element.booleanOrNull
        element.longOrNull != null -> element.longOrNull
        element.doubleOrNull != null -> element.doubleOrNull
        else -> element.content
    }
    else -> null
}

private fun yamlElementToJsonElement(element: YamlElement): JsonElement = when (element) {
    is YamlMap -> buildJsonObject {
        element.content.forEach { (k, v) ->
            val key = k.content?.toString() ?: "null"
            put(key, yamlElementToJsonElement(v))
        }
    }
    is YamlList -> buildJsonArray {
        element.content.forEach { add(yamlElementToJsonElement(it)) }
    }
    is YamlNull -> JsonPrimitive(null as String?)
    is YamlLiteral -> yamlLiteralToJsonPrimitive(element)
    else -> JsonPrimitive(element.content?.toString())
}

private fun yamlLiteralToJsonPrimitive(literal: YamlLiteral): JsonPrimitive {
    val content = literal.content
    val lower = content.lowercase()
    if (lower == "true" || lower == "false") return JsonPrimitive(lower == "true")
    content.toLongOrNull()?.let { return JsonPrimitive(it) }
    content.toDoubleOrNull()?.let { return JsonPrimitive(it) }
    return JsonPrimitive(content)
}
