package at.asitplus.attestation

import kotlinx.serialization.KSerializer
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import net.mamoe.yamlkt.YamlElement
import net.mamoe.yamlkt.YamlLiteral
import net.mamoe.yamlkt.toYamlElement
import kotlin.reflect.KClass

/**
 * Serializer for a list of polymorphic [base] configurations that additionally understands the
 * scalar [sentinel] as an explicit spelling of the empty list, and *emits* [sentinel] whenever the
 * list is empty.
 *
 * This exists because Spring Boot cannot express an empty collection. Its `YamlProcessor` flattens
 * both `foo: []` and `foo: {}` into the empty string for the property `foo`, indistinguishable from
 * an unresolved shell variable, a blank Helm value or an emptied CI secret. Coercing that blank back
 * into an empty list would mean an accidentally empty environment variable silently switches a
 * security control off, so a deliberate, greppable token is required instead:
 *
 * ```yaml
 * attestation:
 *   android:
 *     revocation: DISABLED
 * ```
 *
 * Because the token is a plain scalar it survives every property source unchanged — YAML, properties
 * files, command-line arguments and environment variables alike — and because it round-trips through
 * [serialize] as well, canonical configuration written by `toYamlString()`/`toJsonString()` stays
 * loadable by every format, Spring included.
 *
 * Matching is case-insensitive on read; [sentinel] is emitted verbatim on write.
 */
open class SentinelEmptyListSerializer<T : Any>(
    private val base: KClass<T>,
    private val sentinel: String,
) : KSerializer<List<T>> {

    private val elementSerializer = YamlFlatteningPolymorphicSerializer(base)
    private val listSerializer = ListSerializer(elementSerializer)

    override val descriptor: SerialDescriptor = listSerializer.descriptor

    override fun serialize(encoder: Encoder, value: List<T>) {
        if (value.isEmpty()) {
            when {
                encoder.isYamlEncoder() ->
                    encoder.encodeSerializableValue(YamlElement.serializer(), sentinel.toYamlElement())

                encoder is JsonEncoder -> encoder.encodeJsonElement(JsonPrimitive(sentinel))

                // Formats that can represent an empty list natively do not need the sentinel.
                else -> encoder.encodeSerializableValue(listSerializer, value)
            }
            return
        }
        encoder.encodeSerializableValue(listSerializer, value)
    }

    override fun deserialize(decoder: Decoder): List<T> {
        if (decoder.isYamlDecoder()) {
            val yamlElement = decoder.decodeSerializableValue(YamlElement.serializer())
            if (yamlElement is YamlLiteral && yamlElement.content.matchesSentinel()) return emptyList()
            val json = jsonFor(decoder.serializersModule)
            val flattened = flattenTypeValue(yamlElementToJsonElement(yamlElement))
            return json.decodeFromJsonElement(ListSerializer(PolymorphicSerializer(base)), flattened)
        }
        if (decoder is JsonDecoder) {
            val element = decoder.decodeJsonElement()
            if (element is JsonPrimitive && element.content.matchesSentinel()) return emptyList()
            if (element !is JsonArray) throw SentinelExpectedException(sentinel, element.describe())
            return decoder.json.decodeFromJsonElement(listSerializer, element)
        }
        return decoder.decodeSerializableValue(listSerializer)
    }

    private fun String.matchesSentinel() = equals(sentinel, ignoreCase = true)

    /**
     * Spring Boot's empty string arrives here as [JsonNull], so it must not be reported as the
     * literal `null` — the operator wrote `[]`, `{}`, or nothing at all, not `null`.
     */
    private fun JsonElement.describe(): String = when (this) {
        is JsonNull -> "an empty value"
        is JsonPrimitive if content.isBlank() -> "an empty value"
        else -> toString()
    }

    /**
     * Raised for a scalar that is neither a list nor [sentinel] — most importantly the empty string
     * Spring Boot produces for `[]`, `{}` and for any property whose value went missing upstream.
     * The message has to name the token, because it is the only way to express "no entries" here.
     */
    class SentinelExpectedException(sentinel: String, actual: String) : IllegalArgumentException(
        "Expected either a list or the token '$sentinel', but got: $actual. " +
            "Note that '$sentinel' is the only way to configure an empty list, because Spring Boot " +
            "cannot represent one: it turns both '[]' and '{}' into an empty value, which is " +
            "indistinguishable from a property that was accidentally left blank."
    )
}
