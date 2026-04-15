package at.asitplus.attestation

import com.sksamuel.hoplite.ArrayNode
import com.sksamuel.hoplite.BooleanNode
import com.sksamuel.hoplite.ConfigFailure
import com.sksamuel.hoplite.DecoderContext
import com.sksamuel.hoplite.DoubleNode
import com.sksamuel.hoplite.LongNode
import com.sksamuel.hoplite.MapNode
import com.sksamuel.hoplite.Node
import com.sksamuel.hoplite.NullNode
import com.sksamuel.hoplite.StringNode
import com.sksamuel.hoplite.Undefined
import com.sksamuel.hoplite.decoder.Decoder
import com.sksamuel.hoplite.decoder.NullHandlingDecoder
import com.sksamuel.hoplite.denormalize
import com.sksamuel.hoplite.fp.invalid
import com.sksamuel.hoplite.fp.valid
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlin.reflect.KClass
import kotlin.reflect.KType
import kotlin.reflect.full.companionObjectInstance


/**
 * Creates a Hoplite decoder for an [AttestationConfiguration] that converts the Hoplite node
 * into JSON and delegates to [AttestationConfiguration.Reader.fromJsonObject].
 */
inline fun <reified A : AttestationConfiguration> AttestationConfiguration.Reader<A>.hopliteDecoder(): Decoder<A> =
    AttestationConfigurationHopliteDecoder(this, A::class, serializer())

class AttestationConfigurationHopliteDecoder<A : AttestationConfiguration>(
    private val reader: AttestationConfiguration.Reader<A>,
    private val targetClass: KClass<A>,
    private val relaxedSerializer: KSerializer<A>
) : NullHandlingDecoder<A> {
    override fun supports(type: KType): Boolean = type.classifier == targetClass

    override fun safeDecode(node: Node, type: KType, context: DecoderContext) =
        runCatching {
            reader.fromJsonObject(
                hopliteNodeToJsonElement(node).withRelaxedPropertyNames(relaxedSerializer)
            ).valid()
        }.getOrElse { ex ->
            ConfigFailure.Generic("Failed to decode ${targetClass.qualifiedName}: ${ex.message}").invalid()
        }
}

private fun hopliteNodeToJsonElement(node: Node): JsonElement = when (node) {
    is MapNode -> buildJsonObject {
        node.denormalize().map.forEach { (key, entry) ->
            put(key, hopliteNodeToJsonElement(entry))
        }
    }
    is ArrayNode -> buildJsonArray {
        node.elements.forEach { add(hopliteNodeToJsonElement(it)) }
    }
    is StringNode -> JsonPrimitive(node.value)
    is LongNode -> JsonPrimitive(node.value)
    is DoubleNode -> JsonPrimitive(node.value)
    is BooleanNode -> JsonPrimitive(node.value)
    is NullNode -> JsonNull
    Undefined -> JsonNull
}