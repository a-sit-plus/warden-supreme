package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.encoding.parse
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

/** Hides primitive type metadata behind a mutable map of ordinary Kotlin values. */
object PrimitiveMapSerializer : KSerializer<MutableMap<String, Primitive>> {
    private val delegate = MapSerializer(String.serializer(), PrimitiveSerializer)
    override val descriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: MutableMap<String, Primitive>) =
        delegate.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): MutableMap<String, Primitive> =
        delegate.deserialize(decoder).toMutableMap()
}

/** JSON carries named, native values; other formats carry a stable type ID and ASN.1 DER bytes. */
object PrimitiveSerializer : KSerializer<Primitive> {
    @Serializable
    private data class JsonPayload(val type: String, val value: JsonElement)

    @Serializable
    private data class BinaryPayload(val type: PrimitiveType, val value: ByteArray)

    override val descriptor = JsonPayload.serializer().descriptor

    override fun serialize(encoder: Encoder, value: Primitive) {
        val type = value.type
        if (encoder is JsonEncoder) {
            encoder.encodeSerializableValue(
                JsonPayload.serializer(),
                JsonPayload(type.name.lowercase(), encoder.json.encodeToJsonElement(type.jsonSerializer, value)),
            )
        } else {
            encoder.encodeSerializableValue(
                BinaryPayload.serializer(),
                BinaryPayload(type, type.asn1Encoder(value).derEncoded),
            )
        }
    }

    override fun deserialize(decoder: Decoder): Primitive = if (decoder is JsonDecoder) {
        val payload = decoder.decodeSerializableValue(JsonPayload.serializer())
        val type = PrimitiveType.entries.firstOrNull { it.name.lowercase() == payload.type }
            ?: throw SerializationException("Unknown primitive type: ${payload.type}")
        decoder.json.decodeFromJsonElement(type.jsonSerializer, payload.value)
    } else {
        val payload = decoder.decodeSerializableValue(BinaryPayload.serializer())
        try {
            payload.type.asn1Decoder(Asn1Element.parse(payload.value).asPrimitive())
        } catch (cause: Asn1Exception) {
            throw SerializationException("Invalid ASN.1 primitive for ${payload.type}", cause)
        } catch (cause: Exception) {
            throw SerializationException("Invalid ASN.1 primitive for ${payload.type}", cause)
        }
    }
}
