package at.asitplus.attestation.supreme

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.*

/**
 * Constrained value type for [AttestationChallenge.additionalPayload].
 *
 * Supported values:
 * - `null`
 * - `Boolean`, `String`, `Byte`, `Short`, `Int`, `Long`, `Char`, `Float`, `Double`
 * - nested `Map<String, Constrained>`
 *
 * Unsupported values cause a [SerializationException] at runtime.
 */
typealias Constrained = Any?

/**
 * Format-agnostic serializer for `Map<String, Constrained>`.
 */
object ConstrainedMapSerializer : KSerializer<Map<String, Constrained>> {
    private val delegate: KSerializer<Map<String, Constrained>> by lazy {
        @Suppress("UNCHECKED_CAST")
        MapSerializer(String.serializer(), ConstrainedValueSerializer)
    }

    override val descriptor: SerialDescriptor get() = delegate.descriptor

    override fun serialize(encoder: Encoder, value: Map<String, Constrained>) {
        delegate.serialize(encoder, value)
    }

    override fun deserialize(decoder: Decoder): Map<String, Constrained> =
        delegate.deserialize(decoder)
}

/**
 * Type discriminator for [Constrained] values encoded by [ConstrainedValueSerializer].
 *
 * IDs intentionally start at `1` (not `0`) to stay robust with formats that may elide default scalar values
 * on the wire (e.g. ProtoBuf-style encodings where `0` is the default for integers).
 * If `0` were used as a valid discriminator, it could be indistinguishable from a missing discriminator field.
 */
private enum class ConstrainedType(val id: Int) {
    NULL(1),
    BOOLEAN(2),
    STRING(3),
    BYTE(4),
    SHORT(5),
    INT(6),
    LONG(7),
    CHAR(8),
    FLOAT(9),
    DOUBLE(10),
    MAP(11),
}

private object ConstrainedValueSerializer : KSerializer<Constrained> {
    private val valuePlaceholderDescriptor: SerialDescriptor =
        buildClassSerialDescriptor("at.asitplus.attestation.supreme.ConstrainedValuePayload")

    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("at.asitplus.attestation.supreme.ConstrainedValue") {
            element("type", Byte.serializer().descriptor)
            element("value", valuePlaceholderDescriptor, isOptional = true)
        }

    override fun serialize(encoder: Encoder, value: Constrained) {
        encoder.encodeStructure(descriptor) {
            when (value) {
                null -> encodeByteElement(descriptor, 0, ConstrainedType.NULL.id.toByte())
                is Boolean -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.BOOLEAN.id.toByte())
                    encodeSerializableElement(descriptor, 1, Boolean.serializer(), value)
                }

                is String -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.STRING.id.toByte())
                    encodeSerializableElement(descriptor, 1, String.serializer(), value)
                }

                is Byte -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.BYTE.id.toByte())
                    encodeSerializableElement(descriptor, 1, Byte.serializer(), value)
                }

                is Short -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.SHORT.id.toByte())
                    encodeSerializableElement(descriptor, 1, Short.serializer(), value)
                }

                is Int -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.INT.id.toByte())
                    encodeSerializableElement(descriptor, 1, Int.serializer(), value)
                }

                is Long -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.LONG.id.toByte())
                    encodeSerializableElement(descriptor, 1, Long.serializer(), value)
                }

                is Char -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.CHAR.id.toByte())
                    encodeSerializableElement(descriptor, 1, Char.serializer(), value)
                }

                is Float -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.FLOAT.id.toByte())
                    encodeSerializableElement(descriptor, 1, Float.serializer(), value)
                }

                is Double -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.DOUBLE.id.toByte())
                    encodeSerializableElement(descriptor, 1, Double.serializer(), value)
                }

                is Map<*, *> -> {
                    encodeByteElement(descriptor, 0, ConstrainedType.MAP.id.toByte())
                    val asStringKeyMap: Map<String, Constrained> = value.entries.associate { (k, v) ->
                        val key = k as? String
                            ?: throw SerializationException("Constrained map key must be String, got: ${k?.let { it::class.qualifiedName }}")
                        key to v
                    }
                    encodeSerializableElement(descriptor, 1, ConstrainedMapSerializer, asStringKeyMap)
                }

                else -> throw SerializationException("Unsupported Constrained value: ${value::class.qualifiedName}")
            }
        }
    }

    override fun deserialize(decoder: Decoder): Constrained {
        return decoder.decodeStructure(descriptor) {
            var typeId: Byte? = null
            var sawValue = false
            var decodedValue: Any? = null

            loop@ while (true) {
                when (val index = decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> typeId = decodeByteElement(descriptor, 0)
                    1 -> {
                        val effectiveTypeId = typeId
                            ?: throw SerializationException("Constrained 'type' must be decoded before 'value'")
                        val type = ConstrainedType.entries.firstOrNull { it.id.toByte() == effectiveTypeId }
                            ?: throw SerializationException("Unknown Constrained type id: $effectiveTypeId")

                        sawValue = true
                        decodedValue = when (type) {
                            ConstrainedType.NULL -> null
                            ConstrainedType.BOOLEAN -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Boolean.serializer().nullable
                            )

                            ConstrainedType.STRING -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                String.serializer().nullable
                            )

                            ConstrainedType.BYTE -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Byte.serializer().nullable
                            )

                            ConstrainedType.SHORT -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Short.serializer().nullable
                            )

                            ConstrainedType.INT -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Int.serializer().nullable
                            )

                            ConstrainedType.LONG -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Long.serializer().nullable
                            )

                            ConstrainedType.CHAR -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Char.serializer().nullable
                            )

                            ConstrainedType.FLOAT -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Float.serializer().nullable
                            )

                            ConstrainedType.DOUBLE -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                Double.serializer().nullable
                            )

                            ConstrainedType.MAP -> decodeNullableSerializableElement(
                                descriptor,
                                1,
                                ConstrainedMapSerializer.nullable
                            )
                        }
                    }

                    else -> throw SerializationException("Unknown element index $index for ConstrainedValue")
                }
            }

            val effectiveTypeId = typeId ?: throw SerializationException("Missing Constrained 'type'")
            val type = ConstrainedType.entries.firstOrNull { it.id.toByte() == effectiveTypeId }
                ?: throw SerializationException("Unknown Constrained type id: $effectiveTypeId")

            if (type == ConstrainedType.NULL) {
                if (sawValue) throw SerializationException("Malformed Constrained NULL: value must be absent")
                return@decodeStructure null
            }

            if (!sawValue) {
                return@decodeStructure defaultFor(type)
            }

            if (decodedValue == null) {
                throw SerializationException("Malformed Constrained value: type=$type but value decoded as null")
            }
            return@decodeStructure decodedValue
        }
    }

    private fun defaultFor(type: ConstrainedType): Constrained = when (type) {
        ConstrainedType.BOOLEAN -> false
        ConstrainedType.STRING -> ""
        ConstrainedType.BYTE -> 0.toByte()
        ConstrainedType.SHORT -> 0.toShort()
        ConstrainedType.INT -> 0
        ConstrainedType.LONG -> 0L
        ConstrainedType.CHAR -> '\u0000'
        ConstrainedType.FLOAT -> 0f
        ConstrainedType.DOUBLE -> 0.0
        ConstrainedType.MAP -> emptyMap<String, Constrained>()
        ConstrainedType.NULL -> null
    }
}
