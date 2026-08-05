package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1OctetStringPrimitive
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Primitive value type used for client-provided attested attributes.
 *
 * Supported values:
 * - `null`
 * - `Boolean`, `String`, `Byte`, `Short`, `Int`, `Long`, `Char`, `Float`, `Double`, `ByteArray`
 *
 * Unsupported values cause a [SerializationException] at runtime.
 */
typealias Primitive = Any?


/**
 * Type discriminator and ASN.1 codec for [Primitive] values.
 *
 * IDs intentionally start at `1` (not `0`) to stay robust with formats that may elide default scalar values
 * on the wire (e.g. ProtoBuf-style encodings where `0` is the default for integers).
 * If `0` were used as a valid discriminator, it could be indistinguishable from a missing discriminator field.
 */
@Serializable(with = PrimitiveType.ByteSerializer::class)
enum class PrimitiveType(
    internal val id: Int,
    @Transient
    val asn1Encoder: HashedAttributeEncoder,
    @Transient
    val asn1Decoder: HashedAttributeDecoder,
) {
    NULL(
        1,
        { Asn1Null },
        { if (it == Asn1Null) null else throw IllegalArgumentException("primitive is not an ASN.1 NULL: ${it.prettyPrint()}") },
    ),
    BOOLEAN(
        2,
        { (it as Boolean?)?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else it.decodeToBoolean() }
    ),
    STRING(
        3,
        { (it as String?)?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else Asn1String.decodeFromTlv(it).value }

    ),
    BYTE(
        4,
        { (it as Byte?)?.toInt()?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else Asn1Integer.decodeFromTlv(it).toBigInteger().byteValue(exactRequired = true) }
    ),
    SHORT(
        5,
        { (it as Short?)?.toInt()?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else Asn1Integer.decodeFromTlv(it).toBigInteger().shortValue(exactRequired = true) }
    ),
    INT(
        6,
        { (it as Int?)?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else Asn1Integer.decodeFromTlv(it).toBigInteger().intValue(exactRequired = true) }
    ),
    LONG(
        7,
        { (it as Long?)?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else Asn1Integer.decodeFromTlv(it).toBigInteger().longValue(exactRequired = true) }
    ),
    CHAR(
        8,
        { (it as Char?)?.code?.encodeToAsn1Primitive() ?: Asn1Null },
        {
            if (it == Asn1Null) null else Char(
                Asn1Integer.decodeFromTlv(it).toBigInteger().intValue(exactRequired = true)
            )
        }
    ),
    FLOAT(
        9,
        { (it as Float?)?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else Asn1Real.decodeFromTlv(it).toFloat() }
    ),
    DOUBLE(
        10,
        { (it as Double?)?.encodeToAsn1Primitive() ?: Asn1Null },
        { if (it == Asn1Null) null else Asn1Real.decodeFromTlv(it).toDouble() }
    ),
    BYTEARRAY(
        11,
        { (it as ByteArray?)?.encodeToAsn1OctetStringPrimitive() ?: Asn1Null },
        { if (it == Asn1Null) null else it.asOctetString().content }
    ),

    ;

    internal object ByteSerializer : KSerializer<PrimitiveType> {

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(serialName = "PrimitiveType", kind = PrimitiveKind.BYTE)

        override fun serialize(
            encoder: Encoder,
            value: PrimitiveType
        ) {
            encoder.encodeByte(value.id.toByte())
        }

        override fun deserialize(decoder: Decoder): PrimitiveType = PrimitiveType.of(decoder.decodeByte())
    }
    /** Human-readable enum-name serializer used by externalised verifier configuration. */
    object NameSerializer : KSerializer<PrimitiveType> {

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor(serialName = "PrimitiveType", kind = PrimitiveKind.STRING)

        override fun serialize(
            encoder: Encoder,
            value: PrimitiveType
        ) {
            encoder.encodeString(value.name)
        }

        override fun deserialize(decoder: Decoder): PrimitiveType = PrimitiveType.valueOf(decoder.decodeString())
    }

    companion object {

        /** Resolves the stable binary serializer identifier [id]. */
        fun of(id: Byte): PrimitiveType = PrimitiveType.entries.firstOrNull { it.id.toByte() == id }
            ?: throw SerializationException("Unknown Primitive type id: $id")

    }
}

internal typealias HashedAttributeEncoder = (Primitive) -> Asn1Primitive
internal typealias HashedAttributeDecoder = (Asn1Primitive) -> Primitive?

internal val Primitive.type: PrimitiveType
    get() = when (this) {
        null -> PrimitiveType.NULL
        is Boolean -> PrimitiveType.BOOLEAN
        is String -> PrimitiveType.STRING
        is Byte -> PrimitiveType.BYTE
        is Short -> PrimitiveType.SHORT
        is Int -> PrimitiveType.INT
        is Long -> PrimitiveType.LONG
        is Char -> PrimitiveType.CHAR
        is Float -> PrimitiveType.FLOAT
        is Double -> PrimitiveType.DOUBLE
        is ByteArray -> PrimitiveType.BYTEARRAY
        else -> throw SerializationException("Unsupported Primitive value: ${this::class.simpleName}")
    }
