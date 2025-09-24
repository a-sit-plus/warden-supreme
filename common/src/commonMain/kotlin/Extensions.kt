package at.asitplus.attestation.supreme

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

class InstantLongSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("InstantLongSerializer", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): kotlin.time.Instant {
        return kotlin.time.Instant.fromEpochMilliseconds(decoder.decodeLong())
    }

    override fun serialize(encoder: Encoder, value: kotlin.time.Instant) {
        encoder.encodeLong(value.toEpochMilliseconds())
    }
}