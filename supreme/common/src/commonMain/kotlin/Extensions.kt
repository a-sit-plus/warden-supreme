package at.asitplus.attestation.supreme

import at.asitplus.attestation.android.androidAttestationExtension
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
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


object DigestSerializer : KSerializer<Digest> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("DigestNamer", PrimitiveKind.STRING)
    override fun deserialize(decoder: Decoder): Digest =
        Digest.valueOf(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Digest) {
        encoder.encodeString(value.name)
    }
}

object ECCurveSerializer : KSerializer<ECCurve> {
    private val serializer = at.asitplus.signum.indispensable.ECCurveSerializer
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("EllipticCurveName", PrimitiveKind.STRING)
    override fun deserialize(decoder: Decoder): ECCurve =
        serializer.deserialize(decoder)!!

    override fun serialize(encoder: Encoder, value: ECCurve) {
        serializer.serialize(encoder, value)
    }
}


object DurationWholeSecondsSerializer : KSerializer<Duration> {
    override val descriptor = PrimitiveSerialDescriptor("DurationInWholeSeconds", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): Duration = decoder.decodeLong().seconds

    override fun serialize(encoder: Encoder, value: Duration) {
        encoder.encodeLong(value.inWholeSeconds)
    }
}


object BitLengthSerializer : KSerializer<BitLength> {
    override val descriptor = PrimitiveSerialDescriptor("BitLength", PrimitiveKind.INT)
    override fun deserialize(decoder: Decoder): BitLength {
        val bits = decoder.decodeInt()
        return BitLength.fromBits(bits.toUInt())
    }

    override fun serialize(encoder: Encoder, value: BitLength) {
        encoder.encodeInt(value.bits.toInt())
    }
}

/**
 * Returns a list of certificates that contain an attestation extension; in-order.
 *
 * @throws Throwable In case a certificate in the chain is malformed
 */
@Throws(Throwable::class)
fun CertificateChain.withAndroidAttestationExtensions(): List<X509Certificate> =
    filter { it.androidAttestationExtension != null }

/**
 * Returns the certificate matching the predicate that is closest to the root. Can be the root itself.
 *
 * @throws Throwable if no match is found
 */
fun List<X509Certificate>.closestToRoot(predicate: (X509Certificate) -> Boolean) = last(predicate)

/**
 * Returns the certificate matching the predicate that is closes to the root. Can be the root itself.
 */
fun List<X509Certificate>.closestToRootOrNull(predicate: (X509Certificate) -> Boolean) =
    catchingUnwrapped { closestToRoot(predicate) }.getOrNull()