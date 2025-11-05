package at.asitplus.attestation.android

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.text.SimpleDateFormat
import java.util.*

object PubKeyBasePemSerializer : TransformingSerializerTemplate<java.security.PublicKey, String>(
    parent = String.serializer(),
    encodeAs = { it.toCryptoPublicKey().getOrThrow().encodeToPEM().getOrThrow() },
    decodeAs = { CryptoPublicKey.decodeFromPem(it).getOrThrow().toJcaPublicKey().getOrThrow() }
)

object CertPemSerializer : TransformingSerializerTemplate<java.security.cert.X509Certificate, String>(
    parent = String.serializer(),
    encodeAs = { it.toKmpCertificate().getOrThrow().encodeToPEM().getOrThrow() },
    decodeAs = {
        at.asitplus.signum.indispensable.pki.X509Certificate.decodeFromPem(it).getOrThrow().toJcaCertificateBlocking()
            .getOrThrow()
    }
)

object DateTimeSerializer : KSerializer<Date> {
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    override val descriptor = String.serializer().descriptor

    override fun serialize(encoder: Encoder, value: Date) {
        val formattedDate = dateFormat.format(value)
        encoder.encodeString(formattedDate)
    }

    override fun deserialize(decoder: Decoder): Date {
        val dateString = decoder.decodeString()
        return dateFormat.parse(dateString) ?: throw IllegalArgumentException("Invalid date format: $dateString")
    }
}