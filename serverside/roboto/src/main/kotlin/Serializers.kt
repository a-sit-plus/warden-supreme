package at.asitplus.attestation.android

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.text.SimpleDateFormat
import java.util.*

object PubKeyBasePemSerializer : TransformingSerializerTemplate<java.security.PublicKey, String>(
    parent = String.serializer(),
    encodeAs = { it.toCryptoPublicKey().getOrThrow().encodeToPem() },
    decodeAs = { CryptoPublicKey.decodeFromPem(it).toJcaPublicKey().getOrThrow() }
)

object CertPemSerializer : TransformingSerializerTemplate<java.security.cert.X509Certificate, String>(
    parent = String.serializer(),
    encodeAs = { it.toKmpCertificate().getOrThrow().encodeToPem() },
    decodeAs = {
        at.asitplus.signum.indispensable.pki.Certificate.decodeFromPem(it).toJcaCertificateBlocking()
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