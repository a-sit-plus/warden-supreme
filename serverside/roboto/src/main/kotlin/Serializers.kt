package at.asitplus.attestation.android

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.text.SimpleDateFormat
import java.util.*

object PubKeyBasePemSerializer : TransformingSerializerTemplate<java.security.PublicKey, String>(
    parent = String.serializer(),
    encodeAs = { Signum.Der.encodeToPem(it.toCryptoPublicKey()) },
    decodeAs = { Signum.Der.decodeFromPem<CryptoPublicKey>(it).toJcaPublicKey() }
)

object CertPemSerializer : TransformingSerializerTemplate<java.security.cert.X509Certificate, String>(
    parent = String.serializer(),
    encodeAs = { Signum.Der.encodeToPem(it.toKmpCertificate().getOrThrow()) },
    decodeAs = {
        Signum.Der.decodeFromPem<at.asitplus.signum.indispensable.pki.Certificate>(it).toJcaCertificateBlocking()
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

object CustomPropertiesSerializer : KSerializer<Map<String, String>> {
    private val ser = MapSerializer(String.serializer(), String.serializer())
    override val descriptor: SerialDescriptor
        get() = SerialDescriptor("at.asitplus.attestation.CustomProperties", ser.descriptor)

    @OptIn(ExperimentalSerializationApi::class)
    override fun serialize(
        encoder: Encoder,
        value: Map<String, String>
    ) {
        if (value.isNotEmpty()) ser.serialize(encoder, value)
        else encoder.encodeNull()
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun deserialize(decoder: Decoder): Map<String, String> {
        val additionalProps = decoder.decodeNullableSerializableValue(ser)
        return additionalProps ?: emptyMap()
    }

}