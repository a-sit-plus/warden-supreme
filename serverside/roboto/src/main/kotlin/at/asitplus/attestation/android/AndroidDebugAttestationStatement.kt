package at.asitplus.attestation.android

import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyHardwareAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyNougatHybridAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacySoftwareAttestationEngine
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*

private val jsonDebug = kotlinx.serialization.json.Json {
    encodeDefaults = true
    ignoreUnknownKeys = true
}

//TODO this also needs to be made aware of different engines
@Serializable
class AndroidDebugAttestationStatement(
    val kind: Type,
    val configuration: AndroidAttestationConfiguration,
    @Serializable(with = DateTimeSerializer::class) val verificationTime: Date,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray,
    val attestationStatement: List<@Serializable(with = CertPemSerializer::class) X509Certificate>
) {

    constructor(
        checker: AttestationEngine<*,*>,
        configuration: AndroidAttestationConfiguration,
        verificationTime: Date,
        challenge: ByteArray,
        attestationStatement: List<X509Certificate>
    ) : this(
        when (checker) {
            is LegacyHardwareAttestationEngine -> Type.HARDWARE
            is LegacySoftwareAttestationEngine -> Type.SOFTWARE
            is LegacyNougatHybridAttestationEngine -> Type.NOUGAT_HYBRID
            else -> throw IllegalArgumentException("Unknown checker type")
        },
        configuration,
        verificationTime,
        challenge,
        attestationStatement

    )

    fun checkerFromConfig(): LegacyAttestationEngine =
        when (kind) {
            Type.HARDWARE -> LegacyHardwareAttestationEngine(configuration)
            Type.SOFTWARE -> LegacySoftwareAttestationEngine(configuration)
            Type.NOUGAT_HYBRID -> LegacyNougatHybridAttestationEngine(configuration)
        }

    fun replay() = checkerFromConfig().verifyAttestation(attestationStatement, verificationTime, challenge)


    fun serialize() = jsonDebug.encodeToString(this)

    @Serializable
    enum class Type {
        HARDWARE, SOFTWARE, NOUGAT_HYBRID
    }

    companion object {
        fun deserialize(string: String) = jsonDebug.decodeFromString<AndroidDebugAttestationStatement>(string)
    }
}

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