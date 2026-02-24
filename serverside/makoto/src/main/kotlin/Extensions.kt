@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUtf8String
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1OctetStringPrimitive
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.X509CertificateBase64Serializer
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import ch.veehait.devicecheck.appattest.receipt.Receipt
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.util.encoders.Base64
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneId
import java.util.*
import javax.annotation.processing.Generated
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant


private val ecKeyFactory = KeyFactory.getInstance("EC")
private val rsaKeyFactory = KeyFactory.getInstance("RSA")

//copied from AppAttest Library
private val certificateFactory = CertificateFactory.getInstance("X.509")
fun ByteArray.parseToCertificate(): X509Certificate? = kotlin.runCatching {
    certificateFactory.generateCertificate(this.inputStream()) as X509Certificate
}.getOrNull()

data class AttestationObject(
    val fmt: String,
    val attStmt: AttestationStatement,
    val authData: ByteArray
) {
    data class AttestationStatement(
        val x5c: List<ByteArray>,
        val receipt: ByteArray
    )
}

internal data class AssertionEnvelope(
    val signature: ByteArray,
    val authenticatorData: ByteArray,
) {
    @Generated
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AssertionEnvelope

        if (!signature.contentEquals(other.signature)) return false
        if (!authenticatorData.contentEquals(other.authenticatorData)) return false

        return true
    }

    @Generated
    override fun hashCode(): Int {
        var result = signature.contentHashCode()
        result = 31 * result + authenticatorData.contentHashCode()
        return result
    }
}

internal fun ByteArray.readAsSignedData(): CMSSignedData = ASN1InputStream(this).use {
    it.readObject().let(ContentInfo::getInstance).let(::CMSSignedData)
}
//END COPIED


fun Receipt.serialize(): ByteArray = p7
fun ByteArray.readAsReceipt() = Receipt(Receipt.Payload.parse(readAsSignedData()), this)


fun ValidatedAttestation.canonicalize(): CanonicalIosAttestation = CanonicalIosAttestation(this)

/**
 * Canonical, serializable representation of [ValidatedAttestation]
 */
@Serializable(with = CanonicalIosAttestation.Serializer::class)
data class CanonicalIosAttestation(val cert: X509Certificate, val receipt: Receipt, val iosVersion: String?) :
    Asn1Encodable<Asn1Sequence> {
    constructor(validatedAttestation: ValidatedAttestation) : this(
        validatedAttestation.certificate,
        validatedAttestation.receipt,
        validatedAttestation.iOSVersion
    )

    fun toValidatedAttestation(): ValidatedAttestation = ValidatedAttestation(cert, receipt, iosVersion)

    override fun encodeToTlv() = Asn1.Sequence {
        +cert.toKmpCertificate().getOrThrow()
        +receipt.p7.encodeToAsn1OctetStringPrimitive()
        iosVersion?.let { +Asn1String.UTF8(it) }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CanonicalIosAttestation) return false

        if (!cert.encoded.contentEquals(other.cert.encoded)) return false
        if (!receipt.p7.contentEquals(other.receipt.p7)) return false
        if (iosVersion != other.iosVersion) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cert.encoded.contentHashCode()
        result = 31 * result + receipt.p7.contentHashCode()
        result = 31 * result + (iosVersion?.hashCode() ?: 0)
        return result
    }


    object Serializer : KSerializer<CanonicalIosAttestation> {
        override val descriptor = listSerialDescriptor<String>()

        override fun serialize(
            encoder: Encoder,
            value: CanonicalIosAttestation
        ) {
            encoder.encodeSerializableValue(ValidatedAttestationSerializer, value.toValidatedAttestation())
        }

        override fun deserialize(decoder: Decoder): CanonicalIosAttestation {
            return CanonicalIosAttestation(decoder.decodeSerializableValue(ValidatedAttestationSerializer))
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, CanonicalIosAttestation> {
        override fun doDecode(src: Asn1Sequence): CanonicalIosAttestation = src.decodeAs {
            val cert = at.asitplus.signum.indispensable.pki.X509Certificate.decodeFromTlv(next() as Asn1Sequence)

            val receipt = next().asOctetString().content.let {
                Receipt(Receipt.Payload.parse((it.readAsSignedData())), it)
            }
            val iosVersion = if (hasNext())
                next().asPrimitive().decodeToUtf8String()
            else null

            CanonicalIosAttestation(cert.toJcaCertificateBlocking().getOrThrow(), receipt, iosVersion?.value)
        }
    }
}

object ValidatedAttestationSerializer : KSerializer<ValidatedAttestation> {
    override val descriptor = listSerialDescriptor<String>()

    override fun serialize(
        encoder: Encoder,
        value: ValidatedAttestation
    ) {

        val encoder = encoder.beginCollection(descriptor, if (value.iOSVersion == null) 2 else 3)
        encoder.encodeSerializableElement(
            X509CertificateBase64Serializer.descriptor, 0,
            X509CertificateBase64Serializer, value.certificate.toKmpCertificate().getOrThrow()
        )
        encoder.encodeSerializableElement(
            ByteArrayBase64Serializer.descriptor,
            1,
            ByteArrayBase64Serializer,
            value.receipt.p7
        )
        value.iOSVersion?.let {
            encoder.encodeStringElement(String.serializer().descriptor, 2, it)
        }
        encoder.endStructure(descriptor)
    }

    override fun deserialize(decoder: Decoder): ValidatedAttestation {
        val decoder = decoder.beginStructure(descriptor)
        val cert = decoder.decodeSerializableElement(
            X509CertificateBase64Serializer.descriptor,
            decoder.decodeElementIndex(X509CertificateBase64Serializer.descriptor),
            X509CertificateBase64Serializer
        )
        val receipt =
            decoder.decodeSerializableElement(
                ByteArrayBase64Serializer.descriptor, decoder.decodeElementIndex(
                    ByteArrayBase64Serializer.descriptor
                ), ByteArrayBase64Serializer
            )
                .let {
                    Receipt(Receipt.Payload.parse((it.readAsSignedData())), it)
                }
        val iosVersion = decoder.decodeElementIndex(String.serializer().descriptor)
            .let { if (it == -1) null else decoder.decodeStringElement(String.serializer().descriptor, it) }
        decoder.endStructure(descriptor)
        return ValidatedAttestation(cert.toJcaCertificateBlocking().getOrThrow(), receipt, iosVersion)
    }
}

internal fun PublicKey.transcodeToAllFormats() = toCryptoPublicKey().getOrThrow().let {
    when (it) {
        is CryptoPublicKey.EC -> listOf(
            it.encodeToDer(),
            it.toAnsiX963Encoded(useCompressed = it.preferCompressedRepresentation),
            it.toAnsiX963Encoded(useCompressed = !it.preferCompressedRepresentation),
            it.didEncoded.encodeToByteArray()
        )

        is CryptoPublicKey.RSA -> listOf(
            it.encodeToDer(),
            it.iosEncoded,
            it.didEncoded.encodeToByteArray()
        )
    }
}

internal fun String.decodeBase64ToArray() = Base64.decode(this)

internal fun ByteArray.encodeBase64() = Base64.toBase64String(this)

internal fun Clock.toJavaClock(): java.time.Clock =
    object : java.time.Clock() {
        override fun getZone(): ZoneId = systemDefaultZone().zone


        override fun withZone(zone: ZoneId?): java.time.Clock {
            TODO("Not yet implemented")
        }

        override fun instant(): Instant = now().toJavaInstant()

    }

internal fun kotlin.time.Instant.toJavaDate() = Date.from(toJavaInstant())

fun ByteArray.parseToPublicKey(): PublicKey =
    try {
        CryptoPublicKey.decodeFromDer(this).toJcaPublicKey().getOrThrow()
    } catch (e: Throwable) {
        CryptoPublicKey.fromIosEncoded(this).toJcaPublicKey().getOrThrow()
    }

/**
 * Drops or adds zero bytes at the start until the [size] is reached
 */
private fun ByteArray.ensureSize(size: Int): ByteArray = when {
    this.size > size -> this.drop(1).toByteArray().ensureSize(size)
    this.size < size -> (byteArrayOf(0) + this).ensureSize(size)
    else -> this
}

// taken from https://github.com/Kotlin/kotlinx-datetime/pull/249/
fun java.time.Clock.toKotlinClock(): Clock = let {
    object : Clock {
        override fun now(): kotlin.time.Instant = instant().toKotlinInstant()
    }
}

class InstantLongSerializer : KSerializer<kotlin.time.Instant> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("InstantLongSerializer", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): kotlin.time.Instant {
        return kotlin.time.Instant.fromEpochMilliseconds(decoder.decodeLong())
    }

    override fun serialize(encoder: Encoder, value: kotlin.time.Instant) {
        encoder.encodeLong(value.toEpochMilliseconds())
    }

}
