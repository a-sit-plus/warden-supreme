@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import ch.veehait.devicecheck.appattest.receipt.Receipt
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
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

fun Receipt.serialize(): ByteArray = p7
fun ByteArray.toReceipt() = Receipt(Receipt.Payload.parse(readAsSignedData()), this)

fun ValidatedAttestation.toJson(): JsonObject = buildJsonObject {
    put("cert", certificate.toKmpCertificate().getOrThrow().encodeToPEM().getOrThrow())
    put("receipt", receipt.serialize().encodeBase64())
    iOSVersion?.let { put("iOSVersion", it.toString()) }
}

fun JsonObject.toValidatedAttestation() = ValidatedAttestation(
    at.asitplus.signum.indispensable.pki.X509Certificate.decodeFromPem(get("cert")!!.jsonPrimitive.content).getOrThrow()
        .toJcaCertificateBlocking().getOrThrow(),
    get("receipt")!!.jsonPrimitive.content.decodeBase64ToArray().toReceipt(),
    getOrDefault(
        "iOSVersion",
        JsonNull
    ).jsonPrimitive.contentOrNull
)


internal fun ByteArray.readAsSignedData(): CMSSignedData = ASN1InputStream(this).use {
    it.readObject().let(ContentInfo::getInstance).let(::CMSSignedData)
}

//END COPIED

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
