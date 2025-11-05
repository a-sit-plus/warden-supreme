package at.asitplus.attestation.android

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.ktor.util.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.MessageDigest
import java.security.cert.TrustAnchor


@Serializable(with = TrustedRootSerializer::class)
sealed class TrustedRoot(protected val value: Asn1Encodable<*>) {

    data class PublicKey(val key: java.security.PublicKey) : TrustedRoot(key.toCryptoPublicKey().getOrThrow()) {
        @Throws(Throwable::class)
        constructor(encoded: ByteArray) : this(CryptoPublicKey.decodeFromDer(encoded).toJcaPublicKey().getOrThrow())
    }

    data class Certificate(val certificate: java.security.cert.X509Certificate) :
        TrustedRoot(certificate.toKmpCertificate().getOrThrow()) {
        @Throws(Throwable::class)
        constructor(encoded: ByteArray) : this(
            X509Certificate.decodeFromDer(encoded).toJcaCertificateBlocking().getOrThrow()
        )
    }

    val publicKey: java.security.PublicKey by lazy {
        when (this) {
            is Certificate -> certificate.publicKey
            is PublicKey -> key
        }
    }

    val derEncoded: ByteArray by lazy { value.encodeToDer() }

    val trustAnchor: TrustAnchor by lazy {
        when (this) {
            is Certificate -> TrustAnchor(certificate, null)
            is PublicKey -> TrustAnchor("CN=" + MessageDigest.getInstance("SHA-256").digest(key.encoded), key, null)
        }
    }

    override fun toString(): String = when (this) {
        is TrustedRoot.Certificate -> derEncoded.encodeBase64()
        is TrustedRoot.PublicKey -> derEncoded.encodeBase64()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TrustedRoot) return false

        //better safe than sorry
        if (!derEncoded.contentEquals(other.derEncoded)) return false

        return true
    }

    override fun hashCode(): Int {
        return derEncoded.contentHashCode()
    }

    companion object {
        @JvmStatic
        @Throws(Throwable::class)
        fun decode(encoded: ByteArray): TrustedRoot = catchingUnwrapped { TrustedRoot.PublicKey(encoded) }.getOrElse {
            catchingUnwrapped { TrustedRoot.Certificate(encoded) }.getOrElse { throw Asn1Exception("Input is neither public key nor certificate") }
        }
    }

}

object TrustedRootSerializer : KSerializer<TrustedRoot> {
    override val descriptor: SerialDescriptor = SerialDescriptor("TrustAnchor", String.serializer().descriptor)

    override fun serialize(
        encoder: Encoder,
        value: TrustedRoot
    ) {
        when (value) {
            is TrustedRoot.Certificate -> CertPemSerializer.serialize(encoder, value.certificate)
            is TrustedRoot.PublicKey -> PubKeyBasePemSerializer.serialize(encoder, value.key)
        }
    }

    override fun deserialize(decoder: Decoder): TrustedRoot =
        decoder.decodeString().let {
            try {
                TrustedRoot.PublicKey(
                    CryptoPublicKey.decodeFromPem(it).getOrThrow().toJcaPublicKey().getOrThrow()
                )
            } catch (_: Throwable) {
                TrustedRoot.Certificate(
                    at.asitplus.signum.indispensable.pki.X509Certificate.decodeFromPem(
                        it
                    ).getOrThrow().toJcaCertificateBlocking().getOrThrow()
                )
            }
        }
}
