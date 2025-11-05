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
import javax.security.auth.x500.X500Principal

/**
 * Represents a trusted root entity, which can either be a public key or an X.509 certificate.
 *
 * This sealed class hierarchy encapsulates otherwise disjoint trust anchor types
 *
 * A trusted root can be constructed from either:
 *  - An X.509 certificate, which serves as the trust anchor.
 *  - A raw public key, optionally associated with a certificate authority's distinguished name.
 */
@Serializable(with = TrustedRootSerializer::class)
sealed class TrustedRoot(protected val value: Asn1Encodable<*>) {

    /**
     * Creates a TrustedRoot from a public key.
     * @param key the public key
     * @param caName the common name of the certificate authority issuing the certificate, if known.
     * Leave blank if you do not care for Subject/Issuer name checks inside the Android Cert Path Validator (which makes sense for raw public keys)
     */
    @Serializable(with = TrustedRootSerializer::class)
    data class PublicKey @JvmOverloads constructor(
        val key: java.security.PublicKey,
        val caName: X500Principal? = null
    ) :
        TrustedRoot(key.toCryptoPublicKey().getOrThrow()) {
        @Throws(Throwable::class)
        constructor(encoded: ByteArray) : this(CryptoPublicKey.decodeFromDer(encoded).toJcaPublicKey().getOrThrow())
    }
    
    @Serializable(with = TrustedRootSerializer::class)
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
            is PublicKey -> TrustAnchor(
                caName ?: X500Principal(
                    "CN=" + MessageDigest.getInstance("SHA-256").digest(key.encoded)
                ), key, null
            )
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

        operator fun invoke(publicKey: java.security.PublicKey, caName: X500Principal? = null) =
            TrustedRoot.PublicKey(publicKey, caName)

        operator fun invoke(cert: java.security.cert.X509Certificate) = TrustedRoot.Certificate(cert)
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
