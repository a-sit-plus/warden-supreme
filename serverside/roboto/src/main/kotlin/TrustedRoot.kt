package at.asitplus.attestation.android

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.ktor.util.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SealedSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonPrimitive
import net.mamoe.yamlkt.YamlElement
import net.mamoe.yamlkt.YamlList
import net.mamoe.yamlkt.YamlLiteral
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
sealed interface TrustedRoot {
    val value: Asn1Encodable<*>

    /** Android-only policy attached to a trust root. */
    sealed interface AndroidSpecific : TrustedRoot {
        val enforceFactoryProvisionedChainValidity: Boolean
    }

    /**
     * Creates a TrustedRoot from a public key.
     * @param publicKey the public key
     * @param caName the common name of the certificate authority issuing the certificate, if known.
     * Leave blank if you do not care for Subject/Issuer name checks inside the Android Cert Path Validator (which makes sense for raw public keys)
     */
    @Serializable(with = TrustedRootSerializer::class)
    open class PublicKey @JvmOverloads constructor(
        override val publicKey: java.security.PublicKey,
        val caName: X500Principal? = null
    ) : TrustedRoot {
        @Throws(Throwable::class)
        constructor(encoded: ByteArray) : this(CryptoPublicKey.decodeFromDer(encoded).toJcaPublicKey().getOrThrow())

        override val value = publicKey.toCryptoPublicKey().getOrThrow()

        override val trustAnchor = TrustAnchor(
            caName ?: X500Principal(
                "CN=" + MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
            ), publicKey, null
        )

        override fun toString(): String = derEncoded.encodeBase64()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            return other is PublicKey &&
                    publicKey.encoded.contentEquals(other.publicKey.encoded) &&
                    caName == other.caName &&
                    androidValidityPolicy() == other.androidValidityPolicy()
        }

        override fun hashCode(): Int =
            31 * (31 * publicKey.encoded.contentHashCode() + (caName?.hashCode() ?: 0)) +
                    (androidValidityPolicy()?.hashCode() ?: 0)

        class AndroidSpecific @JvmOverloads constructor(
            publicKey: java.security.PublicKey,
            caName: X500Principal? = null,
            override val enforceFactoryProvisionedChainValidity: Boolean,
        ) : PublicKey(publicKey, caName), TrustedRoot.AndroidSpecific

        companion object {
            /** Constructs an Android-specific public-key trust root. */
            operator fun invoke(
                publicKey: java.security.PublicKey,
                caName: X500Principal? = null,
                enforceFactoryProvisionedChainValidity: Boolean,
            ): PublicKey = AndroidSpecific(publicKey, caName, enforceFactoryProvisionedChainValidity)
        }

    }

    @Serializable(with = TrustedRootSerializer::class)
    open class Certificate(val certificate: java.security.cert.X509Certificate) : TrustedRoot {
        override val value = certificate.toKmpCertificate().getOrThrow()

        @Throws(Throwable::class)
        constructor(encoded: ByteArray) : this(
            X509Certificate.decodeFromDer(encoded).toJcaCertificateBlocking().getOrThrow()
        )

        override val publicKey: java.security.PublicKey by lazy { certificate.publicKey }
        override val trustAnchor = TrustAnchor(certificate, null)

        override fun toString(): String = derEncoded.encodeBase64()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            return other is Certificate &&
                    certificate.encoded.contentEquals(other.certificate.encoded) &&
                    androidValidityPolicy() == other.androidValidityPolicy()
        }

        override fun hashCode(): Int =
            31 * certificate.encoded.contentHashCode() + (androidValidityPolicy()?.hashCode() ?: 0)

        class AndroidSpecific(
            certificate: java.security.cert.X509Certificate,
            override val enforceFactoryProvisionedChainValidity: Boolean,
        ) : Certificate(certificate), TrustedRoot.AndroidSpecific

        companion object {
            /** Constructs an Android-specific certificate trust root. */
            operator fun invoke(
                certificate: java.security.cert.X509Certificate,
                enforceFactoryProvisionedChainValidity: Boolean,
            ): Certificate = AndroidSpecific(certificate, enforceFactoryProvisionedChainValidity)
        }
    }

    val publicKey: java.security.PublicKey


    val derEncoded: ByteArray get() = value.encodeToDer()

    val trustAnchor: TrustAnchor

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

private fun TrustedRoot.androidValidityPolicy(): Boolean? =
    (this as? TrustedRoot.AndroidSpecific)?.enforceFactoryProvisionedChainValidity

object TrustedRootSerializer : KSerializer<TrustedRoot> {
    @OptIn(SealedSerializationApi::class)
    override val descriptor: SerialDescriptor
        get() = object : SerialDescriptor {
            override val serialName = "TrustedRoot"
            override val kind = SerialKind.CONTEXTUAL
            override val elementsCount = 0

            override fun getElementName(index: Int): String =
                throw IndexOutOfBoundsException()

            override fun getElementIndex(name: String): Int =
                CompositeDecoder.UNKNOWN_NAME

            override fun getElementAnnotations(index: Int): List<Annotation> =
                emptyList()

            override fun getElementDescriptor(index: Int): SerialDescriptor =
                throw IndexOutOfBoundsException()

            override fun isElementOptional(index: Int): Boolean =
                throw IndexOutOfBoundsException()
        }

    override fun serialize(
        encoder: Encoder,
        value: TrustedRoot
    ) {
        val pem = when (value) {
            is TrustedRoot.Certificate -> value.certificate.toKmpCertificate().getOrThrow().encodeToPEM().getOrThrow()
            is TrustedRoot.PublicKey -> value.publicKey.toCryptoPublicKey().getOrThrow().encodeToPEM().getOrThrow()
        }
        val caName = (value as? TrustedRoot.PublicKey)?.caName?.name
        val policy = value.androidValidityPolicy()
        if (caName == null && policy == null) {
            encoder.encodeString(pem)
        } else when (encoder) {
            is JsonEncoder -> encoder.encodeJsonElement(JsonArray(buildList {
                add(JsonPrimitive(pem))
                caName?.let { add(JsonPrimitive(it)) }
                policy?.let { add(JsonPrimitive(it)) }
            }))

            else -> encoder.encodeSerializableValue(
                YamlElement.serializer(),
                YamlList(buildList {
                    add(YamlLiteral(pem))
                    caName?.let { add(YamlLiteral(it)) }
                    policy?.let { add(YamlLiteral(it.toString())) }
                }),
            )
        }
    }

    override fun deserialize(decoder: Decoder): TrustedRoot {
        val values = when (decoder) {
            is JsonDecoder -> decoder.decodeJsonElement().let { element ->
                when (element) {
                    is JsonPrimitive -> listOf(element.content to false)
                    is JsonArray -> element.map {
                        require(it is JsonPrimitive) { "Trust root entries must be strings or booleans" }
                        it.content to it.isString.not()
                    }

                    else -> error("Trust root must be a string or list")
                }
            }

            else -> decoder.decodeSerializableValue(YamlElement.serializer()).let { element ->
                when (element) {
                    is YamlLiteral -> listOf(requireNotNull(element.content) to false)
                    is YamlList -> element.map {
                        require(it is YamlLiteral) { "Trust root entries must be scalar values" }
                        requireNotNull(it.content) to false
                    }

                    else -> error("Trust root must be a scalar or list")
                }
            }
        }

        require(values.isNotEmpty()) { "Trust root list must not be empty" }
        val policies = values.filter { (value, isBoolean) -> isBoolean || value == "true" || value == "false" }
        require(policies.size <= 1) { "Trust root may contain at most one validity policy" }
        val policy = policies.singleOrNull()?.first?.toBooleanStrictOrNull()
        require(policy != null || policies.isEmpty()) { "Trust root validity policy must be a boolean" }
        val strings =
            values.filterNot { (value, isBoolean) -> isBoolean || value == "true" || value == "false" }.map { it.first }
        require(strings.isNotEmpty()) { "Trust root is missing its PEM value" }

        val publicKey = strings.firstNotNullOfOrNull { pem ->
            catchingUnwrapped {
                CryptoPublicKey.decodeFromPem(pem).getOrThrow().toJcaPublicKey().getOrThrow()
            }.getOrNull()
        }
        if (publicKey != null) {
            val caNames = strings.filter { pem ->
                catchingUnwrapped { CryptoPublicKey.decodeFromPem(pem).getOrThrow() }.isFailure
            }
            require(caNames.size <= 1) { "Public-key trust root may contain at most one CA name" }
            return if (policy == null) TrustedRoot.PublicKey(publicKey, caNames.singleOrNull()?.let(::X500Principal))
            else TrustedRoot.PublicKey(publicKey, caNames.singleOrNull()?.let(::X500Principal), policy)
        }

        val certificates = strings.mapNotNull { pem ->
            catchingUnwrapped {
                at.asitplus.signum.indispensable.pki.X509Certificate.decodeFromPem(pem).getOrThrow()
                    .toJcaCertificateBlocking().getOrThrow()
            }.getOrNull()
        }
        require(certificates.size == 1 && strings.size == 1) { "Certificate trust root must contain exactly one PEM certificate" }
        return if (policy == null) TrustedRoot.Certificate(certificates.single())
        else TrustedRoot.Certificate(certificates.single(), policy)
    }
}
