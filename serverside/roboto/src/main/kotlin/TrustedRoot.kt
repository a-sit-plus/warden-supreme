package at.asitplus.attestation.android

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.Certificate as SignumCertificate
import at.asitplus.signum.indispensable.pki.Name
import io.ktor.util.*
import kotlinx.serialization.*
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
import kotlin.io.encoding.Base64

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
    val value: WithSourceRepresentation

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
        override val value: CryptoPublicKey,
        val name: Name? = null,
    ) : TrustedRoot {
        @JvmOverloads
        constructor(publicKey: java.security.PublicKey, caName: X500Principal? = null) :
            this(publicKey.toCryptoPublicKey(), caName?.let { Name.fromAsn1(it.encoded) })

        constructor(encoded: ByteArray) : this(CryptoPublicKey.fromAsn1(encoded))

        override val cryptoPublicKey: CryptoPublicKey get() = value

        /** Java compatibility accessors; the stored key and name are Signum models. */
        override val publicKey: java.security.PublicKey get() = value.toJcaPublicKey()
        val caName: X500Principal? get() = name?.let { X500Principal(it.asn1.toDer()) }
        override val trustAnchor: TrustAnchor get() = TrustAnchor(
            caName ?: X500Principal("CN=" + MessageDigest.getInstance("SHA-256").digest(derEncoded)), publicKey, null,
        )

        override fun toString(): String = derEncoded.encodeBase64()

        override fun equals(other: Any?): Boolean = this === other || other is PublicKey &&
            derEncoded.contentEquals(other.derEncoded) && caName == other.caName &&
            androidValidityPolicy() == other.androidValidityPolicy()

        override fun hashCode(): Int =
            31 * (31 * derEncoded.contentHashCode() + (caName?.hashCode() ?: 0)) +
                (androidValidityPolicy()?.hashCode() ?: 0)

        class AndroidSpecific @JvmOverloads constructor(
            value: CryptoPublicKey,
            name: Name? = null,
            override val enforceFactoryProvisionedChainValidity: Boolean,
        ) : PublicKey(value, name), TrustedRoot.AndroidSpecific {
            @JvmOverloads
            constructor(publicKey: java.security.PublicKey, caName: X500Principal? = null,
                enforceFactoryProvisionedChainValidity: Boolean) :
                this(publicKey.toCryptoPublicKey(), caName?.let { Name.fromAsn1(it.encoded) }, enforceFactoryProvisionedChainValidity)

            override fun toString() =
                "[${super.toString()},  enforceFactoryProvisionedChainValidity=$enforceFactoryProvisionedChainValidity]"
        }

        companion object {
            operator fun invoke(value: CryptoPublicKey, name: Name? = null,
                enforceFactoryProvisionedChainValidity: Boolean): PublicKey =
                AndroidSpecific(value, name, enforceFactoryProvisionedChainValidity)

            operator fun invoke(publicKey: java.security.PublicKey, caName: X500Principal? = null,
                enforceFactoryProvisionedChainValidity: Boolean): PublicKey =
                AndroidSpecific(publicKey, caName, enforceFactoryProvisionedChainValidity)
        }
    }

    @Serializable(with = TrustedRootSerializer::class)
    open class Certificate(override val value: SignumCertificate) : TrustedRoot {
        constructor(certificate: java.security.cert.X509Certificate) : this(certificate.toKmpCertificate())
        constructor(encoded: ByteArray) : this(SignumCertificate.fromAsn1(encoded))

        override val cryptoPublicKey: CryptoPublicKey get() = value.publicKey

        /** Java compatibility accessors; certificate data is stored only in Signum form. */
        val certificate: java.security.cert.X509Certificate get() = value.toJcaCertificateBlocking()
        override val publicKey: java.security.PublicKey get() = cryptoPublicKey.toJcaPublicKey()
        override val trustAnchor: TrustAnchor get() = TrustAnchor(certificate, null)

        override fun toString(): String = Base64.encode(derEncoded)

        override fun equals(other: Any?): Boolean = this === other || other is Certificate &&
            derEncoded.contentEquals(other.derEncoded) && androidValidityPolicy() == other.androidValidityPolicy()

        override fun hashCode(): Int = 31 * derEncoded.contentHashCode() + (androidValidityPolicy()?.hashCode() ?: 0)

        class AndroidSpecific(
            value: SignumCertificate,
            override val enforceFactoryProvisionedChainValidity: Boolean,
        ) : Certificate(value), TrustedRoot.AndroidSpecific {
            constructor(certificate: java.security.cert.X509Certificate, enforceFactoryProvisionedChainValidity: Boolean) :
                this(certificate.toKmpCertificate(), enforceFactoryProvisionedChainValidity)

            override fun toString() =
                "[${super.toString()},  enforceFactoryProvisionedChainValidity=$enforceFactoryProvisionedChainValidity]"
        }

        companion object {
            operator fun invoke(value: SignumCertificate, enforceFactoryProvisionedChainValidity: Boolean): Certificate =
                AndroidSpecific(value, enforceFactoryProvisionedChainValidity)

            operator fun invoke(certificate: java.security.cert.X509Certificate,
                enforceFactoryProvisionedChainValidity: Boolean): Certificate =
                AndroidSpecific(certificate, enforceFactoryProvisionedChainValidity)
        }
    }

    val cryptoPublicKey: CryptoPublicKey
    val publicKey: java.security.PublicKey

    val derEncoded: ByteArray
        get() = when (this) {
            is PublicKey -> value.asn1.toDer()
            is Certificate -> value.asn1.toDer()
        }

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
        operator fun invoke(cert: SignumCertificate) = TrustedRoot.Certificate(cert)
        operator fun invoke(publicKey: CryptoPublicKey, name: Name? = null) = TrustedRoot.PublicKey(publicKey, name)
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
            is TrustedRoot.Certificate -> value.value.asn1.toPem()
            is TrustedRoot.PublicKey -> value.value.asn1.toPem()
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
                CryptoPublicKey.fromAsn1(pem)
            }.getOrNull()
        }
        if (publicKey != null) {
            val caNames = strings.filter { pem ->
                catchingUnwrapped { CryptoPublicKey.fromAsn1(pem) }.isFailure
            }
            require(caNames.size <= 1) { "Public-key trust root may contain at most one CA name" }
            return if (policy == null) TrustedRoot.PublicKey(publicKey, caNames.singleOrNull()?.let(Name::fromString))
            else TrustedRoot.PublicKey(publicKey, caNames.singleOrNull()?.let(Name::fromString), policy)
        }

        val certificates = strings.mapNotNull { pem ->
            catchingUnwrapped {
                SignumCertificate.fromAsn1(pem)
            }.getOrNull()
        }
        require(certificates.size == 1 && strings.size == 1) { "Certificate trust root must contain exactly one PEM certificate" }
        return if (policy == null) TrustedRoot.Certificate(certificates.single())
        else TrustedRoot.Certificate(certificates.single(), policy)
    }
}
