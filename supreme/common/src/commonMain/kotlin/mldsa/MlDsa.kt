package at.asitplus.attestation.supreme.mldsa

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.io.UVarInt
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.dsl.PlatformSigningKeyConfigurationBase
import at.asitplus.signum.indispensable.Asn1PublicKeyFormatProvider
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.SignatureFormatProvider
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.sign.Asn1SignatureAlgorithmProvider
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.supreme.installSupreme
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ML-DSA (FIPS 204) parameter sets, with their X.509 OIDs as per RFC 9881.
 *
 * Platform support: Android Keystore (API 37+, KeyMint ≥ 5) and Apple CryptoKit (iOS 26+) only offer
 * [ML_DSA_65] and [ML_DSA_87]. [ML_DSA_44] is only available on the JVM (BouncyCastle).
 */
@Serializable
enum class MlDsaParameterSet(
    val oid: ObjectIdentifier,
    /** JCA algorithm name of this parameter set (also the Android Keystore key algorithm name). */
    val jcaName: String,
    /** Length of the raw FIPS 204 public key encoding in bytes. */
    val publicKeySize: Int,
    /** Length of a signature in bytes. */
    val signatureSize: Int,
) {
    @SerialName("ML-DSA-44")
    ML_DSA_44(ObjectIdentifier("2.16.840.1.101.3.4.3.17"), "ML-DSA-44", 1312, 2420),

    @SerialName("ML-DSA-65")
    ML_DSA_65(ObjectIdentifier("2.16.840.1.101.3.4.3.18"), "ML-DSA-65", 1952, 3309),

    @SerialName("ML-DSA-87")
    ML_DSA_87(ObjectIdentifier("2.16.840.1.101.3.4.3.19"), "ML-DSA-87", 2592, 4627);

    /** RFC 9881: the parameters field MUST be absent. */
    val algorithmIdentifier: X509AlgorithmIdentifier get() = X509AlgorithmIdentifier(oid, null)

    companion object {
        fun byOid(oid: ObjectIdentifier): MlDsaParameterSet? = entries.firstOrNull { it.oid == oid }
        fun byJcaName(name: String): MlDsaParameterSet? = entries.firstOrNull { it.jcaName.equals(name, ignoreCase = true) }
    }
}

/** Pure ML-DSA (no pre-hashing, empty context) as used in X.509 (RFC 9881). One singleton per parameter set. */
class MlDsaSignatureAlgorithm private constructor(val parameterSet: MlDsaParameterSet) : SignatureAlgorithm {
    override val sourceRepresentation = SourceRepresentationStorage()
    override fun toString() = "MlDsaSignatureAlgorithm(${parameterSet.jcaName})"

    companion object {
        val ML_DSA_44 = MlDsaSignatureAlgorithm(MlDsaParameterSet.ML_DSA_44)
        val ML_DSA_65 = MlDsaSignatureAlgorithm(MlDsaParameterSet.ML_DSA_65)
        val ML_DSA_87 = MlDsaSignatureAlgorithm(MlDsaParameterSet.ML_DSA_87)

        operator fun get(parameterSet: MlDsaParameterSet) = when (parameterSet) {
            MlDsaParameterSet.ML_DSA_44 -> ML_DSA_44
            MlDsaParameterSet.ML_DSA_65 -> ML_DSA_65
            MlDsaParameterSet.ML_DSA_87 -> ML_DSA_87
        }
    }
}

/** An ML-DSA public key in its raw FIPS 204 encoding. */
class MlDsaPublicKey(val parameterSet: MlDsaParameterSet, rawBytes: ByteArray) : PublicKey {
    private val raw = rawBytes.copyOf()

    init {
        require(raw.size == parameterSet.publicKeySize) {
            "${parameterSet.jcaName} public key must be ${parameterSet.publicKeySize} bytes, got ${raw.size}"
        }
    }

    /** The raw FIPS 204 public key encoding (copy). */
    val rawBytes: ByteArray get() = raw.copyOf()

    val signatureAlgorithm: MlDsaSignatureAlgorithm get() = MlDsaSignatureAlgorithm[parameterSet]

    override val sourceRepresentation = SourceRepresentationStorage()
    override val additionalProperties: MutableMap<String, String> = mutableMapOf()
    override val didCodec: UVarInt get() = throw UnsupportedOperationException("DID encoding of ML-DSA keys is not supported")
    override val didKeyBytes: ByteArray get() = throw UnsupportedOperationException("DID encoding of ML-DSA keys is not supported")

    internal fun toSubjectPublicKeyInfo() = SubjectPublicKeyInfo(parameterSet.algorithmIdentifier, Asn1BitString(raw))

    override fun equals(other: Any?) =
        (this === other) || ((other is MlDsaPublicKey) && (parameterSet == other.parameterSet) && raw.contentEquals(other.raw))

    override fun hashCode() = 31 * parameterSet.hashCode() + raw.contentHashCode()
    override fun toString() = "MlDsaPublicKey(${parameterSet.jcaName}, ${raw.size} bytes)"
}

/** An ML-DSA signature (raw FIPS 204 encoding). */
class MlDsaSignature(rawBytes: ByteArray) : Signature {
    private val raw = rawBytes.copyOf()

    val rawBytes: ByteArray get() = raw.copyOf()

    override val sourceRepresentation = SourceRepresentationStorage()
    override val humanReadableString: String get() = "MlDsaSignature(${raw.size} bytes)"

    override fun equals(other: Any?) = (this === other) || ((other is MlDsaSignature) && raw.contentEquals(other.raw))
    override fun hashCode() = raw.contentHashCode()
    override fun toString() = humanReadableString
}

/**
 * Pure ASN.1 support for ML-DSA keys, algorithm identifiers and signatures (RFC 9881).
 * Declines everything that is not ML-DSA.
 */
object MlDsaAsn1Provider : Asn1PublicKeyFormatProvider, Asn1SignatureAlgorithmProvider, SignatureFormatProvider {

    override fun encodeToAsn1(value: PublicKey): SubjectPublicKeyInfo? =
        (value as? MlDsaPublicKey)?.toSubjectPublicKeyInfo()

    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): PublicKey? {
        val set = MlDsaParameterSet.byOid(publicKeyInfo.algorithmOid) ?: return null
        require(publicKeyInfo.algorithmParameters == null) { "${set.jcaName} SubjectPublicKeyInfo must not carry parameters (RFC 9881)" }
        val bits = publicKeyInfo.subjectPublicKey
        require(bits.numPaddingBits == 0) { "${set.jcaName} public key must not have padding bits" }
        return MlDsaPublicKey(set, bits.bitCarryingBytes)
    }

    override fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): PublicKey? = null

    override fun encodeToAsn1(value: SignatureAlgorithm): X509AlgorithmIdentifier? =
        (value as? MlDsaSignatureAlgorithm)?.parameterSet?.algorithmIdentifier

    override fun decodeFromAsn1(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm? {
        val set = MlDsaParameterSet.byOid(algorithmIdentifier.oid) ?: return null
        require(algorithmIdentifier.parameters == null) { "${set.jcaName} AlgorithmIdentifier must not carry parameters (RFC 9881)" }
        return MlDsaSignatureAlgorithm[set]
    }

    override fun encodeToAsn1(value: Signature): X509SignatureValue? =
        (value as? MlDsaSignature)?.let { X509SignatureValue(it.rawBytes) }

    override fun parseSignature(signatureAlgorithm: SignatureAlgorithm, signature: X509SignatureValue): Signature? =
        if (signatureAlgorithm is MlDsaSignatureAlgorithm) MlDsaSignature(signature.rawBytes) else null

    override fun parseSignature(x509Algorithm: X509AlgorithmIdentifier, signature: X509SignatureValue): Signature? =
        MlDsaParameterSet.byOid(x509Algorithm.oid)?.let { MlDsaSignature(signature.rawBytes) }
}

/** DSL configuration for an ML-DSA key. */
class MlDsaKeyConfiguration : DSL.Data() {
    /** The ML-DSA parameter set. Defaults to [MlDsaParameterSet.ML_DSA_65]. */
    var parameterSet: MlDsaParameterSet = MlDsaParameterSet.ML_DSA_65
}

/**
 * Generates an ML-DSA key: `createSigningKey(alias) { mlDsa { parameterSet = ML_DSA_65 } }`.
 * Requires [installWardenMlDsa].
 */
val PlatformSigningKeyConfigurationBase<*>.mlDsa
    get() = _algSpecific.option("WARDEN_ML_DSA", ::MlDsaKeyConfiguration)

/** Platform-specific ML-DSA providers (JCA/BC on the JVM, Android Keystore, CryptoKit on iOS). */
internal expect fun installPlatformMlDsa()

private val installMlDsa by lazy {
    // Supreme's providers first: ServiceLoader prefers the most recently registered provider, and Supreme's
    // Android key generator throws (instead of declining) for algorithms it does not know.
    Signum.installSupreme()
    ServiceLoader.register<Asn1PublicKeyFormatProvider>(MlDsaAsn1Provider)
    ServiceLoader.register<Asn1SignatureAlgorithmProvider>(MlDsaAsn1Provider)
    ServiceLoader.register<SignatureFormatProvider>(MlDsaAsn1Provider)
    installPlatformMlDsa()
}

/** Installs Warden's ML-DSA providers into Signum. Idempotent. Also installs Supreme. */
@Suppress("UnusedReceiverParameter")
fun Signum.installWardenMlDsa() {
    installMlDsa
}
